"""Approval authentication: mandatory password for approve/reject.

The password is read from /dev/tty without echo. That stops a plain shell
pipe from supplying it. It doesn't stop a program that runs vhir under a
pseudo-terminal, or a process with administrative rights (limit 3). The
Claude Code deny rules for `vhir approve`/`vhir reject` stop an assistant's
shell tool from running them. They guard against accidents and aren't a
security boundary. Credential files are readable by processes running as the
examiner (limit 2).
A password must be configured before approvals are allowed.

Password hashes are stored in /var/lib/vhir/passwords/{examiner}.json
(0o600, directory 0o700). Claude Code's deny rules keep that client's own
tools from reading them; other programs running as the examiner's user can
(the hash is also the ledger's signing key). Auto-migration from the legacy
config.yaml location happens on first use.
"""

from __future__ import annotations

import codecs
import getpass as getpass_mod
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time

try:
    import termios
    import tty

    _HAS_TERMIOS = True
except ImportError:
    _HAS_TERMIOS = False
from pathlib import Path

import yaml

PBKDF2_ITERATIONS = 600_000
_MAX_PASSWORD_ATTEMPTS = 3
_LOCKOUT_SECONDS = 900  # 15 minutes
_LOCKOUT_FILE = Path.home() / ".vhir" / ".password_lockout"
_MIN_PASSWORD_LENGTH = 8
_PASSWORDS_DIR = Path("/var/lib/vhir/passwords")


_EXAMINER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")


def _validate_examiner_name(analyst: str) -> None:
    """Reject examiner names that don't match canonical slug format."""
    if not _EXAMINER_RE.fullmatch(analyst):
        raise ValueError(f"Invalid examiner name: {analyst!r}")


def _password_file(passwords_dir: Path, analyst: str) -> Path:
    """Return the per-examiner password file path."""
    _validate_examiner_name(analyst)
    return passwords_dir / f"{analyst}.json"


def _load_password_entry(passwords_dir: Path, analyst: str) -> dict | None:
    """Load password entry from per-examiner JSON file. Returns None if missing."""
    path = _password_file(passwords_dir, analyst)
    try:
        data = json.loads(path.read_text())
        if isinstance(data, dict) and "hash" in data and "salt" in data:
            return data
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return None


def _save_password_entry(passwords_dir: Path, analyst: str, entry: dict) -> None:
    """Write password entry atomically with 0o600 permissions."""
    _validate_examiner_name(analyst)
    passwords_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = _password_file(passwords_dir, analyst)
    fd, tmp_path = tempfile.mkstemp(dir=str(passwords_dir), suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(entry, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _maybe_migrate_pin_dir() -> None:
    """Migrate /var/lib/vhir/pins/ → /var/lib/vhir/passwords/ if needed."""
    old_dir = Path("/var/lib/vhir/pins")
    if old_dir.is_dir() and not _PASSWORDS_DIR.is_dir():
        try:
            old_dir.rename(_PASSWORDS_DIR)
        except OSError:
            pass

    # Migrate lockout file: .pin_lockout → .password_lockout
    old_lockout = Path.home() / ".vhir" / ".pin_lockout"
    if old_lockout.exists() and not _LOCKOUT_FILE.exists():
        try:
            old_lockout.rename(_LOCKOUT_FILE)
        except OSError:
            pass


def _maybe_migrate(config_path: Path, passwords_dir: Path, analyst: str) -> None:
    """Auto-migrate password from config.yaml to per-examiner file.

    1. If new location already has the file → no-op.
    2. If old config.yaml has passwords.{analyst} (or legacy pins.{analyst}) → copy to new, strip from old.
    3. If new location write fails → silently continue using old.
    """
    if _load_password_entry(passwords_dir, analyst) is not None:
        return
    config = _load_config(config_path)
    # Check both new key and legacy key
    section = config.get("passwords", config.get("pins", {}))
    entry = section.get(analyst) if isinstance(section, dict) else None
    if not entry or "hash" not in entry or "salt" not in entry:
        return
    try:
        _save_password_entry(
            passwords_dir, analyst, {"hash": entry["hash"], "salt": entry["salt"]}
        )
    except OSError:
        return  # New location not writable — keep using old
    # Strip from config.yaml (both keys)
    for key in ("passwords", "pins"):
        if key in config and analyst in config[key]:
            del config[key][analyst]
            if not config[key]:
                del config[key]
    _save_config(config_path, config)


def _ensure_passwords_dir(passwords_dir: Path) -> None:
    """Ensure the passwords directory exists, creating with sudo if needed."""
    if passwords_dir.is_dir():
        return
    # Try normal mkdir first (works if parent is user-owned)
    try:
        passwords_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        return
    except OSError:
        pass
    # Parent is root-owned — use sudo with list args (no shell interpolation).
    user = getpass_mod.getuser()
    print(f"Creating {passwords_dir}/ (requires sudo)...")
    for cmd in [
        ["sudo", "mkdir", "-p", str(passwords_dir)],
        ["sudo", "chown", f"{user}:{user}", str(passwords_dir)],
        ["sudo", "chmod", "700", str(passwords_dir)],
    ]:
        result = subprocess.run(cmd, timeout=30)
        if result.returncode != 0:
            break
    if result.returncode != 0:
        print(
            f"Could not create {passwords_dir}/. Create it manually:\n"
            f"  sudo mkdir -p {passwords_dir} && "
            f"sudo chown $USER:$USER {passwords_dir} && "
            f"sudo chmod 700 {passwords_dir}",
            file=sys.stderr,
        )
        sys.exit(1)


def require_tty_confirmation(prompt: str) -> bool:
    """Prompt y/N via /dev/tty. Returns True if confirmed."""
    try:
        tty = open("/dev/tty")
    except OSError:
        print(
            "No terminal available (/dev/tty). Cannot confirm interactively.",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        sys.stderr.write(prompt)
        sys.stderr.flush()
        response = tty.readline().strip().lower()
        return response == "y"
    finally:
        tty.close()


def verify_password(
    config_path: Path, analyst: str, password: str, *, passwords_dir: Path | None = None
) -> str | None:
    """The reading of `password` that reproduces the stored hash (new
    location, fallback old), or None. That is the typed text, or for a 0.6
    entry stored byte by byte, its 0.6 reading. Derive keys only from it."""
    passwords_dir = passwords_dir or _PASSWORDS_DIR
    _maybe_migrate(config_path, passwords_dir, analyst)
    entry = _load_password_entry(passwords_dir, analyst)
    if entry is None:
        # Fallback: legacy config.yaml
        config = _load_config(config_path)
        section = config.get("passwords", config.get("pins", {}))
        entry = section.get(analyst) if isinstance(section, dict) else None
    if not entry:
        return None
    try:
        stored_hash = entry["hash"]
        salt = bytes.fromhex(entry["salt"])
    except (KeyError, ValueError):
        return None

    def matches(text: str) -> bool:
        computed = hashlib.pbkdf2_hmac(
            "sha256", text.encode(), salt, PBKDF2_ITERATIONS
        ).hex()
        return secrets.compare_digest(computed, stored_hash)

    if matches(password):
        return password
    # 0.6 read each byte on its own, so a non-ASCII password was stored as
    # that reading. Accept it, and mark the entry for the upgrade at the
    # next signed decision.
    legacy = legacy_decoded(password)
    if legacy == password or not matches(legacy):
        return None
    _mark_legacy_decoding(passwords_dir, analyst)
    return legacy


def _mark_legacy_decoding(passwords_dir: Path, analyst: str) -> None:
    """Record on a 0.6 entry that it was stored with the byte-wise reading."""
    entry = _load_password_entry(passwords_dir, analyst)
    if entry is None or entry.get("legacy_decoding"):
        return
    try:
        _save_password_entry(passwords_dir, analyst, {**entry, "legacy_decoding": True})
    except OSError:
        pass  # the password was accepted; the mark is a hint for the upgrade


def _load_failures() -> dict[str, list[float]]:
    """Load failure timestamps from disk. Returns {} on missing/corrupt file."""
    try:
        data = json.loads(_LOCKOUT_FILE.read_text())
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return {}


def _save_failures(data: dict[str, list[float]]) -> None:
    """Write failure timestamps to disk with 0o600 permissions."""
    _LOCKOUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(_LOCKOUT_FILE.parent), suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp_path, str(_LOCKOUT_FILE))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _recent_failure_count(analyst: str) -> int:
    """Count failures within the lockout window."""
    now = time.time()
    failures = _load_failures().get(analyst, [])
    return sum(1 for t in failures if now - t < _LOCKOUT_SECONDS)


def _check_lockout(analyst: str) -> None:
    """Exit if analyst is locked out from too many failed attempts."""
    if _recent_failure_count(analyst) >= _MAX_PASSWORD_ATTEMPTS:
        now = time.time()
        failures = _load_failures().get(analyst, [])
        recent = [t for t in failures if now - t < _LOCKOUT_SECONDS]
        if recent:
            oldest_recent = min(recent)
            remaining = int(_LOCKOUT_SECONDS - (now - oldest_recent))
            remaining = max(remaining, 1)
        else:
            remaining = _LOCKOUT_SECONDS
        print(
            f"Password locked. Too many failed attempts. Try again in {remaining} seconds.",
            file=sys.stderr,
        )
        sys.exit(1)


def _record_failure(analyst: str) -> None:
    """Record a failed password attempt to disk."""
    data = _load_failures()
    data.setdefault(analyst, []).append(time.time())
    _save_failures(data)


def _clear_failures(analyst: str) -> None:
    """Clear failures on successful authentication."""
    data = _load_failures()
    if analyst in data:
        del data[analyst]
        _save_failures(data)


def getpass_prompt(prompt: str) -> str:
    """Read password from /dev/tty with masked input (shows * per keystroke).

    Raises RuntimeError if /dev/tty or termios is unavailable.
    """
    if not _HAS_TERMIOS:
        raise RuntimeError(
            "Password entry requires a terminal with termios support. "
            "Cannot read password without /dev/tty."
        )

    try:
        tty_in = open("/dev/tty")
    except OSError as err:
        raise RuntimeError(
            "Password entry requires /dev/tty. Cannot read password in this environment. "
            "Ensure you are running from an interactive terminal."
        ) from err
    try:
        fd = tty_in.fileno()
        sys.stderr.write(prompt)
        sys.stderr.flush()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            chars = []  # code points: a multi-byte character is one entry
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            while True:
                ch = decoder.decode(os.read(fd, 1))
                if not ch:
                    continue  # the middle of a multi-byte character
                if ch in ("\r", "\n"):
                    break
                elif ch in ("\x7f", "\x08"):  # backspace/delete
                    if chars:
                        chars.pop()
                        sys.stderr.write("\b \b")
                        sys.stderr.flush()
                elif ch == "\x03":  # Ctrl-C
                    sys.stderr.write("\n")
                    sys.stderr.flush()
                    raise KeyboardInterrupt
                elif ch >= " ":  # printable
                    chars.append(ch)
                    sys.stderr.write("*")
                    sys.stderr.flush()
            return "".join(chars)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            sys.stderr.write("\n")
            sys.stderr.flush()
    finally:
        tty_in.close()


def legacy_decoded(password: str) -> str:
    """`password` as 0.6's reader read it: each byte decoded on its own, so
    every byte of a non-ASCII character became U+FFFD. Only the upgrade's
    one retry against a 0.6 verifier uses it."""
    return "".join(
        ch if ord(ch) < 128 else "\ufffd" * len(ch.encode("utf-8")) for ch in password
    )


def _load_config(config_path: Path) -> dict:
    """Load YAML config file."""
    if not config_path.exists():
        return {}
    try:
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except (yaml.YAMLError, OSError):
        return {}


def _save_config(config_path: Path, config: dict) -> None:
    """Save YAML config file atomically with restricted permissions."""
    config_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(config_path.parent), suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
        os.replace(tmp_path, str(config_path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
