"""Approval authentication: mandatory password for approve/reject.

Password uses getpass (reads from /dev/tty, no echo) to block
both AI-via-Bash AND expect-style terminal automation.
A password must be configured before approvals are allowed.

Password hashes are stored in /var/lib/aiir/passwords/{examiner}.json
(0o600, directory 0o700) — protected by Read/Edit/Write deny
rules so the LLM cannot access the hash material. Auto-migration
from the legacy config.yaml location happens on first use.
"""

from __future__ import annotations

import getpass as getpass_mod
import hashlib
import json
import os
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
_LOCKOUT_FILE = Path.home() / ".aiir" / ".password_lockout"
_MIN_PASSWORD_LENGTH = 8
_PASSWORDS_DIR = Path("/var/lib/aiir/passwords")


def _validate_examiner_name(analyst: str) -> None:
    """Reject examiner names containing path traversal characters."""
    if ".." in analyst or "/" in analyst or "\\" in analyst:
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
    """Migrate /var/lib/aiir/pins/ → /var/lib/aiir/passwords/ if needed."""
    old_dir = Path("/var/lib/aiir/pins")
    if old_dir.is_dir() and not _PASSWORDS_DIR.is_dir():
        try:
            old_dir.rename(_PASSWORDS_DIR)
        except OSError:
            pass

    # Migrate lockout file: .pin_lockout → .password_lockout
    old_lockout = Path.home() / ".aiir" / ".pin_lockout"
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
    # Parent is root-owned — use sudo.
    # Safety: passwords_dir is always _PASSWORDS_DIR (hardcoded constant).
    # This is NOT safe for arbitrary user input — do not generalize.
    user = getpass_mod.getuser()
    print(f"Creating {passwords_dir}/ (requires sudo)...")
    result = subprocess.run(
        [
            "sudo",
            "sh",
            "-c",
            f"mkdir -p {passwords_dir} && chown {user}:{user} {passwords_dir} && chmod 700 {passwords_dir}",
        ],
        timeout=30,
    )
    if result.returncode != 0:
        print(
            f"Could not create {passwords_dir}/. Create it manually:\n"
            f"  sudo mkdir -p {passwords_dir} && "
            f"sudo chown $USER:$USER {passwords_dir} && "
            f"sudo chmod 700 {passwords_dir}",
            file=sys.stderr,
        )
        sys.exit(1)


def require_confirmation(config_path: Path, analyst: str) -> tuple[str, str | None]:
    """Require password confirmation. Returns (mode, password).

    Returns ('password', raw_password_string) on success. The raw password
    is needed for HMAC derivation in the verification ledger.

    Password must be configured for the analyst. If not, prints setup
    instructions and exits.

    Raises SystemExit on failure, lockout, or missing password.
    """
    if not has_password(config_path, analyst):
        print(
            "No approval password configured. Set one with:\n  aiir config --setup-password\n",
            file=sys.stderr,
        )
        sys.exit(1)
    _check_lockout(analyst)
    password = getpass_prompt("Enter password to confirm: ")
    if not verify_password(config_path, analyst, password):
        _record_failure(analyst)
        remaining = _MAX_PASSWORD_ATTEMPTS - _recent_failure_count(analyst)
        if remaining <= 0:
            print(
                f"Too many failed attempts. Locked out for {_LOCKOUT_SECONDS}s.",
                file=sys.stderr,
            )
        else:
            print(
                f"Incorrect password. {remaining} attempt(s) remaining.",
                file=sys.stderr,
            )
        sys.exit(1)
    _clear_failures(analyst)
    return ("password", password)


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


def has_password(
    config_path: Path, analyst: str, *, passwords_dir: Path | None = None
) -> bool:
    """Check if analyst has a password configured (new location, fallback old)."""
    passwords_dir = passwords_dir or _PASSWORDS_DIR
    _maybe_migrate_pin_dir()
    _maybe_migrate(config_path, passwords_dir, analyst)
    if _load_password_entry(passwords_dir, analyst) is not None:
        return True
    # Fallback: legacy config.yaml
    config = _load_config(config_path)
    section = config.get("passwords", config.get("pins", {}))
    return (
        isinstance(section, dict)
        and analyst in section
        and "hash" in section[analyst]
        and "salt" in section[analyst]
    )


def verify_password(
    config_path: Path, analyst: str, password: str, *, passwords_dir: Path | None = None
) -> bool:
    """Verify a password against stored hash (new location, fallback old)."""
    passwords_dir = passwords_dir or _PASSWORDS_DIR
    _maybe_migrate(config_path, passwords_dir, analyst)
    entry = _load_password_entry(passwords_dir, analyst)
    if entry is None:
        # Fallback: legacy config.yaml
        config = _load_config(config_path)
        section = config.get("passwords", config.get("pins", {}))
        entry = section.get(analyst) if isinstance(section, dict) else None
    if not entry:
        return False
    try:
        stored_hash = entry["hash"]
        salt = bytes.fromhex(entry["salt"])
    except (KeyError, ValueError):
        return False
    computed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PBKDF2_ITERATIONS
    ).hex()
    return secrets.compare_digest(computed, stored_hash)


def setup_password(
    config_path: Path, analyst: str, *, passwords_dir: Path | None = None
) -> str:
    """Set up a new password for the analyst. Prompts twice to confirm.

    Returns the raw password string (needed for HMAC re-signing during rotation).
    """
    passwords_dir = passwords_dir or _PASSWORDS_DIR
    _maybe_migrate_pin_dir()
    _maybe_migrate(config_path, passwords_dir, analyst)
    _ensure_passwords_dir(passwords_dir)
    pw1 = getpass_prompt("Enter new password: ")
    if not pw1:
        print("Password cannot be empty.", file=sys.stderr)
        sys.exit(1)
    if len(pw1) < _MIN_PASSWORD_LENGTH:
        print(
            f"Password must be at least {_MIN_PASSWORD_LENGTH} characters.",
            file=sys.stderr,
        )
        sys.exit(1)
    pw2 = getpass_prompt("Confirm new password: ")
    if pw1 != pw2:
        print("Passwords do not match.", file=sys.stderr)
        sys.exit(1)

    salt = secrets.token_bytes(32)
    pw_hash = hashlib.pbkdf2_hmac("sha256", pw1.encode(), salt, PBKDF2_ITERATIONS).hex()

    entry = {"hash": pw_hash, "salt": salt.hex()}

    _save_password_entry(passwords_dir, analyst, entry)

    # Strip old location if present
    config = _load_config(config_path)
    for key in ("passwords", "pins"):
        if key in config and analyst in config[key]:
            del config[key][analyst]
            if not config[key]:
                del config[key]
    _save_config(config_path, config)

    print(f"Password configured for analyst '{analyst}'.")
    return pw1


def reset_password(
    config_path: Path, analyst: str, *, passwords_dir: Path | None = None
) -> None:
    """Reset password. Requires current password first.

    After changing the password, re-signs all verification ledger entries
    for this analyst with the new key.
    """
    if not has_password(config_path, analyst, passwords_dir=passwords_dir):
        print(
            f"No password configured for analyst '{analyst}'. Use --setup-password first.",
            file=sys.stderr,
        )
        sys.exit(1)

    current = getpass_prompt("Enter current password: ")
    if not verify_password(config_path, analyst, current, passwords_dir=passwords_dir):
        print("Incorrect current password.", file=sys.stderr)
        print(
            "\nIf you have forgotten your password, you can force a reset by removing\n"
            "the password file and setting up a new one:\n"
            f"\n  rm /var/lib/aiir/passwords/{analyst}.json"
            "\n  aiir config --setup-password\n"
            "\nThis will invalidate HMAC signatures on previously approved findings.\n"
            "The findings themselves are preserved — only the integrity proof is lost.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Read old salt before setup_password overwrites it
    old_salt = get_analyst_salt(config_path, analyst, passwords_dir=passwords_dir)

    new_password = setup_password(config_path, analyst, passwords_dir=passwords_dir)

    # Re-HMAC verification ledger entries with new key
    new_salt = get_analyst_salt(config_path, analyst, passwords_dir=passwords_dir)
    try:
        from aiir_cli.verification import (
            VERIFICATION_DIR,
            derive_hmac_key,
            rehmac_entries,
        )

        if VERIFICATION_DIR.is_dir():
            old_key = derive_hmac_key(current, old_salt)
            new_key = derive_hmac_key(new_password, new_salt)
            for ledger_file in VERIFICATION_DIR.glob("*.jsonl"):
                case_id = ledger_file.stem
                count = rehmac_entries(
                    case_id,
                    analyst,
                    current,
                    old_salt,
                    new_password,
                    new_salt,
                    old_key=old_key,
                    new_key=new_key,
                )
                if count:
                    print(
                        f"  Re-signed {count} ledger entry/entries for case {case_id}."
                    )
    except (ImportError, OSError) as e:
        print(f"  Warning: could not re-sign ledger entries: {e}", file=sys.stderr)


def get_analyst_salt(
    config_path: Path, analyst: str, *, passwords_dir: Path | None = None
) -> bytes:
    """Get the analyst's PBKDF2 salt. Raises ValueError if missing."""
    passwords_dir = passwords_dir or _PASSWORDS_DIR
    _maybe_migrate(config_path, passwords_dir, analyst)
    entry = _load_password_entry(passwords_dir, analyst)
    if entry is None:
        # Fallback: legacy config.yaml
        config = _load_config(config_path)
        section = config.get("passwords", config.get("pins", {}))
        entry = section.get(analyst) if isinstance(section, dict) else None
    if not entry or "salt" not in entry:
        raise ValueError(f"No salt found for analyst '{analyst}'")
    return bytes.fromhex(entry["salt"])


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
            chars = []
            while True:
                ch = os.read(fd, 1).decode("utf-8", errors="replace")
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
