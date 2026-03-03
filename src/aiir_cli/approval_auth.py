"""Approval authentication: mandatory PIN for approve/reject.

PIN uses getpass (reads from /dev/tty, no echo) to block
both AI-via-Bash AND expect-style terminal automation.
A PIN must be configured before approvals are allowed.

PIN hashes are stored in /var/lib/aiir/pins/{examiner}.json
(0o600, directory 0o700) — protected by Read/Edit/Write deny
rules so the LLM cannot access the hash material. Auto-migration
from the legacy config.yaml location happens on first use.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
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
_MAX_PIN_ATTEMPTS = 3
_LOCKOUT_SECONDS = 900  # 15 minutes
_LOCKOUT_FILE = Path.home() / ".aiir" / ".pin_lockout"
_MIN_PIN_LENGTH = 4
_PINS_DIR = Path("/var/lib/aiir/pins")


def _validate_examiner_name(analyst: str) -> None:
    """Reject examiner names containing path traversal characters."""
    if ".." in analyst or "/" in analyst or "\\" in analyst:
        raise ValueError(f"Invalid examiner name: {analyst!r}")


def _pin_file(pins_dir: Path, analyst: str) -> Path:
    """Return the per-examiner PIN file path."""
    _validate_examiner_name(analyst)
    return pins_dir / f"{analyst}.json"


def _load_pin_entry(pins_dir: Path, analyst: str) -> dict | None:
    """Load PIN entry from per-examiner JSON file. Returns None if missing."""
    path = _pin_file(pins_dir, analyst)
    try:
        data = json.loads(path.read_text())
        if isinstance(data, dict) and "hash" in data and "salt" in data:
            return data
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return None


def _save_pin_entry(pins_dir: Path, analyst: str, entry: dict) -> None:
    """Write PIN entry atomically with 0o600 permissions."""
    _validate_examiner_name(analyst)
    pins_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = _pin_file(pins_dir, analyst)
    fd, tmp_path = tempfile.mkstemp(dir=str(pins_dir), suffix=".tmp")
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


def _maybe_migrate(config_path: Path, pins_dir: Path, analyst: str) -> None:
    """Auto-migrate PIN from config.yaml to per-examiner file.

    1. If new location already has the file → no-op.
    2. If old config.yaml has pins.{analyst} → copy to new, strip from old.
    3. If new location write fails → silently continue using old.
    """
    if _load_pin_entry(pins_dir, analyst) is not None:
        return
    config = _load_config(config_path)
    pins = config.get("pins", {})
    entry = pins.get(analyst)
    if not entry or "hash" not in entry or "salt" not in entry:
        return
    try:
        _save_pin_entry(
            pins_dir, analyst, {"hash": entry["hash"], "salt": entry["salt"]}
        )
    except OSError:
        return  # New location not writable — keep using old
    # Strip from config.yaml
    del config["pins"][analyst]
    if not config["pins"]:
        del config["pins"]
    _save_config(config_path, config)


def require_confirmation(config_path: Path, analyst: str) -> tuple[str, str | None]:
    """Require PIN confirmation. Returns (mode, pin).

    Returns ('pin', raw_pin_string) on success. The raw PIN is needed
    for HMAC derivation in the verification ledger.

    PIN must be configured for the analyst. If not, prints setup
    instructions and exits.

    Raises SystemExit on failure, lockout, or missing PIN.
    """
    if not has_pin(config_path, analyst):
        print(
            "No approval PIN configured. Set one with:\n  aiir config --setup-pin\n",
            file=sys.stderr,
        )
        sys.exit(1)
    _check_lockout(analyst)
    pin = getpass_prompt("Enter PIN to confirm: ")
    if not verify_pin(config_path, analyst, pin):
        _record_failure(analyst)
        remaining = _MAX_PIN_ATTEMPTS - _recent_failure_count(analyst)
        if remaining <= 0:
            print(
                f"Too many failed attempts. Locked out for {_LOCKOUT_SECONDS}s.",
                file=sys.stderr,
            )
        else:
            print(f"Incorrect PIN. {remaining} attempt(s) remaining.", file=sys.stderr)
        sys.exit(1)
    _clear_failures(analyst)
    return ("pin", pin)


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


def has_pin(config_path: Path, analyst: str, *, pins_dir: Path | None = None) -> bool:
    """Check if analyst has a PIN configured (new location, fallback old)."""
    pins_dir = pins_dir or _PINS_DIR
    _maybe_migrate(config_path, pins_dir, analyst)
    if _load_pin_entry(pins_dir, analyst) is not None:
        return True
    # Fallback: legacy config.yaml
    config = _load_config(config_path)
    pins = config.get("pins", {})
    return analyst in pins and "hash" in pins[analyst] and "salt" in pins[analyst]


def verify_pin(
    config_path: Path, analyst: str, pin: str, *, pins_dir: Path | None = None
) -> bool:
    """Verify a PIN against stored hash (new location, fallback old)."""
    pins_dir = pins_dir or _PINS_DIR
    _maybe_migrate(config_path, pins_dir, analyst)
    entry = _load_pin_entry(pins_dir, analyst)
    if entry is None:
        # Fallback: legacy config.yaml
        config = _load_config(config_path)
        pins = config.get("pins", {})
        entry = pins.get(analyst)
    if not entry:
        return False
    try:
        stored_hash = entry["hash"]
        salt = bytes.fromhex(entry["salt"])
    except (KeyError, ValueError):
        return False
    computed = hashlib.pbkdf2_hmac(
        "sha256", pin.encode(), salt, PBKDF2_ITERATIONS
    ).hex()
    return secrets.compare_digest(computed, stored_hash)


def setup_pin(config_path: Path, analyst: str, *, pins_dir: Path | None = None) -> str:
    """Set up a new PIN for the analyst. Prompts twice to confirm.

    Returns the raw PIN string (needed for HMAC re-signing during rotation).
    """
    pins_dir = pins_dir or _PINS_DIR
    pin1 = getpass_prompt("Enter new PIN: ")
    if not pin1:
        print("PIN cannot be empty.", file=sys.stderr)
        sys.exit(1)
    if len(pin1) < _MIN_PIN_LENGTH:
        print(f"PIN must be at least {_MIN_PIN_LENGTH} characters.", file=sys.stderr)
        sys.exit(1)
    pin2 = getpass_prompt("Confirm new PIN: ")
    if pin1 != pin2:
        print("PINs do not match.", file=sys.stderr)
        sys.exit(1)

    salt = secrets.token_bytes(32)
    pin_hash = hashlib.pbkdf2_hmac(
        "sha256", pin1.encode(), salt, PBKDF2_ITERATIONS
    ).hex()

    entry = {"hash": pin_hash, "salt": salt.hex()}

    # Try new location first
    try:
        _save_pin_entry(pins_dir, analyst, entry)
    except OSError:
        # Fall back to config.yaml if /var/lib/aiir/pins not writable
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config = _load_config(config_path)
        if "pins" not in config:
            config["pins"] = {}
        config["pins"][analyst] = entry
        _save_config(config_path, config)
        print(f"PIN configured for analyst '{analyst}'.")
        return pin1

    # Strip old location if present
    config = _load_config(config_path)
    if "pins" in config and analyst in config["pins"]:
        del config["pins"][analyst]
        if not config["pins"]:
            del config["pins"]
        _save_config(config_path, config)

    print(f"PIN configured for analyst '{analyst}'.")
    return pin1


def reset_pin(config_path: Path, analyst: str, *, pins_dir: Path | None = None) -> None:
    """Reset PIN. Requires current PIN first.

    After changing the PIN, re-signs all verification ledger entries
    for this analyst with the new key.
    """
    if not has_pin(config_path, analyst, pins_dir=pins_dir):
        print(
            f"No PIN configured for analyst '{analyst}'. Use --setup-pin first.",
            file=sys.stderr,
        )
        sys.exit(1)

    current = getpass_prompt("Enter current PIN: ")
    if not verify_pin(config_path, analyst, current, pins_dir=pins_dir):
        print("Incorrect current PIN.", file=sys.stderr)
        print(
            "\nIf you have forgotten your PIN, you can force a reset by removing\n"
            "the PIN file and setting up a new one:\n"
            f"\n  rm /var/lib/aiir/pins/{analyst}.json"
            "\n  aiir config --setup-pin\n"
            "\nThis will invalidate HMAC signatures on previously approved findings.\n"
            "The findings themselves are preserved — only the integrity proof is lost.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Read old salt before setup_pin overwrites it
    old_salt = get_analyst_salt(config_path, analyst, pins_dir=pins_dir)

    new_pin = setup_pin(config_path, analyst, pins_dir=pins_dir)

    # Re-HMAC verification ledger entries with new key
    new_salt = get_analyst_salt(config_path, analyst, pins_dir=pins_dir)
    try:
        from aiir_cli.verification import (
            VERIFICATION_DIR,
            derive_hmac_key,
            rehmac_entries,
        )

        if VERIFICATION_DIR.is_dir():
            old_key = derive_hmac_key(current, old_salt)
            new_key = derive_hmac_key(new_pin, new_salt)
            for ledger_file in VERIFICATION_DIR.glob("*.jsonl"):
                case_id = ledger_file.stem
                count = rehmac_entries(
                    case_id,
                    analyst,
                    current,
                    old_salt,
                    new_pin,
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
    config_path: Path, analyst: str, *, pins_dir: Path | None = None
) -> bytes:
    """Get the analyst's PBKDF2 salt. Raises ValueError if missing."""
    pins_dir = pins_dir or _PINS_DIR
    _maybe_migrate(config_path, pins_dir, analyst)
    entry = _load_pin_entry(pins_dir, analyst)
    if entry is None:
        # Fallback: legacy config.yaml
        config = _load_config(config_path)
        pins = config.get("pins", {})
        entry = pins.get(analyst)
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
    if _recent_failure_count(analyst) >= _MAX_PIN_ATTEMPTS:
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
            f"PIN locked. Too many failed attempts. Try again in {remaining} seconds.",
            file=sys.stderr,
        )
        sys.exit(1)


def _record_failure(analyst: str) -> None:
    """Record a failed PIN attempt to disk."""
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
    """Read PIN from /dev/tty with masked input (shows * per keystroke).

    Raises RuntimeError if /dev/tty or termios is unavailable.
    """
    if not _HAS_TERMIOS:
        raise RuntimeError(
            "PIN entry requires a terminal with termios support. "
            "Cannot read PIN without /dev/tty."
        )

    try:
        tty_in = open("/dev/tty")
    except OSError as err:
        raise RuntimeError(
            "PIN entry requires /dev/tty. Cannot read PIN in this environment. "
            "Ensure you are running from an interactive terminal."
        ) from err
    try:
        fd = tty_in.fileno()
        sys.stderr.write(prompt)
        sys.stderr.flush()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            pin = []
            while True:
                ch = os.read(fd, 1).decode("utf-8", errors="replace")
                if ch in ("\r", "\n"):
                    break
                elif ch in ("\x7f", "\x08"):  # backspace/delete
                    if pin:
                        pin.pop()
                        sys.stderr.write("\b \b")
                        sys.stderr.flush()
                elif ch == "\x03":  # Ctrl-C
                    sys.stderr.write("\n")
                    sys.stderr.flush()
                    raise KeyboardInterrupt
                elif ch >= " ":  # printable
                    pin.append(ch)
                    sys.stderr.write("*")
                    sys.stderr.flush()
            return "".join(pin)
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
