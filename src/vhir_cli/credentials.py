"""Signing credentials for every command that sets, changes or uses them.

Which path runs is chosen by the state of `passwords/{x}.json`, never by
whether `keys/{x}.json` exists:

- a 0.6 credential there (verifier only) is **legacy**: the first signed
  decision, `--upgrade-key` or `--reset-password` makes a key pair (fresh
  salts) and writes a stub in its place. A `keys/` file found beside it is
  never adopted: it is set aside byte-identical as `.untrusted-<UTC>` and its
  keys are recorded as retired;
- otherwise `keys/{x}.json` (schema 3) is the credential;
- otherwise there is none.

Every passphrase that is set goes through the passphrase rule (8 to 256 code
points; 15 or more recommended). Valhuntir commands never replace a key
without a retired record.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

from vhir_cli import approval_auth, keys, ledger, passphrase
from vhir_cli.display import one_line
from vhir_cli.identity import valid_name

FINGERPRINT_NOTE = (
    "This fingerprint is printed on every report and export. Any copy that leaves "
    "this machine lets you confirm later that this key is yours."
)


class CredentialError(Exception):
    """A credential command or check that can't go ahead; the message says why."""


class AttemptsExhausted(Exception):
    """The final prompt used up the attempts the lockout leaves."""


# --- State --------------------------------------------------------------------------


def _stub_path(examiner: str) -> Path:
    return approval_auth._password_file(approval_auth._PASSWORDS_DIR, examiner)


def _is_stub(data: object) -> bool:
    return isinstance(data, dict) and data.get("schema") == 3 and "moved_to" in data


def _passwords_entry(examiner: str) -> tuple[bool, dict | None]:
    """(whether `passwords/{x}.json` exists, its 0.6 `hash`/`salt` entry or None)."""
    try:
        data = json.loads(_stub_path(examiner).read_text())
    except FileNotFoundError:
        return False, None
    except (OSError, ValueError):
        return True, None
    legacy = (
        isinstance(data, dict)
        and "hash" in data
        and "salt" in data
        and not _is_stub(data)
    )
    return True, data if legacy else None


def _config_entry(examiner: str, config_path: Path) -> dict | None:
    """A 0.6 entry in the old config.yaml location, read only as a 0.6 source."""
    section = approval_auth._load_config(config_path)
    section = section.get("passwords", section.get("pins", {}))
    entry = section.get(examiner) if isinstance(section, dict) else None
    if isinstance(entry, dict) and "hash" in entry and "salt" in entry:
        return entry
    return None


def _legacy_entry(examiner: str, config_path: Path) -> dict | None:
    """The 0.6 credential (`hash`/`salt`) for the examiner, or None."""
    exists, entry = _passwords_entry(examiner)
    if entry is not None or exists:
        return entry
    return _config_entry(examiner, config_path)


def state(examiner: str, config_path: Path) -> str:
    """ "legacy", "schema3" or "none"; a keys file that doesn't load raises
    KeysFileInvalid. A 0.6 entry in `passwords/` is legacy whatever `keys/`
    holds (a keys file beside it is never adopted). A valid `keys/` file
    outranks a 0.6 entry left in config.yaml, which is then ignored."""
    if not valid_name(examiner):
        raise CredentialError(f"Invalid examiner name: {examiner!r}")
    exists, entry = _passwords_entry(examiner)
    if entry is not None:
        return "legacy"
    data = keys.load(examiner)
    if data is not None and keys.active(data) is not None:
        return "schema3"  # a file of only retired (restored) keys is no credential
    if not exists and _config_entry(examiner, config_path) is not None:
        return "legacy"
    return "none"


def _write_stub(examiner: str) -> None:
    approval_auth._save_password_entry(
        approval_auth._PASSWORDS_DIR,
        examiner,
        {"schema": 3, "moved_to": str(keys.keys_path(examiner))},
    )


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# --- Prompts --------------------------------------------------------------------------


def _new_passphrase(examiner: str, current_checks=(), lead: str = "") -> str:
    """Prompt for a new passphrase twice, with up to three attempts on a rule
    rejection, a mismatch or (for a reset) the current passphrase."""
    if lead:
        print(lead)
    print(passphrase.RECOMMENDATION)
    for _ in range(3):
        first = approval_auth.getpass_prompt("New passphrase: ")
        error, warnings = passphrase.check(first, examiner)
        if error:
            print(error, file=sys.stderr)
            continue
        if any(check(first) for check in current_checks):
            print(
                "Choose a passphrase different from the current one.", file=sys.stderr
            )
            continue
        if approval_auth.getpass_prompt("Confirm new passphrase: ") != first:
            print("Passphrases do not match.", file=sys.stderr)
            continue
        for w in warnings:
            print(f"  Note: {w}")
        return first
    raise CredentialError("No passphrase was set.")


def _print_new_key(data: dict) -> None:
    print(f"Signing key fingerprint: {keys.key_fingerprint(keys.active(data))}")
    print(FINGERPRINT_NOTE)


# --- Ledger key scan ------------------------------------------------------------------


def _ledger_keys(examiner: str) -> list[str]:
    """Public keys this examiner signed with in the local ledgers."""
    found: list[str] = []
    try:
        chains = sorted(ledger.LEDGER_DIR.glob("*.jsonl"))
    except OSError:
        return found
    for path in chains:
        for _, _, line in ledger.read_lines(path):
            if isinstance(line, dict) and line.get("examiner") == examiner:
                pub = line.get("public_key")
                if isinstance(pub, str) and pub not in found:
                    found.append(pub)
    return found


def _ledgers_signed_by(examiner: str, public_key: str) -> list[tuple[str, int, tuple]]:
    """(case id, last seq signed with the key, head) for each local chain."""
    out = []
    for path in sorted(ledger.LEDGER_DIR.glob("*.jsonl")):
        lines = ledger.read_lines(path)
        mine = [
            p["seq"]
            for _, _, p in lines
            if isinstance(p, dict) and isinstance(p.get("seq"), int)
            and p.get("examiner") == examiner and p.get("public_key") == public_key
        ]  # fmt: skip
        if mine:
            out.append((path.stem, max(mine), ledger.head_of(lines)))
    return out


# --- Commands -------------------------------------------------------------------------


def enrol(examiner: str, config_path: Path, *, by_name: bool = False) -> None:
    """Set up a credential for an examiner who has none (an examiner who has one is refused).
    Keys this name signed with in local ledgers are recorded as retired,
    labelled "found in ledger, not confirmed"."""
    current = state(examiner, config_path)
    if current != "none":
        flags = (
            f"`vhir enrol --name {examiner} --upgrade | --reset | --forgot`"
            if by_name
            else "`vhir config --upgrade-key`, `--reset-password` or `--forgot-password`"
        )
        raise CredentialError(
            f"{examiner} already has a credential; nothing was changed. Use {flags}."
        )
    if by_name:
        print(
            f"This enrols {examiner} for approvals. The person named must type their own passphrase here."
        )
    pw = _new_passphrase(examiner)
    data = keys.new_credential(examiner, pw)
    for k in (keys.load(examiner) or {"keys": []})["keys"]:  # restored records kept
        keys.add_retired(data, k["public_key"], k.get("retired_reason") or "restored",
                         k.get("superseded_by"))  # fmt: skip
    for pub in _ledger_keys(examiner):
        if pub != keys.active(data)["public_key"]:
            keys.add_retired(data, pub, "found in ledger, not confirmed")
    keys.save(examiner, data)
    print(f"Passphrase and signing key set up for {examiner}.")
    _print_new_key(data)


def _found_keys(examiner: str) -> list[str]:
    """The public keys a keys file that won't be adopted holds (read, not
    moved). Only a key that decodes to 32 bytes is kept (it is recorded as
    retired); any other entry is named and left out."""
    path = keys.keys_path(examiner)
    try:
        found = json.loads(path.read_text())
        pubs = [
            k.get("public_key") for k in found.get("keys", []) if isinstance(k, dict)
        ]
    except (OSError, ValueError, TypeError, AttributeError):
        pubs = []
    kept = []
    for pub in dict.fromkeys(
        p for p in pubs if p is not None and not isinstance(p, (dict, list))
    ):
        if _is_public_key(pub):
            kept.append(pub)
        else:
            print(
                f"A public key in {path} isn't a valid key and was left out: "
                f"{one_line(str(pub))[:60]!r}",
                file=sys.stderr,
            )
    return kept


def _is_public_key(value) -> bool:
    try:
        return isinstance(value, str) and len(keys.unb64(value)) == 32
    except ValueError:  # not base64, or not ASCII
        return False


def _replace_credential(examiner: str, data: dict, retired: list[str], reason: str,
                        what: str) -> None:  # fmt: skip
    """Write `data` as the credential in one step: the keys it replaces are
    recorded as retired, the file it replaces is kept byte-identical as
    `.untrusted-<UTC>` (a hard link, made first), then the new file replaces
    it atomically and the 0.6 entry becomes a stub. An interruption before
    the replace leaves everything as it was, including a file that doesn't
    load, which is replaced only because its copy was just made."""
    new_fp = keys.key_fingerprint(keys.active(data))
    for pub in retired:
        if pub != keys.active(data)["public_key"]:
            keys.add_retired(data, pub, reason, superseded_by=new_fp)
    path = keys.keys_path(examiner)
    target = None
    if path.exists():
        target = path.with_name(f"{path.name}.untrusted-{_now()}")
        try:
            os.link(path, target)
        except OSError:
            shutil.copy2(path, target)
        print(f"{what} was set aside: {target}")
    keys.save(examiner, data, set_aside=target)
    _write_stub(examiner)


def upgrade(examiner: str, config_path: Path, typed: str | None = None) -> bool:
    """Make the 0.6 credential a schema-3 one. `typed`: the 0.6 password if
    it was already typed. Returns True when a new passphrase was set."""
    current = state(examiner, config_path)
    if current == "schema3":
        print(f"{examiner} already has a signing key.")
        _print_new_key(keys.load(examiner))
        return False
    if current == "none":
        raise CredentialError(
            f"No passphrase for {examiner}; run `vhir config --setup-password`."
        )
    if typed is None:
        approval_auth._check_lockout(examiner)
        typed = approval_auth.getpass_prompt(f"0.6 password for {examiner}: ")
    reading = approval_auth.verify_password(config_path, examiner, typed)
    if reading is None:
        approval_auth._record_failure(examiner)  # nothing is moved
        raise CredentialError("Incorrect password.")
    approval_auth._clear_failures(examiner)
    new_pw = typed
    changed = False
    if len(typed) < passphrase.MIN_LENGTH:
        new_pw = _new_passphrase(
            examiner,
            lead=(
                f"Valhuntir 0.7 needs a passphrase of at least {passphrase.MIN_LENGTH} "
                f"characters (yours is {len(typed)}); 15 or more is recommended. "
                "Choose a new one now; nothing you've done in this command is lost."
            ),
        )
        changed = True
    elif len(typed) < passphrase.RECOMMENDED:
        print(
            f"Your passphrase is {len(typed)} characters; 15 or more is recommended. "
            "You can change it later with `vhir config --reset-password`."
        )
    data = keys.new_credential(examiner, new_pw)
    _replace_credential(examiner, data, _found_keys(examiner), "set aside at upgrade",
                        "A signing-key file found beside your 0.6 password")  # fmt: skip
    print(f"Signing key made for {examiner} (Valhuntir 0.7).")
    _print_new_key(data)
    return changed


def reset(examiner: str, config_path: Path) -> None:
    """Change the passphrase. Schema 3: the same key re-wrapped (its public key
    unchanged). Legacy: a key pair is made. None: as setup."""
    current = state(examiner, config_path)
    if current == "none":
        enrol(examiner, config_path)
        return
    approval_auth._check_lockout(examiner)
    typed = approval_auth.getpass_prompt("Current passphrase: ")
    if current == "legacy":
        if approval_auth.verify_password(config_path, examiner, typed) is None:
            approval_auth._record_failure(examiner)
            raise CredentialError(
                "Incorrect password. If you've forgotten it, run `vhir config --forgot-password`."
            )
        approval_auth._clear_failures(examiner)
        pw = _new_passphrase(examiner)
        data = keys.new_credential(examiner, pw)
        _replace_credential(examiner, data, _found_keys(examiner), "set aside at upgrade",
                            "A signing-key file found beside your 0.6 password")  # fmt: skip
        print(f"Passphrase changed and signing key made for {examiner}.")
        _print_new_key(data)
        return
    data = keys.load(examiner)
    if not keys.check_password(data, typed):
        approval_auth._record_failure(examiner)
        raise CredentialError(
            "Incorrect password. If you've forgotten it, run `vhir config --forgot-password`."
        )
    approval_auth._clear_failures(examiner)
    pw = _new_passphrase(examiner)
    new = keys.rewrap(data, examiner, typed, pw)
    keys.save(examiner, new)
    print(f"Passphrase changed for {examiner}; the signing key is unchanged.")
    print(f"Signing key fingerprint: {keys.key_fingerprint(keys.active(new))}")


def _confirm_new_key() -> None:
    """`NEW KEY`, typed on the terminal, confirms a forgotten-password reset."""
    try:
        tty = open("/dev/tty")
    except OSError as e:
        raise CredentialError(
            "A forgotten-password reset needs a terminal (/dev/tty)."
        ) from e
    try:
        sys.stderr.write(
            "This makes a new signing key; your old key is kept as retired. "
            "Type NEW KEY to continue: "
        )
        sys.stderr.flush()
        answer = tty.readline().strip()
    finally:
        tty.close()
    if answer != "NEW KEY":
        raise CredentialError("Nothing was changed.")


def forgot(examiner: str, config_path: Path) -> None:
    """A new key under a new passphrase; the old key is retired (public key
    kept). Prints both fingerprints and, for each local case it signed in,
    the bounded pin and head to record."""
    try:
        current = state(examiner, config_path)
    except keys.KeysFileInvalid:
        current = "invalid"
    if current == "none":
        enrol(examiner, config_path)
        return
    _confirm_new_key()
    if current == "invalid":  # set aside as K5, then a new key
        pw = _new_passphrase(examiner)
        data = keys.new_credential(examiner, pw)
        retired = _found_keys(examiner) + _ledger_keys(examiner)
        _replace_credential(examiner, data, list(dict.fromkeys(retired)),
                            "set aside: the keys file was invalid",
                            "The keys file that couldn't be read")  # fmt: skip
        print(f"New signing key made for {examiner}.")
        _print_new_key(data)
        return
    if current == "legacy":
        legacy = _legacy_entry(examiner, config_path)

        def same_as_0_6(pw: str) -> bool:
            return approval_auth.verify_password(config_path, examiner, pw) is not None

        pw = _new_passphrase(examiner, current_checks=[same_as_0_6] if legacy else [])
        data = keys.new_credential(examiner, pw)
        _replace_credential(examiner, data, _found_keys(examiner), "set aside at upgrade",
                            "A signing-key file found beside your 0.6 password")  # fmt: skip
        print(f"New signing key made for {examiner}.")
        _print_new_key(data)
        return
    data = keys.load(examiner)
    old = keys.active(data)
    pw = _new_passphrase(
        examiner, current_checks=[lambda p: keys.check_password(data, p)]
    )
    new = keys.replace_key(data, examiner, pw, "forgotten-password reset")
    keys.save(examiner, new)
    old_fp, new_fp = keys.key_fingerprint(old), keys.key_fingerprint(keys.active(new))
    print(f"Old signing key (retired): {old_fp}")
    print(f"New signing key:           {new_fp}")
    print(FINGERPRINT_NOTE)
    for case_id, last, head in _ledgers_signed_by(examiner, old["public_key"]):
        print(f"  Case {case_id}: the old key signed up to seq {last}.")
        print(f"    Record this pin: --expect-key {examiner}={old_fp}:1-{last}")
        if head:
            print(
                f"    Current head: {ledger.format_head(case_id, head)}; record the head after your next approval."
            )


def merge_restored_keys(examiner: str, public_keys: list[str]) -> list[str]:
    """A restore's keys for `examiner`: each one the local keys file doesn't
    hold is appended as retired ("restored from a backup", no private key); a box with no
    credential gets a file of only those. A wrapped private key is never
    installed and a live credential never replaced. Returns the fingerprints
    added."""
    if not valid_name(examiner):
        return []
    data = keys.load(examiner) or keys.public_only()
    added = []
    for pub in public_keys:
        try:
            if keys.add_retired(data, pub, "restored from a backup"):
                added.append(keys.fingerprint(keys.unb64(pub)))
        except (TypeError, ValueError):
            continue
    if added:
        keys.save(examiner, data)
    return added


# --- Signing commands ---------------------------------------------------------------------

FINISH_UPDATE = (
    "Finish the update: run `vhir update` once more "
    "(it creates /var/lib/vhir/keys and ledger)"
)


def signing_folders_problem() -> str:
    """Why this user can't sign here, or "": FINISH_UPDATE when a signing
    folder (keys/, ledger/) is missing (a vhir updated from 0.6 by one
    `vhir update` of the old code can lack them), or, when one exists but
    this user can't write it, which folder and whose it is (`vhir update`
    gives it back)."""
    for folder in (keys.KEYS_DIR, ledger.LEDGER_DIR):
        if not folder.is_dir():
            return FINISH_UPDATE
    for folder in (keys.KEYS_DIR, ledger.LEDGER_DIR):
        if not os.access(folder, os.W_OK | os.X_OK):
            return not_writable_text(folder)
    return ""


def not_writable_text(folder: Path) -> str:
    import getpass
    import pwd

    try:
        uid = folder.stat().st_uid
        owner = pwd.getpwuid(uid).pw_name
    except (OSError, KeyError):
        owner = "another account"
    user = getpass.getuser()
    return (
        f"{folder} exists but {user} can't write to it (it belongs to {owner}); "
        f"run `vhir update`, which gives it back to {user}"
    )


def on_signing_folders(path) -> bool:
    """True for a path in (or of) the signing folders or their parent."""
    if not path:
        return False
    p = Path(os.fsdecode(path)) if not isinstance(path, Path) else path
    roots = {
        keys.KEYS_DIR,
        ledger.LEDGER_DIR,
        keys.KEYS_DIR.parent,
        ledger.LEDGER_DIR.parent,
    }
    return p in roots or any(r in p.parents for r in (keys.KEYS_DIR, ledger.LEDGER_DIR))


def preflight(examiner: str, config_path: Path) -> bool:
    """The checks that can fail, run before any item is displayed: a credential
    exists, no lockout is active, the keys file loads. A 0.6 credential is
    upgraded here, with its own prompts. Returns True when a new passphrase
    was set (the final prompt then says so). The signing folders come first:
    without them nothing can be signed, or upgraded."""
    folders = signing_folders_problem()
    if folders:
        raise CredentialError(folders)
    try:
        current = state(examiner, config_path)
    except keys.KeysFileInvalid as e:
        raise CredentialError(
            f"KEYS_FILE_INVALID: {e}; run `vhir config --forgot-password`."
        ) from e
    if current == "none":
        raise CredentialError(
            "No passphrase configured. Set one with:\n  vhir config --setup-password"
        )
    approval_auth._check_lockout(examiner)
    if current == "legacy":
        return upgrade(examiner, config_path)
    return False


def unlock(examiner: str, prompt: str):
    """The final prompt: retried in place for the attempts the lockout leaves.
    Returns (private key, public key b64). KeyUnwrapFailed (not counted) and
    AttemptsExhausted are for the caller, which saves the decisions unsigned."""
    data = keys.load(examiner)
    while True:
        if (
            approval_auth._recent_failure_count(examiner)
            >= approval_auth._MAX_PASSWORD_ATTEMPTS
        ):
            raise AttemptsExhausted()
        typed = approval_auth.getpass_prompt(prompt)
        if not keys.check_password(data, typed):
            approval_auth._record_failure(examiner)
            left = (
                approval_auth._MAX_PASSWORD_ATTEMPTS
                - approval_auth._recent_failure_count(examiner)
            )
            print(
                f"Incorrect password. {max(left, 0)} attempt(s) remaining.",
                file=sys.stderr,
            )
            continue
        private = keys.open_key(data, examiner, typed)  # KeyUnwrapFailed: not counted
        approval_auth._clear_failures(examiner)
        return private, keys.active(data)["public_key"]


def retired_fingerprints(examiner: str) -> list[str]:
    """The examiner's retired keys, for `supersedes` on a new key's first line."""
    data = keys.load(examiner) or {"keys": []}
    return [
        keys.key_fingerprint(k) for k in data["keys"] if k.get("status") == "retired"
    ]


__all__ = [
    "AttemptsExhausted",
    "CredentialError",
    "FINGERPRINT_NOTE",
    "enrol",
    "forgot",
    "preflight",
    "reset",
    "retired_fingerprints",
    "state",
    "unlock",
    "upgrade",
]
