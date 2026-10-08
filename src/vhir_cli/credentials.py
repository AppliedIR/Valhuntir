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
import sys
from datetime import datetime, timezone
from pathlib import Path

from vhir_cli import approval_auth, keys, ledger, passphrase
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


def _legacy_entry(examiner: str, config_path: Path) -> dict | None:
    """The 0.6 credential (`hash`/`salt`) for the examiner, or None."""
    try:
        data = json.loads(_stub_path(examiner).read_text())
    except (OSError, ValueError):
        data = None
    if (
        isinstance(data, dict)
        and "hash" in data
        and "salt" in data
        and not _is_stub(data)
    ):
        return data
    if data is None:  # the old config.yaml location, read only as a 0.6 source
        section = approval_auth._load_config(config_path)
        section = section.get("passwords", section.get("pins", {}))
        entry = section.get(examiner) if isinstance(section, dict) else None
        if isinstance(entry, dict) and "hash" in entry and "salt" in entry:
            return entry
    return None


def state(examiner: str, config_path: Path) -> str:
    """ "legacy", "schema3" or "none"; a keys file that doesn't load raises
    KeysFileInvalid."""
    if not valid_name(examiner):
        raise CredentialError(f"Invalid examiner name: {examiner!r}")
    if _legacy_entry(examiner, config_path) is not None:
        return "legacy"
    return "schema3" if keys.load(examiner) is not None else "none"


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
            if line and line.get("examiner") == examiner:
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
            if p and p.get("examiner") == examiner and p.get("public_key") == public_key
        ]
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
    for pub in _ledger_keys(examiner):
        if pub != keys.active(data)["public_key"]:
            keys.add_retired(data, pub, "found in ledger, not confirmed")
    keys.save(examiner, data)
    print(f"Passphrase and signing key set up for {examiner}.")
    _print_new_key(data)


def _set_aside(examiner: str) -> list[str]:
    """Move a keys file found beside a 0.6 credential aside, byte-identical,
    and return its public keys (to record as retired)."""
    path = keys.keys_path(examiner)
    if not path.exists():
        return []
    try:
        found = json.loads(path.read_text())
        pubs = [k["public_key"] for k in found.get("keys", []) if isinstance(k, dict)]
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        pubs = []
    target = path.with_name(f"{path.name}.untrusted-{_now()}")
    path.rename(target)
    print(f"A signing-key file found beside your 0.6 password was set aside: {target}")
    return [p for p in pubs if isinstance(p, str)]


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
    retired = _set_aside(examiner)
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
    new_fp = keys.key_fingerprint(keys.active(data))
    for pub in retired:
        keys.add_retired(data, pub, "set aside at upgrade", superseded_by=new_fp)
    keys.save(examiner, data)
    _write_stub(examiner)
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
        retired = _set_aside(examiner)
        data = keys.new_credential(examiner, pw)
        new_fp = keys.key_fingerprint(keys.active(data))
        for pub in retired:
            keys.add_retired(data, pub, "set aside at upgrade", superseded_by=new_fp)
        keys.save(examiner, data)
        _write_stub(examiner)
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
    current = state(examiner, config_path)
    if current == "none":
        enrol(examiner, config_path)
        return
    _confirm_new_key()
    if current == "legacy":
        legacy = _legacy_entry(examiner, config_path)

        def same_as_0_6(pw: str) -> bool:
            return approval_auth.verify_password(config_path, examiner, pw) is not None

        pw = _new_passphrase(examiner, current_checks=[same_as_0_6] if legacy else [])
        retired = _set_aside(examiner)
        data = keys.new_credential(examiner, pw)
        new_fp = keys.key_fingerprint(keys.active(data))
        for pub in retired:
            keys.add_retired(data, pub, "set aside at upgrade", superseded_by=new_fp)
        keys.save(examiner, data)
        _write_stub(examiner)
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


# --- Signing commands ---------------------------------------------------------------------


def preflight(examiner: str, config_path: Path) -> bool:
    """The checks that can fail, run before any item is displayed: a credential
    exists, no lockout is active, the keys file loads. A 0.6 credential is
    upgraded here, with its own prompts. Returns True when a new passphrase
    was set (the final prompt then says so)."""
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
