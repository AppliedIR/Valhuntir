"""The signed decision ledger: /var/lib/vhir/ledger/{case_id}.jsonl.

Every examiner decision (approve, reject, edit, re-attest, and each cascade)
is one line: a canonical JSON body signed with the examiner's Ed25519 key.
Lines are chained: each body names the hash of the previous one, and the first
names the case and freezes the 0.6 ledger beside it (its length and hash).

    canonical(body) = json.dumps(body, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=True)
    line            = canonical(body + {"sig": base64(Ed25519.sign(canonical(body)))})
    prev(seq 1)     = sha256("vhir-ledger-genesis|" + case_id)
    prev(seq n)     = sha256(canonical(body of line n-1))
    head            = (seq of the last line, sha256(canonical(its body)))
    chain_id        = the first 16 hex characters of sha256(canonical(seq-1 body))

This module is the only writer. A writer takes the case lock
(`{case_id}.lock` beside the chain) around its whole load-to-save, and
`commit` refuses to append without it. Every line's signature is checked
against the examiner's active public key before anything is written.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import time
from collections.abc import Callable
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

LEDGER_DIR = Path("/var/lib/vhir/ledger")
VERSION = 3
VIEW = 1
DECISIONS = ("approve", "reject", "edit", "reattest")
TYPES = ("finding", "timeline", "ioc")
_STATUS_AFTER = ("APPROVED", "REJECTED", "DRAFT")


class LedgerError(Exception):
    """A ledger write that didn't happen. Nothing was written, except for
    LedgerTorn, which says part of the write may be left in the chain."""


class LedgerMoved(LedgerError):
    """The chain's head isn't the one the bodies were prepared on (LEDGER_MOVED)."""


class LedgerBusy(LedgerError):
    """Another writer held the case lock past the timeout (LEDGER_BUSY)."""


class LedgerTorn(LedgerError):
    """A failed append that couldn't be cut back: the chain may hold part of it."""


class LockDirMissing(LedgerError):
    """The ledger folder is missing or can't be written."""


class LockNotHeld(LedgerError):
    """`commit` was called without holding this case's lock."""


class CaseCopy(LedgerError):
    """This box's chain for the case id begins in another case folder (CASE_COPY)."""


def copy_text(case_id: str) -> str:
    return (
        f"This folder is a copy of case {case_id}; this box's signed chain for "
        f"{case_id} belongs to the original. Signing here would extend {case_id}'s "
        "chain. Sign in the original folder."
    )


def bound_uuid(lines: list[tuple[int, str, dict | None]]) -> str | None:
    """The case folder the chain's first line binds (its `case_uuid`), or None
    for a chain begun before folders were bound, or none yet."""
    first = lines[0][2] if lines else None
    if not first or first.get("seq") != 1:
        return None
    value = first.get("case_uuid")
    return value if isinstance(value, str) else None


CHAIN_UNREADABLE = (
    "This case's signed chain can't be read; signing is disabled; run "
    "`vhir review --verify`."
)


def first_signed_text(case_id: str) -> str:
    """The refusal for a folder with no identity whose case already signed
    elsewhere (cases upgraded from 0.6.4 had none until their first signing)."""
    return (
        f"This folder is a copy of case {case_id}: the folder that signed first holds "
        "this case's signed record; continue there."
    )


def copy_problem(case_id: str, case_uuid: str | None) -> str:
    """`copy_text` when this box's chain for `case_id` binds a case folder
    other than the one whose identity is `case_uuid`; CHAIN_UNREADABLE when
    the chain can't be read (or isn't UTF-8); else "". Read-only; never raises."""
    try:
        bound = bound_uuid(read_lines(chain_path(case_id)))
    except (OSError, ValueError):  # unreadable, not UTF-8, a bad case id
        return CHAIN_UNREADABLE
    if bound is None or bound == case_uuid:
        return ""
    return first_signed_text(case_id) if not case_uuid else copy_text(case_id)


class BadSignature(LedgerError):
    """A line's signature doesn't verify under the examiner's active key (BAD_SIGNATURE)."""


def validate_case_id(case_id: str) -> None:
    if (
        not case_id
        or case_id in (".", "..")
        or ".." in case_id
        or "/" in case_id
        or "\\" in case_id
        or any(ord(c) < 32 or ord(c) == 127 for c in case_id)
    ):
        raise ValueError(f"Invalid case ID: {case_id!r}")


def chain_path(case_id: str) -> Path:
    validate_case_id(case_id)
    return LEDGER_DIR / f"{case_id}.jsonl"


def lock_path(case_id: str) -> Path:
    validate_case_id(case_id)
    return LEDGER_DIR / f"{case_id}.lock"


def legacy_path(case_id: str) -> Path:
    from vhir_cli import verification

    validate_case_id(case_id)
    return verification.VERIFICATION_DIR / f"{case_id}.jsonl"


# --- Bodies and lines ---------------------------------------------------------


def canonical(body: dict) -> bytes:
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def body_hash(body: dict) -> str:
    return hashlib.sha256(canonical(body)).hexdigest()


def genesis_prev(case_id: str) -> str:
    return hashlib.sha256(f"vhir-ledger-genesis|{case_id}".encode()).hexdigest()


def chain_id(first_body: dict) -> str:
    return body_hash(first_body)[:16]


def body_of(line: dict) -> dict:
    """A parsed line without its signature."""
    return {k: v for k, v in line.items() if k != "sig"}


def sign_body(body: dict, private: Ed25519PrivateKey) -> str:
    """The line for `body`: its canonical form with the signature added."""
    sig = base64.b64encode(private.sign(canonical(body))).decode("ascii")
    return canonical({**body, "sig": sig}).decode("ascii")


def signature_valid(line: dict) -> bool:
    """True when the line's signature verifies under the public key it carries."""
    try:
        public = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(line["public_key"], validate=True)
        )
        public.verify(
            base64.b64decode(line["sig"], validate=True), canonical(body_of(line))
        )
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False
    return True


def read_lines(path: Path) -> list[tuple[int, str, dict | None]]:
    """`(line number, text, parsed or None)` for every non-empty line."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
        out.append((n, raw, parsed if isinstance(parsed, dict) else None))
    return out


def head_of(lines: list[tuple[int, str, dict | None]]) -> tuple[int, str] | None:
    """`(seq, hash)` of the chain's last line, or None for an empty chain."""
    if not lines:
        return None
    last = lines[-1][2]
    if last is None or not isinstance(last.get("seq"), int):
        raise LedgerError(
            "the ledger's last line is incomplete or doesn't parse; nothing was written. "
            "Restore it from a copy."
        )
    return last["seq"], body_hash(body_of(last))


def current_head(case_id: str) -> tuple[int, str] | None:
    return head_of(read_lines(chain_path(case_id)))


def format_head(case_id: str, head: tuple[int, str], chain: str = "") -> str:
    """The printed head, at full length."""
    where = f" {chain}" if chain else ""
    return f"Ledger head {case_id}{where}: seq {head[0]} sha256:{head[1]}"


def _genesis(case_id: str) -> dict:
    """The 0.6 ledger beside this case, frozen by length and hash."""
    try:
        data = legacy_path(case_id).read_bytes()
    except FileNotFoundError:
        data = b""
    return {
        "legacy_sha256": hashlib.sha256(data).hexdigest(),
        "legacy_bytes": len(data),
    }


def _supersedes(
    lines: list[tuple[int, str, dict | None]],
    examiner: str,
    public_b64: str,
    retired: list[str],
) -> list[str]:
    """The retired fingerprints to name in this key's first line in this chain:
    those of `retired` that signed a line of `examiner` here. None once the key
    has a line here, and never the signing key itself."""
    from vhir_cli.keys import fingerprint

    def fp(line: dict) -> str | None:
        try:
            return fingerprint(base64.b64decode(line["public_key"], validate=True))
        except (KeyError, TypeError, ValueError):
            return None

    mine = [p for _, _, p in lines if p and p.get("examiner") == examiner]
    if any(p.get("public_key") == public_b64 for p in mine):
        return []
    signing = fingerprint(base64.b64decode(public_b64))
    used = {fp(p) for p in mine}
    return [r for r in retired if r in used and r != signing]


def prepare(
    case_id: str,
    decisions: list[dict],
    examiner: str,
    public_key: str,
    mode: str,
    at: str,
    *,
    head: tuple[int, str] | None = None,
    retired: list[str] | None = None,
    prior_chains: list[dict] | None = None,
    case_uuid: str | None = None,
) -> list[dict]:
    """The bodies for `decisions`, chained from the box chain's head (read
    now, or `head` as pinned by a portal challenge). Pure apart from reading
    the chain and, for a first line, the 0.6 ledger.

    Each decision is `{item_id, type, decision, status_after, coupled_from,
    content_snapshot}`; `content_snapshot` is `case_io.signed_text(item, type)`.
    `retired`: the examiner's retired fingerprints; those that signed lines
    here are named in `supersedes` on this key's first line in the chain.
    `case_uuid`: the identity of the case folder signing (CASE.yaml's). A first
    line records it; a chain whose first line records another one belongs to
    another folder with this case id, and CaseCopy is raised.
    """
    if mode not in ("cli", "portal"):
        raise ValueError(f"mode {mode!r}")
    lines = read_lines(chain_path(case_id))
    bound = bound_uuid(lines)
    if bound is not None and bound != case_uuid:
        raise CaseCopy(copy_text(case_id))
    if head is None:
        head = head_of(lines)
    seq, prev = (head[0], head[1]) if head else (0, genesis_prev(case_id))
    supersedes = _supersedes(lines, examiner, public_key, list(retired or []))
    bodies = []
    for d in decisions:
        if d["decision"] not in DECISIONS or d["type"] not in TYPES:
            raise ValueError(f"decision {d['decision']!r} on a {d['type']!r}")
        if d["status_after"] not in _STATUS_AFTER:
            raise ValueError(f"status_after {d['status_after']!r}")
        snapshot = d["content_snapshot"]
        seq += 1
        body = {
            "v": VERSION,
            "view": VIEW,
            "seq": seq,
            "prev": prev,
            "case_id": case_id,
            "item_id": d["item_id"],
            "type": d["type"],
            "decision": d["decision"],
            "status_after": d["status_after"],
            "coupled_from": d.get("coupled_from"),
            "examiner": examiner,
            "at": at,
            "mode": mode,
            "public_key": public_key,
            "content_sha256": hashlib.sha256(snapshot.encode("utf-8")).hexdigest(),
            "content_snapshot": snapshot,
        }
        if seq == 1:
            body["genesis"] = _genesis(case_id)
            if case_uuid:
                body["case_uuid"] = case_uuid
        if not bodies:
            if supersedes:
                body["supersedes"] = supersedes
            if prior_chains:
                body["prior_chains"] = prior_chains
        bodies.append(body)
        prev = body_hash(body)
    return bodies


# --- The case lock --------------------------------------------------------------


class CaseLock:
    """`flock` on `{case_id}.lock`, held from a writer's load to its save.

    A new descriptor for every acquisition; never nested (a second lock in one
    process blocks against the first). `timeout=None` waits for as long as it
    takes; otherwise LedgerBusy after `timeout` seconds. Locking never creates
    the chain file.
    """

    def __init__(
        self,
        case_id: str,
        timeout: float | None = None,
        on_wait: Callable[[], None] | None = None,
        poll: float = 0.05,
    ):
        self.case_id = case_id
        self.timeout = timeout
        self.on_wait = on_wait
        self.poll = poll
        self.fd: int | None = None

    @property
    def held(self) -> bool:
        return self.fd is not None

    def acquire(self) -> CaseLock:
        path = lock_path(self.case_id)
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o600)
        except OSError as e:
            raise LockDirMissing(
                f"the case lock directory {LEDGER_DIR}/ is missing or not writable "
                f"({e.strerror or e}); run `vhir update` to create it"
            ) from e
        deadline = None if self.timeout is None else time.monotonic() + self.timeout
        waited = False
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if deadline is not None and time.monotonic() >= deadline:
                    os.close(fd)
                    raise LedgerBusy(
                        f"another writer held the case lock for {self.case_id} "
                        f"for {self.timeout:g}s; nothing was written"
                    ) from None
                if not waited and self.on_wait:
                    self.on_wait()
                waited = True
                time.sleep(self.poll)
        self.fd = fd
        return self

    def release(self) -> None:
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None

    def __enter__(self) -> CaseLock:
        return self.acquire()

    def __exit__(self, *exc) -> None:
        self.release()


def case_lock(case_id: str, timeout: float | None = None, on_wait=None) -> CaseLock:
    return CaseLock(case_id, timeout=timeout, on_wait=on_wait)


# --- The one writer -------------------------------------------------------------


def commit(
    lock: CaseLock, bodies: list[dict], lines: list[str], active_public_key: str
) -> tuple:
    """Append `lines` (the signed `bodies`) to the case's chain and return the
    new head. The caller holds `lock`; this never takes it.

    Refuses, writing nothing:
    - LockNotHeld: `lock` isn't held, or is another case's;
    - LedgerMoved: the chain's head isn't the one the bodies follow;
    - BadSignature: a line isn't its body, isn't signed by `active_public_key`,
      or its signature doesn't verify.
    """
    if not isinstance(lock, CaseLock) or not lock.held:
        raise LockNotHeld("the case lock must be held to write the ledger")
    if not bodies or len(bodies) != len(lines):
        raise ValueError("one signed line per body")
    case_id = lock.case_id
    if any(b.get("case_id") != case_id for b in bodies):
        raise LockNotHeld("the bodies are for another case than the lock")
    path = chain_path(case_id)
    try:
        existing = path.read_bytes()
    except FileNotFoundError:
        existing = b""
    lead = ""  # never glue a line onto one that lacks its newline
    if existing and not existing.endswith(b"\n"):
        try:
            json.loads(existing.rsplit(b"\n", 1)[-1])
        except ValueError:
            raise LedgerError(
                f"the ledger's last line is incomplete ({path}); nothing was written. "
                "Restore it from a copy."
            ) from None
        lead = "\n"
    head = head_of(read_lines(path))
    seq, prev = (head[0], head[1]) if head else (0, genesis_prev(case_id))
    if bodies[0].get("seq") != seq + 1 or bodies[0].get("prev") != prev:
        raise LedgerMoved(
            f"the ledger for {case_id} moved since these decisions were prepared"
        )
    for before, after in zip(bodies, bodies[1:], strict=False):
        if after.get("seq") != before.get("seq") + 1 or after.get("prev") != body_hash(
            before
        ):
            raise ValueError("the bodies don't follow one another")
    for body, text in zip(bodies, lines, strict=True):
        try:
            line = json.loads(text)
        except json.JSONDecodeError:
            raise BadSignature("a signed line doesn't parse") from None
        if (
            canonical(body_of(line)) != canonical(body)
            or body.get("public_key") != active_public_key
            or not signature_valid(line)
        ):
            raise BadSignature(f"the signature on {body.get('item_id')} doesn't verify")
    LEDGER_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    # All or nothing: whatever stops the write (an error, Ctrl-C) cuts the
    # file back to its size before it, so no part of this write is left
    size = path.stat().st_size if path.exists() else 0
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        with os.fdopen(fd, "a", encoding="ascii") as f:
            f.write(lead)
            for text in lines:
                f.write(text + "\n")
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        _cut_back(path, size)
        raise
    return bodies[-1]["seq"], body_hash(bodies[-1])


def _cut_back(path: Path, size: int) -> None:
    """Truncate the chain to `size` and make it durable, or LedgerTorn."""
    try:
        with open(path, "r+b") as f:
            f.truncate(size)
            f.flush()
            os.fsync(f.fileno())
    except OSError as e:
        raise LedgerTorn(
            f"a write to {path} failed and couldn't be cut back ({e}); it may hold part "
            "of that write. Restore it from a copy before signing again."
        ) from e
