"""The case's own copies of its signed history, so it verifies on any box.

Close, export and backup write them under `case_dir/ledger/`, holding the
case lock, so a copy never catches a write half done:
- `chains/<chain_id>.jsonl`: a byte copy of this box's chain for the case;
- `legacy-<chain_id>.jsonl`: a byte copy of this box's 0.6 file, the history
  that chain's genesis froze (a case with no chain keeps 0.6's
  `verification.jsonl` copy instead);
- `keys.json`: every signing key with a verifying line in the case's chains,
  each chain's head, and when the copies were made.

This box's own copy is always at its chain id: a different file found there
is moved beside it (never deleted) and reported. A copy that can't be written
is an error. Bundles carry the copies as data, and their keys and heads as
anchors; an import adds no chain file. Restore copies a backup's chains into
a new case directory, refusing any chain of another case.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from vhir_cli import ledger

_CHAIN_ID = re.compile(r"[0-9a-f]{16}")
_DIVERGED = re.compile(r"chain ([0-9a-f]{16}): copies ")
LOCK_SECONDS = 30


class CopyFailed(OSError):
    """A case copy couldn't be written; the message says which and why."""


def copy_dir(case_dir: Path) -> Path:
    return Path(case_dir) / "ledger"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def add_copy(path: Path, data: bytes, own: bool = False) -> tuple[str, Path]:
    """Write `data` at `path`: ("added" | "updated" | "same" | "kept beside" |
    "moved beside", the path written or moved). Only this box's own write
    (`own`) replaces a file: a stale prefix of it is brought up to date, and
    any other file there is moved beside it first. Otherwise a different
    file at `path` stays, and `data` is kept beside it."""
    try:
        current = path.read_bytes()
    except FileNotFoundError:
        _write(path, data)
        return "added", path
    if current == data:
        return "same", path
    if own and data.startswith(current):  # this box's chain, grown since
        _write(path, data)
        return "updated", path
    beside = _beside(path)
    if own:
        os.rename(path, beside)
        _write(path, data)
        return "moved beside", beside
    _write(beside, data)
    return "kept beside", beside


def _beside(path: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    beside = path.with_name(f"{path.stem}.{stamp}{path.suffix}")
    n = 1
    while beside.exists():
        beside = path.with_name(f"{path.stem}.{stamp}-{n}{path.suffix}")
        n += 1
    return beside


def chain_id_of(data: bytes) -> str | None:
    """The chain id of a chain file's bytes (from its first line), or None."""
    for line in data.splitlines():
        if not line.strip():
            continue
        try:
            first = json.loads(line)
        except ValueError:
            return None
        if isinstance(first, dict) and first.get("seq") == 1:
            return ledger.chain_id(ledger.body_of(first))
        return None
    return None


def write_case_copies(case_id: str, case_dir: Path) -> dict:
    """Write this box's chain, its 0.6 history and the case's keys into the
    case, under the case lock. Returns {"chain_id", "copies": [(what,
    path)], "keys", "heads"}. Raises CopyFailed."""
    box = ledger.chain_path(case_id)
    try:
        lock = ledger.case_lock(case_id, timeout=LOCK_SECONDS).acquire()
    except ledger.LockDirMissing as e:
        if box.exists():
            raise CopyFailed(str(e)) from e
        lock = None  # no ledger folder: no chain here, and nothing can append one
    except ledger.LedgerBusy as e:
        raise CopyFailed(f"{e}; try again") from e
    try:
        return _write_copies(case_id, Path(case_dir), box)
    finally:
        if lock is not None:
            lock.release()


def _write_copies(case_id: str, case_dir: Path, box: Path) -> dict:
    from vhir_cli import verification

    base = copy_dir(case_dir)
    copies: list[tuple[str, Path]] = []
    legacy = verification.VERIFICATION_DIR / f"{case_id}.jsonl"
    try:
        data = box.read_bytes() if box.exists() else b""
        cid = chain_id_of(data) if data else None
        if data and cid is None:
            raise CopyFailed(f"this box's chain {box} doesn't start with seq 1")
        if cid:
            copies.append(add_copy(base / "chains" / f"{cid}.jsonl", data, own=True))
            if legacy.exists():
                copies.append(
                    add_copy(
                        base / f"legacy-{cid}.jsonl", legacy.read_bytes(), own=True
                    )
                )
        elif legacy.exists():  # no signed line yet: 0.6's own close copy
            copies.append(
                add_copy(case_dir / "verification.jsonl", legacy.read_bytes(), own=True)
            )
        summary = case_keys(case_dir)
        if cid:
            record = {"copied_at": _now(), **summary}
            _write(base / "keys.json", json.dumps(record, indent=2).encode())
            copies.append(("written", base / "keys.json"))
    except CopyFailed:
        raise
    except (OSError, ValueError) as e:
        raise CopyFailed(
            f"the case copy of the signed history couldn't be written: {e}"
        ) from e
    return {"chain_id": cid, "copies": copies, **summary}


def case_keys(case_dir: Path) -> dict:
    """{"keys": [{examiner, fingerprint, public_key, chain_id, first_seq,
    last_seq, label}], "heads": [{chain_id, seq, hash}], "diverged":
    [chain_id]}: the anchors close, export and backup print, one chain id at
    a time, counting only verifying lines (of this case, signed, linked).
    - This box's own chain id: its lines come only from the box file,
      verified alone, so no copy of that id (a fork, a longer file) can
      supply a key or a head.
    - Any other chain id: only when verify found its copies agree; copies
      that diverge are listed in "diverged", with no key and no head.
    A key or head a failing or forked line claims is never printed."""
    from vhir_cli.ledger_verify import verify_case

    case_dir = Path(case_dir)
    result = verify_case(case_dir)
    box = ledger.chain_path(result.case_id)
    first = next((p for _, _, p in ledger.read_lines(box)), None)
    own = ledger.chain_id(ledger.body_of(first)) if isinstance(first, dict) else None
    split = {
        m.group(1)
        for code, msg in result.failures
        if code == "CHAIN_COPY_DIVERGED"
        for m in [_DIVERGED.match(msg)]
        if m
    }
    diverged = sorted(split - {own})
    sources = [
        (c, result) for c in result.chains if c.chain_id not in ({own} | set(diverged))
    ]
    if own:
        alone = verify_case(case_dir, ledger_paths=[box])
        sources += [(c, alone) for c in alone.chains if c.chain_id == own]
    ranges: dict[tuple[str, str], dict] = {}
    pubs: dict[tuple[str, str], str] = {}
    labels: dict[tuple[str, str], str] = {}
    heads = []
    for c, judged in sources:
        good = [
            ln
            for ln in c.lines
            if ln.sig_ok
            and ln.obj.get("case_id") == result.case_id
            and (c.broken_at is None or ln.seq < c.broken_at)
        ]
        for ln in good:
            who = (str(ln.obj.get("examiner")), ln.fp)
            pubs.setdefault(who, ln.obj.get("public_key"))
            r = ranges.setdefault(who, {})
            first_seq, last_seq = r.get(c.chain_id, (ln.seq, ln.seq))
            r[c.chain_id] = (min(first_seq, ln.seq), max(last_seq, ln.seq))
        for k in judged.keys:
            labels.setdefault((k["examiner"], k["fingerprint"]), k.get("label", ""))
        if good:
            last = good[-1]
            heads.append({"chain_id": c.chain_id, "seq": last.seq,
                          "hash": ledger.body_hash(ledger.body_of(last.obj))})  # fmt: skip
    keys = [
        {"examiner": ex, "fingerprint": fp, "public_key": pubs[(ex, fp)],
         "chain_id": cid, "first_seq": a, "last_seq": b, "label": labels.get((ex, fp), "")}
        for (ex, fp), r in sorted(ranges.items())
        for cid, (a, b) in sorted(r.items())
    ]  # fmt: skip
    heads.sort(key=lambda h: h["chain_id"])
    return {"keys": keys, "heads": heads, "diverged": diverged,
            "own_diverged": own if own in split else None}  # fmt: skip


def summary_lines(case_id: str, summary: dict) -> list[str]:
    """The printed summary of close, export and backup: every signing key
    with its full fingerprint, and each chain's head."""
    lines = []
    if summary.get("keys"):
        lines.append("Signing keys:")
        for k in summary["keys"]:
            lines.append(
                f"  {k['examiner']} {k['fingerprint']} (chain {k['chain_id']} "
                f"seq {k['first_seq']}-{k['last_seq']}; {k['label']})"
            )
    for h in summary.get("heads", []):
        lines.append(
            ledger.format_head(case_id, (h["seq"], h["hash"]), f"chain {h['chain_id']}")
        )
    if summary.get("own_diverged"):
        lines.append(
            f"Chain {summary['own_diverged']}: a copy in the case differs from this box's "
            "chain; the key and head above are this box's own."
        )
    for cid in summary.get("diverged", []):
        lines.append(
            f"Chain {cid}: its copies diverge, so no key or head is taken from it; "
            "`vhir review --verify` names them."
        )
    return lines


def bundle_block(case_id: str, case_dir: Path, summary: dict | None = None) -> dict:
    """The bundle's `ledger` block: heads, keys, and the chain and 0.6
    copies (as text): data, and anchors for the keys and heads. `summary`:
    the keys and heads `write_case_copies` just read, reused."""
    base = copy_dir(case_dir)
    chains = {
        p.stem: p.read_text(encoding="utf-8")
        for p in sorted((base / "chains").glob("*.jsonl"))
        if _CHAIN_ID.fullmatch(p.stem)
    }
    legacy = {
        p.stem[len("legacy-") :]: p.read_text(encoding="utf-8")
        for p in sorted(base.glob("legacy-*.jsonl"))
        if _CHAIN_ID.fullmatch(p.stem[len("legacy-") :])
    }
    if summary is None:
        summary = case_keys(case_dir)
    return {"keys": summary["keys"], "heads": summary["heads"],
            "diverged": summary.get("diverged", []),
            "own_diverged": summary.get("own_diverged"), "chains": chains,
            "legacy": legacy}  # fmt: skip


def restorable_chain(data: bytes, case_id: str) -> str | None:
    """Why a backup's chain copy isn't restored into case `case_id`, or None:
    its first line must be a signed seq 1 of this case."""
    first = next((ln for ln in data.splitlines() if ln.strip()), b"")
    try:
        obj = json.loads(first)
    except ValueError:
        return "its first line doesn't parse"
    if not isinstance(obj, dict) or obj.get("seq") != 1:
        return "it doesn't start with seq 1"
    if obj.get("case_id") != case_id:
        return f"its first line is case {str(obj.get('case_id'))[:40]!r}, not {case_id}"
    if not ledger.signature_valid(obj):
        return "its first line's signature doesn't verify"
    return None
