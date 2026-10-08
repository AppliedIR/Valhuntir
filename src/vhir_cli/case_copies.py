"""The case's own copies of its signed history, so it verifies on any box.

Close and export write them under `case_dir/ledger/`:
- `chains/<chain_id>.jsonl`: a byte copy of this box's chain for the case;
- `legacy-<chain_id>.jsonl`: a byte copy of this box's 0.6 file, the history
  that chain's genesis froze (a case with no chain keeps 0.6's
  `verification.jsonl` copy instead);
- `keys.json`: every signing key the case's chains hold, each chain's head,
  and when the copies were made.

A copy that can't be written is an error. A copy from elsewhere (a bundle, a
restore) is added under its own chain id and never overwrites: a stale prefix
of it is brought up to date, and a different file with an id already present
is kept beside it with a suffix, and both are reported.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from vhir_cli import ledger

_CHAIN_ID = re.compile(r"^[0-9a-f]{16}$")


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


def add_copy(path: Path, data: bytes) -> tuple[str, Path]:
    """Add `data` at `path` without overwriting anything it doesn't extend:
    ("added" | "updated" | "same" | "kept beside", the path written)."""
    try:
        current = path.read_bytes()
    except FileNotFoundError:
        _write(path, data)
        return "added", path
    if current == data:
        return "same", path
    if data.startswith(current):  # a stale prefix: the same history, extended
        _write(path, data)
        return "updated", path
    if current.startswith(data):  # ours is the older prefix: keep the longer
        return "same", path
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    beside = path.with_name(f"{path.stem}.{stamp}{path.suffix}")
    n = 1
    while beside.exists():
        beside = path.with_name(f"{path.stem}.{stamp}-{n}{path.suffix}")
        n += 1
    _write(beside, data)
    return "kept beside", beside


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
    case. Returns {"chain_id", "copies": [(what, path)], "keys", "heads"}.
    Raises CopyFailed."""
    from vhir_cli import verification

    case_dir = Path(case_dir)
    base = copy_dir(case_dir)
    copies: list[tuple[str, Path]] = []
    box = ledger.chain_path(case_id)
    legacy = verification.VERIFICATION_DIR / f"{case_id}.jsonl"
    try:
        data = box.read_bytes() if box.exists() else b""
        cid = chain_id_of(data) if data else None
        if data and cid is None:
            raise CopyFailed(f"this box's chain {box} doesn't start with seq 1")
        if cid:
            copies.append(add_copy(base / "chains" / f"{cid}.jsonl", data))
            if legacy.exists():
                copies.append(
                    add_copy(base / f"legacy-{cid}.jsonl", legacy.read_bytes())
                )
        elif legacy.exists():  # no signed line yet: 0.6's own close copy
            copies.append(
                add_copy(case_dir / "verification.jsonl", legacy.read_bytes())
            )
        summary = case_keys(case_dir)
        if cid:
            record = {"copied_at": _now(), **summary}
            _write(base / "keys.json", json.dumps(record, indent=2).encode())
            copies.append(("written", base / "keys.json"))
    except CopyFailed:
        raise
    except OSError as e:
        raise CopyFailed(
            f"the case copy of the signed history couldn't be written: {e}"
        ) from e
    return {"chain_id": cid, "copies": copies, **summary}


def case_keys(case_dir: Path) -> dict:
    """{"keys": [{examiner, fingerprint, public_key, chain_id, first_seq,
    last_seq, label}], "heads": [{chain_id, seq, hash}]} over every chain
    the case has (this box's and its copies)."""
    from vhir_cli.ledger_verify import verify_case

    result = verify_case(Path(case_dir))
    keys = [
        {"examiner": k["examiner"], "fingerprint": k["fingerprint"],
         "public_key": k.get("public_key"), "chain_id": cid, "first_seq": first,
         "last_seq": last, "label": k.get("label", "")}
        for k in result.keys
        for cid, (first, last) in sorted(k["ranges"].items())
    ]  # fmt: skip
    heads = [
        {"chain_id": c.chain_id, "seq": c.lines[-1].seq,
         "hash": ledger.body_hash(ledger.body_of(c.lines[-1].obj))}
        for c in result.chains
        if c.lines
    ]  # fmt: skip
    return {"keys": keys, "heads": heads}


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
    return lines


def bundle_block(case_id: str, case_dir: Path) -> dict:
    """The bundle's `ledger` block: heads, keys, and the chain and 0.6
    copies (as text) so an import on another box can verify the case."""
    base = copy_dir(case_dir)
    chains = {
        p.stem: p.read_text(encoding="utf-8")
        for p in sorted((base / "chains").glob("*.jsonl"))
        if _CHAIN_ID.match(p.stem)
    }
    legacy = {
        p.stem[len("legacy-") :]: p.read_text(encoding="utf-8")
        for p in sorted(base.glob("legacy-*.jsonl"))
        if _CHAIN_ID.match(p.stem[len("legacy-") :])
    }
    return {**case_keys(case_dir), "chains": chains, "legacy": legacy}


def add_bundle_copies(case_dir: Path, block: object) -> dict:
    """Add a bundle's chain and 0.6 copies to the case, never overwriting.
    Returns {"added": [...], "kept_beside": [...], "refused": [...]}."""
    out: dict[str, list[str]] = {"added": [], "kept_beside": [], "refused": []}
    if not isinstance(block, dict):
        return out
    base = copy_dir(case_dir)
    for kind, folder, prefix in (
        ("chains", base / "chains", ""),
        ("legacy", base, "legacy-"),
    ):
        items = block.get(kind)
        if not isinstance(items, dict):
            continue
        for cid, text in items.items():
            if not (
                isinstance(cid, str) and _CHAIN_ID.match(cid) and isinstance(text, str)
            ):
                out["refused"].append(f"{kind} {str(cid)[:40]!r}: not a chain id")
                continue
            data = text.encode("utf-8")
            if kind == "chains" and chain_id_of(data) != cid:
                out["refused"].append(
                    f"chain {cid}: its first line isn't that chain's seq 1"
                )
                continue
            what, path = add_copy(folder / f"{prefix}{cid}.jsonl", data)
            if what in ("added", "updated"):
                out["added"].append(str(path))
            elif what == "kept beside":
                out["kept_beside"].append(str(path))
    return out
