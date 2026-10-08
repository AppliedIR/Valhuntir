"""`verify_case`: the one verdict on a case's signed decisions.

It reads the case's items and every ledger copy it can find, and needs no
password, terminal or credential file. Each line is checked with the public
key it carries; trust in a key comes only from `--expect-key` pins, or from
comparing the printed fingerprints with a copy kept off this machine.

Exit codes: 0 when every APPROVED item is VALID, VALID (re-attested),
VALID (cascade) or approved under 0.6, and there is no case-level failure;
2 on any failure; 5 for a usage error (raised by the parser, never here).

Rules that apply to every line (they block exit 0 wherever the line is):
the signature, links and parsing, the key pin and its range, a retired
key's use, the line's case, the item it names, and the chains it references.
Rules that compare a line with its item apply to the item's latest line only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from vhir_cli import ledger
from vhir_cli.case_io import (
    IOC_DERIVED_KEYS,
    VIEW_EXCLUDES,
    ioc_values,
    normalize_ioc,
    signed_text,
)
from vhir_cli.identity import valid_name
from vhir_cli.keys import fingerprint

NOT_ANCHORED = (
    "Not anchored: to prove this independently of this machine, compare the key "
    "fingerprint with a copy kept off it (any earlier report, export or backup)."
)
KEY_CHANGED = (
    "Key changed at seq {seq} without the previous key's signature (expected only "
    "after a forgotten-password reset): compare the fingerprint with an earlier copy."
)
REPLACE_NOTE = (
    "Replace a chain file only with the gateway stopped and no Valhuntir command or "
    "MCP server running, or while holding the case lock "
    "(flock /var/lib/vhir/ledger/<case>.lock); move the file being replaced aside "
    "with a .replaced-<UTC> suffix, never delete it."
)

_FAIL_ITEM = {
    "TAMPERED",
    "ALTERED_AFTER_APPROVAL",
    "REVOKED",
    "UNSIGNED_STATUS",
    "APPROVED_NO_LINE",
    "LEGACY_AFTER_GENESIS",
    "PREFIX_ALTERED",
    "KEY_NOT_PINNED",
    "RETIRED_KEY_USE",
    "WRONG_CASE",
    "CHAIN_BROKEN",
    "CHAIN_FORK",
    "CASCADE_UNSUPPORTED",
}

# What verify prints for each failing status: a route that reaches exit 0, or
# a new case. "Decide again": a finding or timeline event in the portal (its
# approve takes any status) or `vhir reject`; an IOC with `vhir reject
# IOC-...` (v1 can't approve a decided IOC again).
RECOVERY = {
    "UNSIGNED_STATUS": (
        "The item's status differs from what its latest line records (printed). If a "
        "signed decision wasn't applied, re-run the same command for this id, or set the "
        "status and its approved_*/rejected_* fields back to the printed values. If the "
        "status was changed without a decision, set it back, or decide again"
    ),
    "REVOKED": (
        "Reject again with `vhir reject <id>` (findings, timeline events and IOCs); "
        "findings and timeline events can also be rejected in the portal"
    ),
    "ALTERED_AFTER_APPROVAL": (
        "Review the change against the signed content printed above. To keep it, approve "
        "it again in the portal (an edit re-approval); to undo it, restore the signed "
        "content; or reject the item. For an IOC: restore the signed content, or "
        "`vhir reject IOC-...`"
    ),
    "APPROVED_NO_LINE": "Optionally `vhir approve --reattest <id>`, or decide again",
    "LEGACY_AFTER_GENESIS": "`vhir approve --reattest <id>`",
    "PREFIX_ALTERED": "`vhir approve --reattest <id>`",
    "TAMPERED": (
        "The line stays in the chain, so deciding the item again doesn't clear it. "
        "Restore the original line from a copy taken before the change, and move the "
        "altered file aside (otherwise CHAIN_COPY_DIVERGED). If no copy holds it, as "
        "CHAIN_BROKEN"
    ),
    "KEY_NOT_PINNED": (
        "Compare the key with your record and the other examiners' records. If it's one "
        "of them, add its pin with its range. If not, the line keeps the exit above 0: "
        "if every examiner with a line after your most recent head has given their own "
        "most recent head (not counting lines being cut whose keys you can't match to a "
        "record), and no other chain references this one after the latest of those heads "
        "(listed above), cut every copy of the chain (the box file, "
        "case_dir/ledger/chains/, and any backup you'll present) back to that head and "
        "decide again what was decided after it; otherwise as CHAIN_BROKEN"
    ),
    "RETIRED_KEY_USE": (
        "A key that an earlier line of yours retired signed this line: treat it as "
        "exposed (limit 4) and recover as for KEY_NOT_PINNED with a key that isn't yours"
    ),
    "WRONG_CASE": (
        "The line belongs to another case: move that chain file aside and restore this "
        "case's chain from a copy; if none has it, as CHAIN_BROKEN. A type mismatch on "
        "the latest line only: decide again"
    ),
    "CASCADE_UNSUPPORTED": "Decide the item directly (for an IOC, `vhir reject IOC-...`)",
    "CHAIN_BROKEN": (
        "Restore the chain, or the missing or altered lines, from a copy (a restore from "
        "a shorter copy is held to KEY_NOT_PINNED's cut-back conditions). If no copy has "
        "them, export the items, open a new case, and decide again"
    ),
    "UNPARSEABLE_LINE": (
        "Restore the line from a copy. If no copy has it, export the items, open a new "
        "case, and decide again"
    ),
    "TAMPERED_LINE": (
        "As TAMPERED: restore the original line from a copy and move the altered file "
        "aside; if no copy holds it, as CHAIN_BROKEN"
    ),
    "CHAIN_FORK": (
        "Decided on two boxes after the case was copied: restore the other box's chain, "
        "or copy it into case_dir/ledger/chains/, and decide again"
    ),
    "CHAIN_COPY_DIVERGED": (
        "Keep the copy that holds every examiner's most recent head and whose lines all "
        "pass every line rule, and move the other aside. Copies differing only in "
        "signature bytes: the one whose signature fails is the altered one. If both hold "
        "the heads, both verify and no other chain references the part to be moved "
        "aside, either can be kept, and items decided only in the other copy are decided "
        "again; otherwise as CHAIN_BROKEN"
    ),
    "CHAIN_MISSING": (
        "Restore the chain copy from the other box or a backup. If it can't be restored, "
        "as CHAIN_BROKEN"
    ),
    "HEAD_MISMATCH": (
        "The chain doesn't contain that head. Restore the ledger from a copy or backup "
        "that does; if none does, as CHAIN_BROKEN"
    ),
    "ITEM_MISSING": (
        "Restore the item from a backup or the other box. If it can't be restored, as "
        "CHAIN_BROKEN"
    ),
    "LEDGER_MISSING": (
        "Restore the box ledger or the case's chain copies from a backup; otherwise "
        "`vhir approve --reattest`"
    ),
    "KEY_CHANGED": (
        "If the new key is yours (a forgotten-password reset), pin it with --expect-key "
        "after comparing it with your record; otherwise treat the line as KEY_NOT_PINNED"
    ),
    "CASE_FILE_UNREADABLE": "Restore the case file from a backup",
}
_RESTORE_ROWS = {
    "TAMPERED",
    "TAMPERED_LINE",
    "CHAIN_BROKEN",
    "UNPARSEABLE_LINE",
    "KEY_NOT_PINNED",
    "RETIRED_KEY_USE",
    "CHAIN_COPY_DIVERGED",
    "CHAIN_MISSING",
    "HEAD_MISMATCH",
}


class UsageError(ValueError):
    """A malformed --expect-key or --expect-head (exit 5)."""


@dataclass(frozen=True)
class Pin:
    examiner: str
    fingerprint: str
    chain: str | None = None
    first: int = 1
    last: int | None = None

    def covers(self, fp: str, chain: str, seq: int) -> bool:
        return (
            fp == self.fingerprint
            and (self.chain is None or self.chain == chain)
            and self.first <= seq
            and (self.last is None or seq <= self.last)
        )


@dataclass(frozen=True)
class Head:
    seq: int
    hash: str
    chain: str | None = None


_PIN_RE = re.compile(
    r"^(?P<name>[a-z0-9][a-z0-9-]{0,19})=(?P<fp>SHA256:[A-Za-z0-9+/]{43})"
    r"(?::(?:(?P<chain>[0-9a-f]{16})@)?(?P<first>\d+)-(?P<last>\d*))?$"
)
_HEAD_RE = re.compile(
    r"^(?:(?P<chain>[0-9a-f]{16})@)?(?P<seq>\d+):(?P<hash>[0-9a-f]{64})$"
)


def parse_pin(text: str) -> Pin:
    """`NAME=SHA256:<43 chars>[:[CHAIN@]FROM-TO]`; TO may be empty."""
    m = _PIN_RE.match(text)
    if not m:
        raise UsageError(
            f"--expect-key {text!r}: expected NAME=SHA256:<43 characters>[:FROM-TO]"
        )
    first = int(m["first"]) if m["first"] else 1
    last = int(m["last"]) if m["last"] else None
    if first < 1 or (last is not None and last < first):
        raise UsageError(f"--expect-key {text!r}: bad range")
    return Pin(m["name"], m["fp"], m["chain"], first, last)


def parse_head(text: str) -> Head:
    """`[CHAIN@]SEQ:HASH`, the hash at full length."""
    m = _HEAD_RE.match(text)
    if not m or int(m["seq"]) < 1:
        raise UsageError(f"--expect-head {text!r}: expected [CHAIN@]SEQ:<64 hex>")
    return Head(int(m["seq"]), m["hash"], m["chain"])


# --- Results ----------------------------------------------------------------------


@dataclass
class Line:
    chain: str
    seq: int
    obj: dict
    sig_ok: bool
    fp: str


@dataclass
class Chain:
    chain_id: str
    lines: list[Line]
    sources: list[str]
    broken_at: int | None = None  # first seq whose link or parse failed


@dataclass
class ItemVerdict:
    item_id: str
    item_type: str
    status: str  # VALID, APPROVED_UNDER_0_6 or a failing status
    label: str = ""
    detail: list[str] = field(default_factory=list)
    content_sha256: str = ""  # of the record judged, in the view judged
    view: int = 1


@dataclass
class Result:
    case_id: str
    case_id_source: str
    sources: list[str] = field(default_factory=list)
    chains: list[Chain] = field(default_factory=list)
    items: list[ItemVerdict] = field(default_factory=list)
    failures: list[tuple[str, str]] = field(default_factory=list)  # (code, message)
    notices: list[str] = field(default_factory=list)
    keys: list[dict] = field(default_factory=list)
    anchored: bool = False
    # every entry of each case file exactly as verify read it: (file key, entry)
    records: list[tuple[str, object]] = field(default_factory=list)
    duplicate_ids: set[str] = field(default_factory=set)
    missing: list[str] = field(default_factory=list)  # why it isn't anchored
    after_head: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        failed = self.failures or any(v.status in _FAIL_ITEM for v in self.items)
        return 2 if failed else 0

    def verdict(self, item_id: str) -> ItemVerdict | None:
        return next((v for v in self.items if v.item_id == item_id), None)


# --- Reading ------------------------------------------------------------------


def _case_id(case_dir: Path) -> tuple[str, str]:
    from vhir_cli.case_io import load_case_meta

    meta = load_case_meta(case_dir)
    if meta.get("case_id"):
        return str(meta["case_id"]), "CASE.yaml"
    return case_dir.name, "the directory name"


def _items(case_dir: Path, result: Result) -> dict[str, tuple[str, dict]]:
    """Every item by id, with its type. A case file that doesn't parse, an
    entry that isn't a record and an id used twice fail. Each entry is kept in
    `result.records`, so a report judges exactly what was verified."""
    items: dict[str, tuple[str, dict]] = {}
    for name, kind, key in (
        ("findings.json", "finding", "findings"),
        ("timeline.json", "timeline", "timeline"),
        ("iocs.json", "ioc", "iocs"),
    ):
        path = case_dir / name
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text())
            if not isinstance(data, list):
                raise ValueError("not a list")
        except (OSError, ValueError) as e:
            result.failures.append(
                ("CASE_FILE_UNREADABLE", f"{name} couldn't be read ({e})")
            )
            continue
        for n, item in enumerate(data, 1):
            result.records.append((key, item))
            if not isinstance(item, dict):
                result.failures.append(
                    ("MALFORMED_RECORD", f"{name} entry {n} isn't a record")
                )
                continue
            if item.get("id"):
                item_id = str(item["id"])
                if item_id in items:  # one record per id, across all three files
                    result.duplicate_ids.add(item_id)
                    result.failures.append(
                        (
                            "DUPLICATE_ID",
                            f"{item_id} is used by more than one record ({name}, {items[item_id][0]})",
                        )
                    )
                    continue
                items[item_id] = (kind, item)
    return items


def _fp(obj: dict) -> str:
    try:
        return fingerprint(base64.b64decode(obj["public_key"], validate=True))
    except (KeyError, TypeError, ValueError):
        return "?"


def _read_copy(
    path: Path, label: str
) -> tuple[str | None, list[tuple[int, str, dict | None]]]:
    lines = ledger.read_lines(path)
    first = lines[0][2] if lines else None
    if first and first.get("seq") == 1:
        return ledger.chain_id(ledger.body_of(first)), lines
    return None, lines


def _group_copies(
    copies: list[tuple[str, Path]], case_id: str, result: Result
) -> dict[str, tuple[list[tuple[int, str, dict | None]], list[str]]]:
    """One chain per chain_id: copies that are byte prefixes of the longest are
    one chain (the longest); copies that differ are CHAIN_COPY_DIVERGED."""
    by_id: dict[str, list[tuple[str, list]]] = {}
    for label, path in copies:
        cid, lines = _read_copy(path, label)
        if not lines:
            continue
        result.sources.append(f"{label}: {path} ({len(lines)} lines)")
        if cid is None:
            result.failures.append(
                ("CHAIN_BROKEN", f"{path}: its first line isn't seq 1 of a chain")
            )
            continue
        by_id.setdefault(cid, []).append((label, lines))
    chains = {}
    for cid, group in by_id.items():
        group.sort(key=lambda g: len(g[1]), reverse=True)
        longest = group[0][1]
        labels = [g[0] for g in group]
        for label, lines in group[1:]:
            for (_, a, _), (_, b, _) in zip(longest, lines, strict=False):
                if a != b:
                    break
            else:
                continue
            seq = next(
                (
                    i + 1
                    for i, ((_, a, _), (_, b, _)) in enumerate(
                        zip(longest, lines, strict=False)
                    )
                    if a != b
                ),
                0,
            )
            ok = {
                lbl: all(ledger.signature_valid(p) for _, _, p in ls if p)
                for lbl, ls in ((group[0][0], longest), (label, lines))
            }
            result.failures.append(
                (
                    "CHAIN_COPY_DIVERGED",
                    f"chain {cid}: copies {group[0][0]} and {label} differ from seq {seq} "
                    f"(every line verifies: {group[0][0]} {ok[group[0][0]]}, {label} {ok[label]})",
                )
            )
            if ok[label] and not ok[group[0][0]]:
                longest = lines  # judge items on the copy that verifies
        chains[cid] = (longest, labels)
    return chains


_STR_FIELDS = (
    "prev", "case_id", "item_id", "type", "decision", "status_after", "examiner",
    "at", "mode", "public_key", "content_sha256", "content_snapshot", "sig",
)  # fmt: skip


def _int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _malformed(obj: dict) -> str:
    """The field of a parsed line that has the wrong type or form ("" when
    they're fine). An examiner name must meet the enrolment rule, so a
    look-alike name can't pass as a second examiner."""
    if obj.get("v") != ledger.VERSION or not _int(obj.get("v")):
        return "v"
    if not _int(obj.get("view")) or obj["view"] not in VIEW_EXCLUDES:
        return "view"
    if not _int(obj.get("seq")) or obj["seq"] < 1:
        return "seq"
    bad = [f for f in _STR_FIELDS if not isinstance(obj.get(f), str)]
    if bad:
        return bad[0]
    if not valid_name(obj["examiner"]):
        return "examiner"
    if obj.get("coupled_from") is not None and not isinstance(obj["coupled_from"], str):
        return "coupled_from"
    sup = obj.get("supersedes")
    if sup is not None and not (
        isinstance(sup, list) and all(isinstance(x, str) for x in sup)
    ):
        return "supersedes"
    refs = obj.get("prior_chains")
    if refs is not None and not (
        isinstance(refs, list)
        and all(
            isinstance(r, dict)
            and isinstance(r.get("chain_id"), str)
            and _int(r.get("head_seq"))
            and isinstance(r.get("head_hash"), str)
            for r in refs
        )
    ):
        return "prior_chains"
    gen = obj.get("genesis")
    if gen is not None and not (
        isinstance(gen, dict)
        and isinstance(gen.get("legacy_sha256"), str)
        and _int(gen.get("legacy_bytes"))
    ):
        return "genesis"
    return ""


def _check_chain(
    cid: str,
    lines: list[tuple[int, str, dict | None]],
    labels: list[str],
    case_id: str,
    result: Result,
) -> Chain:
    """The rules every line meets: parsing, links, case id. Signatures are
    recorded per line; they're judged per item or as TAMPERED_LINE later."""
    chain = Chain(cid, [], labels)
    expected, prev = 1, ledger.genesis_prev(case_id)
    for n, _, obj in lines:
        if obj is None:
            result.failures.append(
                ("UNPARSEABLE_LINE", f"chain {cid} line {n} doesn't parse")
            )
            chain.broken_at = chain.broken_at or expected
            expected += 1
            continue
        bad = _malformed(obj)
        if bad:
            result.failures.append(
                (
                    "MALFORMED_LINE",
                    f"chain {cid} line {n}: the field {bad!r} has the wrong type or form",
                )
            )
            chain.broken_at = chain.broken_at or expected
            expected += 1
            continue
        if obj.get("case_id") != case_id:
            result.failures.append(
                (
                    "WRONG_CASE",
                    f"chain {cid} seq {obj.get('seq')} names case {obj.get('case_id')!r}",
                )
            )
        body = ledger.body_of(obj)
        if obj.get("seq") != expected or obj.get("prev") != prev:
            result.failures.append(
                (
                    "CHAIN_BROKEN",
                    f"chain {cid}: a gap, duplicate or changed line at seq {expected}",
                )
            )
            if chain.broken_at is None:
                chain.broken_at = min(expected, obj.get("seq") or expected)
        chain.lines.append(
            Line(
                cid,
                obj.get("seq", expected),
                obj,
                ledger.signature_valid(obj),
                _fp(obj),
            )
        )
        prev = ledger.body_hash(body)
        expected = (obj.get("seq") or expected) + 1
    return chain


def _legacy(
    case_id: str, case_dir: Path, chains: dict[str, Chain], result: Result
) -> tuple[list[tuple[dict, bool]], bool]:
    """The 0.6 lines that judge each item, with whether each was written
    before signing began; and whether a frozen prefix was altered.

    With no signed chain yet, every 0.6 line from every source is before
    signing (informational). Once a chain has its genesis:
    - A prefix a genesis froze (its length and hash matching) is
      authenticated: the box 0.6 file and a chain's own legacy copy are held
      to that chain's genesis, any other copy to whichever genesis it matches.
      For every item such a prefix covers, only the prefix's lines decide, in
      its own order; no other source can reorder, supersede or add to them.
    - For an item no prefix covers, other lines count: a line past a matching
      or own cut was written after signing began; the box 0.6 file of a box
      that holds no chain for the case, matching no genesis, is bound by none,
      so its lines (pre-signing work on that box) are before signing."""
    from vhir_cli import verification

    geneses = [g for g in (_genesis(c) for c in chains.values()) if g is not None]
    box_chain = next((c for c in chains.values() if "box" in c.sources), None)
    sources: list[tuple[str, Path, dict | None]] = [
        (
            "box legacy",
            verification.VERIFICATION_DIR / f"{case_id}.jsonl",
            _genesis(box_chain),
        )
    ]
    for cid, chain in chains.items():
        sources.append(
            (
                f"legacy copy {cid}",
                case_dir / "ledger" / f"legacy-{cid}.jsonl",
                _genesis(chain),
            )
        )
    sources.append(("0.6 close copy", case_dir / "verification.jsonl", None))
    authentic: dict[bytes, dict] = {}  # lines inside a matching frozen prefix, in order
    other: dict[bytes, tuple[dict, bool]] = {}  # line → (record, before signing)
    altered = False
    for label, path, own in sources:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        result.sources.append(f"{label}: {path}")
        matched, unbound = False, not geneses
        if not geneses:
            cut = len(data)  # no signed line yet: all 0.6 lines are before signing
        else:
            matching = [
                int(g["legacy_bytes"])
                for g in ([own] if own is not None else geneses)
                if hashlib.sha256(data[: int(g["legacy_bytes"])]).hexdigest()
                == g["legacy_sha256"]
            ]
            matched = bool(matching)
            # an altered prefix still marks where signing began (PREFIX_ALTERED);
            # a copy matching no genesis has no line from before signing
            cut = max(
                matching, default=int(own["legacy_bytes"]) if own is not None else 0
            )
            if own is not None and not matching:
                altered = True
                result.notices.append(
                    f"PREFIX_ALTERED: {path}'s first {own['legacy_bytes']} bytes don't match "
                    "this case's signed genesis; its 0.6 lines fail"
                )
            unbound = label == "box legacy" and own is None and not matching
        pos = 0
        for raw in data.splitlines(keepends=True):
            pos += len(raw)
            text = raw.strip()
            if not text:
                continue
            before = unbound or pos <= cut  # the whole line inside the cut
            try:
                obj = json.loads(text)
            except json.JSONDecodeError:
                continue
            if not (isinstance(obj, dict) and obj.get("finding_id")):
                continue
            if matched and pos <= cut:
                authentic.setdefault(text, obj)
            elif text not in other or (before and not other[text][1]):
                other[text] = (obj, before)
    covered = {str(obj["finding_id"]) for obj in authentic.values()}
    out = [(obj, True) for obj in authentic.values()]
    out += [
        (obj, before)
        for text, (obj, before) in other.items()
        if text not in authentic and str(obj["finding_id"]) not in covered
    ]
    return out, altered


def _genesis(chain: Chain | None) -> dict | None:
    if chain and chain.lines and chain.lines[0].seq == 1:
        return chain.lines[0].obj.get("genesis") or {
            "legacy_sha256": "",
            "legacy_bytes": 0,
        }
    return None


# --- Order across chains ------------------------------------------------------------


class _Order:
    """Within a chain, by seq; across chains, every line up to a referenced
    head precedes the line that references it. A vector clock per line,
    computed iteratively (pass by pass until nothing changes), never by
    recursion, so a long chain can't exhaust the stack."""

    def __init__(self, chains: dict[str, Chain]):
        self.chains = chains
        self.index = {
            cid: {ln.seq: i for i, ln in enumerate(c.lines)}
            for cid, c in chains.items()
        }
        self.clocks: dict[str, list[dict[str, int]]] = {
            cid: [{} for _ in c.lines] for cid, c in chains.items()
        }
        for _ in range(
            len(chains) + 1
        ):  # references are acyclic in practice; bounded anyway
            changed = False
            for cid, c in chains.items():
                known: dict[str, int] = {}
                for i, ln in enumerate(c.lines):
                    known = dict(known)
                    known[cid] = max(known.get(cid, 0), ln.seq)
                    for ref in ln.obj.get("prior_chains") or []:
                        j = self.index.get(ref.get("chain_id"), {}).get(
                            ref.get("head_seq")
                        )
                        if j is None:
                            continue
                        for other, s in self.clocks[ref["chain_id"]][j].items():
                            known[other] = max(known.get(other, 0), s)
                    if self.clocks[cid][i] != known:
                        self.clocks[cid][i] = known
                        changed = True
            if not changed:
                break

    def _line(self, cid: str, seq: int) -> Line | None:
        i = self.index.get(cid, {}).get(seq)
        return None if i is None else self.chains[cid].lines[i]

    def before(self, a: Line, b: Line) -> bool:
        """`a` precedes `b`."""
        if a.chain == b.chain:
            return a.seq < b.seq
        i = self.index[b.chain].get(b.seq)
        return i is not None and self.clocks[b.chain][i].get(a.chain, 0) >= a.seq


# --- The verdict --------------------------------------------------------------------


def verify_case(
    case_dir: Path,
    ledger_paths: list[Path] | None = None,
    expect_heads: list[Head] | None = None,
    expect_keys: list[Pin] | None = None,
    registry: dict[str, dict] | None = None,
) -> Result:
    """Verify every decided or APPROVED item of the case against the ledger.

    `ledger_paths`: chain copies to read instead of the box chain and the
    case's copies. `registry`: examiner → keys file, for labels only.
    """
    case_id, source = _case_id(case_dir)
    result = Result(case_id, source)
    pins = list(expect_keys or [])
    heads = list(expect_heads or [])
    items = _items(case_dir, result)

    if ledger_paths:
        copies = [("--ledger", Path(p)) for p in ledger_paths]
    else:
        copies = [("box", ledger.chain_path(case_id))]
        copies += [
            ("case copy", p)
            for p in sorted((case_dir / "ledger" / "chains").glob("*.jsonl"))
        ]
    grouped = _group_copies(copies, case_id, result)
    chains: dict[str, Chain] = {}
    for cid, (lines, labels) in grouped.items():
        chains[cid] = _check_chain(cid, lines, labels, case_id, result)
    result.chains = list(chains.values())
    legacy, prefix_altered = _legacy(case_id, case_dir, chains, result)
    order = _Order(chains)

    every_line = [ln for c in chains.values() for ln in c.lines]
    pinned_names = {p.examiner for p in pins}

    def pinned(ln: Line) -> bool:
        return any(
            p.examiner == ln.obj.get("examiner") and p.covers(ln.fp, ln.chain, ln.seq)
            for p in pins
        )

    # Retired keys: a valid line of E naming K in `supersedes` retires K for
    # E's later lines in that chain (a superseding line counts only if, when
    # E has pins, its own key is pinned within range).
    def retired_use(ln: Line) -> bool:
        ex = ln.obj.get("examiner")
        for m in chains[ln.chain].lines:
            if m.seq >= ln.seq:
                break
            if (
                m.obj.get("examiner") == ex
                and ln.fp in (m.obj.get("supersedes") or [])
                and m.sig_ok
                and (ex not in pinned_names or pinned(m))
            ):
                return True
        return False

    latest_of: dict[str, list[Line]] = {}
    for ln in every_line:
        latest_of.setdefault(str(ln.obj.get("item_id")), []).append(ln)

    def latest_line(item_id: str) -> tuple[Line | None, list[Line]]:
        mine = latest_of.get(item_id, [])
        last_per_chain: dict[str, Line] = {}
        for ln in mine:
            if ln.chain not in last_per_chain or ln.seq > last_per_chain[ln.chain].seq:
                last_per_chain[ln.chain] = ln
        cands = list(last_per_chain.values())
        top = [
            c
            for c in cands
            if not any(o is not c and order.before(c, o) for o in cands)
        ]
        return (top[0] if top else None), top

    latest_ids = set()
    for item_id in latest_of:
        top, _ = latest_line(item_id)
        if top:
            latest_ids.add(id(top))

    # Rules on every line (a non-latest line reports case-level).
    for ln in every_line:
        item_id = ln.obj.get("item_id")
        if str(item_id) not in items:
            result.failures.append(
                (
                    "ITEM_MISSING",
                    f"chain {ln.chain} seq {ln.seq} names {item_id}, which the case doesn't have",
                )
            )
        if id(ln) in latest_ids:
            continue
        where = f"chain {ln.chain} seq {ln.seq} ({item_id}, {ln.obj.get('examiner')} {ln.fp})"
        if not ln.sig_ok:
            result.failures.append(
                ("TAMPERED_LINE", f"{where}: its signature doesn't verify")
            )
        if ln.obj.get("examiner") in pinned_names and not pinned(ln):
            result.failures.append(
                ("KEY_NOT_PINNED", f"{where}: key not pinned for that seq")
            )
        if retired_use(ln):
            result.failures.append(
                ("RETIRED_KEY_USE", f"{where}: signed with a key its examiner retired")
            )

    # References between chains.
    for ln in every_line:
        for ref in ln.obj.get("prior_chains") or []:
            rc, rs, rh = ref.get("chain_id"), ref.get("head_seq"), ref.get("head_hash")
            if rc not in chains:
                result.failures.append(
                    (
                        "CHAIN_MISSING",
                        f"chain {ln.chain} seq {ln.seq} references chain {rc}, which isn't presented",
                    )
                )
            else:
                target = order._line(rc, rs) if isinstance(rs, int) else None
                if target is None or ledger.body_hash(ledger.body_of(target.obj)) != rh:
                    result.failures.append(
                        (
                            "HEAD_MISMATCH",
                            f"chain {ln.chain} seq {ln.seq} references chain {rc} at seq {rs}, which that copy doesn't hold",
                        )
                    )

    # More than one key for one examiner, across every chain presented, whatever
    # their order: a warning and a failure unless every one of the keys is pinned.
    keys_of: dict[str, dict[str, list[Line]]] = {}
    for ln in every_line:
        keys_of.setdefault(str(ln.obj.get("examiner")), {}).setdefault(
            ln.fp, []
        ).append(ln)
    for ex, by_key in sorted(keys_of.items()):
        if len(by_key) < 2:
            continue
        pinned_fps = {p.fingerprint for p in pins if p.examiner == ex}
        if all(fp in pinned_fps for fp in by_key):
            continue
        firsts = sorted(
            (min(ln.seq for ln in lines), lines[0].chain, fp)
            for fp, lines in by_key.items()
        )
        listed = "; ".join(
            f"{fp} from chain {cid} seq {seq}" for seq, cid, fp in firsts
        )
        result.failures.append(
            ("KEY_CHANGED", f"{ex} signed with {len(by_key)} keys ({listed}): "
             + KEY_CHANGED.format(seq=firsts[1][0]))
        )  # fmt: skip

    # Items.
    legacy_by_item: dict[str, list[tuple[dict, bool]]] = {}
    for obj, before in legacy:
        legacy_by_item.setdefault(str(obj["finding_id"]), []).append((obj, before))
    for lid in legacy_by_item:
        if lid not in items:
            result.notices.append(
                f"ITEM_MISSING (0.6 line, informational): {lid} isn't in the case"
            )

    for item_id, (kind, item) in sorted(items.items()):
        status = item.get("status", "DRAFT")
        if item_id in latest_of:
            v = _v3_verdict(
                item_id, kind, item, latest_line, chains, pinned, pinned_names,
                retired_use, legacy_by_item,
            )  # fmt: skip
            line, _ = latest_line(item_id)
            v.view = line.obj.get("view", 1) if line else 1
        elif item_id in legacy_by_item and status == "APPROVED":
            v = _legacy_verdict(
                item_id, kind, item, legacy_by_item[item_id], prefix_altered
            )
            v.view = 0
        elif status == "APPROVED":
            v = ItemVerdict(
                item_id,
                kind,
                "APPROVED_NO_LINE",
                "no approval record exists for this item",
            )
        else:
            continue
        # the verdict is about this exact record: its type and its content
        v.content_sha256 = _record_sha(item, kind, v.view)
        result.items.append(v)

    if (
        any(i[1].get("status") == "APPROVED" for i in items.values())
        and not chains
        and not legacy
    ):
        result.failures.append(
            ("LEDGER_MISSING", "APPROVED items, and no ledger in any source")
        )
    if not chains and legacy and not ledger_paths:
        result.notices.append(
            "No signed chain on this box for this case; if it ever had signed approvals, "
            "verify with --expect-head."
        )

    if registry is None:  # the credential files here, for labels only
        registry = keys_registry({str(ln.obj.get("examiner")) for ln in every_line})
    _keys(result, chains, registry)
    _anchor(result, chains, heads, pins, every_line, pinned)
    return result


def _record_sha(item: dict, kind: str, view: int) -> str:
    return hashlib.sha256(signed_text(item, kind, view).encode("utf-8")).hexdigest()


def _differs(signed: str, item: dict, kind: str, view: int) -> list[str]:
    """The fields of the item whose current value differs from the signed one."""
    try:
        was = json.loads(signed)
    except json.JSONDecodeError:
        return ["(the signed content doesn't parse)"]
    now = json.loads(signed_text(item, kind, view))
    return sorted(k for k in set(was) | set(now) if was.get(k) != now.get(k))


def _v3_verdict(
    item_id,
    kind,
    item,
    latest_line,
    chains,
    pinned,
    pinned_names,
    retired_use,
    legacy_by_item,
) -> ItemVerdict:
    status = item.get("status", "DRAFT")
    ln, top = latest_line(item_id)
    if ln is None:
        return ItemVerdict(item_id, kind, "CHAIN_BROKEN", "its lines can't be ordered")
    o = ln.obj
    if len(top) > 1 and any(
        (t.obj.get("status_after"), t.obj.get("content_sha256"))
        != (o.get("status_after"), o.get("content_sha256"))
        for t in top
    ):
        return ItemVerdict(
            item_id,
            kind,
            "CHAIN_FORK",
            "decided differently on two boxes after the case was copied",
        )
    chain = chains[ln.chain]
    if chain.broken_at is not None and chain.broken_at <= ln.seq:
        return ItemVerdict(
            item_id,
            kind,
            "CHAIN_BROKEN",
            f"chain {ln.chain} is broken at seq {chain.broken_at}",
        )
    if not ln.sig_ok:
        return ItemVerdict(
            item_id,
            kind,
            "TAMPERED",
            f"the signature on chain {ln.chain} seq {ln.seq} doesn't verify",
        )
    if o.get("examiner") in pinned_names and not pinned(ln):
        return ItemVerdict(
            item_id, kind, "KEY_NOT_PINNED", f"{ln.fp} isn't pinned for seq {ln.seq}"
        )
    if retired_use(ln):
        return ItemVerdict(
            item_id, kind, "RETIRED_KEY_USE", f"{ln.fp} was retired before seq {ln.seq}"
        )
    if o.get("type") != kind:
        return ItemVerdict(
            item_id,
            kind,
            "WRONG_CASE",
            f"the line says {o.get('type')!r}, the item is a {kind}",
        )
    printed = (
        f"latest line: {o.get('decision')} → {o.get('status_after')} by {o.get('examiner')} at "
        f"{o.get('at')} (chain {ln.chain} seq {ln.seq})"
    )
    if status != o.get("status_after"):
        code = (
            "REVOKED"
            if status == "APPROVED" and o.get("status_after") == "REJECTED"
            else "UNSIGNED_STATUS"
        )
        return ItemVerdict(item_id, kind, code, f"the item is {status}", [printed])
    view = o.get("view", 1)
    current = hashlib.sha256(signed_text(item, kind, view).encode("utf-8")).hexdigest()
    if current != o.get("content_sha256"):
        fields = _differs(o.get("content_snapshot", ""), item, kind, view)
        return ItemVerdict(
            item_id, kind, "ALTERED_AFTER_APPROVAL" if status == "APPROVED" else "UNSIGNED_STATUS",
            f"changed since it was signed: {', '.join(fields)}",
            [f"signed content: {o.get('content_snapshot', '')}"],
        )  # fmt: skip
    label = ""
    if status == "APPROVED":
        if o.get("decision") == "reattest":
            if (item.get("reattested_by"), item.get("reattested_at")) != (
                o.get("examiner"),
                o.get("at"),
            ):
                return ItemVerdict(
                    item_id,
                    kind,
                    "ALTERED_AFTER_APPROVAL",
                    "the re-attestation stamp differs from the signed line",
                    [printed],
                )
            legacy = [obj for obj, _ in legacy_by_item.get(item_id, [])]
            if legacy:
                last = legacy[-1]
                if (item.get("approved_by"), item.get("approved_at")) != (
                    last.get("approved_by"),
                    last.get("approved_at"),
                ):
                    return ItemVerdict(
                        item_id,
                        kind,
                        "ALTERED_AFTER_APPROVAL",
                        "approved_by/approved_at differ from the 0.6 line",
                        [printed],
                    )
                label = (
                    f"re-attested {o.get('at')} by {o.get('examiner')}; legacy approval by "
                    f"{last.get('approved_by')} on {last.get('approved_at')}, unverified"
                )
            else:
                if (item.get("approved_by"), item.get("approved_at")) != (
                    o.get("examiner"),
                    o.get("at"),
                ):
                    return ItemVerdict(
                        item_id,
                        kind,
                        "ALTERED_AFTER_APPROVAL",
                        "approved_by/approved_at differ from the signed line",
                        [printed],
                    )
                label = f"re-attested {o.get('at')}; no earlier approval record"
        elif (item.get("approved_by"), item.get("approved_at")) != (
            o.get("examiner"),
            o.get("at"),
        ):
            return ItemVerdict(
                item_id,
                kind,
                "ALTERED_AFTER_APPROVAL",
                "approved_by/approved_at differ from the signed line",
                [printed],
            )
    if o.get("coupled_from"):
        why = _cascade_unsupported(ln, item, kind, chains)
        if why:
            return ItemVerdict(item_id, kind, "CASCADE_UNSUPPORTED", why, [printed])
        label = f"cascade from {o['coupled_from']}"
    return ItemVerdict(item_id, kind, "VALID", label)


def _cascade_unsupported(
    ln: Line, item: dict, kind: str, chains: dict[str, Chain]
) -> str:
    """Why a cascade line isn't supported by its source decision ("" if it is)."""
    o = ln.obj
    source = None
    for m in chains[ln.chain].lines:
        if m.seq >= ln.seq:
            break
        if (
            m.obj.get("item_id") == o["coupled_from"]
            and m.fp == ln.fp
            and m.obj.get("at") == o.get("at")
        ):
            source = m
    if source is None:
        return f"no decision on {o['coupled_from']} by the same key at the same time precedes it"
    if source.obj.get("status_after") != o.get("status_after"):
        return f"{o['coupled_from']}'s decision doesn't match"
    try:
        signed_source = json.loads(source.obj.get("content_snapshot", ""))
        signed_item = json.loads(o.get("content_snapshot", ""))
    except json.JSONDecodeError:
        return "a signed snapshot doesn't parse"
    if kind == "timeline":
        if (
            signed_source.get("timeline_event_id") != o["item_id"]
            or signed_item.get("auto_created_from") != o["coupled_from"]
        ):
            return "the timeline link isn't in the signed source and event"
    elif kind == "ioc":
        if normalize_ioc(str(signed_item.get("value", ""))) not in ioc_values(
            signed_source.get("iocs")
        ):
            return "the IOC's value isn't among the source finding's signed IOCs"
    else:
        return "a finding is never a cascade"
    return ""


def _legacy_verdict(item_id, kind, item, lines, prefix_altered) -> ItemVerdict:
    frozen = [obj for obj, before in lines if before]
    if not frozen:
        return ItemVerdict(
            item_id,
            kind,
            "LEGACY_AFTER_GENESIS",
            "its only 0.6 lines were written after signing began",
        )
    if prefix_altered:
        return ItemVerdict(
            item_id,
            kind,
            "PREFIX_ALTERED",
            "the 0.6 ledger was changed after signing began",
        )
    last = frozen[-1]
    try:
        snap = json.loads(last.get("content_snapshot", ""))
    except json.JSONDecodeError:
        snap = None
    if isinstance(snap, dict) and kind == "ioc":
        snap = {k: v for k, v in snap.items() if k not in IOC_DERIVED_KEYS}
    now = json.loads(signed_text(item, kind, 0))
    if snap != now or item.get("approved_by") != last.get("approved_by"):
        return ItemVerdict(
            item_id, kind, "ALTERED_AFTER_APPROVAL", "changed since its 0.6 approval",
            [f"0.6 content: {last.get('content_snapshot', '')}; approved by {last.get('approved_by')} at {last.get('approved_at')}"],
        )  # fmt: skip
    return ItemVerdict(item_id, kind, "APPROVED_UNDER_0_6")


def _keys(result: Result, chains: dict[str, Chain], registry: dict[str, dict]) -> None:
    from vhir_cli.keys import key_fingerprint

    seen: dict[tuple[str, str], dict] = {}
    for c in chains.values():
        for ln in c.lines:
            k = seen.setdefault(
                (str(ln.obj.get("examiner")), ln.fp),
                {
                    "examiner": str(ln.obj.get("examiner")),
                    "fingerprint": ln.fp,
                    "public_key": ln.obj.get("public_key"),
                    "ranges": {},
                    "lines": 0,
                },
            )
            first, last = k["ranges"].get(c.chain_id, (ln.seq, ln.seq))
            k["ranges"][c.chain_id] = (min(first, ln.seq), max(last, ln.seq))
            k["lines"] += 1
    for (ex, fp), k in seen.items():
        entry = next(
            (
                e
                for e in (registry.get(ex) or {}).get("keys", [])
                if key_fingerprint(e) == fp
            ),
            None,
        )
        if entry is None:
            k["label"] = "not registered here"
        elif entry.get("status") == "active":
            k["label"] = "registered here (active, from the credential file)"
        else:
            k["label"] = (
                f"registered here (retired: {entry.get('retired_reason', '')}, from the credential file)"
            )
        result.keys.append(k)


def _anchor(result: Result, chains, heads, pins, every_line, pinned) -> None:
    """Apply --expect-head and --expect-key: `anchored` when every signing key is
    pinned within range and each chain's supplied head is its last line."""
    head_for: dict[str, Head] = {}
    for h in heads:
        if h.chain is not None:
            if h.chain not in chains:
                result.failures.append(
                    (
                        "CHAIN_MISSING",
                        f"--expect-head names chain {h.chain}, which isn't presented",
                    )
                )
                continue
            targets = [h.chain]
        else:
            targets = list(chains)
        hit = None
        for cid in targets:
            line = next((ln for ln in chains[cid].lines if ln.seq == h.seq), None)
            if line and ledger.body_hash(ledger.body_of(line.obj)) == h.hash:
                hit = cid
                break
        if hit is None:
            result.failures.append(
                (
                    "HEAD_MISMATCH",
                    f"no chain presented holds seq {h.seq} sha256:{h.hash}",
                )
            )
            continue
        head_for[hit] = h
    for cid, chain in chains.items():
        last = chain.lines[-1].seq if chain.lines else 0
        h = head_for.get(cid)
        if h is None:
            result.missing.append(f"no head for chain {cid}")
        elif h.seq < last:
            result.missing.append(f"chain {cid} has lines after your head")
            result.after_head.append(
                f"{last - h.seq} lines after your head in chain {cid} (seq {h.seq + 1}–{last}) aren't anchored:"
            )
            for ln in chain.lines[h.seq :]:
                o = ln.obj
                result.after_head.append(
                    f"  seq {ln.seq}: {o.get('item_id')} {o.get('decision')} by {o.get('examiner')} {ln.fp}"
                )
    names = {p.examiner for p in pins}
    for ln in every_line:
        ex = ln.obj.get("examiner")
        if ex not in names:
            msg = f"no key list for examiner {ex}"
            if msg not in result.missing:
                result.missing.append(msg)
    result.anchored = (
        not result.missing and all(pinned(ln) for ln in every_line) and bool(chains)
    )


# --- Output -----------------------------------------------------------------------


def render(result: Result) -> str:
    """The verify report. Every value from the case or the ledger is printed
    through the display rule."""
    from vhir_cli.display import one_line as s
    from vhir_cli.ledger import format_head

    out = [
        f"Case {s(result.case_id)} (case id from {result.case_id_source})",
        "Sources:",
    ]
    out += [f"  {s(x)}" for x in result.sources] or ["  none"]
    for c in result.chains:
        if c.lines:
            last = c.lines[-1]
            head = (last.seq, ledger.body_hash(ledger.body_of(last.obj)))
            out.append(
                f"  {format_head(s(result.case_id), head, f'chain {c.chain_id}')} ({', '.join(c.sources)})"
            )
    out.append("Signing keys:")
    for k in result.keys:
        ranges = "; ".join(
            f"chain {cid} seq {a}–{b}" for cid, (a, b) in k["ranges"].items()
        )
        out.append(
            f"  {s(k['examiner'])} {k['fingerprint']} ({ranges}; {k['lines']} lines; {k['label']})"
        )
    if not result.keys:
        out.append("  none")
    out.append("Items:")
    for v in result.items:
        label = f" ({s(v.label)})" if v.label else ""
        shown = (
            "approved under 0.6 (before signing)"
            if v.status == "APPROVED_UNDER_0_6"
            else v.status
        )
        out.append(f"  {s(v.item_id):<24} {shown}{label}")
        for d in v.detail:
            out.append(f"      {s(d)}")
        if v.status in RECOVERY and v.status in _FAIL_ITEM:
            out.append(f"      Recovery: {RECOVERY[v.status]}")
            if v.status in _RESTORE_ROWS:
                out.append(f"      {REPLACE_NOTE}")
    for code, msg in result.failures:
        out.append(f"{code}: {s(msg)}")
        if code in RECOVERY:
            out.append(f"  Recovery: {RECOVERY[code]}")
            if code in _RESTORE_ROWS:
                out.append(f"  {REPLACE_NOTE}")
    for n in result.notices:
        out.append(s(n))
    if result.anchored:
        out.append("anchored")
    else:
        out.append(NOT_ANCHORED)
        out += [f"  {s(m)}" for m in result.missing]
    out += [s(x) for x in result.after_head]
    out.append(f"Exit {result.exit_code}")
    return "\n".join(out)


def keys_registry(examiners: set[str]) -> dict[str, dict]:
    """The credential files on this box, for key labels only."""
    from vhir_cli.keys import KeysFileInvalid, load

    out = {}
    for ex in examiners:
        try:
            data = load(ex)
        except (KeysFileInvalid, ValueError):
            continue
        if data:
            out[ex] = data
    return out


DERIVED_IOC_NOTE = "IOC context (sources, sightings, confidence, MITRE techniques) is derived, not signed."


def _heads(result: Result) -> list[str]:
    from vhir_cli.ledger import format_head

    out = []
    for c in result.chains:
        if c.lines:
            last = c.lines[-1]
            out.append(
                format_head(
                    result.case_id,
                    (last.seq, ledger.body_hash(ledger.body_of(last.obj))),
                    f"chain {c.chain_id}",
                )
            )
    return out


def verification_block(view: dict) -> list[str]:
    """The block every report and export ends with : what verified,
    what didn't, the "Not anchored" sentence, every signing key with its full
    fingerprint, and each chain's head. A copy that leaves this machine is an
    anchor for the keys as they were then."""
    result: Result = view["result"]
    approved = [i for key in ("findings", "timeline", "iocs") for i in view[key]]
    old = sum(
        1
        for i in approved
        if view["labels"].get(i.get("id")) == "approved under 0.6 (before signing)"
    )
    lines = ["VERIFICATION", "=" * 50]
    lines.append(
        f"Approvals shown as approved: {len(approved)} (approved under 0.6, before signing: {old})"
    )
    if view["not_verified"]:
        lines.append("Not verified, so not shown as approved:")
        lines += [f"  {n['id']} {n['status']}" for n in view["not_verified"]]
    for code, msg in result.failures:
        lines.append(f"Case-level: {code}: {msg}")
    lines.append(NOT_ANCHORED)
    lines.append("Signing keys:")
    for k in result.keys:
        ranges = "; ".join(
            f"chain {cid} seq {a}–{b}" for cid, (a, b) in k["ranges"].items()
        )
        lines.append(f"  {k['examiner']} {k['fingerprint']} ({ranges}; {k['label']})")
    if not result.keys:
        lines.append("  none")
    lines += _heads(result) or ["Ledger head: no signed chain"]
    lines.append(DERIVED_IOC_NOTE)
    lines.append("Status counts count by status; they aren't verification.")
    return lines


def verification_json(view: dict) -> dict:
    result: Result = view["result"]
    return {
        "exit_code": result.exit_code,
        "not_anchored": NOT_ANCHORED,
        "not_verified": view["not_verified"],
        "labels": view["labels"],
        "case_failures": [{"code": c, "message": m} for c, m in result.failures],
        "keys": [
            {
                "examiner": k["examiner"],
                "fingerprint": k["fingerprint"],
                "public_key": k["public_key"],
                "first_seq": min(a for a, _ in k["ranges"].values()),
                "last_seq": max(b for _, b in k["ranges"].values()),
                "chains": {cid: [a, b] for cid, (a, b) in k["ranges"].items()},
                "label": k["label"],
            }
            for k in result.keys
        ],
        "heads": _heads(result),
        "derived_ioc_note": DERIVED_IOC_NOTE,
    }


def approved_view(case_dir: Path) -> dict:
    """The items a report may show as approved: VALID (in any form) and
    approved under 0.6, each with its label. Every other APPROVED item is in
    `not_verified` with its status. It judges the records verify read, not a
    second read of the files."""
    result = verify_case(case_dir)
    by_id = {v.item_id: v for v in result.items}
    kinds = {"findings": "finding", "timeline": "timeline", "iocs": "ioc"}
    view: dict = {
        "findings": [],
        "timeline": [],
        "iocs": [],
        "not_verified": [],
        "labels": {},
    }
    for key, item in result.records:
        if not isinstance(item, dict) or item.get("status") != "APPROVED":
            continue
        v = by_id.get(str(item.get("id")))
        own = (
            v is not None
            and v.item_type == kinds[key]  # this record's own verdict:
            and v.content_sha256 == _record_sha(item, kinds[key], v.view)
        )
        if (
            own
            and v.status in ("VALID", "APPROVED_UNDER_0_6")
            and not result.failures  # nothing counts while the case fails
        ):
            view[key].append(item)
            shown = (
                "approved under 0.6 (before signing)"
                if v.status == "APPROVED_UNDER_0_6"
                else v.label
            )
            if shown:
                view["labels"][item["id"]] = shown
            continue
        if v is None:
            status = (
                "DUPLICATE_ID"
                if str(item.get("id")) in result.duplicate_ids
                else "NO_SIGNED_LINE"
            )
        elif not own:
            status = "DUPLICATE_ID"  # another record holds this id's verdict
        elif v.status in ("VALID", "APPROVED_UNDER_0_6"):
            status = "CASE_FAILURE"
        else:
            status = v.status
        view["not_verified"].append({"id": item.get("id"), "status": status})
    view["result"] = result
    return view
