"""A saved text report (`vhir report ... --save`) defangs every network IOC a
case records and leaves every other value live. "The saved body" is every
byte the save writes; each row first asserts that its value is in it, live or
defanged, then asserts which.

The three routes put the IOC in a finding's `iocs` list ({"value", "type"}),
in its {type: [values]} form, or in an IOC record in iocs.json.

- Every spelling of domain-name, ipv4-addr and url in the type table, and its
  upper-case, `-`->`_`, `-`->space and padded forms, is defanged.
- The type rule and the selector are each looked up through vhir_cli.defang:
  patched, every route's saved output flips.
- A name typed file:name, named-pipe or hostname stays live, even where
  another finding or record types the same string under a network key.
- A URL or an IPv4 address (a range: its base) is defanged whatever type it
  folds to, under a network key too, as 0.6.6 saved it; a name of that type
  in the same case stays live.
- Free-text types holding a network word, and every url:path spelling, are
  defanged; IPv4-of-C2 with a port is kept live, as before.
- Nested values are walked to the display's depth limit (8) through either
  finding route, and a record's `value` counts from where a finding's `iocs`
  field does; a depth-9 value stays live, as the display shows it.
- An IPv4 address with a port is defanged as its bare address when its
  nearest type is ipv4-addr (any spelling) or absent; other types keep it."""

from __future__ import annotations

import json
import re
import sys
import traceback

import pytest

from vhir_cli import approval_auth, defang, ioc_types

from .signing import PASSPHRASE, enrol, sign_approved

F, F2, IOC, IOC2 = "F-tester-001", "F-tester-002", "IOC-tester-001", "IOC-tester-002"
DOM, IP, URL = "evil.example.com", "10.1.2.3", "http://bad.example.com/x.php"
TABLE = {"domain-name": DOM, "ipv4-addr": IP, "url": URL}
ROUTES = ("list", "dict", "record")
SAVES = {
    "findings": ("report", "--findings", F),
    "executive": ("report", "--executive-summary"),
    "ioc": ("report", "--ioc"),
}


def fanged(v: str) -> str:
    """`v` as a saved report defangs it: hxxp for a scheme, [.] for each dot of
    the host (a URL's path is kept)."""
    m = re.fullmatch(r"(?i)(https?)://([^/\s:?#]+)(\S*)", v)
    if m:
        return f"hxxp{m.group(1)[4:]}://{m.group(2).replace('.', '[.]')}{m.group(3)}"
    return v.replace(".", "[.]")


def _record(t, v, status="DRAFT", rid=IOC) -> dict:
    r = {"id": rid, "value": v, "type": t, "category": "network", "description": "",
         "status": status, "source_findings": [], "manually_reviewed": False,
         "tags": [], "mitre_techniques": []}  # fmt: skip
    if status == "APPROVED":
        r.update(source_findings=[F], manually_reviewed=True)
    return r


def _route(route, t, v) -> tuple:
    """The finding's `iocs` and the case's IOC records for one route."""
    if route == "list":
        return [{"value": v, "type": t}], []
    if route == "dict":
        return {str(t): [v]}, []
    return [], [_record(t, v)]


def _finding(fid, obs, iocs, status="DRAFT", title="Beacon") -> dict:
    return {"id": fid, "title": title, "observation": obs, "interpretation": "i",
            "confidence": "HIGH", "status": status, "iocs": iocs}  # fmt: skip


def _case(root, monkeypatch, findings, records):
    d = root / "C-net"
    d.mkdir(parents=True)
    for name in ("reports", "audit"):
        (d / name).mkdir()
    (d / "CASE.yaml").write_text(
        "case_id: C-net\nname: Net\nstatus: open\nexaminer: tester\n"
    )
    (d / "findings.json").write_text(json.dumps(findings))
    (d / "iocs.json").write_text(json.dumps(records))
    (d / "timeline.json").write_text("[]")
    (d / "todos.json").write_text("[]")
    (d / "evidence.json").write_text(json.dumps({"files": []}))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setattr(approval_auth, "_LOCKOUT_FILE", root / "lockout")
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": PASSPHRASE)
    enrol("tester")
    if any(i.get("status") == "APPROVED" for i in [*findings, *records]):
        sign_approved(d)
    return d


def _vhir(monkeypatch, capsys, *argv) -> dict:
    from vhir_cli.main import main

    monkeypatch.setattr("builtins.input", lambda p="": "")
    monkeypatch.setattr(sys, "argv", ["vhir", *argv])
    raised = None
    try:
        main()
        rc = 0
    except SystemExit as e:
        rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except Exception as e:  # noqa: BLE001  (shown in the assertion's message)
        rc = "raised"
        raised = (
            f"{type(e).__name__}: {e} at {traceback.extract_tb(e.__traceback__)[-1]}"
        )
    out = capsys.readouterr()
    assert raised is None, f"raised {raised}"
    assert "Traceback" not in out.out + out.err, (out.out + out.err)[-800:]
    assert rc == 0, f"rc {rc}: {(out.out + out.err)[-400:]}"
    return {"stdout": out.out, "text": out.out + out.err}


def _save(root, monkeypatch, capsys, findings, records, route="findings") -> str:
    """The saved body of one save route on a case holding `findings` and
    `records`."""
    d = _case(root, monkeypatch, findings, records)
    _vhir(monkeypatch, capsys, *SAVES[route], "--save", "r.txt")
    saved = d / "reports" / "r.txt"
    assert saved.exists(), "the report wasn't saved"
    return saved.read_text()


def _saved(root, monkeypatch, capsys, obs, iocs, records) -> str:
    return _save(root, monkeypatch, capsys, [_finding(F, obs, iocs)], records)


def _defanged(body, v):
    assert v in body or fanged(v) in body, f"{v} isn't in the saved report"
    assert v not in body, f"{v} is live in the saved report"


def _live(body, v):
    assert v in body, f"{v} isn't live in the saved report"
    assert fanged(v) not in body, f"{v} is defanged in the saved report"


# -- every table spelling of a network type --------------------------------------

SPELLINGS = [(cid, s) for cid in TABLE for s in (cid, *ioc_types.IDS[cid][2].split())]
VARIANTS = {
    "as-written": lambda s: s,
    "upper": str.upper,
    "underscore": lambda s: s.replace("-", "_"),
    "space": lambda s: s.replace("-", " "),
    "padded": lambda s: f"  {s} ",
}


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("variant", list(VARIANTS))
@pytest.mark.parametrize("cid,spelling", SPELLINGS, ids="-".join)
def test_every_table_spelling_is_defanged(
    tmp_path, monkeypatch, capsys, cid, spelling, variant, route
):
    v = TABLE[cid]
    iocs, recs = _route(route, VARIANTS[variant](spelling), v)
    _defanged(_saved(tmp_path, monkeypatch, capsys, f"Seen: {v} .", iocs, recs), v)


# -- the type rule and the selector are looked up through vhir_cli.defang -----------

OBS_PORT = "Seen 10.1.2.3 first, then 10.1.2.3:443."
BARE = re.compile(r"(?<![\d.])10\.1\.2\.3(?![\d]|\.\d)")  # a whole 10.1.2.3
FLIPS = {
    # name: (attribute, patch, type, value, observation, outcome unpatched, patched)
    "type-rule-false": ("_network_type", lambda t: False, "domain-name", DOM, None),
    "type-rule-true": ("_network_type", lambda t: True, "hostname", "ws01.corp.example", None),
    "selector-none": ("select_network_ioc", lambda v, t=None, *, network=...: None,
                      "domain-name", DOM, None),
    "selector-identity": ("select_network_ioc", lambda v, t=None, *, network=...: v,
                          "ipv4-addr", "10.1.2.3:443", OBS_PORT),
}  # fmt: skip


def _flip_outcome(body, v, obs):
    if obs == OBS_PORT:  # the bare address the selector picks
        held = bool(BARE.search(body)) or fanged(IP) in body
        assert held, f"{IP} isn't in the saved report"
        return "live" if BARE.search(body) else "defanged"
    assert v in body or fanged(v) in body, f"{v} isn't in the saved report"
    return "live" if v in body else "defanged"


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("name", list(FLIPS))
def test_patching_the_owner_flips_every_route(
    tmp_path, monkeypatch, capsys, name, route
):
    attr, patch, t, v, obs = FLIPS[name]
    obs = obs or f"Seen: {v} ."
    iocs, recs = _route(route, t, v)
    before = _saved(tmp_path / "a", monkeypatch, capsys, obs, iocs, recs)
    with monkeypatch.context() as m:
        m.setattr(defang, attr, patch)
        after = _saved(tmp_path / "b", monkeypatch, capsys, obs, iocs, recs)
    got = (_flip_outcome(before, v, obs), _flip_outcome(after, v, obs))
    want = ("live", "defanged") if name == "type-rule-true" else ("defanged", "live")
    assert got == want, f"{name} on {route}: {got}"


# -- what stays live, and the free-text and url:path types --------------------------

NEGATIVES = (("file:name", "a.ps1"), ("named-pipe", "svc.pipe.example"),
             ("hostname", "ws01.corp.example"))  # fmt: skip


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("t,v", NEGATIVES)
def test_a_non_network_type_stays_live(tmp_path, monkeypatch, capsys, t, v, route):
    iocs, recs = _route(route, t, v)
    _live(_saved(tmp_path, monkeypatch, capsys, f"Seen: {v} .", iocs, recs), v)


# (value, its own type, the network key another finding or record holds it under)
COLLATERAL = (("a.ps1", "file:name", "urls"), ("svc.pipe.example", "named-pipe", "urls"),
              ("ws01.corp.example", "hostname", "domain"), ("svc.backup", "user-account", "url"),
              ("rundll32.exe", "process:command-line", "domain"))  # fmt: skip


@pytest.mark.parametrize("save", list(SAVES))
@pytest.mark.parametrize("status", ["DRAFT", "APPROVED"])
@pytest.mark.parametrize("form", ROUTES)
@pytest.mark.parametrize("v,own,key", COLLATERAL)
def test_a_value_typed_non_network_stays_live_under_a_network_key(
    tmp_path, monkeypatch, capsys, v, own, key, form, status, save
):
    """An approved finding names `v` with its own type (title, text, iocs); a
    second finding or record, DRAFT or APPROVED, types the same string with
    that type under a network key. `v` stays live everywhere in the save,
    PROVENANCE included."""
    carrier = _finding(F2, f"ran {v} on the host", [{"value": v, "type": own}],
                       status="APPROVED", title=f"Saw {v}")  # fmt: skip
    inner = [{"value": v, "type": own}]
    iocs, recs = {"dict": ({key: inner}, []), "list": ([{key: inner}], []),
                  "record": ([], [_record(key, inner, status, IOC2)])}[form]  # fmt: skip
    second = _finding(F, "beacons to c2.example.net", iocs, status=status)
    findings = [second, carrier]
    route = ("report", "--findings", F2) if save == "findings" else SAVES[save]
    d = _case(tmp_path, monkeypatch, findings, recs)
    _vhir(monkeypatch, capsys, *route, "--save", "r.txt")
    body = (d / "reports" / "r.txt").read_text()
    provenance = body.split("PROVENANCE")[-1].splitlines()
    assert f"[{F2}] Saw {v}" in provenance, "the carrier isn't in PROVENANCE"
    _live(body, v)


POSITIVES = [("c2-domain", DOM), ("malicious-url", URL), ("IPv4-of-C2", IP)]
POSITIVES += [
    (s, "index.php") for s in ("url:path", *ioc_types.IDS["url:path"][2].split())
]


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("t,v", POSITIVES)
def test_a_free_text_network_type_and_every_url_path_spelling_are_defanged(
    tmp_path, monkeypatch, capsys, t, v, route
):
    iocs, recs = _route(route, t, v)
    _defanged(_saved(tmp_path, monkeypatch, capsys, f"Seen: {v} .", iocs, recs), v)


@pytest.mark.parametrize("route", ROUTES)
def test_ipv4_of_c2_with_a_port_is_kept_live(tmp_path, monkeypatch, capsys, route):
    v = "10.1.2.3:443"
    iocs, recs = _route(route, "IPv4-of-C2", v)
    body = _saved(tmp_path, monkeypatch, capsys, f"Seen: {v} .", iocs, recs)
    assert v in body, "the address isn't live in the saved report"
    assert fanged(IP) not in body, "the address is defanged in the saved report"


# -- a URL or an IPv4 address, whatever type it folds to ---------------------------

ADDR, LINK = "10.9.8.7", "http://evil.example.com/x"
# (type, value): a URL- or IPv4-shaped value under a type that folds to a
# non-network table id, and a range under one
SHAPED = (("hostname", ADDR), ("hostname", LINK), ("user-account", ADDR),
          ("file:path", LINK), ("process:command-line", LINK), ("file:name", ADDR),
          ("hostname", "10.9.8.0/24"))  # fmt: skip
NAMED = (("hostname", "ws01.corp.example"), ("user-account", "svc.backup"),
         ("file:name", "a.ps1"), ("process:command-line", "rundll32.exe"),
         ("named-pipe", "svc.pipe.example"))  # fmt: skip


def _under_key(route, t, v) -> tuple:
    """`v` typed `t`, held under a network key on one route."""
    inner = [{"value": v, "type": t}]
    return {"dict": ({"domain": inner}, []), "list": ([{"url": inner}], []),
            "record": ([], [_record("url", inner)])}[route]  # fmt: skip


@pytest.mark.parametrize("route", ROUTES)
def test_an_ipv4_typed_address_is_defanged(tmp_path, monkeypatch, capsys, route):
    iocs, recs = _route(route, "ipv4-addr", ADDR)
    body = _saved(tmp_path, monkeypatch, capsys, f"Seen: {ADDR} .", iocs, recs)
    _defanged(body, ADDR)


@pytest.mark.parametrize("held", ["own", "under-key"])
@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("t,v", SHAPED)
def test_a_url_or_ipv4_value_is_defanged_whatever_its_type(
    tmp_path, monkeypatch, capsys, t, v, route, held
):
    iocs, recs = (_route if held == "own" else _under_key)(route, t, v)
    _defanged(_saved(tmp_path, monkeypatch, capsys, f"Seen: {v} .", iocs, recs), v)


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("t,name", NAMED)
def test_a_name_stays_live_beside_an_address_of_its_type(
    tmp_path, monkeypatch, capsys, t, name, route
):
    """A name and an IPv4 address under the same non-network type, in one
    case: the address is defanged and the name stays live."""
    iocs = {"list": [{"value": name, "type": t}, {"value": ADDR, "type": t}],
            "dict": {t: [name, ADDR]}, "record": []}[route]  # fmt: skip
    recs = [_record(t, name), _record(t, ADDR, rid=IOC2)] if route == "record" else []
    obs = f"Seen: {name} and {ADDR} ."
    body = _saved(tmp_path, monkeypatch, capsys, obs, iocs, recs)
    _live(body, name)
    _defanged(body, ADDR)


# -- nesting and records ---------------------------------------------------------

SHAPES = {
    "N0": ({"c2": [{"value": "n0.example.com", "type": "domain-name"}]}, ["n0.example.com"]),
    "N1": ([{"value": ["n1a.example.com", "n1b.example.com"], "type": "domain-name"}],
           ["n1a.example.com", "n1b.example.com"]),
    "N2": ({"domain": [["n2.example.com"]]}, ["n2.example.com"]),
    "N3": ({"domain-name": {"value": "n3.example.com"}}, ["n3.example.com"]),
    "N4": ([[{"value": "n4.example.com", "type": "domain-name"}]], ["n4.example.com"]),
    "N5": ([{"value": {"value": "n5.example.com", "type": "domain-name"}, "type": "c2"}],
           ["n5.example.com"]),
    "S1": ({"type": "domain-name", "values": ["s1.example.com"]}, ["s1.example.com"]),
    "S2": ({"domain": [{"value": "s2.example.com", "type": ""}]}, ["s2.example.com"]),
    "S3": ({"domain": [{"value": "s3.example.com", "type": None}]}, ["s3.example.com"]),
    "S4": ({"domain": {"value": "s4.example.com", "type": "c2"}}, ["s4.example.com"]),
    "S4-list": ({"domain": [{"value": "s4l.example.com", "type": "c2"}]}, ["s4l.example.com"]),
    "S5": ([{"Value": "s5.example.com", "Type": "domain"}], ["s5.example.com"]),
}  # fmt: skip
N6 = {"id": IOC, "type": "domain-name", "value": ["n6.example.com"], "status": "DRAFT"}


def depth_of(node, target, depth=0):
    """The display's depth of `target` in `node`: one level per dict or list."""
    if isinstance(node, str):
        return depth if node == target else None
    items = node.values() if isinstance(node, dict) else node
    for item in items if isinstance(node, (dict, list)) else ():
        if (found := depth_of(item, target, depth + 1)) is not None:
            return found
    return None


def nested(node, values, k):
    """`node` with each of `values` put k lists deeper (a `type` is left alone)."""
    if isinstance(node, str):
        for _ in range(k if node in values else 0):
            node = [node]
        return node
    if isinstance(node, dict):
        return {
            key: v if key == "type" else nested(v, values, k) for key, v in node.items()
        }
    if isinstance(node, list):
        return [nested(v, values, k) for v in node]
    return node


def _nesting_cells():
    for tag, (field, values) in SHAPES.items():
        own = depth_of(field, values[0])
        native = "dict" if isinstance(field, dict) else "list"
        other = "list" if native == "dict" else "dict"
        for depth in range(max(2, own), 10):
            yield tag, native, depth
            if depth - 1 >= own:
                yield tag, other, depth
    own = depth_of(N6["value"], "n6.example.com")  # a record counts from its value
    for depth in range(max(2, own), 10):
        yield "N6", "record", depth


def _nesting_case(tag, route, depth):
    """The finding's `iocs`, the records and the values for one cell."""
    if tag == "N6":
        k = depth - depth_of(N6["value"], "n6.example.com")
        rec = dict(N6, value=nested(N6["value"], {"n6.example.com"}, k))
        assert depth_of(rec["value"], "n6.example.com") == depth
        return [], [rec], ["n6.example.com"]
    field, values = SHAPES[tag]
    native = "dict" if isinstance(field, dict) else "list"
    inner = nested(
        field, set(values), depth - depth_of(field, values[0]) - (route != native)
    )
    if route != native:  # the other finding route holds it one level deeper,
        # under a non-network key: the shape's own type decides
        inner = [inner] if route == "list" else {"file:name": inner}
    iocs = inner
    assert depth_of(iocs, values[0]) == depth
    return iocs, [], values


@pytest.mark.parametrize("tag,route,depth", list(_nesting_cells()), ids=str)
def test_a_nested_value_is_walked_to_the_display_limit(
    tmp_path, monkeypatch, capsys, tag, route, depth
):
    """Depths 2-8 are saved with no live value. Depth 9 is past the limit: the
    save and the display hold the value live in the finding's text only, and
    both show the finding's IOCs line with "..." where the nesting is cut. An
    N6 finding holds no iocs (its value is a record), so neither shows "..."."""
    iocs, recs, values = _nesting_case(tag, route, depth)
    obs = "Seen: " + ", ".join(values) + "."
    body = _saved(tmp_path, monkeypatch, capsys, obs, iocs, recs)
    if depth <= 8:
        for v in values:
            _defanged(body, v)
        return
    shown = _vhir(monkeypatch, capsys, "report", "--findings", F)["stdout"]
    for v in values:
        assert (body.count(v), shown.count(v)) == (1, 1), (
            body.count(v),
            shown.count(v),
        )
    cut = tag != "N6"
    assert ("..." in body, "..." in shown) == (cut, cut), (body, shown)


@pytest.mark.parametrize("depth", [7, 8, 9])
def test_a_record_value_reaches_the_limit_a_finding_iocs_field_does(
    tmp_path, monkeypatch, capsys, depth
):
    """The same nested value as a finding's `iocs` field and as an IOC record's
    `value` saves the finding's text the same way: defanged through depth 8,
    live at 9 on both."""
    v = f"x{depth}.example.com"
    value = [{"value": nested(v, {v}, depth - 2), "type": "domain-name"}]
    assert depth_of(value, v) == depth
    obs = f"Seen: {v}."
    lines = []
    for where, iocs, recs in (("finding", value, []),
                              ("record", [], [_record("domain-name", value)])):  # fmt: skip
        body = _saved(tmp_path / where, monkeypatch, capsys, obs, iocs, recs)
        lines.append([s for s in body.splitlines() if "Seen: " in s])
    want = f"Seen: {v if depth == 9 else fanged(v)}."
    assert lines[0] == lines[1], lines
    assert len(lines[0]) == 1 and lines[0][0].endswith(f" {want}"), lines


OTHER = [{"value": DOM, "type": "other"}]
RECORDS = {
    "uri-url": ([], [_record("uri", "http://urirec.example.com/p")], "http://urirec.example.com/p"),
    "c2-ipv4": ([], [_record("c2", "10.9.8.7")], "10.9.8.7"),
    "other-dict": ({"url": OTHER}, [], DOM),
    "other-list": ([{"url": OTHER}], [], DOM),
    "other-record": ([], [_record("url", OTHER)], DOM),
}  # fmt: skip


@pytest.mark.parametrize("name", list(RECORDS))
def test_a_uri_or_c2_record_and_an_other_type_under_url_are_defanged(
    tmp_path, monkeypatch, capsys, name
):
    iocs, recs, v = RECORDS[name]
    _defanged(_saved(tmp_path, monkeypatch, capsys, f"Seen: {v}.", iocs, recs), v)


# -- an IPv4 address with a port --------------------------------------------------

PORT = "10.1.2.3:443"
ALIASES = ioc_types.IDS["ipv4-addr"][2].split()


def _port_cells():
    for t in ("ipv4-addr", *ALIASES, ""):
        for route in ROUTES:
            yield f"{route}-{t or 'empty'}", *_route(route, t, PORT), 0
    yield "untyped-value", [{"value": PORT}], [], 0
    yield "untyped-plain", [PORT], [], 0
    yield "untyped-record", [], [{"id": IOC, "value": PORT, "status": "DRAFT"}], 0
    yield "url-holding-ip-src", {"url": [{"value": PORT, "type": "ip-src"}]}, [], 0
    yield "domain-name-values-ipv4-addr", {"type": "domain-name", "values": [
        {"value": PORT, "type": "ipv4-addr"}]}, [], 0  # fmt: skip
    # kept as before: the bare address stays live (whole occurrences counted)
    for t in ("url", "domain-name", 5):
        for route in ROUTES:
            yield f"{route}-{t}", *_route(route, t, PORT), 2 if route == "record" else 3
    yield "dict-indicator", {"indicator": [PORT]}, [], 3
    yield "ipv4-holding-url", {"ipv4": [{"value": PORT, "type": "url"}]}, [], 3
    yield "ipv4-addr-values-hostname", {"type": "ipv4-addr", "values": [
        {"value": PORT, "type": "hostname"}]}, [], 3  # fmt: skip


@pytest.mark.parametrize(
    "name,iocs,recs,live", list(_port_cells()), ids=lambda x: str(x)
)
def test_an_ipv4_address_with_a_port(
    tmp_path, monkeypatch, capsys, name, iocs, recs, live
):
    """Typed ipv4-addr (any spelling), typed "", or untyped: no whole 10.1.2.3
    is live. Typed otherwise, the bare address is kept live, as before."""
    body = _saved(tmp_path, monkeypatch, capsys, OBS_PORT, iocs, recs)
    assert PORT in body or fanged(IP) + ":443" in body, "the address isn't in the save"
    assert len(BARE.findall(body)) == live, BARE.findall(body)
    if live:
        assert fanged(IP) not in body
