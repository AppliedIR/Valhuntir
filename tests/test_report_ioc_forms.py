"""An IOC cited in any of its forms is one IOC in every report. For each form
of the corpus (hxxp at the scheme, inside the host and inside the path; [.]
and [@] bracketed to depth 3; upper case), through `vhir report --findings`
and `--ioc`: a saved report writes none of it live; a signed rejection of its
records keeps it out of the IOC report's listing, and a saved report still
writes none of it live (every recorded value is defanged, whatever its
status); and the listing holds it once, however many forms cite it. The records are those record_finding stores for the
citations (sift-mcp's tests check that against the real one). report-mcp's
tests state the same rows against its report."""

from __future__ import annotations

import json
import re

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.test_report import _make_args, case_dir, identity  # noqa: F401
from vhir_cli import ioc_types, keys, ledger
from vhir_cli.case_io import load_iocs, save_findings, signed_text
from vhir_cli.commands.report import _extract_all_iocs, cmd_report
from vhir_cli.ledger_verify import approved_view

FINDING = "F-tester-001"
AT = "2026-10-08T10:00:00+00:00"
CORPUS = {  # each IOC: its type, the live names none of its forms may show, its forms
    "a URL, hxxp at the scheme": ("url", ["evil-s.example.com"], [
        "http://evil-s.example.com/a", "hxxp://evil-s.example.com/a",
        "hxxp[:]//evil-s[.]example[.]com/a", "HXXP://EVIL-S.EXAMPLE.COM/A"]),
    "a domain, hxxp inside the host": ("domain-name", ["hxxp.example.com", "http.example.com"], [
        "hxxp.example.com", "hxxp[.]example[.]com", "hxxp[[.]]example.com",
        "HXXP.EXAMPLE.COM"]),
    "a URL, hxxp inside the path": ("url", ["safe.example.com"], [
        "https://safe.example.com/hxxp/payload", "hxxps://safe[.]example[.]com/hxxp/payload",
        "https://safe[[.]]example.com/hxxp/payload", "HTTPS://SAFE.EXAMPLE.COM/HXXP/PAYLOAD"]),
    "a domain, [.] to depth 3": ("domain-name", ["evil-d.example.org"], [
        "evil-d.example.org", "evil-d[.]example[.]org", "evil-d[[.]]example[[.]]org",
        "evil-d[[[.]]]example[[[.]]]org", "EVIL-D[.]EXAMPLE[.]ORG"]),
    "a URL, [@] to depth 3": ("url", ["evil-u.example.org"], [
        "http://user@evil-u.example.org/x", "hxxp://user[@]evil-u[.]example[.]org/x",
        "hxxp://user[[@]]evil-u.example.org/x", "hxxp://user[[[@]]]evil-u.example.org/x",
        "HXXP://USER[@]EVIL-U.EXAMPLE.ORG/X"]),
}  # fmt: skip
ROWS = [  # (id, the IOC, the forms the finding cites)
    *((f"{name}, cited as {form}", name, [form])
      for name, (_, _, forms) in CORPUS.items() for form in forms),
    *((f"{name}, cited in every form", name, forms)
      for name, (_, _, forms) in CORPUS.items()),
]  # fmt: skip
IDS = [r[0] for r in ROWS]
KNOWN = {  # forms a saved report writes as cited, host live, as public main (0.6.5) does
    "hxxp://evil-s.example.com/a", "HXXP://EVIL-S.EXAMPLE.COM/A",
    "hxxp://user[[@]]evil-u.example.org/x", "hxxp://user[[[@]]]evil-u.example.org/x",
    "HXXP://USER[@]EVIL-U.EXAMPLE.ORG/X",
}  # fmt: skip
WRITTEN_LIVE = pytest.mark.xfail(strict=True, reason=(
    "known issue, as at public main (0.6.5): a URL cited with its host's dots live "
    "(only the scheme defanged, or a nested [@] the defanger doesn't read) is written "
    "as cited; there: AssertionError: assert ['evil-s.example.com'] == []"))  # fmt: skip
HOST_IN_TEXT = pytest.mark.xfail(strict=True, reason=(
    "known issue, as at public main (0.6.5): the IOC report lists the host inside a "
    "recorded URL, named in the finding's text, as found in text and not recorded, and "
    "writes it live; there: Found in text, not recorded (1): evil-s.example.com"))  # fmt: skip


def stored(forms: list[str], kind: str) -> list[dict]:
    """The IOC records record_finding stores for a finding citing `forms`
    typed `kind`: each refanged, joined to a record that is the same IOC."""
    records: list[dict] = []
    for form in forms:
        value = ioc_types.refang(form.strip())
        if not any(ioc_types.keys(value, kind) & ioc_types.keys(r["value"], kind)
                   for r in records):  # fmt: skip
            records.append({"id": f"IOC-tester-{len(records) + 1:03d}", "value": value,
                            "type": kind, "status": "DRAFT", "manually_reviewed": False,
                            "source_findings": [FINDING]})  # fmt: skip
    return records


def live(text: str, name: str) -> list[str]:
    """The IOC's live names that `text` shows, in any letter case."""
    return [h for h in CORPUS[name][1] if re.search(re.escape(h), text, re.I)]


def _case(case_dir, name: str, forms: list[str], status: str, text="o") -> list[dict]:  # noqa: F811
    """The case: one approved finding citing `forms` (its observation
    `text`), and its records, each set to `status` by the examiner (APPROVED
    or REJECTED), all signed in the ledger as vhir approve and reject sign
    them. Returns the records."""
    kind = CORPUS[name][0]
    finding = {"id": FINDING, "title": "t", "observation": text, "interpretation": "i",
               "confidence": "HIGH", "status": "APPROVED", "approved_by": "tester",
               "approved_at": AT, "iocs": [{"value": f, "type": kind} for f in forms]}  # fmt: skip
    records = [{**r, "status": status, "manually_reviewed": True}
               for r in stored(forms, kind)]  # fmt: skip
    for r in records:
        if status == "APPROVED":
            r.update(approved_by="tester", approved_at=AT)
    key = Ed25519PrivateKey.generate()
    pub = keys.b64(keys.public_raw(key))
    decisions = [{"item_id": FINDING, "type": "finding", "decision": "approve",
                  "status_after": "APPROVED", "coupled_from": None,
                  "content_snapshot": signed_text(finding, "finding"),
                  "checks": {"result": "not-applicable", "items": []}}]  # fmt: skip
    decisions += [{"item_id": r["id"], "type": "ioc",
                   "decision": "approve" if status == "APPROVED" else "reject",
                   "status_after": status, "coupled_from": None,
                   "content_snapshot": signed_text(r, "ioc")} for r in records]  # fmt: skip
    ledger.LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    bodies = ledger.prepare(case_dir.name, decisions, "tester", pub, "cli", AT)
    with ledger.case_lock(case_dir.name) as lock:
        ledger.commit(lock, bodies, [ledger.sign_body(b, key) for b in bodies], pub)
    save_findings(case_dir, [finding])
    (case_dir / "iocs.json").write_text(json.dumps(records))
    return records


def _listed(case_dir) -> list[str]:  # noqa: F811
    """The IOC report's listing, as `vhir report --ioc` gathers it."""
    view = approved_view(case_dir)
    assert view["result"].exit_code == 0, view["result"].failures
    groups = _extract_all_iocs(view["findings"], view["iocs"], load_iocs(case_dir))
    return [v for values in groups.values() for v in values]


def _saved(case_dir, identity, **report) -> str:  # noqa: F811
    cmd_report(_make_args(save="r.txt", **report), identity)
    return (case_dir / "reports" / "r.txt").read_text()


REPORTS = {
    "the findings report": {"report_findings": FINDING},
    "the IOC report": {"ioc": True},
}


def _known(name: str, forms: list[str], report: str) -> list:
    """The known issue a row of the test below fails on, if any."""
    if report == "the findings report":
        return [WRITTEN_LIVE] if KNOWN & set(forms) else []
    # The IOC report writes the text's IOCs only, and the text pattern reads a
    # lowercase top-level domain only
    lower = any(f != f.upper() for f in forms)
    return [HOST_IN_TEXT] if CORPUS[name][0] == "url" and lower else []


@pytest.mark.parametrize(("name", "forms", "report"), [
    pytest.param(name, forms, report, id=f"{row}-{report}", marks=_known(name, forms, report))
    for report in REPORTS for row, name, forms in ROWS
])  # fmt: skip
def test_a_saved_report_writes_no_form_of_an_ioc_live(  # noqa: F811
    case_dir, identity, name, forms, report  # noqa: F811
):  # fmt: skip
    """The finding names it in every form cited and as stored."""
    named = [*forms, *(r["value"] for r in stored(forms, CORPUS[name][0]))]
    _case(case_dir, name, forms, "APPROVED", text="Seen: " + "; ".join(named) + ".")
    assert live(_saved(case_dir, identity, **REPORTS[report]), name) == []


@pytest.mark.parametrize(("name", "forms"), [r[1:] for r in ROWS], ids=IDS)
def test_a_signed_rejection_keeps_every_form_out_of_the_listing(  # noqa: F811
    case_dir, identity, name, forms  # noqa: F811
):  # fmt: skip
    _case(case_dir, name, forms, "REJECTED")
    assert _listed(case_dir) == []
    saved = _saved(case_dir, identity, ioc=True)
    assert live(saved, name) == []


@pytest.mark.parametrize(("name", "forms"), [
    pytest.param(name, forms, id=row, marks=_known(name, forms, "the findings report"))
    for row, name, forms in ROWS
])  # fmt: skip
def test_a_saved_report_writes_no_form_of_a_rejected_ioc_live(  # noqa: F811
    case_dir, identity, name, forms  # noqa: F811
):  # fmt: skip
    """The finding names it in every form cited and as stored."""
    named = [*forms, *(r["value"] for r in stored(forms, CORPUS[name][0]))]
    _case(case_dir, name, forms, "REJECTED", text="Seen: " + "; ".join(named) + ".")
    assert live(_saved(case_dir, identity, report_findings=FINDING), name) == []


@pytest.mark.parametrize(("name", "forms"), [r[1:] for r in ROWS], ids=IDS)
def test_the_listing_holds_an_ioc_once_however_it_is_cited(case_dir, name, forms):  # noqa: F811
    _case(case_dir, name, forms, "APPROVED")
    assert len(_listed(case_dir)) == 1
