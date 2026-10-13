"""Tests for review command views."""

import json
import re
from argparse import Namespace

import pytest
import yaml

from vhir_cli.case_io import (
    compute_content_hash,
    load_findings,
    save_findings,
    save_timeline,
    verify_approval_integrity,
    write_approval_log,
)
from vhir_cli.commands.review import (
    _extract_iocs_from_findings,
    _extract_text_iocs,
    cmd_review,
)

from .signing import approve_under_0_6


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """Create a minimal flat case directory structure."""
    case_id = "INC-2026-TEST"
    case_path = tmp_path / case_id
    case_path.mkdir()

    monkeypatch.setenv("VHIR_EXAMINER", "tester")

    meta = {
        "case_id": case_id,
        "name": "Test Case",
        "status": "open",
        "created": "2026-02-19",
        "examiner": "tester",
    }
    with open(case_path / "CASE.yaml", "w") as f:
        yaml.dump(meta, f)

    with open(case_path / "evidence.json", "w") as f:
        json.dump({"files": []}, f)

    monkeypatch.setenv("VHIR_CASE_DIR", str(case_path))
    return case_path


@pytest.fixture
def identity():
    return {
        "os_user": "testuser",
        "examiner": "analyst1",
        "examiner_source": "flag",
        "analyst": "analyst1",
        "analyst_source": "flag",
    }


@pytest.fixture
def sample_findings(case_dir):
    findings = [
        {
            "id": "F-tester-001",
            "status": "APPROVED",
            "title": "Lateral movement via PsExec",
            "confidence": "HIGH",
            "audit_ids": ["ev-001", "ev-002"],
            "observation": "PsExec executed from 192.168.1.50 to target host",
            "interpretation": "Attacker moved laterally",
            "iocs": {
                "IPv4": ["192.168.1.50", "10.0.0.15"],
                "Domain": ["evil.example.com"],
                "File": ["C:\\Windows\\Temp\\payload.exe"],
            },
        },
        {
            "id": "F-tester-002",
            "status": "DRAFT",
            "title": "Suspicious scheduled task",
            "confidence": "MEDIUM",
            "audit_ids": ["ev-003"],
            "observation": "Observed connection to 172.16.0.99",
            "interpretation": "Possible persistence",
            "iocs": {"IPv4": ["172.16.0.99"]},
        },
        {
            "id": "F-tester-003",
            "status": "REJECTED",
            "title": "Potential data staging",
            "confidence": "LOW",
            "audit_ids": [],
            "observation": "Files found in temp directory",
            "interpretation": "Benign activity",
        },
    ]
    save_findings(case_dir, findings)
    return findings


@pytest.fixture
def sample_timeline(case_dir):
    events = [
        {
            "id": "T-tester-001",
            "status": "APPROVED",
            "timestamp": "2026-02-19T10:00:00Z",
            "description": "Initial access via phishing email",
            "audit_ids": ["ev-001"],
        },
        {
            "id": "T-tester-002",
            "status": "DRAFT",
            "timestamp": "2026-02-19T11:00:00Z",
            "description": "Lateral movement detected",
        },
    ]
    save_timeline(case_dir, events)
    return events


class TestFindingsTable:
    def test_findings_table(self, case_dir, sample_findings, capsys):
        args = Namespace(
            case=None,
            findings=True,
            detail=False,
            verify=False,
            iocs=False,
            timeline=False,
            audit=False,
            evidence=False,
            limit=50,
        )
        cmd_review(args, {})
        output = capsys.readouterr().out
        # Summary view: Title, Confidence, Provenance, Status (ID moved to detail)
        assert "APPROVED" in output
        assert "HIGH" in output
        assert "Lateral movement" in output

    def test_findings_empty(self, case_dir, capsys):
        save_findings(case_dir, [])
        args = Namespace(
            case=None,
            findings=True,
            detail=False,
            verify=False,
            iocs=False,
            timeline=False,
            audit=False,
            evidence=False,
            limit=50,
        )
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "No findings" in output


class TestFindingsDetail:
    def test_detail_shows_all_fields(self, case_dir, sample_findings, capsys):
        args = Namespace(
            case=None,
            findings=True,
            detail=True,
            verify=False,
            iocs=False,
            timeline=False,
            audit=False,
            evidence=False,
            limit=50,
        )
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "F-tester-001" in output
        assert "Observation:" in output
        assert "Interpretation:" in output
        assert "Evidence:" in output


class TestFindingsVerify:
    """--verify reads the signed ledger, not approvals.jsonl (an unsigned
    activity log): a record there doesn't make an approval verify."""

    def _verify(self, capsys):
        args = Namespace(case=None, findings=True, detail=False, verify=True, iocs=False,
                         timeline=False, audit=False, evidence=False, limit=50)  # fmt: skip
        with pytest.raises(SystemExit) as e:
            cmd_review(args, {})
        return capsys.readouterr().out, e.value.code

    def test_an_approval_log_record_is_not_verification(
        self, case_dir, sample_findings, identity, capsys
    ):
        write_approval_log(
            case_dir, "F-tester-001", "APPROVED", identity, mode="interactive"
        )
        out, code = self._verify(capsys)
        assert re.search(r"F-tester-001\s+APPROVED_NO_LINE", out), out
        assert code == 2

    def test_an_approved_finding_with_no_record_fails(
        self, case_dir, sample_findings, capsys
    ):
        out, code = self._verify(capsys)
        assert re.search(r"F-tester-001\s+APPROVED_NO_LINE", out), out
        assert "LEDGER_MISSING" in out and code == 2

    def test_draft_and_rejected_items_without_lines_aren_t_listed(
        self, case_dir, capsys
    ):
        save_findings(
            case_dir,
            [{"id": "F-tester-010", "status": "DRAFT", "title": "Test"},
             {"id": "F-tester-011", "status": "REJECTED", "title": "Test"}],
        )  # fmt: skip
        out, code = self._verify(capsys)
        assert "F-tester-010" not in out and "F-tester-011" not in out and code == 0


class TestVerifyIntegrity:
    def test_confirmed(self, case_dir, identity):
        finding = {"id": "F-tester-001", "status": "APPROVED", "title": "Test"}
        finding["content_hash"] = compute_content_hash(finding)
        save_findings(case_dir, [finding])
        write_approval_log(case_dir, "F-tester-001", "APPROVED", identity)
        results = verify_approval_integrity(case_dir)
        assert results[0]["verification"] == "confirmed"

    def test_no_record(self, case_dir):
        save_findings(
            case_dir, [{"id": "F-tester-001", "status": "APPROVED", "title": "Test"}]
        )
        results = verify_approval_integrity(case_dir)
        assert results[0]["verification"] == "no approval record"

    def test_mismatched_action(self, case_dir, identity):
        save_findings(
            case_dir, [{"id": "F-tester-001", "status": "APPROVED", "title": "Test"}]
        )
        write_approval_log(case_dir, "F-tester-001", "REJECTED", identity)
        results = verify_approval_integrity(case_dir)
        assert results[0]["verification"] == "no approval record"

    def test_draft_unverified(self, case_dir):
        save_findings(
            case_dir, [{"id": "F-tester-001", "status": "DRAFT", "title": "Test"}]
        )
        results = verify_approval_integrity(case_dir)
        assert results[0]["verification"] == "draft"


class TestIOCExtraction:
    def test_structured_iocs(self, case_dir, sample_findings, capsys):
        args = Namespace(
            case=None,
            findings=False,
            detail=False,
            verify=False,
            iocs=True,
            timeline=False,
            audit=False,
            evidence=False,
            limit=50,
        )
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "Approved Findings" in output
        assert "192.168.1.50" in output
        assert "evil.example.com" in output
        assert "Draft Findings" in output
        assert "172.16.0.99" in output

    def test_extract_from_dict_iocs(self):
        findings = [
            {
                "iocs": {"IPv4": ["1.2.3.4"], "Domain": ["bad.com"]},
                "observation": "",
                "interpretation": "",
            }
        ]
        result = _extract_iocs_from_findings(findings)
        assert "1.2.3.4" in result["IPv4"]
        assert "bad.com" in result["Domain"]

    def test_extract_from_list_iocs(self):
        findings = [
            {
                "iocs": [{"type": "IPv4", "value": "5.6.7.8"}],
                "observation": "",
                "interpretation": "",
            }
        ]
        result = _extract_iocs_from_findings(findings)
        assert "5.6.7.8" in result["IPv4"]

    def test_extract_text_ipv4(self):
        collected = {}
        _extract_text_iocs("Connected to 10.20.30.40 from source", collected)
        assert "10.20.30.40" in collected["IPv4"]

    def test_extract_text_sha256(self):
        collected = {}
        h = "a" * 64
        _extract_text_iocs(f"Hash: {h}", collected)
        assert h in collected["SHA256"]

    def test_extract_text_windows_path(self):
        collected = {}
        _extract_text_iocs(r"Found at C:\Windows\Temp\evil.exe on disk", collected)
        assert r"C:\Windows\Temp\evil.exe" in collected["File"]

    def test_extract_text_domain(self):
        collected = {}
        _extract_text_iocs("Resolved evil.example.com via DNS", collected)
        assert "evil.example.com" in collected["Domain"]

    def test_no_iocs(self, case_dir, capsys):
        save_findings(
            case_dir,
            [
                {
                    "id": "F-tester-001",
                    "status": "DRAFT",
                    "title": "Nothing",
                    "observation": "clean",
                    "interpretation": "benign",
                }
            ],
        )
        args = Namespace(
            case=None,
            findings=False,
            detail=False,
            verify=False,
            iocs=True,
            timeline=False,
            audit=False,
            evidence=False,
            limit=50,
        )
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "No IOCs" in output


class TestTimeline:
    def test_timeline_summary(self, case_dir, sample_timeline, capsys):
        args = Namespace(
            case=None,
            findings=False,
            detail=False,
            verify=False,
            iocs=False,
            timeline=True,
            audit=False,
            evidence=False,
            limit=50,
        )
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "T-tester-001" in output
        assert "APPROVED" in output

    def test_timeline_detail(self, case_dir, sample_timeline, capsys):
        args = Namespace(
            case=None,
            findings=False,
            detail=True,
            verify=False,
            iocs=False,
            timeline=True,
            audit=False,
            evidence=False,
            limit=50,
        )
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "Description:" in output
        assert "Initial access" in output

    def test_timeline_empty(self, case_dir, capsys):
        save_timeline(case_dir, [])
        args = Namespace(
            case=None,
            findings=False,
            detail=False,
            verify=False,
            iocs=False,
            timeline=True,
            audit=False,
            evidence=False,
            limit=50,
        )
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "No timeline" in output


class TestSummary:
    def test_summary_shows_counts(
        self, case_dir, sample_findings, sample_timeline, capsys
    ):
        args = Namespace(
            case=None,
            findings=False,
            detail=False,
            verify=False,
            iocs=False,
            timeline=False,
            audit=False,
            evidence=False,
            limit=50,
        )
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "1 draft" in output
        assert "1 approved" in output
        assert "1 rejected" in output


class TestTimelineFiltering:
    def test_filter_by_status(self, case_dir, sample_timeline, capsys):
        args = Namespace(
            case=None,
            findings=False,
            detail=False,
            verify=False,
            iocs=False,
            timeline=True,
            audit=False,
            evidence=False,
            limit=50,
            status="APPROVED",
            start=None,
            end=None,
            type=None,
        )
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "T-tester-001" in output
        assert "T-tester-002" not in output

    def test_filter_by_date_range(self, case_dir, sample_timeline, capsys):
        args = Namespace(
            case=None,
            findings=False,
            detail=False,
            verify=False,
            iocs=False,
            timeline=True,
            audit=False,
            evidence=False,
            limit=50,
            status=None,
            start="2026-02-19T10:30:00Z",
            end=None,
            type=None,
        )
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "T-tester-002" in output
        assert "T-tester-001" not in output

    def test_filter_by_event_type(self, case_dir, capsys):
        events = [
            {
                "id": "T-tester-010",
                "status": "DRAFT",
                "timestamp": "2026-02-19T10:00:00Z",
                "description": "Process execution",
                "event_type": "execution",
            },
            {
                "id": "T-tester-011",
                "status": "DRAFT",
                "timestamp": "2026-02-19T11:00:00Z",
                "description": "Registry change",
                "event_type": "registry",
            },
        ]
        save_timeline(case_dir, events)
        args = Namespace(
            case=None,
            findings=False,
            detail=False,
            verify=False,
            iocs=False,
            timeline=True,
            audit=False,
            evidence=False,
            limit=50,
            status=None,
            start=None,
            end=None,
            type="execution",
        )
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "T-tester-010" in output
        assert "T-tester-011" not in output

    def test_no_results_after_filter(self, case_dir, sample_timeline, capsys):
        args = Namespace(
            case=None,
            findings=False,
            detail=False,
            verify=False,
            iocs=False,
            timeline=True,
            audit=False,
            evidence=False,
            limit=50,
            status="REJECTED",
            start=None,
            end=None,
            type=None,
        )
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "No timeline" in output


class TestVerifyTampered:
    def test_a_hash_and_log_record_don_t_make_an_approval(
        self, case_dir, identity, capsys
    ):
        """A status flip with a recomputed content_hash and an appended
        approvals.jsonl line (F12's forgery) has no signed line."""
        save_findings(
            case_dir,
            [
                {
                    "id": "F-tester-010",
                    "title": "Test",
                    "observation": "original",
                    "status": "DRAFT",
                }
            ],
        )
        findings = load_findings(case_dir)
        findings[0]["content_hash"] = compute_content_hash(findings[0])
        findings[0]["status"] = "APPROVED"
        save_findings(case_dir, findings)
        write_approval_log(case_dir, "F-tester-010", "APPROVED", identity)
        args = Namespace(case=None, findings=True, detail=False, verify=True, iocs=False,
                         timeline=False, audit=False, evidence=False, limit=50)  # fmt: skip
        with pytest.raises(SystemExit) as e:
            cmd_review(args, {})
        out = capsys.readouterr().out
        assert re.search(r"F-tester-010\s+APPROVED_NO_LINE", out), out
        assert "confirmed" not in out and e.value.code == 2


# --- --verify with no findings still checks the ledger ----------------------
# load_findings returns [] when findings.json is absent, empty or corrupt;
# the verifier then printed "No findings recorded." and stopped, skipping the
# reconciliation that reports ledger entries without findings. The case
# directory's name differs from its case_id: the ledger is under the case_id.


@pytest.fixture
def ledger_case(tmp_path, monkeypatch):
    import vhir_cli.approval_auth as auth
    import vhir_cli.verification as ver

    monkeypatch.setattr(ver, "VERIFICATION_DIR", tmp_path / "ledger")
    prompts = []
    monkeypatch.setattr(auth, "getpass_prompt", lambda p: (prompts.append(p), "pw")[1])
    case = tmp_path / "V-case"
    case.mkdir()
    (case / "CASE.yaml").write_text(
        "case_id: INC-REAL-1\nstatus: open\nexaminer: steve\n"
    )
    now = "2026-01-01T00:00:00+00:00"
    common = {
        "status": "DRAFT",
        "staged": now,
        "modified_at": now,
        "created_by": "steve",
    }
    finding = {
        "id": "F-steve-001",
        "title": "First finding",
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "MEDIUM",
        "type": "finding",
        "examiner": "steve",
        "timeline_event_id": "T-steve-001",
        **common,
    }
    event = {
        "id": "T-steve-001",
        "timestamp": "2026-01-01T00:00:00Z",
        "description": "First finding",
        "auto_created_from": "F-steve-001",
        "examiner": "steve",
        **common,
    }
    (case / "findings.json").write_text(json.dumps([finding]))
    (case / "timeline.json").write_text(json.dumps([event]))
    return case, prompts


def _approve_and_verify(case, prompts, capsys, *, findings, mine=False, alice=False):
    """F-steve-001 and its event approved under 0.6 (as 0.6's approve left
    them), findings.json then set to `findings` ("intact", "absent", "[]",
    "corrupt"), then --verify. Returns (output, exit code)."""
    import vhir_cli.verification as ver
    from vhir_cli.commands.review import _show_findings_verify

    ident = {"examiner": "steve", "os_user": "steve", "analyst": "steve"}
    if findings != "none":
        approve_under_0_6(case, {"F-steve-001", "T-steve-001"}, "steve")
    if alice:  # another examiner's 0.6 line
        entry = {
            "finding_id": "F-alice-001",
            "type": "finding",
            "hmac": "00",
            "hmac_version": 2,
            "content_snapshot": "{}",
            "approved_by": "alice",
            "approved_at": "2026-01-01",
            "case_id": "INC-REAL-1",
        }
        with open(ver.VERIFICATION_DIR / "INC-REAL-1.jsonl", "a") as fh:
            fh.write(json.dumps(entry) + "\n")
    path = case / "findings.json"
    path.chmod(0o644)
    if findings == "absent":
        path.unlink()
    elif findings in ("[]", "none"):
        path.write_text("[]")
    elif findings == "corrupt":
        path.write_text('[{"id": "F-steve-001", "status": "APPRO')
    capsys.readouterr()
    prompts.clear()
    with pytest.raises(SystemExit) as e:
        _show_findings_verify(case, identity=ident, mine_only=mine)
    return capsys.readouterr().out, e.value.code


@pytest.mark.parametrize("findings", ["absent", "[]"])
def test_0_6_lines_without_their_findings_are_reported(ledger_case, capsys, findings):
    case, prompts = ledger_case
    out, code = _approve_and_verify(case, prompts, capsys, findings=findings)
    assert "ITEM_MISSING (0.6 line, informational): F-steve-001" in out, out
    assert code == 0 and not prompts


def test_a_corrupt_findings_file_fails(ledger_case, capsys):
    case, prompts = ledger_case
    out, code = _approve_and_verify(case, prompts, capsys, findings="corrupt")
    assert "CASE_FILE_UNREADABLE" in out and code == 2, out


def test_intact_0_6_approvals_verify_with_no_password(ledger_case, capsys):
    case, prompts = ledger_case
    out, code = _approve_and_verify(case, prompts, capsys, findings="intact")
    assert re.search(r"F-steve-001\s+approved before 0.6.4", out), out
    assert re.search(r"T-steve-001\s+approved before 0.6.4", out), out
    assert code == 0 and not prompts


def test_no_findings_and_no_ledger_passes_quietly(ledger_case, capsys):
    case, prompts = ledger_case
    out, code = _approve_and_verify(case, prompts, capsys, findings="none")
    assert code == 0 and not prompts and "FAIL" not in out


def test_mine_filters_what_s_shown_and_asks_nothing(ledger_case, capsys):
    case, prompts = ledger_case
    out, code = _approve_and_verify(
        case, prompts, capsys, findings="intact", mine=True, alice=True
    )
    items = [x for x in out.split("Items:")[1].splitlines() if x.startswith("  ")]
    assert not prompts and items and not any("F-alice-001" in x for x in items), out
    assert "the whole case; --mine only filters what's shown" in out
