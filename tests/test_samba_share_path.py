"""The Samba share isn't repointed at a case path with a control character.

The share's `path = <case dir>` line is written to smb.conf.d with
`sudo tee`. A cases folder whose name holds a line break (case-mcp's
`cases_dir` is only length-checked, and the CLI takes VHIR_CASES_DIR) wrote
extra lines of its own, e.g. a second `path = /`, read-write. The path is now
refused before anything is written or run; callers report it as a warning.
"""

from __future__ import annotations

import json
from argparse import Namespace

import pytest
import yaml

from vhir_cli.commands.join import _repoint_samba_share
from vhir_cli.main import _case_activate

INJECTED = "inj\n    path = /\n    #"
IDENT = {"examiner": "tester", "os_user": "u", "examiner_source": "flag"}


@pytest.fixture
def sudo(tmp_path, monkeypatch):
    """A fake sudo on PATH that records each call and what tee was given."""
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    (home / ".vhir" / "samba.yaml").write_text(
        yaml.dump({"share_name": "cases", "wintools_ip": "192.0.2.5"})
    )
    monkeypatch.setenv("HOME", str(home))
    log = tmp_path / "sudo.log"
    stub = tmp_path / "bin" / "sudo"
    stub.parent.mkdir()
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "data = sys.stdin.read() if sys.argv[1:2] == ['tee'] else None\n"
        f"open({str(log)!r}, 'a').write(json.dumps([sys.argv[1:], data]) + '\\n')\n"
    )
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{stub.parent}:/usr/bin:/bin")
    # the sift group step runs first at activation; here it has nothing to do
    from vhir_cli import main

    monkeypatch.setattr(
        main, "_set_case_wintools_permissions", lambda d: None, raising=False
    )

    def calls():
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]

    return calls


def test_a_case_path_with_a_line_break_is_refused(sudo, tmp_path):
    with pytest.raises(ValueError, match="control character"):
        _repoint_samba_share(tmp_path / INJECTED / "C-1")
    assert sudo() == []


@pytest.mark.parametrize("char", ["\r", "\t", "\x1b", "\x7f"])
def test_any_control_character_is_refused(sudo, tmp_path, char):
    with pytest.raises(ValueError, match="control character"):
        _repoint_samba_share(tmp_path / f"cases{char}x" / "C-1")
    assert sudo() == []


def test_case_activate_warns_and_leaves_the_share_alone(
    sudo, tmp_path, monkeypatch, capsys
):
    cases = tmp_path / INJECTED
    (cases / "C-1").mkdir(parents=True)
    (cases / "C-1" / "CASE.yaml").write_text("case_id: C-1\nstatus: open\n")
    monkeypatch.setenv("VHIR_CASES_DIR", str(cases))
    _case_activate(Namespace(case_id="C-1"), IDENT)
    err = capsys.readouterr().err
    assert "Warning: wintools share update failed" in err
    assert "control character" in err
    assert sudo() == []


def test_anchor_a_plain_case_path_is_written_as_before(sudo, tmp_path):
    case = tmp_path / "cases" / "C-1"
    _repoint_samba_share(case)
    calls = sudo()
    assert calls[0][0] == ["tee", "/etc/samba/smb.conf.d/vhir-cases.conf"]
    assert f"    path = {case}\n" in calls[0][1]
    assert calls[0][1].count("path = ") == 1


def test_case_activate_of_a_line_break_cases_folder_leaves_the_share_where_it_was(
    sudo, tmp_path, monkeypatch, capsys
):
    """The share points at a good case; activating one under a cases folder
    whose name holds a line break warns and changes nothing."""
    import os

    samba = tmp_path / "home" / ".vhir" / "samba.yaml"
    doc = yaml.safe_load(samba.read_text())
    good = str(tmp_path / "cases" / "W2")
    samba.write_text(yaml.dump({**doc, "active_share_target": good}))
    cases = tmp_path / INJECTED
    (cases / "C-1").mkdir(parents=True)
    (cases / "C-1" / "CASE.yaml").write_text("case_id: C-1\nstatus: open\n")
    monkeypatch.setenv("VHIR_CASES_DIR", str(cases))
    before = os.stat(samba).st_mtime_ns, samba.read_text()
    _case_activate(Namespace(case_id="C-1"), IDENT)
    assert "case path has a control character" in capsys.readouterr().err
    assert sudo() == []  # no smb.conf write, no reload
    assert (os.stat(samba).st_mtime_ns, samba.read_text()) == before
    assert yaml.safe_load(samba.read_text())["active_share_target"] == good


def test_the_share_is_repointed_only_at_a_path_smb_conf_can_hold(sudo, tmp_path):
    """The same check the join uses: a trailing backslash would join the next
    smb.conf line onto `path =`."""
    with pytest.raises(ValueError, match="ends with a backslash"):
        _repoint_samba_share(tmp_path / "C-1\\")
    assert sudo() == []


def test_a_bad_target_already_tracked_is_still_refused(sudo, tmp_path):
    samba = tmp_path / "home" / ".vhir" / "samba.yaml"
    bad = str(tmp_path / INJECTED / "C-1")
    samba.write_text(
        yaml.dump({**yaml.safe_load(samba.read_text()), "active_share_target": bad})
    )
    with pytest.raises(ValueError, match="control character"):
        _repoint_samba_share(tmp_path / INJECTED / "C-1")
    assert sudo() == []
