"""Wintools' folder and audit file in a case take the group the share writes
as: on a box joined with vhir's own share, its `force_group`; on a box still
on the old share, `sift`. Groups are stand-ins; the ownership calls are
recorded, the files and modes are real. Values are synthetic.
"""

from __future__ import annotations

import grp
import os
import stat
import types

import pytest
import yaml

from vhir_cli import main
from vhir_cli.commands import join

GIDS = {"examiner": 1111, "sift": 2222}


@pytest.fixture
def box(tmp_path, monkeypatch):
    """`box(samba)`: a home whose samba.yaml is `samba`; returns the case and
    the groups the case's wintools paths were given."""
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".vhir").mkdir()
    asked, given = [], {}
    monkeypatch.setattr(
        grp, "getgrnam",
        lambda name: asked.append(name) or types.SimpleNamespace(gr_gid=GIDS[name]),
    )  # fmt: skip

    def fchown(fd, uid, gid):
        given[os.readlink(f"/proc/self/fd/{fd}")] = gid

    monkeypatch.setattr(os, "fchown", fchown)

    def make(samba: dict, case=None):
        (tmp_path / ".vhir" / "samba.yaml").write_text(yaml.safe_dump(samba))
        case = case or tmp_path / "cases" / "CASE-1"
        case.mkdir(parents=True, exist_ok=True)
        return case, asked, given

    return make


VHIRS_OWN_SHARE = {
    "share_name": join.SHARE_NAME,
    "force_user": "examiner",
    "force_group": "examiner",
}


def _wintools_paths(case):
    return str(case / "extractions" / "wintools"), str(
        case / "audit" / "wintools-mcp.jsonl"
    )


def test_a_box_on_vhirs_own_share_gives_wintools_paths_its_group(box):
    case, asked, given = box(VHIRS_OWN_SHARE)
    warning = main._set_case_wintools_permissions(case) or ""
    assert "Group permissions not applied" not in warning, warning
    assert "sift" not in asked and "examiner" in asked
    folder, audit = _wintools_paths(case)
    assert given[folder] == given[audit] == GIDS["examiner"]
    assert stat.S_IMODE(os.stat(folder).st_mode) == 0o2775


def test_a_migrated_box_moves_an_old_cases_wintools_paths_to_the_shares_group(
    box, tmp_path
):
    """The case was made on the old share, so wintools' folder and audit file
    exist already; the box has since re-joined."""
    case = tmp_path / "cases" / "OLD-1"
    (case / "extractions" / "wintools").mkdir(parents=True)
    (case / "audit").mkdir()
    (case / "audit" / "wintools-mcp.jsonl").write_text("")
    case, asked, given = box(VHIRS_OWN_SHARE, case)
    main._set_case_wintools_permissions(case)
    folder, audit = _wintools_paths(case)
    assert given[folder] == given[audit] == GIDS["examiner"]


def test_anchor_a_box_still_on_the_old_share_keeps_the_sift_group(box):
    case, asked, given = box({"share_name": "cases", "force_user": "examiner"})
    main._set_case_wintools_permissions(case)
    folder, audit = _wintools_paths(case)
    assert given[folder] == given[audit] == GIDS["sift"] and "examiner" not in asked


def test_a_missing_share_group_says_to_re_join(box, monkeypatch):
    case, _, _ = box({**VHIRS_OWN_SHARE, "force_group": "gone"})
    with pytest.raises(
        RuntimeError,
        match="'gone', which the share writes as, not found. Re-join with 'vhir setup join-code'",
    ):
        main._set_case_wintools_permissions(case)
