"""vhir's own wintools share, and what a case gives it.

The share is `[vhir-cases]`, writing files as the installer and the
installer's own group, which join first checks no other account can use. A
box joined under the old `[cases]` keeps that share as it was until it joins
again, and update says so. Sharing a case writes its marker (the case's folder
name, which wintools checks before it writes) and opens `extractions/` and
`audit/` to the owner's group. Accounts and commands are stand-ins.
"""

from __future__ import annotations

import grp
import json
import os
import pwd
import stat
import types

import pytest
import yaml

from vhir_cli import main
from vhir_cli.commands import join, update

# -- the installer's group is its own


def _accounts(monkeypatch, members=(), others=()):
    """The installer `ex1`, primary group 1500 `ex1`; `members` are listed
    in the group, `others` are accounts with it as their primary group."""
    users = [types.SimpleNamespace(pw_name="ex1", pw_gid=1500)]
    users += [types.SimpleNamespace(pw_name=n, pw_gid=1500) for n in others]
    users.append(types.SimpleNamespace(pw_name="svc", pw_gid=1600))
    monkeypatch.setattr(
        pwd, "getpwnam", lambda n: next(u for u in users if u.pw_name == n)
    )
    monkeypatch.setattr(pwd, "getpwall", lambda: users)
    group = types.SimpleNamespace(gr_name="ex1", gr_gid=1500, gr_mem=list(members))
    monkeypatch.setattr(grp, "getgrgid", lambda gid: group)


def test_a_group_only_the_installer_uses_is_the_shares(monkeypatch):
    _accounts(monkeypatch, members=["ex1"])
    assert join.private_primary_group("ex1") == "ex1"


@pytest.mark.parametrize(
    "members, others", [(["ex1", "ana"], []), ([], ["ana"])], ids=["listed", "primary"]
)
def test_a_group_another_account_can_use_stops_join(monkeypatch, members, others):
    _accounts(monkeypatch, members=members, others=others)
    with pytest.raises(RuntimeError, match=r"isn't ex1's alone \(ana can use it\)"):
        join.private_primary_group("ex1")


@pytest.mark.parametrize(
    "passwd, group",
    [
        ("files systemd sss", "files systemd sss"),
        ("files sss", "files"),
        ("files", "files ldap"),
        ("compat winbind", "compat"),
    ],
)
def test_non_local_account_sources_in_nsswitch_dont_stop_join(
    monkeypatch, passwd, group
):
    """A stock SIFT VM lists sss. The box is trusted, so only local accounts
    are checked, whatever /etc/nsswitch.conf lists."""
    _accounts(monkeypatch)
    conf = f"passwd: {passwd}\ngroup: {group}\nhosts: files dns\n"
    read_text = join.Path.read_text

    def read(path, *args, **kwargs):
        if str(path) == "/etc/nsswitch.conf":
            return conf
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(join.Path, "read_text", read)
    assert join.private_primary_group("ex1") == "ex1"


# -- repointing follows samba.yaml's share


@pytest.fixture
def sudo(tmp_path, monkeypatch):
    """A fake sudo on PATH that records each call and what tee was given;
    `write(doc)` sets samba.yaml."""
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
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

    def write(doc):
        (home / ".vhir" / "samba.yaml").write_text(yaml.dump(doc))

    def calls():
        lines = log.read_text().splitlines() if log.exists() else []
        return [json.loads(line) for line in lines]

    return types.SimpleNamespace(write=write, calls=calls)


def test_a_box_joined_with_vhirs_share_is_repointed_under_it(sudo, tmp_path):
    sudo.write({"share_name": "vhir-cases", "wintools_ip": "192.0.2.5",
                "force_user": "ex1", "force_group": "ex1"})  # fmt: skip
    case = tmp_path / "cases" / "C-1"
    join._repoint_samba_share(case)
    (tee, conf), *rest = sudo.calls()
    assert conf == (
        f"[vhir-cases]\n    path = {case}\n    valid users = vhir-smb\n    read only = no\n"
        "    create mask = 0664\n    directory mask = 0775\n    force user = ex1\n"
        "    force group = ex1\n    browsable = no\n    hosts allow = 192.0.2.5\n"
    )
    assert [c[0] for c in rest][-1] == [
        "smbcontrol",
        "smbd",
        "close-share",
        "vhir-cases",
    ]


def test_a_box_joined_with_the_old_share_keeps_it_until_it_joins_again(sudo, tmp_path):
    sudo.write({"share_name": "cases", "wintools_ip": "192.0.2.5", "force_user": "ex1"})
    case = tmp_path / "cases" / "C-1"
    join._repoint_samba_share(case)
    (tee, conf), *rest = sudo.calls()
    assert conf == (
        f"[cases]\n    path = {case}\n    valid users = vhir-smb\n    read only = no\n"
        "    create mask = 0644\n    directory mask = 0755\n    force user = ex1\n"
        "    force group = sift\n    browsable = no\n    hosts allow = 192.0.2.5\n"
    )
    assert [c[0] for c in rest][-1] == ["smbcontrol", "smbd", "close-share", "cases"]


# -- update says when wintools has to join again


@pytest.mark.parametrize(
    "doc, said",
    [
        ({"share_name": "cases"}, True),
        ({"share_name": "vhir-cases"}, False),
        (None, False),
    ],
    ids=["old share", "vhir's share", "not joined"],
)
def test_update_says_wintools_must_join_again_only_on_an_old_share(
    tmp_path, monkeypatch, capsys, doc, said
):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".vhir").mkdir()
    if doc is not None:
        (tmp_path / ".vhir" / "samba.yaml").write_text(yaml.dump(doc))
    update._print_share_rejoin_notice()
    out = capsys.readouterr().out
    assert ("//SIFT/vhir-cases" in out and "vhir setup join-code" in out) is said
    assert bool(out) is said
    assert ("Re-join before updating wintools on Windows" in out) is said


# -- the marker moves with the share


@pytest.fixture
def case(tmp_path, monkeypatch):
    """A case whose sift group is this process's own group."""
    monkeypatch.setattr(
        grp, "getgrnam", lambda name: types.SimpleNamespace(gr_gid=os.getgid())
    )
    d = tmp_path / "cases" / "INC-7"
    d.mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: INC-7\n")
    return d


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_the_marker_names_its_case_readable_by_all(case):
    old = os.umask(0o077)
    try:
        assert join.mark_case(case) is None
    finally:
        os.umask(old)
    marker = case / ".vhir-share-case"
    assert marker.read_text() == "INC-7" and _mode(marker) == 0o644


def test_a_marker_from_another_case_is_replaced(case):
    (case / ".vhir-share-case").write_text("INC-OTHER-AND-LONGER")
    join.mark_case(case)
    assert (case / ".vhir-share-case").read_text() == "INC-7"


def test_a_marker_that_is_a_link_is_never_followed(case, tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("keep")
    (case / ".vhir-share-case").symlink_to(outside)
    assert "Share marker not written" in join.mark_case(case)
    assert outside.read_text() == "keep"


def test_a_marker_hard_linked_to_a_case_file_never_empties_it(case):
    findings = case / "findings.json"
    findings.write_text('[{"id": "F-steve-001"}]')
    os.link(findings, case / ".vhir-share-case")
    assert "Share marker not written" in join.mark_case(case)
    assert findings.read_text() == '[{"id": "F-steve-001"}]'


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no named pipes here")
def test_a_marker_that_is_a_pipe_is_refused_without_waiting(case):
    os.mkfifo(case / ".vhir-share-case")
    assert ".vhir-share-case" in join.mark_case(case)


def test_pointing_the_share_at_a_case_marks_it_even_when_already_tracked(sudo, case):
    """An upgraded box: the share already points at the case, which has no
    marker yet. Activating it again writes the marker."""
    sudo.write({"share_name": "cases", "wintools_ip": "192.0.2.5", "force_user": "ex1",
                "active_share_target": str(case)})  # fmt: skip
    join._repoint_samba_share(case)
    assert sudo.calls() == []  # the share itself didn't move
    assert (case / ".vhir-share-case").read_text() == "INC-7"


def test_pointing_the_share_away_leaves_the_old_marker_naming_its_own_case(
    sudo, case, tmp_path
):
    sudo.write({"share_name": "vhir-cases", "wintools_ip": "192.0.2.5", "force_user": "ex1",
                "force_group": "ex1"})  # fmt: skip
    join._repoint_samba_share(case)
    other = tmp_path / "cases" / "INC-8"
    other.mkdir()
    join._repoint_samba_share(other)
    assert (case / ".vhir-share-case").read_text() == "INC-7"
    assert (other / ".vhir-share-case").read_text() == "INC-8"


# -- the case's folders, on a box joined with vhir's own share


def _joined(monkeypatch, tmp_path, share_name="vhir-cases"):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    own = grp.getgrgid(os.getgid()).gr_name
    (home / ".vhir" / "samba.yaml").write_text(
        yaml.dump({"share_name": share_name, "force_user": "ex1", "force_group": own})
    )
    real = grp.getgrnam
    monkeypatch.setattr(
        grp, "getgrnam",
        lambda name: types.SimpleNamespace(gr_gid=os.getgid()) if name in ("sift", own)
        else real(name),
    )  # fmt: skip


def _closed(case):
    for folder in ("extractions", "audit"):
        (case / folder).mkdir(mode=0o700, exist_ok=True)
        (case / folder).chmod(0o700)


def test_an_old_cases_folders_are_opened_to_the_private_group(
    case, tmp_path, monkeypatch
):
    _joined(monkeypatch, tmp_path)
    _closed(case)
    assert main._set_case_wintools_permissions(case) is None
    assert _mode(case / "extractions") == 0o775 and _mode(case / "audit") == 0o775
    assert _mode(case / "extractions" / "wintools") == 0o2775


def test_a_folder_of_another_group_is_left_as_it_is(case, tmp_path, monkeypatch):
    _joined(monkeypatch, tmp_path)
    _closed(case)
    real = os.fstat

    def other_group(fd):  # the folder belongs to a shared group, not the private one
        st = real(fd)
        if stat.S_ISDIR(st.st_mode):
            return os.stat_result((*st[:5], st.st_gid + 1, *st[6:]))
        return st

    monkeypatch.setattr(os, "fstat", other_group)
    warning = main._set_case_wintools_permissions(case)
    assert "left as it is: its group isn't" in warning
    assert _mode(case / "audit") == 0o700


def test_a_failed_group_step_still_opens_the_folders(case, tmp_path, monkeypatch):
    _joined(monkeypatch, tmp_path)
    _closed(case)

    def chown(fd, uid, gid):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "fchown", chown)
    warning = main._set_case_wintools_permissions(case)
    assert "Group permissions not applied" in warning
    assert _mode(case / "extractions") == 0o775 and _mode(case / "audit") == 0o775


def test_a_box_not_joined_with_vhirs_share_leaves_the_folders(
    case, tmp_path, monkeypatch
):
    _joined(monkeypatch, tmp_path, share_name="cases")
    _closed(case)
    main._set_case_wintools_permissions(case)
    assert _mode(case / "audit") == 0o700


def test_sharing_a_case_no_longer_writes_the_marker_itself(case, tmp_path, monkeypatch):
    _joined(monkeypatch, tmp_path)
    main._set_case_wintools_permissions(case)
    assert not (case / ".vhir-share-case").exists()
