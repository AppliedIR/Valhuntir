"""Every join code leaves the wintools share usable.

A join code sets the Samba password Windows derives from it, even when the
existing share setup is kept. A join while a case is active points the share
at that case. Every command is recorded, none run.
"""

from __future__ import annotations

import subprocess
import types

import pytest
import yaml

from vhir_cli.commands import join


@pytest.fixture
def box(tmp_path, monkeypatch):
    """An isolated HOME, recorded commands and pushes, and scripted answers."""
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".vhir").mkdir()
    ran, pushed, answers = [], [], []

    def run(cmd, **kwargs):
        ran.append((cmd, kwargs.get("input")))
        out = "" if kwargs.get("text") else b""
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr=out)

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(join, "_push_smb_credentials", pushed.append)
    monkeypatch.setattr(join, "_get_sift_ip", lambda: None)
    monkeypatch.setattr(
        join, "private_primary_group", lambda user: "examiner", raising=False
    )
    monkeypatch.setattr(join, "_ask", lambda prompt, no_terminal: answers.pop(0))
    return types.SimpleNamespace(home=tmp_path, ran=ran, pushed=pushed, answers=answers)


def _configured(box, share_name="vhir-cases"):
    (box.home / ".vhir" / "samba.yaml").write_text(
        yaml.dump({"share_name": share_name, "wintools_ip": "10.0.0.20"})
    )


def _smbpasswd_inputs(box):
    return [i for cmd, i in box.ran if "smbpasswd" in cmd]


def _case(box, case_id="INC-1"):
    case_dir = box.home / "cases" / case_id
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text(f"case_id: {case_id}\n")
    (box.home / ".vhir" / "active_case").write_text(str(case_dir))
    return case_dir


SHARE_CONF = "/etc/samba/smb.conf.d/vhir-cases.conf"


def _share_conf(box):
    (conf,) = [i.decode() for cmd, i in box.ran if cmd[-1:] == [SHARE_CONF]]
    return conf


def test_a_join_code_that_keeps_the_setup_still_sets_its_password(box):
    _configured(box)
    box.answers.append("n")
    assert join._setup_samba_share("CODE-TWO") == "10.0.0.20"
    password = join.derive_smb_password("CODE-TWO")
    assert _smbpasswd_inputs(box) == [f"{password}\n{password}\n".encode()]
    assert box.pushed == [password]


def test_a_password_that_fails_to_set_is_not_silent(box, monkeypatch):
    _configured(box)
    box.answers.append("n")

    def refuse(cmd, **kwargs):
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(subprocess, "run", refuse)
    with pytest.raises(RuntimeError, match="Failed to set SMB password"):
        join._setup_samba_share("CODE-TWO")
    assert box.pushed == []


def test_a_join_with_a_case_active_points_the_share_at_it(box):
    case_dir = _case(box)
    box.answers.append("10.0.0.20")
    join._setup_samba_share("CODE-ONE")
    assert f"path = {case_dir}\n" in _share_conf(box)
    samba = yaml.safe_load((box.home / ".vhir" / "samba.yaml").read_text())
    assert samba["active_share_target"] == str(case_dir)


@pytest.mark.parametrize("pointer", ["none", "no case file", "relative"])
def test_a_join_with_no_valid_active_case_points_the_share_at_the_placeholder(
    box, pointer, monkeypatch
):
    if pointer == "no case file":
        (box.home / "cases" / "INC-1").mkdir(parents=True)
        (box.home / ".vhir" / "active_case").write_text(
            str(box.home / "cases" / "INC-1")
        )
    elif pointer == "relative":
        # a relative pointer isn't read against wherever join happens to run
        _case(box)
        monkeypatch.chdir(box.home / "cases")
        (box.home / ".vhir" / "active_case").write_text("INC-1")
    box.answers.append("10.0.0.20")
    join._setup_samba_share("CODE-ONE")
    placeholder = box.home / ".vhir" / "share-inactive"
    assert f"path = {placeholder}\n" in _share_conf(box)
    assert placeholder.is_dir()


@pytest.mark.parametrize("name", ["INC-1\n[evil]", "INC-1\\"])
def test_a_case_path_that_would_break_the_share_config_is_refused(box, name):
    _case(box, name)
    box.answers.append("10.0.0.20")
    with pytest.raises(ValueError, match="case path"):
        join._setup_samba_share("CODE-ONE")
    assert not [cmd for cmd, _ in box.ran if "tee" in cmd]  # no smb.conf write
    assert not (box.home / ".vhir" / "samba.yaml").exists()


# -- vhir's own share name


def _sudoers(box):
    (rules,) = [
        i.decode()
        for cmd, i in box.ran
        if cmd[-2:] == ["tee", "/etc/sudoers.d/vhir-samba"]
    ]
    return rules


def test_a_join_writes_vhirs_own_share_and_none_of_sifts(box):
    import getpass

    box.answers.append("10.0.0.20")
    join._setup_samba_share("CODE-ONE")
    conf = _share_conf(box)
    assert conf.startswith("[vhir-cases]\n") and "[cases]" not in conf
    for line in (
        "valid users = vhir-smb",
        "create mask = 0664",
        "directory mask = 0775",
        f"force user = {getpass.getuser()}",
        "force group = examiner",
        "hosts allow = 10.0.0.20",
    ):
        assert f"    {line}\n" in conf
    assert "close-share vhir-cases\n" in _sudoers(box)
    assert "close-share cases\n" not in _sudoers(box)
    samba = yaml.safe_load((box.home / ".vhir" / "samba.yaml").read_text())
    assert samba["share_name"] == "vhir-cases" and samba["force_group"] == "examiner"


def test_a_join_on_a_box_joined_with_the_old_share_moves_it_without_asking(box, capsys):
    _configured(box, "cases")
    box.answers.append("10.0.0.30")  # the only question: the Windows address
    assert join._setup_samba_share("CODE-TWO") == "10.0.0.30"
    assert "moves from [cases] to [vhir-cases]" in capsys.readouterr().out
    assert _share_conf(box).startswith("[vhir-cases]\n")
    samba = yaml.safe_load((box.home / ".vhir" / "samba.yaml").read_text())
    assert samba["share_name"] == "vhir-cases"


def test_a_join_whose_group_isnt_the_installers_alone_changes_nothing(box, monkeypatch):
    def shared(user):
        raise RuntimeError(f"{user}'s primary group 'staff' isn't {user}'s alone")

    monkeypatch.setattr(join, "private_primary_group", shared, raising=False)
    with pytest.raises(RuntimeError, match="isn't .*alone"):
        join._setup_samba_share("CODE-ONE")
    assert box.ran == [] and box.answers == []
    assert not (box.home / ".vhir" / "samba.yaml").exists()


def test_a_join_with_a_case_active_marks_that_case_for_wintools(box):
    """A fresh join, or the re-join after an update, while a case is open:
    the share and its marker move together, so wintools' first run is
    accepted."""
    case_dir = _case(box)
    box.answers.append("10.0.0.20")
    join._setup_samba_share("CODE-ONE")
    assert f"path = {case_dir}\n" in _share_conf(box)
    assert (case_dir / ".vhir-share-case").read_text() == "INC-1"


def test_a_join_with_no_case_active_marks_nothing(box):
    box.answers.append("10.0.0.20")
    join._setup_samba_share("CODE-ONE")
    assert not list((box.home / ".vhir" / "share-inactive").iterdir())


def test_a_join_that_keeps_the_setup_still_marks_the_active_case(box):
    case_dir = _case(box)
    _configured(box)
    box.answers.append("n")
    assert join._setup_samba_share("CODE-TWO") == "10.0.0.20"
    assert (case_dir / ".vhir-share-case").read_text() == "INC-1"
