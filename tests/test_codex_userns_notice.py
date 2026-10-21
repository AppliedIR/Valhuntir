"""The userns notice, at both places it prints: the Codex controls lines
(setup test) and deploying the controls (setup client, update).

With kernel.apparmor_restrict_unprivileged_userns=1, Codex's sandbox runs
through /usr/bin/bwrap when it's there, and starts only with an AppArmor
profile for it (/etc/apparmor.d/bwrap). The notice prints when the sysctl is 1
and either file is missing, names what's missing and points to the docs. At
sysctl 0, with both files there, or inside Codex's sandbox, nothing prints.
"""

from __future__ import annotations

import errno
import json
import os

import pytest

from vhir_cli.commands import codex_controls as cc

NOTICE = "kernel.apparmor_restrict_unprivileged_userns=1"


def _state_lines():
    return "\n".join(cc.state_lines())


def _deploy(capsys):
    assert cc.deploy_codex_controls(consent=False) == "missing"
    return capsys.readouterr().out


SITES = {"state_lines": lambda capsys: _state_lines(), "deploy": _deploy}


@pytest.fixture
def box(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    (home / ".vhir" / "manifest.json").write_text(json.dumps({"clients": ["codex"]}))
    monkeypatch.setattr(cc.Path, "home", staticmethod(lambda: home))
    req = tmp_path / "etc-codex" / "requirements.toml"
    req.parent.mkdir()
    req.write_text(cc.MARKER + "\n")
    monkeypatch.setattr(cc, "REQUIREMENTS", req)
    monkeypatch.setattr(cc, "_sources", lambda: None)
    monkeypatch.setattr(cc, "USERNS", tmp_path / "userns")
    monkeypatch.setattr(cc, "BWRAP", tmp_path / "usr-bin-bwrap", raising=False)
    monkeypatch.setattr(cc, "BWRAP_PROFILE", tmp_path / "apparmor-bwrap", raising=False)
    return tmp_path


def _set(box, sysctl, bwrap, profile):
    (box / "userns").write_text(sysctl + "\n")
    for name, there in (("usr-bin-bwrap", bwrap), ("apparmor-bwrap", profile)):
        if there:
            (box / name).write_text("")


@pytest.mark.parametrize("site", SITES)
@pytest.mark.parametrize("profile", [True, False], ids=["profile", "no-profile"])
@pytest.mark.parametrize("bwrap", [True, False], ids=["bwrap", "no-bwrap"])
def test_at_sysctl_0_nothing_prints(box, capsys, site, bwrap, profile):
    """No-change twins: nothing printed at 0 before either."""
    _set(box, "0", bwrap, profile)
    assert NOTICE not in SITES[site](capsys)


@pytest.mark.parametrize("site", SITES)
def test_at_sysctl_1_with_bwrap_and_its_profile_nothing_prints(box, capsys, site):
    _set(box, "1", True, True)
    assert NOTICE not in SITES[site](capsys)


@pytest.mark.parametrize("site", SITES)
@pytest.mark.parametrize(
    "bwrap, profile",
    [(True, False), (False, True), (False, False)],
    ids=["no-profile", "no-bwrap", "neither"],
)
def test_at_sysctl_1_the_notice_names_what_is_missing(
    box, capsys, site, bwrap, profile
):
    _set(box, "1", bwrap, profile)
    out = SITES[site](capsys)
    notices = [ln for ln in out.splitlines() if NOTICE in ln]
    assert len(notices) == 1
    notice = notices[0]
    assert f"needs {cc.BWRAP} with an AppArmor profile for it" in notice
    assert "docs/codex.md#sandbox" in notice
    missing = notice.split("Missing here: ")[1].split(". Until")[0]
    assert (str(cc.BWRAP) in missing) is not bwrap
    assert (str(cc.BWRAP_PROFILE) in missing) is not profile


@pytest.mark.parametrize("site", SITES)
def test_inside_codex_s_sandbox_nothing_prints(box, capsys, monkeypatch, site):
    _set(box, "1", False, False)

    def refused(*a, **k):
        raise OSError(errno.EPERM, "refused")

    monkeypatch.setenv("CODEX_SANDBOX_NETWORK_DISABLED", "1")
    monkeypatch.setattr("socket.socket", refused)
    assert NOTICE not in SITES[site](capsys)


@pytest.mark.skipif(os.geteuid() == 0, reason="root searches any directory")
@pytest.mark.parametrize("site", SITES)
@pytest.mark.parametrize("bwrap", [True, False], ids=["bwrap", "no-bwrap"])
def test_a_profile_that_can_t_be_checked_counts_as_there(
    box, capsys, monkeypatch, site, bwrap
):
    """/etc/apparmor.d not searchable by this user: the profile's state is
    unknown, so it counts as there. setup carries on, and the notice names
    only a missing /usr/bin/bwrap."""
    _set(box, "1", bwrap, False)
    locked = box / "apparmor.d"
    locked.mkdir()
    (locked / "bwrap").write_text("")
    monkeypatch.setattr(cc, "BWRAP_PROFILE", locked / "bwrap", raising=False)
    locked.chmod(0)
    try:
        out = SITES[site](capsys)
    finally:
        locked.chmod(0o755)
    notices = [ln for ln in out.splitlines() if NOTICE in ln]
    if bwrap:
        assert notices == []
    else:
        assert len(notices) == 1
        missing = notices[0].split("Missing here: ")[1].split(". Until")[0]
        assert missing == str(cc.BWRAP)
