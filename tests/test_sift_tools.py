"""The out-of-date SIFT tools warning: Volatility 3 that can't save symbols, no Hayabusa.

A SANS OVA from April 2026 ships Volatility 3 2.27.0 in a root-owned folder,
so every Windows plugin fails with "Cannot write necessary symbol file", and
has no Hayabusa. Setup ended without saying so. These run the check against
stub tools in a scratch PATH and HOME: a stub Python prints what Volatility's
constants would (its version, then its symbol folders).
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

import vhir_cli.commands.setup as setup
from tests import test_update
from tests.test_reconnect_hint import _run
from vhir_cli import sift_tools
from vhir_cli.commands.update import cmd_update

TEXT = (
    "Some SIFT tools are out of date and parts of Valhuntir won't work with them "
    "({}). Update SIFT with: `sudo cast install teamdfir/sift` "
    "(about 5 minutes on the SANS OVA; if it reports failed states, run it again, "
    "since a download outage can cause them), then re-run `./setup-sift.sh` "
    "with the options you installed with (for example `--remote`)."
)
VOL = "Volatility 3 {}: memory analysis fails"
HAYABUSA = "Hayabusa missing: no event-log detections"
# Valhuntir's installer only; only when Hayabusa is missing
CHOICE = (
    " For Hayabusa, run `vhir setup hayabusa` (installs the current Hayabusa "
    "release; the current SIFT release doesn't include it)."
)
# Hayabusa the only problem: no SIFT update named
ONLY_HAYABUSA = HAYABUSA + "." + CHOICE


def _exe(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)
    return path


@pytest.fixture
def box(tmp_path, monkeypatch):
    """A scratch HOME and a PATH holding only the stubs (plus the shell's own tools)."""
    home = tmp_path / "home"
    home.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin")
    # /usr/bin's own python3 and any hayabusa there must not be found
    monkeypatch.setattr(
        sift_tools,
        "_search_path",
        lambda: os.pathsep.join([str(home / ".local" / "bin"), str(bin_dir)]),
    )

    class Box:
        pass

    b = Box()
    b.home, b.bin, b.tmp = home, bin_dir, tmp_path
    return b


def _python(box, name: str, version: str, folders: list[Path], rc: int = 0) -> Path:
    """A stub interpreter that answers the constants probe (-E -c) and, running
    Volatility bare, prints its banner and exits 2 as Volatility 3 does."""
    lines = [" ".join(version.split("."))] + [str(f) for f in folders]
    body = "".join(f"echo '{ln}'\n" for ln in lines)
    return _exe(
        box.tmp / "py" / name / "python3",
        f'#!/bin/sh\nif [ "$1" = "-E" ]; then\n{body}exit {rc}\nfi\n'
        f"echo 'Volatility 3 Framework {version}' >&2\nexit 2\n",
    )


def _vol(box, name: str, interp: str) -> Path:
    return _exe(box.bin / name, f"#!{interp}\nimport sys\n")


def _locked(box, name: str) -> Path:
    """A symbols folder the user can't write (root-owned on SIFT)."""
    d = box.tmp / name / "symbols"
    d.mkdir(parents=True)
    d.chmod(0o555)
    return d


def _hayabusa(box, where: Path) -> None:
    _exe(where / "hayabusa", "#!/bin/sh\n")


def test_volatility_2_27_in_a_folder_the_user_cannot_write_is_named(box):
    py = _python(box, "opt", "2.27.0", [_locked(box, "a"), _locked(box, "b")])
    _vol(box, "vol", str(py))
    _hayabusa(box, box.bin)
    assert sift_tools.warning() == TEXT.format(VOL.format("2.27.0"))


def test_an_older_volatility_the_user_owns_is_not_named(box):
    # a pipx 2.26.2 in $HOME: it can save its own symbols
    own = box.home / ".local/share/pipx/venvs/volatility3/symbols"
    own.mkdir(parents=True)
    py = _python(box, "pipx", "2.26.2", [_locked(box, "a"), own])
    _vol(box, "vol", str(py))
    _hayabusa(box, box.bin)
    assert sift_tools.warning() is None


def test_a_symbols_folder_not_made_yet_counts_when_its_parent_is_writable(box):
    py = _python(box, "opt", "2.27.0", [_locked(box, "a"), box.home / "v" / "symbols"])
    _vol(box, "vol", str(py))
    assert sift_tools.volatility_problem() is None


def test_volatility_2_28_is_not_named_even_with_root_owned_folders(box):
    py = _python(box, "opt", "2.28.2", [_locked(box, "a"), _locked(box, "b")])
    _vol(box, "vol", str(py))
    _hayabusa(box, box.bin)
    assert sift_tools.warning() is None


def test_no_hayabusa_is_named(box):
    py = _python(box, "opt", "2.28.2", [_locked(box, "a")])
    _vol(box, "vol", str(py))
    assert sift_tools.warning() == ONLY_HAYABUSA


def test_a_missing_hayabusa_alone_does_not_send_the_user_to_cast(box):
    # SANS's installer has no Hayabusa: updating SIFT would install nothing
    py = _python(box, "opt", "2.28.2", [_locked(box, "a")])
    _vol(box, "vol", str(py))
    text = sift_tools.warning()
    assert "cast" not in text and "setup-sift.sh" not in text
    assert "`vhir setup hayabusa`" in text


def test_the_rerun_advice_keeps_the_install_flags(box):
    # Both `vhir update` and setup-sift.sh print this warning. A remote box
    # re-run flagless reconfigures the gateway as a local install, so the
    # re-run advice must not be the bare flagless `./setup-sift.sh`.
    py = _python(box, "opt", "2.27.0", [_locked(box, "a")])
    _vol(box, "vol", str(py))
    text = sift_tools.warning()
    assert "with the options you installed with (for example `--remote`)" in text
    assert "then re-run `./setup-sift.sh`." not in text


def test_both_are_named_in_one_warning(box):
    py = _python(box, "opt", "2.27.0", [_locked(box, "a")])
    _vol(box, "vol", str(py))
    assert (
        sift_tools.warning()
        == TEXT.format(f"{VOL.format('2.27.0')}; {HAYABUSA}") + CHOICE
    )


def test_the_hayabusa_choice_is_only_for_a_missing_hayabusa(box):
    py = _python(box, "opt", "2.27.0", [_locked(box, "a")])
    _vol(box, "vol", str(py))
    _hayabusa(box, box.bin)
    text = sift_tools.warning()
    assert text == TEXT.format(VOL.format("2.27.0"))
    assert "vhir setup hayabusa" not in text


def test_hayabusa_in_local_bin_counts_though_not_on_path(box):
    # cast links it into ~/.local/bin, on the login PATH only; the gateway adds it
    _hayabusa(box, box.home / ".local" / "bin")
    assert not sift_tools.hayabusa_missing()


def test_local_bin_is_searched_with_the_real_path(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".local" / "bin").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", f"/usr/bin{os.pathsep}/bin")
    assert sift_tools._search_path().split(os.pathsep) == [
        str(home / ".local" / "bin"),
        "/usr/bin",
        "/bin",
    ]


def test_local_bin_already_on_path_keeps_its_place(tmp_path, monkeypatch):
    # the gateway adds ~/.local/bin only when it's missing (prepend_local_bin)
    home = tmp_path / "home"
    local_bin = home / ".local" / "bin"
    local_bin.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    path = os.pathsep.join(["/opt/x/bin", str(local_bin), "/usr/bin"])
    monkeypatch.setenv("PATH", path)
    assert sift_tools._search_path() == path


def test_a_missing_local_bin_is_not_added(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PATH", f"/usr/bin{os.pathsep}/bin")
    assert sift_tools._search_path() == f"/usr/bin{os.pathsep}/bin"


def test_a_vol3_that_is_not_volatility_is_skipped_as_the_ingest_does(box):
    # the ingest runs each candidate bare and takes the first with the banner
    _exe(box.bin / "vol3", "#!/bin/sh\necho 'some other tool'\n")
    py = _python(box, "opt", "2.27.0", [_locked(box, "a")])
    _vol(box, "vol", str(py))
    assert sift_tools.volatility_problem() == "Volatility 3 2.27.0"


def test_a_writable_basepath_whose_windows_folder_is_not_is_named(box):
    # 2.27 saves a Windows kernel's symbols in <basepath>/windows/<pdb>/, and
    # Volatility ships framework/symbols/windows: the basepath alone can be writable
    base = box.tmp / "framework" / "symbols"
    (base / "windows").mkdir(parents=True)
    (base / "windows").chmod(0o555)
    py = _python(box, "opt", "2.27.0", [_locked(box, "a"), base])
    _vol(box, "vol", str(py))
    assert sift_tools.volatility_problem() == "Volatility 3 2.27.0"


def test_an_env_shebang_runs_the_python_on_path(box):
    py = _python(box, "env", "2.27.0", [_locked(box, "a")])
    _exe(box.bin / "python3", f'#!/bin/sh\nexec "{py}" "$@"\n')
    _vol(box, "vol", "/usr/bin/env python3")
    assert sift_tools.volatility_problem() == "Volatility 3 2.27.0"


def test_vol3_is_tried_before_vol_as_the_ingest_does(box):
    old = _python(box, "old", "2.27.0", [_locked(box, "a")])
    new = _python(box, "new", "2.28.2", [_locked(box, "b")])
    _vol(box, "vol3", str(new))
    _vol(box, "vol", str(old))
    assert sift_tools.volatility_problem() is None


def test_python_m_volatility3_is_the_last_resort(box):
    py = _python(box, "m", "2.27.0", [_locked(box, "a")])
    _exe(box.bin / "python3", f'#!/bin/sh\nexec "{py}" "$@"\n')
    assert sift_tools.volatility_problem() == "Volatility 3 2.27.0"


@pytest.mark.parametrize(
    "case",
    ["probe fails", "no volatility", "not a python script", "garbled version"],
)
def test_what_it_could_not_measure_is_not_named(box, case):
    if case == "probe fails":
        py = _python(box, "x", "2.27.0", [_locked(box, "a")], rc=1)
        _vol(box, "vol", str(py))
    elif case == "not a python script":
        _vol(box, "vol", "/bin/sh")
    elif case == "garbled version":
        py = _python(box, "x", "two.27", [_locked(box, "a")])
        _vol(box, "vol", str(py))
    assert sift_tools.volatility_problem() is None


def test_the_module_prints_the_warning_or_nothing(box, capsys):
    _hayabusa(box, box.bin)
    assert sift_tools.main() == 0 and capsys.readouterr().out == ""
    (box.bin / "hayabusa").unlink()
    assert sift_tools.main() == 0
    assert capsys.readouterr().out == ONLY_HAYABUSA + "\n"


def test_setup_test_prints_it_before_the_gateway_is_reached(monkeypatch, capsys):
    monkeypatch.setattr(sift_tools, "warning", lambda: "TOOLS ARE OLD")
    import vhir_cli.gateway as gateway

    def no_gateway():
        raise RuntimeError("no gateway here")

    monkeypatch.setattr(gateway, "get_local_gateway_url", no_gateway)
    with pytest.raises(RuntimeError):
        setup._run_connectivity_test()
    assert "\n  WARNING: TOOLS ARE OLD\n" in capsys.readouterr().out


def test_setup_test_can_leave_it_to_the_caller(monkeypatch, capsys):
    monkeypatch.setattr(sift_tools, "warning", lambda: "TOOLS ARE OLD")
    import vhir_cli.gateway as gateway

    def no_gateway():
        raise RuntimeError("no gateway here")

    monkeypatch.setattr(gateway, "get_local_gateway_url", no_gateway)
    with pytest.raises(RuntimeError):
        setup._run_connectivity_test(sift_tools=False)
    assert "TOOLS ARE OLD" not in capsys.readouterr().out


def test_a_check_that_breaks_is_reported_not_raised(monkeypatch, capsys):
    def broken():
        raise PermissionError("denied")

    monkeypatch.setattr(sift_tools, "warning", broken)
    setup._print_sift_tools_warning()
    assert capsys.readouterr().out == (
        "\n  SIFT tools: couldn't check (PermissionError: denied)\n"
    )


manifest_dir = test_update.manifest_dir  # the update tests' install layout


@pytest.mark.parametrize("no_restart", [False, True])
def test_vhir_update_ends_with_it_and_the_smoke_test_leaves_it_out(
    manifest_dir, capsys, monkeypatch, no_restart
):
    monkeypatch.setattr(sift_tools, "warning", lambda: "TOOLS ARE OLD")
    with (
        patch("pathlib.Path.home", return_value=manifest_dir[0]),
        patch("subprocess.run", side_effect=_run(0)),
        patch("vhir_cli.commands.client_setup._deploy_claude_code_assets"),
        patch("vhir_cli.commands.setup._run_connectivity_test") as smoke,
        patch("time.sleep"),
    ):
        cmd_update(test_update._make_args(no_restart=no_restart), {})
    out = capsys.readouterr().out
    assert out.endswith("\n  WARNING: TOOLS ARE OLD\n")
    assert out.count("TOOLS ARE OLD") == 1
    if no_restart:
        smoke.assert_not_called()
    else:
        smoke.assert_called_once_with(sift_tools=False)
