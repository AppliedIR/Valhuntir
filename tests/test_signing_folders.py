"""The signing folders after an update from 0.6.

A 0.6 `vhir update` runs its own (old) code after pulling this one, so it
doesn't make /var/lib/vhir/keys and ledger. It does import this vhir's
client_setup after the pull and calls `_isolate_gateway_launchers` from it:
that is where one update makes them. Signing checks for them before any
prompt, and a permission error on them is one line, never a traceback.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from vhir_cli import credentials, keys, ledger
from vhir_cli.commands import client_setup as cs


@pytest.fixture
def folders(tmp_path, monkeypatch):
    """The signing folders, not yet made, and every sudo call recorded."""
    wanted = (tmp_path / "vhir" / "keys", tmp_path / "vhir" / "ledger")
    monkeypatch.setattr(cs, "SIGNING_DIRS", wanted)
    monkeypatch.setenv("HOME", str(tmp_path))  # no gateway launcher files here
    calls = []

    def run(argv, **kw):
        calls.append(argv)
        if argv[1:3] == ["-I", "-c"] and argv[3] == cs._ENSURE_SCRIPT:
            cs.ensure_signing_dirs()  # what the fresh process runs, with new modules
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        if argv[:1] == ["sudo"]:
            if run.fail:
                return types.SimpleNamespace(returncode=1, stdout="", stderr="no")
            made = argv[3].split("mkdir -p ", 1)[1].split(" &&", 1)[0]
            Path(made).mkdir(parents=True, exist_ok=True)
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        return types.SimpleNamespace(returncode=1, stdout="", stderr="")

    run.fail = False
    import subprocess

    monkeypatch.setattr(
        subprocess, "run", run
    )  # client_setup imports it where it runs it
    return types.SimpleNamespace(dirs=wanted, calls=calls, run=run)


def _older_update(monkeypatch):
    """The update module a 0.6 vhir has loaded while it runs: no folder step."""
    old = types.ModuleType("vhir_cli.commands.update")
    old.cmd_update = lambda args, identity: None
    monkeypatch.setitem(sys.modules, "vhir_cli.commands.update", old)


def _sudo(calls):
    return [c for c in calls if c[:1] == ["sudo"]]


def test_under_pytest_the_launcher_step_never_reaches_sudo(folders, monkeypatch):
    # loaded or not, this vhir's own update module has the folder step
    monkeypatch.delitem(sys.modules, "vhir_cli.commands.update", raising=False)
    cs._isolate_gateway_launchers()
    from vhir_cli.commands import update  # noqa: F401 - loads this vhir's

    cs._isolate_gateway_launchers()
    assert not cs._under_an_older_update()
    assert _sudo(folders.calls) == []
    assert not any(f.exists() for f in folders.dirs)


def test_an_older_update_makes_the_folders_through_the_launcher_step(
    folders, monkeypatch, capsys
):
    _older_update(monkeypatch)
    assert cs._isolate_gateway_launchers() == []
    sudo = _sudo(folders.calls)
    assert [c[:3] for c in sudo] == [["sudo", "sh", "-c"]] * 2
    for cmd, folder in zip(sudo, folders.dirs, strict=True):
        assert (
            f"mkdir -p {folder} && find {folder} -xdev -uid 0 -exec chown -h " in cmd[3]
        )
        assert cmd[3].endswith(f"chmod 700 {folder}")
    assert all(f.is_dir() for f in folders.dirs)
    assert capsys.readouterr().out.count("... done") == 2


def test_an_update_gives_back_a_folder_this_user_can_t_write(
    folders, monkeypatch, capsys
):
    """The preflight sends the examiner to `vhir update` for it, so the
    update's folder step must fix it (still never under pytest's own run)."""
    keys_dir, ledger_dir = folders.dirs
    keys_dir.mkdir(parents=True)
    ledger_dir.mkdir()
    keys_dir.chmod(0o500)  # as a folder root left behind is, to the examiner
    try:
        from vhir_cli.commands import update

        update._ensure_signing_dirs()
    finally:
        keys_dir.chmod(0o700)
    (cmd,) = _sudo(folders.calls)
    assert f"find {keys_dir} -xdev -uid 0 -exec chown -h " in cmd[3]
    assert cmd[3].endswith(f"chmod 700 {keys_dir}")
    assert f"Giving back {keys_dir}... done" in capsys.readouterr().out


def test_folders_that_exist_are_left_alone(folders, monkeypatch):
    for f in folders.dirs:
        f.mkdir(parents=True)
    _older_update(monkeypatch)
    cs._isolate_gateway_launchers()
    assert _sudo(folders.calls) == []


@pytest.mark.parametrize("how", ["exit 1", "raises"])
def test_a_sudo_failure_prints_the_command_and_never_raises(
    folders, monkeypatch, capsys, how
):
    _older_update(monkeypatch)
    if how == "exit 1":
        folders.run.fail = True
    else:
        import subprocess

        def boom(argv, **kw):
            if argv[:1] != ["sudo"]:  # the fresh process runs the step
                return folders.run(argv, **kw)
            raise subprocess.TimeoutExpired(argv, 300)

        monkeypatch.setattr(subprocess, "run", boom)
    assert cs._isolate_gateway_launchers() == []  # the update carries on
    err = capsys.readouterr().err
    for f in folders.dirs:
        assert f"Run manually: sudo mkdir -p {f} && sudo find {f} -xdev -uid 0 " in err


def test_this_vhir_s_update_makes_them_with_the_same_step(folders):
    from vhir_cli.commands import update

    update._ensure_signing_dirs()
    assert len(_sudo(folders.calls)) == 2 and all(f.is_dir() for f in folders.dirs)


# --- Signing checks for them first ---------------------------------------------------


@pytest.mark.parametrize("which", ["keys", "ledger"])
@pytest.mark.parametrize("state", ["missing", "read-only"])
def test_a_missing_or_read_only_folder_is_the_problem(which, state):
    folder = keys.KEYS_DIR if which == "keys" else ledger.LEDGER_DIR
    assert credentials.signing_folders_problem() == ""
    if state == "missing":
        folder.rmdir()
    else:
        folder.chmod(0o500)
    try:
        if state == "missing":
            assert credentials.signing_folders_problem() == credentials.FINISH_UPDATE
        else:  # named, with its owner; an update gives it back
            problem = credentials.signing_folders_problem()
            assert problem == credentials.not_writable_text(folder)
            assert str(folder) in problem and "run `vhir update`" in problem
            assert "it belongs to " in problem
    finally:
        if state != "missing":
            folder.chmod(0o700)


def test_the_message_is_one_line_naming_the_command():
    assert credentials.FINISH_UPDATE == (
        "Finish the update: run `vhir update` once more "
        "(it creates /var/lib/vhir/keys and ledger)"
    )


def test_the_permission_error_keys_py_raises_is_recognised(tmp_path, monkeypatch):
    """What an upgrade into a keys folder it can't make raises, as on a box
    updated once by 0.6's update code."""
    parent = tmp_path / "vhir"
    parent.mkdir(mode=0o555)
    monkeypatch.setattr(keys, "KEYS_DIR", parent / "keys")
    data = keys.new_credential("steve", "x" * 20)
    with pytest.raises(PermissionError) as raised:
        keys.save("steve", data)
    parent.chmod(0o755)
    assert credentials.on_signing_folders(raised.value.filename)
    assert not credentials.on_signing_folders(str(tmp_path / "elsewhere.json"))


def _main(monkeypatch, capsys, error):
    from vhir_cli import main as M

    def approve(args, identity):
        raise error

    monkeypatch.setattr(M, "cmd_approve", approve)
    monkeypatch.setattr(sys, "argv", ["vhir", "approve"])
    with pytest.raises(SystemExit) as out:
        M.main()
    return out.value.code, capsys.readouterr().err


def test_a_permission_error_on_the_folders_is_one_line_not_a_traceback(
    monkeypatch, capsys
):
    error = PermissionError(13, "Permission denied", str(keys.KEYS_DIR))
    code, err = _main(monkeypatch, capsys, error)
    assert code == 1 and err.splitlines()[-1] == credentials.FINISH_UPDATE
    assert "Traceback" not in err


def test_any_other_permission_error_is_not_dressed_as_an_update(monkeypatch, capsys):
    from vhir_cli import main as M

    monkeypatch.setattr(
        M, "cmd_approve",
        lambda a, i: (_ for _ in ()).throw(PermissionError(13, "no", "/etc/shadow")),
    )  # fmt: skip
    monkeypatch.setattr(sys, "argv", ["vhir", "approve"])
    with pytest.raises(PermissionError):
        M.main()


# --- Whose folder it is ---------------------------------------------------------


def _root_owned(monkeypatch, *paths):
    """Paths that stat as root's (tests can't make a root-owned file)."""
    import os
    import pathlib

    real_stat, real_scandir = pathlib.Path.stat, os.scandir
    wanted = {str(p) for p in paths}

    def as_root(result):
        values = list(result)
        values[4] = 0  # st_uid
        return os.stat_result(values)

    def stat(self, *a, **k):
        result = real_stat(self, *a, **k)
        return as_root(result) if str(self) in wanted else result

    class Entry:
        def __init__(self, entry):
            self._e, self.path, self.name = entry, entry.path, entry.name

        def stat(self, **k):
            result = self._e.stat(**k)
            return as_root(result) if self.path in wanted else result

    def scandir(path):
        return [Entry(e) for e in real_scandir(path)]

    monkeypatch.setattr(pathlib.Path, "stat", stat)
    monkeypatch.setattr(os, "scandir", scandir)


def test_a_root_owned_folder_or_root_owned_files_in_it_are_given_back(
    folders, capsys, monkeypatch
):
    keys_dir, ledger_dir = folders.dirs
    keys_dir.mkdir(parents=True)
    ledger_dir.mkdir()
    (ledger_dir / "C1.lock").write_text("")
    _root_owned(monkeypatch, keys_dir, ledger_dir / "C1.lock")
    assert cs._signing_dir_state(keys_dir) == "give back"
    assert cs._signing_dir_state(ledger_dir) == "give back"  # a file inside is root's
    from vhir_cli.commands import update

    update._ensure_signing_dirs()
    assert len(_sudo(folders.calls)) == 2
    assert capsys.readouterr().out.count("Giving back") == 2


def test_another_account_s_folder_is_never_taken(folders, capsys, monkeypatch):
    """The installer's rule: one examiner OS user per machine."""
    import os

    keys_dir, ledger_dir = folders.dirs
    keys_dir.mkdir(parents=True)
    ledger_dir.mkdir()
    for var in ("USER", "LOGNAME"):  # getuser() would otherwise look the uid up
        monkeypatch.setenv(var, "examiner")
    real = os.getuid()
    monkeypatch.setattr(
        os, "getuid", lambda: real + 1
    )  # the folders are someone else's
    assert cs._signing_dir_state(keys_dir) == "other"
    from vhir_cli.commands import update

    update._ensure_signing_dirs()
    assert _sudo(folders.calls) == []
    err = capsys.readouterr().err
    assert credentials.other_owner_text(keys_dir) in err
    assert "the ledger is theirs. One examiner OS user per machine is supported" in err


def test_signing_names_another_account_s_folder_with_the_installer_s_words(monkeypatch):
    import os

    for var in ("USER", "LOGNAME"):  # getuser() would otherwise look the uid up
        monkeypatch.setenv(var, "examiner")
    real = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real + 1)
    problem = credentials.signing_folders_problem()
    assert problem == credentials.other_owner_text(keys.KEYS_DIR)
    assert "sign as " in problem and "vhir update" not in problem


def test_signing_names_a_root_owned_file_in_a_folder(monkeypatch):
    lock = ledger.LEDGER_DIR / "C1.lock"
    lock.write_text("")
    _root_owned(monkeypatch, lock)
    problem = credentials.signing_folders_problem()
    assert problem == credentials.not_writable_text(lock)
    assert "run `vhir update`, which gives it back" in problem


def test_inside_an_older_update_the_folders_are_made_in_a_fresh_process(
    folders, monkeypatch
):
    """The 0.6.4 updater has its own vhir_cli.identity loaded, with no
    valid_name: this code's credentials module can't be imported there. The
    folder step runs in a new Python process, which imports only this code."""
    import vhir_cli

    old_identity = types.ModuleType("vhir_cli.identity")  # 0.6.4's: no valid_name
    monkeypatch.setitem(sys.modules, "vhir_cli.identity", old_identity)
    monkeypatch.setattr(vhir_cli, "identity", old_identity, raising=False)
    monkeypatch.delitem(sys.modules, "vhir_cli.credentials", raising=False)
    with pytest.raises(ImportError):  # what the in-process step hit
        import vhir_cli.credentials  # noqa: F401
    monkeypatch.delitem(sys.modules, "vhir_cli.credentials", raising=False)
    _older_update(monkeypatch)
    import subprocess

    spawned = []
    monkeypatch.setattr(
        subprocess, "run", lambda argv, **kw: spawned.append((argv, kw))
    )
    cs._isolate_gateway_launchers()
    ((argv, kw),) = spawned
    assert argv == [sys.executable, "-I", "-c", cs._ENSURE_SCRIPT]
    assert "capture_output" not in kw  # its output and sudo's prompt use the terminal


def test_a_fresh_process_that_can_t_start_never_raises(folders, monkeypatch, capsys):
    import subprocess

    _older_update(monkeypatch)

    def boom(argv, **kw):
        raise OSError("no python")

    monkeypatch.setattr(subprocess, "run", boom)
    assert cs._isolate_gateway_launchers() == []
    assert "The signing folders weren't made (no python)" in capsys.readouterr().out
