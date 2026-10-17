"""setup-sift.sh -y: join's "Reconfigure?" questions take their safe answer.

With VHIR_ASSUME_DEFAULTS=true the two "Reconfigure?" questions take their
safe answer (the one they take with no terminal) without asking: stderr says
the answer taken, and what the examiner typed is left unread. Which static
IP to set, and the questions after a typed answer, are still asked. The rows run the real code in a child whose terminal is a pty with
the answers already typed on it, and whose stdout is a pipe, as under
setup-sift.sh's capture. Values are synthetic; nothing runs.
"""

from __future__ import annotations

import io
import os
import pty
import select
import subprocess
import sys

import pytest
import yaml

from vhir_cli.commands import join

CHILD = """
import os, subprocess, sys
from vhir_cli.commands import join

def run(argv, **kwargs):
    print("RAN", " ".join(argv), file=sys.stderr)
    return subprocess.CompletedProcess(argv, 0, "" if kwargs.get("text") else b"", b"")

subprocess.run = run
join.private_primary_group = lambda user: "ex1"
join._push_smb_credentials = lambda password: None
join._detect_current_ip = lambda: "10.0.0.9"
scenario = os.environ["SCENARIO"]
if scenario == "netplan":  # the real _apply_static_ip, over the OS's netplan file
    import glob

    netplan = os.path.join(os.environ["HOME"], "50-cloud-init.yaml")
    real_glob = glob.glob
    glob.glob = lambda p, *a, **k: (
        [netplan] if p == "/etc/netplan/*.yaml" else real_glob(p, *a, **k)
    )

    def run(argv, **kwargs):
        print("RAN", " ".join(argv), file=sys.stderr)
        out = "8.8.8.8 via 10.0.0.1 dev eth0" if argv[:3] == ["ip", "route", "get"] else ""
        return subprocess.CompletedProcess(argv, 0, out if kwargs.get("text") else out.encode(), b"")

    subprocess.run = run
    print("RESULT", join._ensure_static_ip())
    scenario = "done"
join._apply_static_ip = lambda ip, path: print("APPLIED", ip) or ip
if scenario == "done":
    pass
elif scenario == "share":
    print("RESULT", join._setup_samba_share("ABCD-EFGH"))
elif scenario == "static":
    print("RESULT", join._ensure_static_ip())
else:
    join._post_join_code_setup({"code": "ABCD-EFGH", "expires_hours": 2}, "10.0.0.9")
try:
    fd = os.open("/dev/tty", os.O_RDONLY | os.O_NONBLOCK)
except OSError:
    sys.exit(0)
left = b""
try:
    while chunk := os.read(fd, 1024):
        left += chunk
except BlockingIOError:
    pass
print("UNREAD", repr(left.decode()))
"""


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".vhir").mkdir()
    return tmp_path


def _share(home):
    (home / ".vhir" / "samba.yaml").write_text(
        yaml.dump({"share_name": join.SHARE_NAME, "wintools_ip": "10.0.0.20"})
    )


def _network(home, ip):
    (home / ".vhir" / "network.yaml").write_text(yaml.dump({"static_ip": ip}))


def _drain(fd):
    seen = b""
    while select.select([fd], [], [], 0.2)[0]:
        try:
            chunk = os.read(fd, 4096)
        except OSError:  # EIO: no slave open any more
            break
        if not chunk:
            break
        seen += chunk
    return seen.decode()


def _run(home, scenario, typed=None, assume="true", merged=False):
    """Run the child; typed=None gives it no terminal at all, assume=None
    leaves the variable unset, merged=True sends stderr into stdout (as
    setup-sift.sh's 2>&1). Returns what the terminal showed, stdout, stderr,
    and what was left unread."""
    env = {
        "HOME": str(home),
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": os.pathsep.join(p for p in sys.path if p),
        "SCENARIO": scenario,
    }
    if assume is not None:
        env["VHIR_ASSUME_DEFAULTS"] = assume
    master = slave = ctty = None
    if typed is not None:
        master, slave = pty.openpty()
        name = os.ttyname(slave)
        os.write(master, typed.encode())  # typed before anything is asked
        ctty = lambda: os.close(os.open(name, os.O_RDWR))  # noqa: E731
    child = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", CHILD],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if merged else subprocess.PIPE,
        env=env,
        start_new_session=True,  # no controlling terminal unless ctty opens one
        preexec_fn=ctty,
    )
    shown = ""
    try:
        try:
            out, err = child.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            child.kill()
            out, err = child.communicate()
            if master is not None:
                shown = _drain(master)
            pytest.fail(
                f"still waiting for an answer after 20 s; the terminal showed "
                f"{shown!r}, stdout {out!r}, stderr {err!r}"
            )
        if master is not None:
            shown = _drain(master).replace("\r\n", "\n")
    finally:
        child.kill()
        child.wait()
        for fd in (slave, master):
            if fd is not None:
                os.close(fd)
    out, err = out.decode(), (err or b"").decode()
    unread = [s for s in out.splitlines() if s.startswith("UNREAD ")]
    return shown, out, err, (eval(unread[0][7:]) if unread else None)  # noqa: S307


def _took(err, question, answer):
    """The stderr line that says -y took the answer to this question."""
    return [
        s
        for s in err.splitlines()
        if question in s and f"answered {answer!r} (-y)" in s
    ]


def test_the_samba_reconfigure_takes_n_and_reads_nothing(home):
    _share(home)
    shown, out, err, unread = _run(home, "share", typed="y\n\n")
    assert "RESULT 10.0.0.20" in out.splitlines(), (shown, out, err)
    assert unread == "y\n\n", (shown, out, err)
    assert len(_took(err, "Reconfigure? [y/N]", "n")) == 1, err
    assert "Reconfigure? [y/N]: answered 'n' (-y)" in err.splitlines(), err
    assert "Reconfigure?" not in shown and "(-y)" not in out
    assert "Enter the Windows machine's IP address" not in shown
    assert join.SMB_CONF_PATH not in err  # the share is not rewritten


def test_the_active_static_ip_reconfigure_takes_n_and_reads_nothing(home):
    _network(home, "10.0.0.9")
    shown, out, err, unread = _run(home, "static", typed="y\n\n\n")
    assert "RESULT 10.0.0.9" in out.splitlines(), (shown, out, err)
    assert "APPLIED" not in out
    assert unread == "y\n\n\n", (shown, out, err)
    assert len(_took(err, "Reconfigure? [y/N]", "n")) == 1, err
    assert "Reconfigure?" not in shown and "(-y)" not in out
    assert "Enter static IP" not in shown


@pytest.mark.parametrize("assume", [None, "false"], ids=["unset", "false"])
@pytest.mark.parametrize("scenario", ["share", "static"])
def test_without_the_variable_reconfigure_is_asked_as_before(home, scenario, assume):
    if scenario == "share":
        _share(home)
    else:
        _network(home, "10.0.0.9")
    shown, out, err, unread = _run(home, scenario, typed="n\n", assume=assume)
    assert unread == "", (shown, out, err)
    assert "Reconfigure? [y/N] " in shown and "(-y)" not in shown + out + err
    result = "10.0.0.20" if scenario == "share" else "10.0.0.9"
    assert f"RESULT {result}" in out.splitlines(), (shown, out, err)


def test_which_static_ip_to_set_is_still_asked_and_so_is_its_confirmation(home):
    """No safe answer to "Enter static IP": -y asks it. Its "Correct?" follows
    a typed answer, so it is asked too; taking its "n" would ask for the IP
    again and again."""
    shown, out, err, unread = _run(home, "static", typed="10.0.0.7\ny\n")
    assert "APPLIED 10.0.0.7" in out.splitlines(), (shown, out, err)
    assert unread == ""
    assert "Enter static IP for this machine [10.0.0.9]: " in shown
    assert "Correct? [Y/n] " in shown
    assert "(-y)" not in shown + out + err


def test_overriding_the_os_netplan_for_a_typed_ip_is_still_asked(home):
    """It follows a typed IP: taking its "n" would drop the IP just typed."""
    (home / "50-cloud-init.yaml").write_text(
        yaml.dump({"network": {"ethernets": {"eth0": {}}}})
    )
    shown, out, err, unread = _run(home, "netplan", typed="10.0.0.7\ny\ny\n")
    assert "RESULT 10.0.0.7" in out.splitlines(), (shown, out, err)
    assert unread == ""
    assert "Override with Valhuntir static config? [y/N] " in shown
    assert "(-y)" not in shown + out + err
    assert "Skipped static IP configuration." not in err
    assert [s for s in err.splitlines() if s.startswith("RAN sudo ")], err


def _setup_sift_reads(out):
    """setup-sift.sh's own pipeline for the code: grep "Join code:" | awk."""
    pipe = subprocess.Popen(  # noqa: S603
        ["/bin/sh", "-c", "grep 'Join code:' | awk '{print $3}'"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    return pipe.communicate(out.encode(), timeout=10)[0].decode().strip()


@pytest.mark.parametrize("typed", ["y\n\n", None], ids=["terminal", "no-terminal"])
def test_the_join_code_still_parses_with_the_answer_taken_in_the_capture(home, typed):
    """setup-sift.sh captures join-code with 2>&1 and parses it for the code:
    the -y line is in the capture, and the code still reads."""
    _share(home)
    shown, out, _, _ = _run(home, "join-code", typed=typed, merged=True)
    assert len(_took(out, "Reconfigure? [y/N]", "n")) == 1, (shown, out)
    assert _setup_sift_reads(out) == "ABCD-EFGH", (shown, out)
    assert "setup-windows.ps1 -JoinCode ABCD-EFGH" in out  # the share kept its IP


def test_with_stdout_a_terminal_the_answer_taken_shows_there(home, monkeypatch, capsys):
    """setup-sift.sh's Network Configuration runs uncaptured: input() is not
    called, and stderr says the answer taken."""
    _network(home, "10.0.0.9")
    monkeypatch.setenv("VHIR_ASSUME_DEFAULTS", "true")
    monkeypatch.setattr(join, "_detect_current_ip", lambda: "10.0.0.9")
    monkeypatch.setattr(join, "_apply_static_ip", lambda ip, path: ip)
    asked = []
    monkeypatch.setattr("builtins.input", lambda prompt="": asked.append(prompt) or "y")

    class Terminal(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdout", Terminal())
    assert join._ensure_static_ip() == "10.0.0.9"
    assert asked == []
    assert "Reconfigure?" not in sys.stdout.getvalue()
    assert len(_took(capsys.readouterr().err, "Reconfigure? [y/N]", "n")) == 1
