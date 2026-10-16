"""join-code's questions are seen and answered even when its output is captured.

setup-sift.sh runs `vhir setup join-code` inside `$(...)`, so stdout is a
pipe. A question printed there is never seen, and the run waits. The pty
rows run the real code in a child whose controlling terminal is a pty and
whose stdout is a pipe: the question must show on the terminal and the
typed answer must be used. With no terminal at all, each question takes
its safe answer: no netplan change, the share kept, and no Windows IP
gives the code for the examiner machines only. Values are synthetic;
nothing runs.
"""

from __future__ import annotations

import io
import os
import select
import subprocess
import sys
import time

import pytest
import yaml

from vhir_cli.commands import join

CHILD = """
import os, sys
from vhir_cli.commands import join
join._detect_current_ip = lambda: "10.0.0.9"
join._apply_static_ip = lambda ip, path: print("APPLIED", ip) or ip
print("RESULT", join._ensure_static_ip())
"""


def _child(home, ctty):
    env = {
        "HOME": str(home),
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": os.pathsep.join(p for p in sys.path if p),
    }
    return dict(
        args=[sys.executable, "-c", CHILD],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,  # no controlling terminal unless ctty opens one
        preexec_fn=ctty,
    )


def _on_a_pty(home, steps):
    """Run the child with a pty as its terminal; answer each question there."""
    import pty

    master, slave = pty.openpty()
    name = os.ttyname(slave)
    child = subprocess.Popen(  # noqa: S603
        **_child(home, lambda: os.close(os.open(name, os.O_RDWR)))
    )
    seen = b""
    try:
        for question, answer in steps:
            deadline = time.monotonic() + 15
            while question.encode() not in seen:
                if select.select([master], [], [], 0.2)[0]:
                    seen += os.read(master, 4096)
                elif child.poll() is not None or time.monotonic() > deadline:
                    child.kill()
                    out, err = child.communicate()
                    pytest.fail(
                        f"{question!r} never shown on the terminal: {seen!r}; "
                        f"the child wrote {out!r} and {err!r}"
                    )
            os.write(master, answer.encode() + b"\n")
        out, err = child.communicate(timeout=15)
    finally:
        child.kill()
        child.wait()
        os.close(slave)  # held open until here: with no slave open, reads fail
        os.close(master)
    return seen.decode(), out.decode(), err.decode()


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".vhir").mkdir()
    return tmp_path


def _network(home, ip):
    (home / ".vhir" / "network.yaml").write_text(yaml.dump({"static_ip": ip}))


@pytest.mark.parametrize(
    "kind, stored, steps, result",
    [
        (  # y/N: "y" reconfigures; the default would keep 10.0.0.9 unapplied
            "y/N",
            "10.0.0.9",
            [
                ("Reconfigure? [y/N]", "y"),
                ("Enter static IP for this machine [10.0.0.9]:", ""),
                ("Correct? [Y/n]", ""),
            ],
            "APPLIED 10.0.0.9",
        ),
        (  # Y/n: "n" then blank skips; the default would apply 10.0.0.5
            "Y/n",
            "10.0.0.5",
            [("Apply 10.0.0.5 now? [Y/n]", "n"), ("blank to skip:", "")],
            "RESULT None",
        ),
        (  # free text: the typed IP, not the detected one
            "text",
            None,
            [
                ("Enter static IP for this machine [10.0.0.9]:", "10.0.0.7"),
                ("Correct? [Y/n]", "y"),
            ],
            "APPLIED 10.0.0.7",
        ),
    ],
)
def test_with_stdout_captured_the_question_is_asked_on_the_terminal(
    home, kind, stored, steps, result
):
    if stored:
        _network(home, stored)
    tty, out, err = _on_a_pty(home, steps)
    assert result in out.splitlines(), (out, err)
    if kind == "Y/n":
        assert "APPLIED" not in out
    for question, _ in steps:
        assert question in tty
        assert question not in out  # not lost in the capture
    # the lines saying what it asks about show with it
    context = {
        "y/N": "Static IP configured and active: 10.0.0.9",
        "Y/n": "The static IP was stored but never applied to the interface.",
        "text": "A static IP ensures they can reconnect after reboot.",
    }[kind]
    assert context in tty and context not in out


def test_with_no_terminal_at_all_no_static_ip_is_set(home):
    child = subprocess.run(**_child(home, None), timeout=30, check=False)  # noqa: S603
    out = child.stdout.decode()
    assert child.returncode == 0, child.stderr.decode()
    assert "RESULT None" in out.splitlines() and "APPLIED" not in out
    assert "No terminal to ask" in child.stderr.decode()


@pytest.fixture
def no_tty(home, monkeypatch):
    """stdout captured, and no terminal: opening it fails."""
    monkeypatch.setattr(join, "TTY", str(home / "no-such-tty"), raising=False)
    monkeypatch.setattr(join, "_detect_current_ip", lambda: "10.0.0.9")
    applied = []
    monkeypatch.setattr(
        join, "_apply_static_ip", lambda ip, path: applied.append(ip) or ip
    )
    return applied


@pytest.mark.parametrize(
    "stored, result",
    [("10.0.0.9", "10.0.0.9"), ("10.0.0.5", None), (None, None)],
    ids=["active-kept", "stored-not-applied", "none-stays-none"],
)
def test_with_no_terminal_the_static_ip_questions_change_no_network(
    home, no_tty, capsys, stored, result
):
    if stored:
        _network(home, stored)
    assert join._ensure_static_ip() == result
    assert no_tty == []
    assert "No terminal to ask" in capsys.readouterr().err


def test_with_no_terminal_an_existing_netplan_config_is_not_overridden(
    home, monkeypatch, capsys
):
    import glob

    monkeypatch.setattr(join, "TTY", str(home / "no-such-tty"), raising=False)
    netplan = home / "50-cloud-init.yaml"
    netplan.write_text(yaml.dump({"network": {"ethernets": {"eth0": {}}}}))
    real_glob = glob.glob
    monkeypatch.setattr(
        glob,
        "glob",
        lambda p, *a, **k: (
            [str(netplan)] if p == "/etc/netplan/*.yaml" else real_glob(p, *a, **k)
        ),
    )
    ran = []

    def run(argv, **kwargs):
        ran.append(argv)
        out = (
            "8.8.8.8 via 10.0.0.1 dev eth0"
            if argv[:3] == ["ip", "route", "get"]
            else ""
        )
        return subprocess.CompletedProcess(
            argv, 0, out if kwargs.get("text") else out.encode(), ""
        )

    monkeypatch.setattr(subprocess, "run", run)
    assert join._apply_static_ip("10.0.0.7", home / ".vhir" / "network.yaml") is None
    assert not [a for a in ran if a[:1] == ["sudo"]]
    assert "Skipped static IP configuration." in capsys.readouterr().err


@pytest.fixture
def share(home, monkeypatch):
    monkeypatch.setattr(join, "TTY", str(home / "no-such-tty"), raising=False)
    ran = []

    def run(argv, **kwargs):
        ran.append(argv)
        return subprocess.CompletedProcess(
            argv, 0, "" if kwargs.get("text") else b"", b""
        )

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(join, "private_primary_group", lambda user: "ex1")
    monkeypatch.setattr(join, "_push_smb_credentials", lambda password: None)
    return ran


def test_with_no_terminal_an_existing_share_is_kept(home, share):
    (home / ".vhir" / "samba.yaml").write_text(
        yaml.dump({"share_name": join.SHARE_NAME, "wintools_ip": "10.0.0.20"})
    )
    assert join._setup_samba_share("ABCD-EFGH") == "10.0.0.20"
    assert not [a for a in share if "apt-get" in a or "tee" in a]


def _join_code(capsys):
    join._post_join_code_setup({"code": "ABCD-EFGH", "expires_hours": 2}, "10.0.0.9")
    out, err = capsys.readouterr()
    return out, err


def _setup_sift_reads(out):
    """setup-sift.sh's own pipeline for the code: grep "Join code:" | awk."""
    pipe = subprocess.Popen(  # noqa: S603
        ["/bin/sh", "-c", "grep 'Join code:' | awk '{print $3}'"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    return pipe.communicate(out.encode(), timeout=10)[0].decode().strip()


@pytest.mark.parametrize("terminal", [True, False], ids=["blank-answer", "no-terminal"])
def test_no_windows_ip_gives_the_code_with_no_share_and_no_windows_line(
    home, share, capsys, monkeypatch, terminal
):
    """No Windows machine is not a failed share: the code still prints, for
    the examiner machines only (setup-sift --remote's LLM-client code)."""
    if terminal:
        monkeypatch.setattr(join, "_ask", lambda question, no_terminal: "  ")
    out, err = _join_code(capsys)
    assert _setup_sift_reads(out) == "ABCD-EFGH"
    assert "vhir setup client" in out
    assert "run 'vhir setup join-code' again when you add one" in out
    assert "PowerShell" not in out and "setup-windows.ps1" not in out
    assert not [a for a in share if a[-1:] == [join.SMB_CONF_PATH]]
    assert not [a for a in share if "ufw" in a]
    assert ("No terminal to ask" in err) is not terminal


def test_reconfigure_then_a_blank_ip_keeps_the_configured_share(
    home, share, capsys, monkeypatch
):
    """Blank means "no Windows machine" only when there is no share: after
    "Reconfigure? y" it keeps the share and its IP, as "n" does."""
    (home / ".vhir" / "samba.yaml").write_text(
        yaml.dump({"share_name": join.SHARE_NAME, "wintools_ip": "10.0.0.20"})
    )
    answers = ["y", ""]
    monkeypatch.setattr(join, "_ask", lambda question, no_terminal: answers.pop(0))
    out, _ = _join_code(capsys)
    assert answers == []
    assert _setup_sift_reads(out) == "ABCD-EFGH"
    assert "No Windows machine" not in out
    assert "setup-windows.ps1 -JoinCode ABCD-EFGH" in out
    assert not [a for a in share if a[-1:] == [join.SMB_CONF_PATH]]
    assert (home / ".vhir" / "samba.yaml").read_text().count("10.0.0.20") == 1


def test_a_share_under_the_old_name_moves_with_its_ip_on_a_blank_answer(
    home, share, capsys, monkeypatch
):
    """The move asks no question: a blank IP keeps the IP the share had."""
    (home / ".vhir" / "samba.yaml").write_text(
        yaml.dump({"share_name": "cases", "wintools_ip": "10.0.0.21"})
    )
    answers = [""]
    monkeypatch.setattr(join, "_ask", lambda question, no_terminal: answers.pop(0))
    out, _ = _join_code(capsys)
    assert answers == []
    assert _setup_sift_reads(out) == "ABCD-EFGH"
    assert "No Windows machine" not in out
    assert "setup-windows.ps1 -JoinCode ABCD-EFGH" in out
    assert [a for a in share if a[-1:] == [join.SMB_CONF_PATH]]
    doc = yaml.safe_load((home / ".vhir" / "samba.yaml").read_text())
    assert (doc["share_name"], doc["wintools_ip"]) == (join.SHARE_NAME, "10.0.0.21")


def test_an_invalid_windows_ip_still_stops_join_code_with_no_code(
    home, share, capsys, monkeypatch
):
    monkeypatch.setattr(join, "_ask", lambda question, no_terminal: "10.0.0")
    with pytest.raises(SystemExit) as stop:
        _join_code(capsys)
    assert stop.value.code not in (0, None)
    out, err = capsys.readouterr()
    assert "ABCD-EFGH" not in out + err
    assert "Samba share setup failed: Invalid IPv4 address: 10.0.0" in err
    assert not [a for a in share if a[-1:] == [join.SMB_CONF_PATH]]


def test_with_stdout_a_terminal_input_asks_as_before(home, monkeypatch, capsys):
    """Interactive runs: input() with the same text the user saw before."""
    _network(home, "10.0.0.9")
    monkeypatch.setattr(join, "_detect_current_ip", lambda: "10.0.0.9")
    asked = []
    monkeypatch.setattr("builtins.input", lambda prompt="": asked.append(prompt) or "")

    class Terminal(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdout", Terminal())
    assert join._ensure_static_ip() == "10.0.0.9"
    seen = sys.stdout.getvalue() + "".join(asked)
    assert "Static IP configured and active: 10.0.0.9\nReconfigure? [y/N] " in seen
    assert len(asked) == 1


APPLY_TRANSCRIPT = (
    "Warning: network.yaml says 10.0.0.5 but interface has 10.0.0.9\n"
    "The static IP was stored but never applied to the interface.\n"
    "Apply 10.0.0.5 now? [Y/n] "
    "Enter a different IP, or blank to skip: "
)
INTRO_TRANSCRIPT = (
    "Remote machines (Windows workstation, LLM clients) connect to this\n"
    "SIFT workstation by IP. A static IP ensures they can reconnect after reboot.\n"
    "\n"
    "Enter static IP for this machine [10.0.0.9]: "
)


@pytest.mark.parametrize(
    "stored, answers, transcript",
    [
        ("10.0.0.5", ["n", ""], APPLY_TRANSCRIPT),
        (None, ["10.0.0.7", "n", "10.0.0.8", "y"], INTRO_TRANSCRIPT),
    ],
    ids=["stored-not-applied", "first-question"],
)
def test_on_a_terminal_the_folded_lines_read_as_before(
    home, monkeypatch, stored, answers, transcript
):
    """The terminal shows the same text, in the same order, as when these
    lines were printed before the question; the intro shows once."""
    if stored:
        _network(home, stored)
    monkeypatch.setattr(join, "_detect_current_ip", lambda: "10.0.0.9")
    monkeypatch.setattr(join, "_apply_static_ip", lambda ip, path: ip)

    class Terminal(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdout", Terminal())
    monkeypatch.setattr(
        "builtins.input", lambda prompt="": sys.stdout.write(prompt) and answers.pop(0)
    )
    join._ensure_static_ip()
    seen = sys.stdout.getvalue()
    assert seen.startswith(transcript), seen
    assert seen.count("Remote machines") == (0 if stored else 1)
