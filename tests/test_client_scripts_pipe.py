"""The Linux and macOS client scripts ask on the terminal under `curl … | bash`.

The README's install line pipes the script into bash, so the script itself is
the prompts' stdin. A prompt read the script's next line: Linux took the
default examiner and client without asking, the macOS client prompt read the
`case` line and the run died on a syntax error, and an uninstall's first y/n
prompt read the rest of the script, said "Please enter y or n." for each line,
and kept the files the examiner chose to remove. Now, when the script is on
stdin, the prompts read the terminal. With no terminal they take the default
and say so (a y/n prompt answers n). Run from a file, they read stdin as before.

The whole script runs in a scratch HOME. A stand-in curl answers the join and
fails every other fetch; claude, codex and vhir are stand-ins too.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

pty = pytest.importorskip("pty")

REPO = Path(__file__).parent.parent
SCRIPTS = {
    "linux": REPO / "setup-client-linux.sh",
    "macos": REPO / "setup-client-macos.sh",
}
ARGS = ["--sift=http://sift.example:4508", "--code=ABCD-1234"]
JOIN = {
    "status": "joined",
    "gateway_token": "vhir_gw_" + "0" * 24,
    "gateway_url": "http://sift.example:4508",
    "backends": ["forensic-mcp", "case-mcp"],
}
CURL = """#!/bin/bash
for a in "$@"; do
    case "$a" in */api/v1/setup/join) cat "$JOIN_FILE"; exit 0 ;; esac
done
exit 22
"""
STUB = '#!/bin/bash\necho "$(basename "$0") $*" >> "$HOME/stub-calls.log"\n'
# BSD sed: -i takes a suffix argument, here empty. GNU sed reads it as the script.
BSD_SED = """#!/bin/bash
if [[ "${1:-}" == "-i" && "${2-x}" == "" ]]; then shift 2; exec /usr/bin/sed -i "$@"; fi
exec /usr/bin/sed "$@"
"""
# Make the pty our controlling terminal, so /dev/tty opens, then run the command.
CTTY = (
    "import fcntl, os, sys, termios\n"
    "fcntl.ioctl(0, termios.TIOCSCTTY, 0)\n"
    "os.execv('/bin/bash', ['bash', '-c', sys.argv[1]])\n"
)
ANSI = re.compile(r"\x1b\[[0-9;]*m")
INSTALL = "alice\n2\n"
UNINSTALL = "y\nn\ny\n"


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home"
    h.mkdir()
    (h / ".bashrc").write_text("")
    return h


def _env(tmp_path, home, script):
    bin_ = tmp_path / "bin"
    if not bin_.exists():
        bin_.mkdir()
        (bin_ / "curl").write_text(CURL)
        for name in ("claude", "codex", "vhir"):
            (bin_ / name).write_text(STUB)
        if script == "macos":
            (bin_ / "sed").write_text(BSD_SED)
        for f in bin_.iterdir():
            f.chmod(0o755)
        (tmp_path / "join.json").write_text(json.dumps(JOIN))
    return {
        "HOME": str(home),
        "PATH": f"{bin_}:/usr/bin:/bin",
        "JOIN_FILE": str(tmp_path / "join.json"),
    }


def _run(tmp_path, home, script, form, answers="", args=ARGS):
    """form: "pipe" (`cat S | bash -s -- ARGS` on a terminal the answers are
    typed into), "pipe-no-tty" (the same with no terminal), or "file-no-tty"
    (`bash S ARGS < answers` with no terminal)."""
    env = _env(tmp_path, home, script)
    s = str(SCRIPTS[script])
    a = " ".join(args)
    if form == "pipe":
        master, slave = pty.openpty()
        try:
            os.write(master, answers.encode())
            p = subprocess.run(
                [sys.executable, "-I", "-c", CTTY, f"cat {s} | bash -s -- {a}"],
                stdin=slave,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                cwd=home,
                start_new_session=True,
                timeout=120,
            )
        finally:
            os.close(slave)
            os.close(master)
    else:
        feed = tmp_path / "answers.txt"
        feed.write_text(answers)
        cmd = f"cat {s} | bash -s -- {a}" if form == "pipe-no-tty" else f"bash {s} {a}"
        with feed.open() as stdin:
            p = subprocess.run(
                ["/bin/bash", "-c", cmd],
                stdin=stdin if form == "file-no-tty" else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                cwd=home,
                start_new_session=True,
                timeout=120,
            )
    return p.returncode, ANSI.sub("", p.stdout.decode(errors="replace"))


def _examiner(home):
    """The examiner value as a YAML reader sees it: one pair of quotes around it is dropped."""
    cfg = (home / ".vhir" / "config.yaml").read_text()
    value = re.search(r"^examiner: (.*)$", cfg, re.M).group(1)
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _desktop(home, script):
    if script == "linux":
        return home / ".config" / "claude" / "claude_desktop_config.json"
    return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"  # fmt: skip


def _codex_files(home):
    return [
        home / ".codex" / "valhuntir.config.toml",
        home / ".codex" / "agents" / "finding-skeptic.toml",
        home / ".agents" / "skills" / "vhir-ingest" / "SKILL.md",
        home / ".agents" / "skills" / "finding-skeptic" / "SKILL.md",
    ]


def _installed(home, script):
    """What an install leaves for the uninstall to ask about: Codex's files,
    the workspace with a case and the Desktop config."""
    for f in [*_codex_files(home), _desktop(home, script)]:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("{}\n")
    (home / "vhir" / "cases" / "demo").mkdir(parents=True)
    (home / "vhir" / "cases" / "demo" / "CASE.yaml").write_text("keep\n")
    (home / "vhir" / ".mcp.json").write_text("{}\n")
    (home / ".vhir").mkdir()
    (home / ".vhir" / "config.yaml").write_text("examiner: bob\n")


def _chose_codex(out, home, script):
    if script == "linux":
        assert "[OK] Client: codex" in out, out[-2000:]
    else:
        assert "=== Codex ===" in out, out[-2000:]
    assert not (home / "vhir" / ".mcp.json").exists(), out[-2000:]


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_the_piped_install_asks_on_the_terminal(tmp_path, home, script):
    rc, out = _run(tmp_path, home, script, "pipe", INSTALL)
    assert rc == 0, out[-2000:]
    assert _examiner(home) == "alice", out[-2000:]
    _chose_codex(out, home, script)


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_the_piped_uninstall_asks_on_the_terminal(tmp_path, home, script):
    _installed(home, script)
    rc, out = _run(tmp_path, home, script, "pipe", UNINSTALL, ["--uninstall"])
    assert rc == 0, out[-2000:]
    assert out.count("Please enter y or n.") == 0, out[-2000:]
    assert not any(f.exists() for f in _codex_files(home)), out[-2000:]
    desktop = _desktop(home, script)
    assert not desktop.exists(), out[-2000:]
    assert list(desktop.parent.glob(desktop.name + ".vhir-backup-*")), out[-2000:]
    assert (home / "vhir" / "cases" / "demo" / "CASE.yaml").exists()


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_with_no_terminal_the_piped_install_takes_the_defaults_and_says_so(
    tmp_path, home, script
):
    rc, out = _run(tmp_path, home, script, "pipe-no-tty")
    assert rc == 0, out[-2000:]
    client = "Which LLM client?" if script == "linux" else "Choose"
    assert f'No terminal to ask "{client}": answering 1.' in out, out[-2000:]
    examiner = _examiner(home)
    assert (
        f'No terminal to ask "Examiner identity (name slug)": answering {examiner}.'
        in out
    ), out[-2000:]


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_run_from_a_file_the_answers_still_come_from_stdin(tmp_path, home, script):
    rc, out = _run(tmp_path, home, script, "file-no-tty", INSTALL)
    assert rc == 0, out[-2000:]
    assert "No terminal to ask" not in out
    assert _examiner(home) == "alice", out[-2000:]
    _chose_codex(out, home, script)
