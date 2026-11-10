"""U11: every step `vhir update` leaves for the examiner is in one framed block.

The block opens with OPEN and closes with CLOSE, on stderr, after the run's
own output; each step is indented two spaces. With no terminal, a start block
(NOTERM1, NOTERM2) prints before anything else, in the first process only,
and the end block always prints. A terminal run with nothing to do prints no
block. A line that tells the examiner to run, re-run or restart something
(SCAN) never prints outside a block.

The harness runs cmd_update in this process with every outside effect faked:
subprocess.run, os.execv, input and the passphrase prompt. A hand-over to the
pulled code (os.execv) ends the first process: the vhir_cli module globals are
put back as they were before the run, and cmd_update runs again with the
argv it was handed, as process "2". Output written after the exec call, while
the first process unwinds, is kept apart as "1-after-exec": a real exec never
returns, so it must be empty. The first process's end block is not printed
there: a real exec never reaches cmd_update's finally.
"""

from __future__ import annotations

import builtins
import copy
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import traceback
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

import vhir_cli
from tests import test_update_lock
from tests.stub_check import stub, stub_check  # noqa: F401 (the fixture)
from vhir_cli import approval_auth, controls, credentials, human_steps, keys, sift_tools
from vhir_cli import gateway as gateway_mod
from vhir_cli import main as main_mod
from vhir_cli.commands import client_setup, codex_controls, join, setup
from vhir_cli.commands import update as upd

box = test_update_lock.box  # the fixture: a scratch home with an install

_REAL_ENSURE_PASSWORD_DIR = upd._ensure_password_dir  # before conftest's stand-in
_REAL_FIND_SPEC = importlib.util.find_spec
_REAL_VERSION = importlib.metadata.version

OPEN = "==== vhir update: steps for you ===="
CLOSE = "==== end of steps ===="
NOTERM1 = "Forensic controls NOT applied: no terminal."
NOTERM2 = (
    "If you are an AI assistant, stop and ask the examiner to run `vhir update`"
    " in their own terminal."
)

# A line that hands the examiner something to do.
SCAN = re.compile(
    r"try manually|run manually|re-?run|run it again|finish with|then run"
    r"|restart your|set one with|update it:|use claude code"
    r"|vhir (config|setup|update)\b|bash [~/]|sudo |systemctl --user"
    r"|update incomplete: run `vhir update` again|run: vhir update"
    r"|restart the gateway|update manually:|run setup-sift\.sh"
    r"|git -C \S+ checkout main|stash (push|pop)",
    re.I,
)
# Information, not a step: the build line, --check's closing line, the
# signing-key question, a declined offer, the controls block.
EXEMPT_START = (
    "PyTorch build:",
    "Run 'vhir update' to apply.",
    "Upgrade it now (vhir config --upgrade-key)? [Y/n]",
    "Declined earlier",
)
EXEMPT_LINES = {
    line.strip() for c in controls.ALL for line in controls.block_lines(c, False, "")
}

HEADS = {
    "sift-mcp": ("1" * 40, "2" * 40),
    "vhir": ("a" * 40, "b" * 40),
    "opensearch-mcp": ("c" * 40, "d" * 40),
}
PASS = SimpleNamespace(outcome="pass", reason="", fix="", stale=False)
LONG_PW = "Qz7mVt2pLxR4nW8s"  # 16
MID_PW = "Qz7mVt2pLx"  # 10
CJK = "漢字仮名交じり文書体系統計画表"  # 15 code points


class HarnessError(Exception):
    """The harness couldn't run the row as written."""


class InputExhausted(BaseException):
    """The product read input the row gave no answer for."""


class ExecEnded(BaseException):
    """os.execv was called: the first process ends here."""


class RowTimeout(BaseException):
    """The row ran past its 60 s alarm."""


class Args(SimpleNamespace):
    """cmd_update's args: a flag the row doesn't set is None."""

    def __getattr__(self, name):
        return None


class _Stream(io.TextIOBase):
    """sys.stdout or sys.stderr: each whole line goes to the run's log as
    (process, stream, line)."""

    encoding = "utf-8"
    errors = "strict"

    def __init__(self, run, name):
        super().__init__()
        self.run, self.name, self.buf = run, name, ""

    def writable(self):
        return True

    def isatty(self):
        return False

    def write(self, s):
        self.buf += s
        *lines, self.buf = self.buf.split("\n")
        for line in lines:
            self.run.log.append((self.run.proc, self.name, line))
        return len(s)

    def flush(self):
        pass

    def end(self):
        if self.buf:
            self.run.log.append((self.run.proc, self.name, self.buf))
            self.buf = ""


class _Stdin(io.TextIOBase):
    def __init__(self, tty):
        super().__init__()
        self.tty = tty

    def isatty(self):
        return self.tty

    def readable(self):
        return True

    def read(self, *a):
        raise InputExhausted("stdin read")

    def readline(self, *a):
        raise InputExhausted("stdin readline")


def _result(kw, rc=0, out="", err=""):
    text = kw.get("text") or kw.get("universal_newlines") or kw.get("encoding")
    if not text:
        out, err = out.encode(), err.encode()
    return SimpleNamespace(returncode=rc, stdout=out, stderr=err)


_IMMUTABLE = (str, int, float, bool, type(None), tuple, frozenset, bytes)


def _snapshot():
    """The vhir_cli module globals, to put back at the emulated exec."""
    snap = []
    for name, mod in list(sys.modules.items()):
        if mod is None or not (name == "vhir_cli" or name.startswith("vhir_cli.")):
            continue
        for k, v in list(vars(mod).items()):
            if k.startswith("__"):
                continue
            if isinstance(v, (list, dict, set)):
                snap.append(("mut", mod, k, v, copy.copy(v)))
            elif isinstance(v, _IMMUTABLE):
                snap.append(("imm", mod, k, v, None))
            elif (
                type(v).__module__.startswith("vhir_cli")
                and not isinstance(v, type)
                and not callable(v)
                and hasattr(v, "__dict__")
            ):
                try:
                    snap.append(("obj", mod, k, v, copy.deepcopy(vars(v))))
                except Exception:  # noqa: BLE001 — not copyable: left as is
                    pass
    return snap


def _restore(snap):
    for kind, mod, k, v, saved in snap:
        setattr(mod, k, v)
        if kind == "mut":
            if isinstance(v, list):
                v[:] = saved
            else:
                v.clear()
                v.update(saved)
        elif kind == "obj":
            v.__dict__.clear()
            v.__dict__.update(saved)


def _legacy(pw):
    """A 0.6 passphrase entry for alice."""
    salt = bytes(range(32))
    path = approval_auth._password_file(approval_auth._PASSWORDS_DIR, "alice")
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.pbkdf2_hmac(
        "sha256", pw.encode(), salt, approval_auth.PBKDF2_ITERATIONS
    ).hex()
    path.write_text(json.dumps({"hash": digest, "salt": salt.hex()}))


class Run:
    """One row's run of `vhir update`, and what it printed."""

    def __init__(self, box, monkeypatch, tmp_path):
        self.box, self.mp, self.tmp = box, monkeypatch, tmp_path
        self.log: list[tuple[str, str, str]] = []
        self.calls: list[list[str]] = []
        self.proc = "1"
        self.rc = None
        self.exec_argv = None
        self.prompts: list[str] = []
        self.state_at_prompt: dict[str, object] = {}
        self.problems: list[str] = []

    # ---- what the run printed -------------------------------------------

    def lines(self, proc=None, stream=None):
        return [
            line
            for p, s, line in self.log
            if (proc is None or p == proc) and (stream is None or s == stream)
        ]

    def _spans(self):
        """(proc, [indexes of the lines inside]) for each closed block."""
        spans, cur = [], None
        for i, (p, s, line) in enumerate(self.log):
            if s != "stderr":
                continue
            if cur is not None and cur[0] != p:
                cur = None  # a process ended inside it: not a block
            if line.strip() == OPEN and cur is None:
                cur = (p, i, [])
            elif line.strip() == CLOSE and cur is not None:
                spans.append((cur[0], cur[1], i, cur[2]))
                cur = None
            elif cur is not None:
                cur[2].append(i)
        return spans

    def blocks(self, proc=None):
        return [
            [self.log[i][2] for i in inner]
            for p, _o, _c, inner in self._spans()
            if proc is None or p == proc
        ]

    def last_block(self):
        b = self.blocks()
        return b[-1] if b else []

    def in_last(self, text):
        return any(text in line for line in self.last_block())

    def in_blocks(self, text, proc=None):
        return sum(text in line for b in self.blocks(proc) for line in b)

    def outside(self):
        inside = set()
        for _p, o, c, _inner in self._spans():
            inside.update(range(o, c + 1))
        return [line for i, (_p, s, line) in enumerate(self.log) if i not in inside]

    def out_has(self, text):
        return any(text in line for line in self.outside())

    def scan_hits(self):
        return [line for line in self.outside() if _scan_hit(line)]

    def traceback(self):
        return any(
            line.startswith("Traceback (most recent call last):")
            for _p, _s, line in self.log
        )

    def opens(self, proc):
        return sum(
            1
            for p, s, line in self.log
            if p == proc and s == "stderr" and line.strip() == OPEN
        )

    def index_of(self, pred):
        for i, (_p, _s, line) in enumerate(self.log):
            if pred(line):
                return i
        return None

    def last_open(self):
        return max((o for _p, o, _c, _i in self._spans()), default=None)

    def install_argv(self):
        for c in self.calls:
            if c[:3] == ["uv", "pip", "install"] and "-c" in c:
                return c
        return []

    def state(self):
        path = self.box.home / ".vhir" / "update-state.json"
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return None

    # ---- the fakes ------------------------------------------------------

    def _repo(self, p):
        name = Path(str(p)).name
        if name not in HEADS:
            self.problems.append(f"git on an unknown repo {p}")
        return name

    def _git(self, cmd, kw):
        k = self.k
        repo = self._repo(cmd[2])
        sub = cmd[3:]
        old, new = HEADS.get(repo, ("0" * 40, "f" * 40))
        if sub == ["fetch", "origin"]:
            if repo in k["fetch_fail"]:
                return _result(
                    kw,
                    1,
                    "",
                    "fatal: unable to access 'https://github.com/x/': Could not resolve host",
                )
            return _result(kw)
        if sub == ["rev-list", "HEAD..origin/main", "--count"]:
            return _result(kw, 0, "0\n")
        if sub[:1] == ["rev-list"] and len(sub) == 3 and sub[2] == "--count":
            return _result(kw, 0, "3\n")
        if sub == ["rev-parse", "origin/main"]:
            return _result(kw, 0, new + "\n")
        if sub == ["rev-parse", "HEAD"]:
            return _result(kw, 0, self.head[repo] + "\n")
        if sub == ["symbolic-ref", "--short", "HEAD"]:
            return _result(kw, 0, k["branch"].get(repo, "main") + "\n")
        if sub == ["pull", "--ff-only"]:
            how = k["pulls"].get(repo, "ok")
            if repo in k["moves"] or how.endswith("-moved"):
                self.head[repo] = new
            how = how.replace("-moved", "")
            if how == "timeout":
                raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
            if how == "fail":
                return _result(
                    kw,
                    1,
                    "",
                    "error: Your local changes to the following files would be "
                    "overwritten by merge:\n\tREADME.md\nAborting",
                )
            return _result(kw, 0, "Already up to date.\n")
        if sub[:2] == ["diff", "--unified=0"]:
            return _result(kw)
        self.problems.append(f"unexpected git command {cmd}")
        return _result(kw)

    def _run(self, cmd, *a, **kw):
        cmd = [str(c) for c in cmd]
        self.calls.append(cmd)
        k = self.k
        if cmd[:2] == ["git", "-C"]:
            return self._git(cmd, kw)
        if cmd[:2] == ["uv", "--version"]:
            if k["uv_missing"]:
                raise FileNotFoundError(2, "No such file or directory", "uv")
            return _result(kw, 0, k["uv"] + "\n")
        if cmd[:3] == ["uv", "self", "update"]:
            return _result(kw)
        if cmd[:3] == ["uv", "pip", "install"]:
            if "-c" not in cmd:
                self.problems.append(f"an install without the lock: {cmd}")
            return _result(
                kw,
                k["install_rc"],
                "",
                "" if not k["install_rc"] else "error: resolution failed",
            )
        if cmd[:2] == ["uv", "pip"]:
            return _result(kw)
        if len(cmd) > 2 and cmd[1].endswith("check-lock.py"):
            return _result(
                kw, 0, {"--installed": "setuptools starlette"}.get(cmd[2], "")
            )
        if len(cmd) > 2 and cmd[1] == "-I" and cmd[2] == "-c" and "torch" in cmd[-1]:
            return _result(kw, 0, "2.14.0\n")
        if cmd[0] == "systemctl":
            return _result(kw, 0, "active\n")
        if cmd[:2] == ["docker", "inspect"]:
            if cmd[3] == "{{.Config.Image}}":
                if k["image"] is None:
                    return _result(kw, 1, "", "Error: No such object: vhir-opensearch")
                return _result(kw, 0, k["image"] + "\n")
            return _result(kw, 0, "volume vhir-snapshots false\n")
        if cmd[0] == "bash":
            if k["bash_timeout"]:
                raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
            return _result(kw)
        if cmd[0] == "bwrap":
            return _result(kw, 1, "", "bwrap: setting up uid map: Permission denied")
        if cmd[0] == "sysctl":
            return _result(kw, 0, "1\n")
        if cmd[:2] == ["sudo", "tee"]:
            return _result(kw)
        if cmd[0] == "sudo":
            return _result(kw, 1, "", "sudo: a password is required")
        self.problems.append(f"unexpected command {cmd}")
        return _result(kw)

    def _input(self, prompt=""):
        sys.stdout.write(prompt)
        self.prompts.append(prompt)
        self.state_at_prompt[prompt] = self.state()
        for i, (rx, reply, keep) in enumerate(self.rules):
            if re.search(rx, prompt):
                if not keep:
                    del self.rules[i]
                if reply is EOFError:
                    sys.stdout.write("\n")
                    raise EOFError
                sys.stdout.write(reply + "\n")
                return reply
        sys.stdout.write("\n")
        raise InputExhausted(prompt)

    def _getpass(self, prompt):
        sys.stderr.write(prompt + "\n")
        if not self.secrets:
            raise InputExhausted(prompt)
        item = self.secrets.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def _execv(self, path, argv):
        if self.k["exec_oserror"]:
            raise OSError(8, "Exec format error")
        if self.exec_argv is not None:
            self.problems.append(f"a second exec: {argv}")
        else:
            self.exec_argv = [str(a) for a in argv]
        self.proc = "1-after-exec"
        raise ExecEnded

    def _find_spec(self, name, *a, **kw):
        if name == "opensearch_mcp":
            return self.os_spec
        if name == "opencti_mcp":
            return None
        return _REAL_FIND_SPEC(name, *a, **kw)

    # ---- the row's state ------------------------------------------------

    def _prepare(self, k):
        b, mp = self.box, self.mp
        self.k = k
        self.head = {r: h[0] for r, h in HEADS.items()}
        self.rules = list(k["answers"]) + [(r"(?i)opensearch", "n", True)]
        self.secrets = list(k["secrets"])
        mpath = b.home / ".vhir" / "manifest.json"
        manifest = json.loads(mpath.read_text())
        manifest["client"] = k["client"]
        manifest["torch_variant"] = "gpu"
        for key, value in k["manifest"].items():
            manifest[key] = value
        mpath.write_text(json.dumps(manifest))
        (b.home / "venv" / "bin" / "vhir").write_text("#!/bin/sh\n")
        (b.home / ".claude").mkdir(exist_ok=True)
        self.os_spec = None
        if k["opensearch"] == "missing":
            init = self.tmp / "site" / "opensearch_mcp" / "__init__.py"
            init.parent.mkdir(parents=True)
            self.os_spec = SimpleNamespace(origin=str(init))
        elif k["opensearch"]:
            repo = b.home / "opensearch-mcp"
            (repo / ".git").mkdir(parents=True)
            (repo / "docker").mkdir()
            (repo / "docker" / "docker-compose.yml").write_text(
                "services:\n  opensearch:\n    image: opensearchproject/opensearch:3.5.0\n"
            )
            (repo / "scripts").mkdir()
            (repo / "scripts" / "setup-opensearch.sh").write_text("#!/bin/bash\n")
            init = repo / "src" / "opensearch_mcp" / "__init__.py"
            init.parent.mkdir(parents=True)
            init.write_text("")
            self.os_spec = SimpleNamespace(origin=str(init))
            client = types.ModuleType("opensearch_mcp.client")
            client.get_client = lambda: SimpleNamespace(
                nodes=SimpleNamespace(info=lambda **kw: {"nodes": {}})
            )
            mp.setitem(
                sys.modules, "opensearch_mcp", types.ModuleType("opensearch_mcp")
            )
            mp.setitem(sys.modules, "opensearch_mcp.client", client)
        if k["key"] == "legacy":
            _legacy(k["pw"])
        if k["setup"]:
            k["setup"](b)

    def _patch(self, k):
        b, mp = self.box, self.mp
        mp.setenv("HOME", str(b.home))
        mp.delenv("VHIR_ASSUME_DEFAULTS", raising=False)
        mp.setattr(Path, "home", staticmethod(lambda: b.home))
        mp.setattr(subprocess, "run", self._run)
        mp.setattr(importlib.util, "find_spec", self._find_spec)
        mp.setattr(
            shutil,
            "which",
            lambda name, *a, **kw: (
                "/usr/bin/bwrap" if name == "bwrap" and k["bwrap"] else None
            ),
        )
        mp.setattr(os, "execv", self._execv)
        finish = human_steps.finish
        mp.setattr(
            human_steps,
            "finish",
            lambda terminal: None if self.proc == "1-after-exec" else finish(terminal),
        )
        mp.setattr(approval_auth, "_LOCKOUT_FILE", self.tmp / ".password_lockout")
        mp.setattr(
            importlib.metadata,
            "version",
            lambda name: (
                vhir_cli.__version__ if name == "vhir-cli" else _REAL_VERSION(name)
            ),
        )
        mp.setattr(time, "sleep", lambda *a: None)
        mp.setattr(builtins, "input", self._input)
        mp.setattr(upd, "_BWRAP_PROFILE_PATH", self.tmp / "apparmor.d" / "bwrap")
        if k["real_password_dir"]:
            mp.setattr(upd, "_ensure_password_dir", _REAL_ENSURE_PASSWORD_DIR)
        stub(mp, approval_auth, "getpass_prompt", self._getpass, calls="any")
        # the base has no check_gateway yet; Step 8 reaches it at the fix
        stub(
            mp,
            gateway_mod,
            "check_gateway",
            lambda *a, **kw: PASS,
            exists=False,
            calls="any",
        )
        stub(mp, setup, "_run_connectivity_test", lambda *a, **kw: None, calls="any")
        stub(mp, controls, "applied", lambda *a, **kw: (False, ""), calls="any")
        settings = b.home / ".claude" / "settings.json"

        def deploy_claude(*a, **kw):
            if not k["kept"]:
                return settings, "unchanged"
            settings.write_text("old\n")
            status = client_setup._write_user_file(
                settings, "new\n", "the hooks changed"
            )
            return settings, status

        stub(mp, client_setup, "_deploy_claude_code_assets", deploy_claude, calls="any")

        def launchers(*a, **kw):
            if k["launcher"]:
                path = b.home / ".vhir" / "start-gateway.sh"
                client_setup._LAUNCHERS_UPDATED.append(path)
                return [path]
            return []

        stub(mp, client_setup, "_isolate_gateway_launchers", launchers, calls="any")
        stub(mp, sift_tools, "volatility_problem", lambda: None, calls="any")
        stub(mp, sift_tools, "hayabusa_missing", lambda: k["hayabusa"], calls="any")
        stub(mp, join, "share_needs_rejoin", lambda: k["share"], calls="any")
        stub(mp, upd, "_ensure_signing_dirs", lambda: None, calls="any")
        stub(mp, client_setup, "deploy_skills", lambda *a, **kw: None, calls="any")
        stub(mp, client_setup, "_sift_root_dir", lambda *a, **kw: None, calls="any")
        stub(
            mp, client_setup, "_deploy_copy", lambda *a, **kw: "unchanged", calls="any"
        )
        stub(
            mp,
            client_setup,
            "_codex_servers_from_box",
            lambda *a, **kw: None,
            calls="any",
        )
        stub(
            mp,
            codex_controls,
            "codex_controls_state",
            lambda *a, **kw: "off",
            calls="any",
        )
        stub(mp, codex_controls, "state_lines", lambda *a, **kw: [], calls="any")
        for obj, name, value in k["stubs"]:
            stub(mp, obj, name, value, calls="any")

    # ---- running it -----------------------------------------------------

    def _call(self, args):
        try:
            upd.cmd_update(args, {"examiner": "alice"})
            return 0
        except SystemExit as e:
            if e.code is None:
                return 0
            if isinstance(e.code, int):
                return e.code
            print(e.code, file=sys.stderr)
            return 1
        except Exception:  # noqa: BLE001 — as the interpreter prints it
            sys.stderr.write(traceback.format_exc())
            return 1

    def _args_from(self, argv):
        rest = argv[3:]
        if rest[:1] != ["--after-pull"] or len(rest) < 2:
            raise HarnessError(f"exec argv not a hand-over: {argv}")
        args = Args(after_pull=rest[1])
        for flag in rest[2:]:
            name = {"--no-restart": "no_restart", "--cpu": "cpu", "--gpu": "gpu"}.get(
                flag
            )
            if name is None:
                raise HarnessError(f"exec argv has an unknown flag {flag}: {argv}")
            setattr(args, name, True)
        return args

    def go(self, **kw):
        k = dict(
            client="claude-code",
            tty=True,
            answers=(),
            secrets=(),
            uv="uv 0.12.20",
            uv_missing=False,
            fetch_fail=(),
            branch={},
            pulls={},
            moves=(),
            install_rc=0,
            cpu=None,
            gpu=None,
            check=None,
            no_restart=None,
            after_pull=None,
            exec_oserror=False,
            opensearch=None,
            image="opensearchproject/opensearch:3.5.0",
            bash_timeout=False,
            kept=False,
            launcher=False,
            share=False,
            hayabusa=False,
            key="none",
            pw="",
            bwrap=False,
            real_password_dir=False,
            manifest={},
            setup=None,
            stubs=(),
        )
        unknown = set(kw) - set(k)
        if unknown:
            raise HarnessError(f"unknown knobs {sorted(unknown)}")
        k.update(kw)
        if k["real_password_dir"] and Path("/var/lib/vhir/passwords").exists():
            raise HarnessError("/var/lib/vhir/passwords exists here: run in the rig")
        self._prepare(k)
        self._patch(k)
        snap = _snapshot()
        args = Args(
            cpu=k["cpu"],
            gpu=k["gpu"],
            check=k["check"],
            no_restart=k["no_restart"],
            after_pull=k["after_pull"],
        )
        out, err = _Stream(self, "stdout"), _Stream(self, "stderr")
        saved = sys.stdout, sys.stderr, sys.stdin
        old_alarm = signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(60)
        try:
            sys.stdout, sys.stderr, sys.stdin = out, err, _Stdin(k["tty"])
            try:
                self.rc = self._call(args)
            except ExecEnded:
                out.end()
                err.end()
                _restore(snap)
                self.proc = "2"
                try:
                    self.rc = self._call(self._args_from(self.exec_argv))
                except ExecEnded:
                    self.problems.append("the second process ran exec too")
        finally:
            out.end()
            err.end()
            sys.stdout, sys.stderr, sys.stdin = saved
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_alarm)
        if self.problems:
            raise HarnessError("; ".join(self.problems))
        return self

    def warn(self):
        """main's incomplete-update warning, as the next vhir command prints it."""
        out, err = _Stream(self, "stdout"), _Stream(self, "stderr")
        saved = sys.stdout, sys.stderr
        self.proc = "warn"
        try:
            sys.stdout, sys.stderr = out, err
            main_mod._warn_if_update_incomplete()
        finally:
            out.end()
            err.end()
            sys.stdout, sys.stderr = saved
        return self.lines("warn", "stderr")


def _alarm(signum, frame):
    raise RowTimeout("row ran past 60 s")


def _scan_hit(line):
    s = line.strip()
    if not SCAN.search(s):
        return False
    return not (s.startswith(EXEMPT_START) or s in EXEMPT_LINES)


@pytest.fixture
def u(box, monkeypatch, tmp_path, stub_check):  # noqa: F811 (the fixture)
    return Run(box, monkeypatch, tmp_path)


def _state_complete(state):
    return (
        isinstance(state, dict)
        and state.get("version") == vhir_cli.__version__
        and state.get("status", "complete") == "complete"
    )


# ---- stop states: the run stops, and its fix is the last block's ---------


def _no_manifest(b):
    (b.home / ".vhir" / "manifest.json").unlink()


def _bad_manifest(b):
    (b.home / ".vhir" / "manifest.json").write_text("{")


def _no_source(b):
    path = b.home / ".vhir" / "manifest.json"
    m = json.loads(path.read_text())
    m["source"] = str(b.home / "gone" / "sift-mcp")
    path.write_text(json.dumps(m))


def _venv_corrupt(b):
    (b.home / "venv" / "bin" / "python").unlink()


STOPS = {
    "no_manifest": (dict(setup=_no_manifest), "No manifest found"),
    "bad_manifest": (dict(setup=_bad_manifest), "Cannot read manifest"),
    "no_source": (dict(setup=_no_source), "Source directory not found"),
    "venv_corrupt": (dict(setup=_venv_corrupt), "Re-run setup-sift.sh to rebuild."),
    "uv_missing": (dict(uv_missing=True), "uv not found. Run setup-sift.sh"),
    "fetch_failed": (dict(fetch_fail={"sift-mcp"}), "git fetch failed for sift-mcp"),
    "wrong_branch": (dict(branch={"sift-mcp": "dev"}), "checkout main"),
    "pull_fail": (dict(pulls={"sift-mcp": "fail"}), "Failed to pull sift-mcp"),
    "pull_timeout": (dict(pulls={"sift-mcp": "timeout"}), "timed out after 60 seconds"),
    "uv_floor": (dict(uv="uv 0.5.0"), "Update it: uv self update"),
    "install_fail": (dict(install_rc=1), "finish with: vhir update"),
    "cpu_hint": (dict(install_rc=1, cpu=True), "re-run with --gpu"),
    "incomplete": (dict(moves={"vhir"}, exec_oserror=True), "UPDATE INCOMPLETE"),
}
STOP_SCAN_GUARD = {
    "no_manifest",
    "bad_manifest",
    "no_source",
    "fetch_failed",
    "pull_timeout",
}


@pytest.mark.parametrize("state,declared", [(s, "RED") for s in STOPS], ids=list(STOPS))
def test_a_stop_puts_its_fix_in_the_last_block(u, state, declared):
    knobs, marker = STOPS[state]
    r = u.go(**knobs)
    assert r.rc == 1
    assert r.blocks(), "no block"
    assert r.in_last(marker), r.last_block()
    assert not r.out_has(marker), r.outside()


@pytest.mark.parametrize(
    "state,declared",
    [(s, "GUARD" if s in STOP_SCAN_GUARD else "RED") for s in STOPS],
    ids=list(STOPS),
)
def test_a_stop_prints_no_step_outside_a_block(u, state, declared):
    knobs, _marker = STOPS[state]
    r = u.go(**knobs)
    assert r.rc == 1
    assert r.scan_hits() == []


# ---- normal ends: every step left is in the last block -------------------


def _desktop(b):
    path = b.home / ".vhir" / "manifest.json"
    m = json.loads(path.read_text())
    m["client"] = "claude-desktop"
    path.write_text(json.dumps(m))


def _unreadable(*a, **kw):
    raise keys.KeysFileInvalid("keys file: not valid JSON")


ENDS = {
    "missing_repo": (dict(opensearch="missing"), ["Update manually:"]),
    "snapshot_setup": (dict(opensearch="snapshot"), ["isn't set up for snapshots"]),
    "opensearch_timeout": (
        dict(
            opensearch="mismatch",
            image="opensearchproject/opensearch:3.4.0",
            answers=[(r"Upgrade OpenSearch now", "y", False)],
            bash_timeout=True,
        ),
        ["Run it again:"],
    ),
    "desktop": (dict(setup=_desktop), ["Claude Desktop is no longer supported"]),
    "no_client": (dict(client=""), ["No client type in manifest"]),
    "controls_kept": (
        dict(kept=True, tty=False),
        ["Forensic controls NOT applied to", "Not changed:"],
    ),
    "codex_kept": (
        dict(client="codex"),
        ["can't be reached, so its backends can't be listed"],
    ),
    "no_restart": (dict(no_restart=True), ["Gateway restart skipped (--no-restart)"]),
    "launcher": (
        dict(launcher=True, no_restart=True),
        ["takes effect at the next gateway restart"],
    ),
    "restart_llm": (dict(), ["Restart your LLM client"]),
    "reconnect": (dict(), ["run /mcp in each"]),
    "share_rejoin": (dict(share=True), ["Join wintools again"]),
    "sift_tools": (dict(hayabusa=True), ["run `vhir setup hayabusa`"]),
    "key_none": (dict(), ["set one with `vhir config --setup-password`"]),
    "key_unreadable": (
        dict(stubs=[(credentials, "state", _unreadable)]),
        ["can't be read"],
    ),
    "key_legacy_no": (
        dict(key="legacy", pw=LONG_PW, answers=[(r"Upgrade it now", "n", False)]),
        ["when you're ready"],
    ),
    "key_upgrade_fail": (
        dict(
            key="legacy",
            pw=LONG_PW,
            answers=[(r"Upgrade it now", "y", False)],
            secrets=["not-the-passphrase"],
        ),
        ["to try again"],
    ),
    "apparmor": (dict(bwrap=True), ["Try manually"]),
    "password_dir": (dict(real_password_dir=True), ["Run manually: sudo mkdir"]),
}


@pytest.mark.parametrize("state,declared", [(s, "RED") for s in ENDS], ids=list(ENDS))
def test_a_finished_update_puts_its_steps_in_the_last_block(u, state, declared):
    knobs, markers = ENDS[state]
    r = u.go(**knobs)
    assert r.blocks(), "no block"
    for marker in markers:
        assert r.in_last(marker), (marker, r.last_block())
        assert not r.out_has(marker), (marker, r.outside())


@pytest.mark.parametrize("state,declared", [(s, "RED") for s in ENDS], ids=list(ENDS))
def test_a_finished_update_prints_no_step_outside_a_block(u, state, declared):
    knobs, _markers = ENDS[state]
    r = u.go(**knobs)
    assert r.scan_hits() == []


# ---- no terminal: a start block and an end block -------------------------


def test_with_no_terminal_a_start_and_an_end_block_print(u):
    r = u.go(tty=False)
    blocks = r.blocks()
    assert len(blocks) == 2, blocks
    for b in blocks:
        assert any(NOTERM1 in line for line in b), b
        assert any(NOTERM2 in line for line in b), b
    first_open = r.index_of(lambda line: line.strip() == OPEN)
    first_step2 = r.index_of(lambda line: ": up to date (" in line)
    assert first_open is not None and first_step2 is not None
    assert first_open < first_step2


def test_check_on_a_terminal_prints_no_block(u):
    r = u.go(check=True)
    assert r.rc == 0
    assert r.opens("1") == 0
    assert r.out_has("Run 'vhir update' to apply.")


def test_check_with_no_terminal_says_the_controls_are_not_applied(u):
    r = u.go(check=True, tty=False)
    assert r.in_blocks(NOTERM1) >= 1, r.blocks()


# ---- K11: a failed or hung pull of a later repo ---------------------------

K11 = {
    "earlier_moved": dict(moves={"sift-mcp"}),
    "this_moved": dict(),
    "none": dict(),
}


@pytest.mark.parametrize("how", ["timeout", "fail"])
@pytest.mark.parametrize("which,declared", [(w, "RED") for w in K11], ids=list(K11))
def test_a_later_repo_that_fails_to_pull_says_whether_code_changed(
    u, which, declared, how
):
    knobs = dict(K11[which])
    pull = how + ("-moved" if which == "this_moved" else "")
    knobs["pulls"] = {"vhir": pull}
    r = u.go(**knobs)
    assert r.rc == 1
    assert not r.traceback()
    if which == "none":
        assert not any("finish with: vhir update" in line for line in r.lines())
        marker = "Pulling vhir timed out" if how == "timeout" else "Failed to pull vhir"
        assert r.in_last(marker), r.last_block()
    else:
        assert r.in_last("finish with: vhir update"), r.last_block()


# ---- K21: the signing-key question comes before the block ----------------


def test_k21_the_block_is_last_after_the_signing_key_question(u):
    r = u.go(
        key="legacy",
        pw=LONG_PW,
        answers=[(r"Upgrade it now", "n", False)],
        hayabusa=True,
    )
    assert r.log and r.log[-1][2].strip() == CLOSE, r.log[-3:]
    last_open = r.last_open()
    asked = r.index_of(lambda line: "Upgrade it now" in line)
    warned = r.index_of(lambda line: "WARNING:" in line and "Hayabusa" in line)
    assert last_open is not None and asked is not None and warned is not None
    assert asked < last_open and warned < last_open
    assert r.in_last("when you're ready"), r.last_block()
    at_prompt = [v for p, v in r.state_at_prompt.items() if "Upgrade it now" in p]
    assert at_prompt and _state_complete(at_prompt[0]), at_prompt


# ---- V6 / X5: a signing-key upgrade that fails ---------------------------

V6 = {
    "wrong": (dict(secrets=["not-the-passphrase"]), "Incorrect passphrase"),
    "short": (
        dict(pw="abc1234", secrets=["abc1234", "abc", "abc", "abc"]),
        "No passphrase was set",
    ),
}


@pytest.mark.parametrize("which,declared", [(w, "RED") for w in V6], ids=list(V6))
def test_v6_a_failed_upgrade_ends_the_update_with_its_reason_in_the_block(
    u, which, declared
):
    knobs, reason = V6[which]
    knobs = {"pw": LONG_PW, **knobs}
    r = u.go(key="legacy", answers=[(r"Upgrade it now", "y", False)], **knobs)
    assert not r.traceback(), r.lines(stream="stderr")
    assert r.in_last(reason), r.last_block()
    assert r.log and r.log[-1][2].strip() == CLOSE, r.log[-3:]
    assert _state_complete(r.state()), r.state()
    assert r.rc == 0


def test_x5_ctrl_c_at_the_passphrase_stops_the_update(u):
    with pytest.raises(KeyboardInterrupt):
        u.go(
            key="legacy",
            pw=LONG_PW,
            answers=[(r"Upgrade it now", "y", False)],
            secrets=[KeyboardInterrupt()],
        )


# ---- V10 / X6 / X21: the reset hint for a short kept passphrase ----------

RESET = "--reset-password"


@pytest.mark.parametrize(
    "pw,new,hint,declared",
    [
        pytest.param(MID_PW, [], True, "RED", id="v10-10-ascii"),
        pytest.param(LONG_PW, [], False, "RED", id="v10-16-ascii"),
        pytest.param("abc1234", [MID_PW, MID_PW], False, "GUARD", id="x6-new-10"),
        pytest.param(CJK[:8], [], True, "RED", id="x21-8-cjk"),
        pytest.param(CJK[:7], [LONG_PW, LONG_PW], False, "GUARD", id="x21-7-cjk-new"),
        pytest.param(CJK[:14], [], True, "RED", id="x21-14-cjk"),
    ],
)
def test_the_reset_hint_is_in_the_block_only_for_a_kept_short_passphrase(
    u, pw, new, hint, declared
):
    r = u.go(
        key="legacy",
        pw=pw,
        answers=[(r"Upgrade it now", "y", False)],
        secrets=[pw, *new],
    )
    if hint:
        assert r.in_last(RESET), r.last_block()
        assert not r.out_has(RESET), r.outside()
        assert r.scan_hits() == []
    elif new:  # a new passphrase was set: its note, and no hint anywhere
        assert (
            any(
                f"Note: Your passphrase is {len(new[0])} characters" in line
                for line in r.lines()
            )
            or len(new[0]) >= 15
        )
        assert not any(RESET in line for line in r.lines())
    else:
        assert not any(RESET in line for line in r.lines())
        assert r.scan_hits() == []


# ---- The hand-over keeps one block and carries the first process's steps


def test_a_missing_repo_notice_is_carried_into_the_one_end_block(u):
    r = u.go(opensearch="missing", moves={"vhir"})
    assert r.exec_argv is not None, "no hand-over"
    assert r.lines("1-after-exec") == []
    assert r.in_blocks("Update manually:", "2") == 1, r.blocks("2")
    assert "Update manually" in " ".join(r.exec_argv), r.exec_argv


def test_with_no_terminal_each_process_prints_one_block(u):
    r = u.go(tty=False, moves={"vhir"})
    assert r.exec_argv is not None, "no hand-over"
    assert r.lines("1-after-exec") == []
    assert len(r.blocks("1")) == 1 and len(r.blocks("2")) == 1, r.blocks()
    assert any(NOTERM1 in line for line in r.blocks("1")[0])


def test_an_exec_that_fails_puts_the_carried_steps_in_its_block(u):
    r = u.go(opensearch="missing", moves={"vhir"}, exec_oserror=True)
    last = r.blocks("1")[-1] if r.blocks("1") else []
    assert any("UPDATE INCOMPLETE" in line for line in last), last
    assert any("Update manually:" in line for line in last), last


def test_opensearch_is_asked_once_across_the_hand_over(u):
    r = u.go(
        opensearch="mismatch",
        image="opensearchproject/opensearch:3.4.0",
        moves={"vhir"},
    )
    assert r.exec_argv is not None, "no hand-over"
    assert r.lines("1-after-exec") == []
    assert sum("OpenSearch" in p for p in r.prompts) == 1, r.prompts


def test_a_terminal_hand_over_prints_no_block_in_the_first_process(u):
    r = u.go(moves={"vhir"})
    assert r.exec_argv is not None, "no hand-over"
    assert r.lines("1-after-exec") == []
    assert r.opens("1") == 0


# ---- The scan finds each form a step takes --------------------------------

STEP_FORMS = [
    "  UPDATE INCOMPLETE: run `vhir update` again",
    "Your update to 0.6.6.1 didn't finish. Run: vhir update",
    "  Then restart the gateway: systemctl --user restart vhir-gateway",
    "  WARNING: opensearch-mcp is installed but its repo was not found. Update manually:",
    "Run setup-sift.sh to install it.",
    "Switch to main: git -C /home/x/.vhir/src/vhir checkout main",
    "    git -C /home/x/.vhir/src/vhir stash push -u",
    "    git -C /home/x/.vhir/src/vhir stash pop",
]


@pytest.mark.parametrize(
    "form", STEP_FORMS, ids=[f"form-{i}" for i in range(len(STEP_FORMS))]
)
def test_the_scan_finds_a_step_printed_outside_a_block(u, form):
    r = u
    out, err = _Stream(r, "stdout"), _Stream(r, "stderr")
    saved = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = out, err
        print(form, file=sys.stderr)
        print(OPEN, file=sys.stderr)
        print("  inside", file=sys.stderr)
        print(CLOSE, file=sys.stderr)
    finally:
        out.end()
        err.end()
        sys.stdout, sys.stderr = saved
    assert r.scan_hits() == [form]
