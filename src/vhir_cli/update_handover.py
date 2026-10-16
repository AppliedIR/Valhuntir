"""Hand an older vhir's update over to this code.

An update before 0.6.4.1 pulls this code and then keeps running its own
steps in the same process, importing this code's modules lazily. The first
of those that it calls (client_setup.ensure_signing_dirs on 0.6.4,
_deploy_claude_code_assets or _isolate_gateway_launchers on 0.6.3, and on
0.6.0-0.6.2 _deploy_claude_code_assets or gateway.get_local_gateway_url)
calls hand_over_older_update() first. It replaces the process with this
code's `vhir update --after-pull`, which runs Step 4 again from the lock and
then every later step, so one `vhir update` ends on this release.

Standard library only: it runs inside the older process.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_tried = False


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)

    def exit(self, status=0, message=None):
        raise ValueError(message or "")


def _update_args(argv: list[str]) -> argparse.Namespace | None:
    """The update options as the older vhir parsed them, or None when argv
    is not `vhir update` (abbreviations accepted, as argparse accepts them)."""
    parser = _Parser(prog="vhir", add_help=False)
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--case")
    sub = parser.add_subparsers(dest="command")
    update = sub.add_parser("update", add_help=False)
    update.add_argument("--check", action="store_true")
    update.add_argument("--no-restart", action="store_true")
    update.add_argument("--cpu", action="store_true")
    update.add_argument("--gpu", action="store_true")
    try:
        args = parser.parse_args(argv)
    except ValueError:
        return None
    return args if args.command == "update" else None


def hand_over_older_update() -> None:
    """Replace an older vhir's running update with this code's. Returns when
    there is none to replace, or when the new process cannot be started (the
    older update then carries on, and every later command shows the banner).
    Never raises: the older update calls this unguarded."""
    try:
        _hand_over()
    except Exception as e:
        print(f"  Cannot start the new code: {e}", file=sys.stderr)


def _hand_over() -> None:
    global _tried
    if _tried:
        return
    module = sys.modules.get("vhir_cli.commands.update")
    if module is None or hasattr(module, "_reexec_after_pull"):
        return  # not an update, or this release's update is the one running
    args = _update_args(sys.argv[1:])
    if args is None or args.check:
        return
    _tried = True
    try:
        manifest = json.loads((Path.home() / ".vhir" / "manifest.json").read_text())
        venv = manifest["venv"]
    except (OSError, ValueError, KeyError, TypeError):
        return
    if not isinstance(venv, str) or not venv:
        return
    venv = Path(venv)
    python, script = venv / "bin" / "python", venv / "bin" / "vhir"
    if not script.is_file():
        return
    argv = [str(python), str(script), "update", "--after-pull"]
    argv.append(json.dumps({"older_update": True}))
    for flag in ("no_restart", "cpu", "gpu"):
        if getattr(args, flag):
            argv.append("--" + flag.replace("_", "-"))
    print("  Continuing the update with the new code...", flush=True)
    sys.stderr.flush()
    try:
        os.execv(str(python), argv)
    except OSError as e:
        print(f"  Cannot start the new code: {e}", file=sys.stderr)
