"""Claude Code refuses to start without a working sandbox
(failIfUnavailable: true). Deploying it otherwise takes the hidden
--allow-unsandboxed flag and a phrase typed on a terminal: -y never gives
it, no terminal deploys nothing, a wrong phrase deploys nothing, and the
controls block then says SANDBOX OFF. The box is a stand-in SIFT (see
test_user_settings_guard); nothing is installed."""

from __future__ import annotations

import argparse
import json
import types

import pytest

from vhir_cli.commands import client_setup as cs

from .test_user_settings_guard import TEMPLATE, box  # noqa: F401 (a fixture)


def _template(box):  # noqa: F811
    t = json.loads(json.dumps(TEMPLATE))
    t["sandbox"]["failIfUnavailable"] = True
    p = box.repo / "claude-code" / "full" / "settings.json"
    p.write_text(json.dumps(t, indent=2))


def _run(box, monkeypatch, tty, answers, **kw):  # noqa: F811
    _template(box)
    monkeypatch.setattr(cs, "_claude_mcp_add_available", lambda: False)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: tty))
    asked = []

    def answer(prompt=""):
        """The phrase prompt takes `answers[0]`; a yes/no question "y";
        anything else its default."""
        asked.append(prompt)
        if cs.UNSANDBOXED_PHRASE in prompt:
            return answers[0]
        return "y" if "[y/N]" in prompt or "[Y/n]" in prompt else ""

    monkeypatch.setattr("builtins.input", answer)
    args = argparse.Namespace(
        client="claude-code", sift="http://127.0.0.1:9", windows=None, windows_token=None,
        remnux=None, remnux_token=None, examiner="steve", no_mslearn=True, uninstall=False,
        **{"yes": False, "allow_unsandboxed": True, **kw},
    )  # fmt: skip
    cs.cmd_setup_client(args, {"examiner": "steve"})
    return asked


def _fail_if_unavailable(box):  # noqa: F811
    return json.loads(box.settings.read_text())["sandbox"].get("failIfUnavailable")


def test_the_sandbox_is_required_by_default(box, monkeypatch, capsys):  # noqa: F811
    _run(box, monkeypatch, False, [], yes=True, allow_unsandboxed=False)
    assert _fail_if_unavailable(box) is True
    assert "Sandbox:     enabled" in capsys.readouterr().out


def test_y_never_gives_the_phrase(box, monkeypatch, capsys):  # noqa: F811
    asked = _run(box, monkeypatch, False, [], yes=True)
    assert _fail_if_unavailable(box) is True and not asked
    assert "--allow-unsandboxed needs the typed phrase, which -y doesn't give" in (
        capsys.readouterr().out
    )


def test_no_terminal_deploys_nothing(box, monkeypatch, capsys):  # noqa: F811
    with pytest.raises(SystemExit) as e:
        _run(box, monkeypatch, False, [])
    assert e.value.code == 1 and not box.settings.exists()
    assert (
        "needs the phrase typed on a terminal. Nothing was deployed"
        in capsys.readouterr().err
    )


def test_a_wrong_phrase_deploys_nothing(box, monkeypatch, capsys):  # noqa: F811
    with pytest.raises(SystemExit) as e:
        _run(box, monkeypatch, True, ["run without a sandbox"])
    assert e.value.code == 1 and not box.settings.exists()


def test_the_phrase_deploys_it_and_the_block_says_sandbox_off(box, monkeypatch, capsys):  # noqa: F811
    asked = _run(box, monkeypatch, True, [cs.UNSANDBOXED_PHRASE])
    assert cs.UNSANDBOXED_PHRASE in asked[0]
    assert _fail_if_unavailable(box) is False
    assert "SANDBOX OFF" in capsys.readouterr().out
    assert cs._ALLOW_UNSANDBOXED is False  # never carried into a later run
