"""U12: the AI nudge line reaches both of the update's outputs, from one checkout.

The line (UPDATE_NUDGE) is in sift-mcp's AGENTS.md. `vhir update` deploys that
file as ~/.claude/rules/AGENTS.md and builds Codex's developer_instructions
from it, so both carry the line with no second edit. Both outputs come from
the checkout the update pulled (manifest["source"]) and from no other: not a
different checkout at ~/.vhir/src/sift-mcp or at gateway.yaml's sift_mcp_dir,
and never the cwd's AGENTS.md. The user's ~/.codex/config.toml is never
written. An edited deployed copy is kept, and the end block names it.

The bed rows run update._redeploy_clients (Step 5) with every file under
tmp_path: a scratch HOME holding fake sift-mcp checkouts, a gateway.yaml and a
manifest written here. The gateway's backends are stubbed; nothing reaches a
gateway or the box's own ~/.vhir. The E1b row runs the whole update through
U11's harness.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import types
from pathlib import Path

import pytest

import vhir_cli
from tests.stub_check import stub, stub_check  # noqa: F401 (the fixture)
from tests.test_update_human_steps_u11 import box, u  # noqa: F401 (the fixtures)
from vhir_cli.commands import client_setup
from vhir_cli.commands import codex_controls as cc
from vhir_cli.commands import update as upd

tomllib = pytest.importorskip("tomllib")

UPDATE_NUDGE = (
    "Don't run vhir update yourself. Ask the examiner to run it in their own"
    " terminal, where it can apply the forensic controls."
)
# Version 1 of AGENTS.md, the same in every checkout: the deployed copy the
# examiner never edited, which each checkout's history holds.
OLD = "# Valhuntir core\n\nEvidence guides theory.\n"
EDITED = "# Valhuntir core\n\nEvidence guides theory.\n\nMy own rule.\n"
USER_CODEX = "# the user's own Codex settings\n"
TOKEN = "vhir_gw_" + "ab" * 12
BACKENDS = ["forensic-mcp", "case-mcp", "sift-mcp"]
_REAL_FIND_SPEC = importlib.util.find_spec


def _git(repo, *args):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(repo), "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
    )


def _checkout(path, marker):
    """A sift-mcp checkout whose AGENTS.md is OLD at v1, then at v2 OLD plus a
    line naming this checkout (marker) and the nudge. Its discipline and
    overlay files carry the marker too, so any file of it is traceable."""
    full = path / "claude-code" / "full"
    full.mkdir(parents=True)
    (path / "claude-code" / "shared").mkdir()
    (full / "FORENSIC_DISCIPLINE.md").write_text(f"# Discipline\n\nFrom {marker}.\n")
    (path / "codex").mkdir()
    (path / "codex" / "OVERLAY.md").write_text(f"## Codex\n\nOverlay of {marker}.\n")
    (path / "AGENTS.md").write_text(OLD)
    _git(path, "init", "-q")
    _git(path, "add", "-A")
    _git(path, "commit", "-q", "-m", "v1")
    (path / "AGENTS.md").write_text(f"{OLD}\nCheckout: {marker}\n\n{UPDATE_NUDGE}\n")
    _git(path, "add", "-A")
    _git(path, "commit", "-q", "-m", "v2")
    return path


@pytest.fixture
def bed(tmp_path, monkeypatch, stub_check):  # noqa: F811 (the fixture)
    """A SIFT box set up for Claude Code and Codex: HOME and the cwd (no
    AGENTS.md) under tmp_path, no terminal, a gateway that lists BACKENDS."""
    home, cwd = tmp_path / "home", tmp_path / "cwd"
    (home / ".vhir").mkdir(parents=True)
    (home / ".claude" / "rules").mkdir(parents=True)
    cwd.mkdir()
    rule = home / ".claude" / "rules" / "AGENTS.md"
    rule.write_text(OLD)  # the unedited deployed copy
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.chdir(cwd)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    monkeypatch.setattr(
        cc, "REQUIREMENTS", tmp_path / "etc-codex" / "requirements.toml"
    )
    monkeypatch.setattr(  # this suite's venv may hold opensearch-mcp
        importlib.util,
        "find_spec",
        lambda name, *a, **kw: (
            None if name == "opensearch_mcp" else _REAL_FIND_SPEC(name, *a, **kw)
        ),
    )
    stub(monkeypatch, client_setup, "_read_local_token", lambda: TOKEN)
    stub(
        monkeypatch,
        client_setup,
        "_discover_services",
        lambda url, token: [{"name": n, "started": True} for n in BACKENDS],
    )
    stub(monkeypatch, cc, "codex_controls_state", lambda *a, **kw: "off")
    stub(monkeypatch, cc, "state_lines", lambda *a, **kw: [])

    def run(source, sift_mcp_dir):
        """Step 5 of an update that pulled `source`."""
        (home / ".vhir" / "gateway.yaml").write_text(f"sift_mcp_dir: {sift_mcp_dir}\n")
        manifest = {
            "version": vhir_cli.__version__,
            "source": str(source),
            "clients": ["claude-code", "codex"],
        }
        (home / ".vhir" / "manifest.json").write_text(json.dumps(manifest))
        upd._redeploy_clients(manifest)

    return types.SimpleNamespace(
        home=home,
        tmp=tmp_path,
        cwd=cwd,
        rule=rule,
        profile=home / ".codex" / "valhuntir.config.toml",
        config=home / ".codex" / "config.toml",
        src=home / ".vhir" / "src" / "sift-mcp",
        run=run,
    )


def _default(bed):
    """The installer's layout: the pulled checkout is ~/.vhir/src/sift-mcp,
    and gateway.yaml's sift_mcp_dir names it."""
    p = _checkout(bed.src, "the pulled checkout")
    bed.run(p, p)
    return p


def _instructions(bed):
    return tomllib.loads(bed.profile.read_text())["developer_instructions"]


def _from_only(text, source, others):
    """Every line of source's AGENTS.md is in text, and no marker of another
    checkout is."""
    lines = [ln for ln in (source / "AGENTS.md").read_text().splitlines() if ln]
    missing = [ln for ln in lines if ln not in text.splitlines()]
    foreign = [m for m in others if m in text]
    return missing, foreign


# ---- the default layout: both outputs carry the line ---------------------


def test_v1a_the_deployed_rule_has_the_nudge_from_sift_mcps_agents_md(bed):
    p = _default(bed)
    assert bed.rule.read_bytes() == (p / "AGENTS.md").read_bytes(), (
        f"{bed.rule} is not {p / 'AGENTS.md'}",
        bed.rule.read_text(),
    )
    assert UPDATE_NUDGE in bed.rule.read_text().splitlines()


def test_v1b_codex_developer_instructions_have_the_nudge(bed):
    # path pending arch (spec :1021/:727 vs client_setup.py:2113)
    p = _default(bed)
    text = _instructions(bed)
    assert UPDATE_NUDGE in text.splitlines(), text
    assert _from_only(text, p, []) == ([], [])


def test_v2_the_users_codex_config_is_never_written(bed):
    # path pending arch (spec :1021/:727 vs client_setup.py:2113)
    bed.config.parent.mkdir(parents=True)
    bed.config.write_text(USER_CODEX)
    _default(bed)
    assert bed.config.read_bytes() == USER_CODEX.encode()
    assert UPDATE_NUDGE in _instructions(bed).splitlines()


def test_v3_the_cwds_agents_md_reaches_neither_output(bed):
    (bed.cwd / "AGENTS.md").write_text("# Some repo's own agent file\n\nCWD ONLY.\n")
    p = _default(bed)
    assert bed.rule.read_bytes() == (p / "AGENTS.md").read_bytes()
    assert "CWD ONLY." not in bed.rule.read_text()
    assert "CWD ONLY." not in _instructions(bed)


# ---- K17: one checkout, manifest["source"], on every layout --------------

K17 = [
    ("decoy_at_vhir_src", "rule", "RED"),
    ("decoy_at_vhir_src", "codex", "GUARD"),
    ("decoy_at_sift_mcp_dir", "rule", "GUARD"),
    ("decoy_at_sift_mcp_dir", "codex", "RED"),
]


@pytest.mark.parametrize(
    "leg,output,declared", K17, ids=[f"{a}-{b}" for a, b, _ in K17]
)
def test_k17_both_outputs_come_from_the_pulled_checkout_only(
    bed, leg, output, declared
):
    if leg == "decoy_at_vhir_src":  # sift_mcp_dir isn't ~/.vhir/src/sift-mcp
        p = _checkout(bed.tmp / "pulled" / "sift-mcp", "the pulled checkout")
        _checkout(bed.src, "a decoy checkout")
        bed.run(p, p)
    else:
        p = _checkout(bed.src, "the pulled checkout")
        decoy = _checkout(bed.tmp / "other" / "sift-mcp", "a decoy checkout")
        bed.run(p, decoy)
    if output == "rule":
        text = bed.rule.read_text()
        assert bed.rule.read_bytes() == (p / "AGENTS.md").read_bytes(), (
            f"{bed.rule} is not {p / 'AGENTS.md'}",
            text,
        )
    else:
        text = _instructions(bed)
    assert _from_only(text, p, ["a decoy checkout"]) == ([], []), text


# ---- an edited copy is kept, and the block names it ----------------------


def test_e1a_an_edited_rule_is_kept_with_no_terminal(bed, capsys):
    bed.rule.write_text(EDITED)
    _default(bed)
    out = capsys.readouterr().out
    assert bed.rule.read_text() == EDITED
    assert f"Not changed: {bed.rule}." in out, out


def test_e1b_the_block_names_the_kept_rule(u):  # noqa: F811 (the fixture)
    rule = u.box.home / ".claude" / "rules" / "AGENTS.md"
    settings = u.box.home / ".claude" / "settings.json"
    new = f"{OLD}\n{UPDATE_NUDGE}\n"
    why = "it differs from every version vhir shipped, so it may hold your edits"

    def deploy(*a, **kw):  # Step 5's rule deploy, as _deploy_copy does it
        rule.parent.mkdir(parents=True, exist_ok=True)
        rule.write_text(EDITED)
        client_setup._write_user_file(rule, new, why)
        return settings, "unchanged"

    r = u.go(tty=False, stubs=[(client_setup, "_deploy_claude_code_assets", deploy)])
    assert rule.read_text() == EDITED
    assert r.blocks(), "no block"
    assert r.in_last(f"Not changed: {rule}"), r.last_block()
    assert not r.out_has(f"Not changed: {rule}"), r.outside()
