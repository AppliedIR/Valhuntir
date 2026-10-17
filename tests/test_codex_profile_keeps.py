"""Valhuntir's Codex profile keeps a backend that isn't started and the tables
Codex adds.

Codex writes its own tables into the profile it reads: its first interactive
launch appends `[tui]` / `screen_reader_detection_done = true`. vhir carries
every table that isn't an `mcp_servers` one, found only after the
developer_instructions value closes, and leaves it out of the checks that
decide whether the profile is still the one vhir wrote. Every backend the
gateway lists gets its section, started or not, with the current URL and
token, and the ones not started are named. Claude Code's config is built as
before. Everything here is under tmp_path; no gateway is reached.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import types
from pathlib import Path

import pytest

from vhir_cli.commands import client_setup as cs

TOKEN = "vhir_gw_" + "ab" * 12
NEW_TOKEN = "vhir_gw_" + "cd" * 12
AGENTS = "# Valhuntir core\n\nEvidence guides theory.\n"
# the discipline's shape: [-leading lines of text inside the instructions
FD = (
    "# Forensic Discipline\n\n"
    "[Actual log entry / record / content - NOT a summary]\n"
    "[tui]\n"
    "[mcp_servers.fake]\n"
    'url = "http://192.0.2.1/mcp"\n'
    "Show the evidence.\n"
)
OVERLAY = "## Codex\n\nStart with codex -p valhuntir.\n"
SKILL = "---\nname: vhir-welcome\ndescription: w\n---\n\nwelcome\n"
CODEX_AGENT = 'name = "finding-skeptic"\n'
REQUIREMENTS = "# managed-by: valhuntir\n"
# what Codex 0.163's first interactive launch appended (measured, 43 bytes)
CODEX_TUI = "\n[tui]\nscreen_reader_detection_done = true\n"
WIN = "wintools-mcp"


def _git(repo, *args):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(repo), "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
    )


def _no_prompt(prompt=""):
    raise AssertionError(f"prompted: {prompt}")


@pytest.fixture
def box(tmp_path, monkeypatch):
    """A SIFT box whose gateway lists forensic-mcp, sift-mcp and wintools-mcp
    (each started unless the test says not), on a terminal that fails the
    test if anything asks."""
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    repo = tmp_path / "sift-mcp"
    full = repo / "claude-code" / "full"
    full.mkdir(parents=True)
    (repo / "claude-code" / "shared").mkdir()
    (full / "FORENSIC_DISCIPLINE.md").write_text(FD)
    (repo / "AGENTS.md").write_text(AGENTS)
    (repo / "codex").mkdir()
    (repo / "codex" / "OVERLAY.md").write_text(OVERLAY)
    (repo / "skills" / "vhir-welcome").mkdir(parents=True)
    (repo / "skills" / "vhir-welcome" / "SKILL.md").write_text(SKILL)
    (repo / "agents" / "finding-skeptic").mkdir(parents=True)
    (repo / "agents" / "finding-skeptic" / "codex.toml").write_text(CODEX_AGENT)
    (repo / "codex" / "requirements.toml").write_text(REQUIREMENTS)
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "v1")
    (home / ".vhir" / "gateway.yaml").write_text(f"sift_mcp_dir: {repo}\n")
    manifest = home / ".vhir" / "manifest.json"
    manifest.write_text(json.dumps({"version": "0.6.5"}))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(cs.Path, "home", staticmethod(lambda: home))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("builtins.input", _no_prompt)
    token = {"value": TOKEN}
    monkeypatch.setattr(cs, "_read_local_token", lambda: token["value"])
    started = {"forensic-mcp": True, "sift-mcp": True, WIN: True}
    asked = []

    def discover(url, tok):
        asked.append((url, tok))
        return [{"name": n, "started": s} for n, s in started.items()]

    monkeypatch.setattr(cs, "_discover_services", discover)
    # Codex's managed layer isn't what these rows test
    from vhir_cli.commands import codex_controls as cc

    monkeypatch.setattr(cc, "deploy_codex_controls", lambda consent=None: None)
    monkeypatch.setattr("importlib.util.find_spec", lambda name: None)
    return types.SimpleNamespace(
        home=home,
        repo=repo,
        fd=full / "FORENSIC_DISCIPLINE.md",
        manifest=manifest,
        started=started,
        token=token,
        asked=asked,
        profile=home / ".codex" / "valhuntir.config.toml",
    )


def _args(**kw):
    base = {
        "client": "codex",
        "sift": "http://127.0.0.1:4508",
        "windows": None,
        "windows_token": None,
        "remnux": None,
        "remnux_token": None,
        "examiner": "analyst",
        "no_mslearn": True,
        "no_zeltser": True,
        "yes": True,  # no wizard
        "uninstall": False,
        "ask_user_files": True,  # a user file is asked about, not changed by -y
    }
    base.update(kw)
    return argparse.Namespace(**base)


def _setup(**kw):
    cs.cmd_setup_client(_args(**kw), {"examiner": "analyst"})


def _toml(text: str):
    """The parsed profile where tomllib exists (3.11+), else None."""
    try:
        import tomllib
    except ImportError:
        return None
    return tomllib.loads(text)


def _servers(text: str) -> dict[str, str]:
    """Each [mcp_servers.<name>] section's text, after the instructions."""
    return {n: t for n, t in cs._profile_sections(text).items()}


INTERNET = {"zeltser-ir-writing"}  # added on every setup, not from the gateway


def _gateway(names) -> set[str]:
    return set(names) - INTERNET


def _instructions_intact(text: str) -> None:
    for line in FD.splitlines():
        assert text.count(line) >= 1
    parsed = _toml(text)
    if parsed is not None:
        assert FD.strip() in parsed["developer_instructions"]
        assert "fake" not in parsed["mcp_servers"]


def _backups(box):
    return list(box.profile.parent.glob("valhuntir.config.toml.vhir-backup-*"))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _recorded(box) -> str:
    return json.loads(box.manifest.read_text())["codex_profile_sha256"]


# --- a backend that isn't started ----------------------------------------------


def test_an_update_with_wintools_down_keeps_its_section_built_now_and_names_it(
    box, capsys
):
    _setup()
    box.started[WIN] = False
    box.token["value"] = NEW_TOKEN  # the token changed since the last write
    capsys.readouterr()
    assert cs.deploy_codex_assets() == "updated"
    out = capsys.readouterr().out
    text = box.profile.read_text()
    win = _servers(text)[WIN]
    assert 'url = "http://127.0.0.1:4508/mcp/wintools-mcp"' in win
    assert NEW_TOKEN in win and TOKEN not in text
    assert "Not started now: wintools-mcp. Kept in Codex's profile" in out
    parsed = _toml(text)
    if parsed is not None:
        assert parsed["mcp_servers"][WIN]["http_headers"] == {
            "Authorization": f"Bearer {NEW_TOKEN}"
        }


def test_local_setup_with_wintools_down_writes_its_section_and_names_it(box, capsys):
    box.started[WIN] = False
    _setup()
    out = capsys.readouterr()
    assert _gateway(_servers(box.profile.read_text())) == {
        "forensic-mcp",
        "sift-mcp",
        WIN,
    }
    assert "Not started now: wintools-mcp." in out.out
    assert "excluded from config" not in out.err


def test_with_every_backend_started_nothing_is_named(box, capsys):
    _setup()
    assert cs.deploy_codex_assets() == "unchanged"
    assert "Not started now" not in capsys.readouterr().out


def test_lazy_start_gives_every_section_on_setup_and_update(box, capsys):
    """A lazy_start gateway lists every backend and has started none."""
    for name in box.started:
        box.started[name] = False
    _setup()
    sections = _gateway(_servers(box.profile.read_text()))
    assert sections == {"forensic-mcp", "sift-mcp", WIN}  # not the aggregate vhir
    assert cs.deploy_codex_assets() == "unchanged"  # not "kept"
    out = capsys.readouterr().out
    assert "Not started now: forensic-mcp, sift-mcp, wintools-mcp." in out
    assert "can't be reached" not in out


def test_a_gateway_listing_none_keeps_the_profile_as_before(box, capsys):
    _setup()
    before = box.profile.read_bytes()
    box.started.clear()
    capsys.readouterr()
    assert cs.deploy_codex_assets() == "kept"
    assert box.profile.read_bytes() == before
    assert "Not started now" not in capsys.readouterr().out


def test_a_listed_entry_without_a_name_is_left_out(monkeypatch, capsys):
    listed = cs._codex_listed(
        [
            {"name": "a", "started": True},
            {"name": "b"},
            {"started": True},
            {"name": 7},
            "c",
        ]
    )
    assert listed == ["a", "b"]
    assert "Not started now: b." in capsys.readouterr().out


# --- the tables Codex adds -------------------------------------------------------


def test_codex_tui_on_an_unchanged_profile_gives_no_prompt_and_stays(box, capsys):
    _setup()
    written = box.profile.read_bytes()
    box.profile.write_bytes(written + CODEX_TUI.encode())
    assert cs.deploy_codex_assets() == "unchanged"
    assert box.profile.read_bytes() == written + CODEX_TUI.encode()
    assert _recorded(box) == _sha(written)
    assert "vhir would change" not in capsys.readouterr().out


def test_changed_instructions_and_codex_tui_update_with_no_prompt(box, capsys):
    _setup()
    box.profile.write_bytes(box.profile.read_bytes() + CODEX_TUI.encode())
    box.fd.write_text(FD + "Name the gap.\n")
    capsys.readouterr()
    assert cs.deploy_codex_assets() == "updated"
    out = capsys.readouterr().out
    text = box.profile.read_text()
    assert "Name the gap." in text
    assert text.endswith(CODEX_TUI)
    assert text.count("[tui]\nscreen_reader_detection_done = true\n") == 1
    assert "vhir would change" not in out and not _backups(box)
    assert _recorded(box) == _sha(text[: -len(CODEX_TUI)].encode())
    _instructions_intact(text)
    parsed = _toml(text)
    if parsed is not None:
        assert parsed["tui"] == {"screen_reader_detection_done": True}


def test_a_profile_recorded_before_the_carry_plus_codex_tui_updates(box, capsys):
    """The manifest holds the sha of the whole file as an earlier vhir wrote
    it (no tables then); Codex then appended [tui]; this release's
    instructions differ."""
    _setup()
    earlier = box.profile.read_bytes()
    assert _recorded(box) == _sha(earlier)
    box.profile.write_bytes(earlier + CODEX_TUI.encode())
    box.fd.write_text(FD + "Name the gap.\n")
    assert cs.deploy_codex_assets() == "updated"
    text = box.profile.read_text()
    assert text.endswith(CODEX_TUI) and "Name the gap." in text
    assert "vhir would change" not in capsys.readouterr().out
    assert cs.deploy_codex_assets() == "unchanged"  # and stays settled


def test_unknown_tables_are_carried_in_order(box):
    _setup()
    added = (
        "\n[notice]\nhide_full_access_warning = true\n"
        '\n[projects."/home/x/case a"] # Codex trusts this folder\n'
        'trust_level = "trusted"\n'
        "\n[[profiles_seen]]\nname = 'one'\n"
        "\n[ tui . notifications ]\nenabled = false\n"
    )
    box.profile.write_bytes(box.profile.read_bytes() + added.encode())
    box.fd.write_text(FD + "Name the gap.\n")
    assert cs.deploy_codex_assets() == "updated"
    text = box.profile.read_text()
    assert text.endswith(added)
    parsed = _toml(text)
    if parsed is not None:
        assert parsed["notice"] == {"hide_full_access_warning": True}
        assert parsed["projects"]["/home/x/case a"]["trust_level"] == "trusted"
        assert parsed["tui"]["notifications"] == {"enabled": False}


def test_a_table_between_server_sections_is_carried_and_the_servers_rebuilt(box):
    _setup()
    text = box.profile.read_text()
    first = text.index("[mcp_servers.sift-mcp]")
    moved = text[:first] + "[tui]\nx = 1\n\n" + text[first:]
    box.profile.write_text(moved)
    assert cs.deploy_codex_assets() == "unchanged"  # vhir's part is the same
    assert box.profile.read_text() == moved  # nothing written
    box.fd.write_text(FD + "Name the gap.\n")
    assert cs.deploy_codex_assets() == "updated"
    after = box.profile.read_text()
    assert after.endswith("\n[tui]\nx = 1\n")
    assert _gateway(_servers(after)) == {"forensic-mcp", "sift-mcp", WIN}


def test_a_server_section_the_user_added_still_makes_the_profile_theirs(
    box, capsys, monkeypatch
):
    _setup()
    edited = box.profile.read_text() + CODEX_TUI + '\n[mcp_servers.mine]\nurl = "x"\n'
    box.profile.write_text(edited)
    box.fd.write_text(FD + "Name the gap.\n")
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    assert cs.deploy_codex_assets() == "kept"
    assert box.profile.read_text() == edited
    assert "vhir would change" in capsys.readouterr().out


# a profile that already has Codex's [tui]: the table Codex wrote, and that
# table with the user's own keys and a sub-table
USER_TUI = (
    "\n[tui]\nscreen_reader_detection_done = true\nanimations = false\n"
    "\n[tui.notifications]\nenabled = false\n"
)
TUI_TABLES = {
    "codex": (
        CODEX_TUI,
        ["[tui]"],
        {"screen_reader_detection_done": True},
    ),
    "with-user-keys": (
        USER_TUI,
        ["[tui]", "[tui.notifications]"],
        {
            "screen_reader_detection_done": True,
            "animations": False,
            "notifications": {"enabled": False},
        },
    ),
}


def _one_tui(text: str, shape: str) -> None:
    added, headers, tui = TUI_TABLES[shape]
    # the instructions hold a "[tui]" line of text too; tables come after them
    tail = cs._after_instructions(text)[1]
    assert [ln for ln in tail.splitlines() if ln.startswith("[tui")] == headers
    assert text.endswith(added)
    parsed = _toml(text)  # TOML refuses a table defined twice
    if parsed is not None:
        assert parsed["tui"] == tui


def _by_update(box):
    from vhir_cli.commands import update

    update._redeploy_clients({"clients": ["codex"]})


def _by_deploy(box):
    assert cs.deploy_codex_assets() in ("updated", "unchanged")


def _by_setup(box):
    _setup()


def _by_remnux(box):
    from vhir_cli.commands import codex_controls as cc

    entry = {"type": "http", "url": "http://192.0.2.9:3000/mcp"}
    assert cc.add_to_codex_profile("remnux-mcp", entry) in ("updated", "unchanged")


@pytest.mark.parametrize("shape", sorted(TUI_TABLES))
@pytest.mark.parametrize("write", [_by_update, _by_deploy, _by_setup, _by_remnux])
def test_a_profile_with_a_tui_table_keeps_exactly_one_through_each_writer(
    box, capsys, write, shape
):
    _setup()
    box.profile.write_bytes(box.profile.read_bytes() + TUI_TABLES[shape][0].encode())
    box.fd.write_text(FD + "Name the gap.\n")
    capsys.readouterr()
    write(box)
    _one_tui(box.profile.read_text(), shape)
    assert "Name the gap." in box.profile.read_text()
    write(box)  # a second run
    _one_tui(box.profile.read_text(), shape)
    out = capsys.readouterr().out
    assert "vhir would change" not in out and not _backups(box)


@pytest.mark.parametrize("shape", sorted(TUI_TABLES))
def test_remote_setup_with_a_tui_table_keeps_exactly_one(laptop, capsys, shape):
    _remote()
    added = TUI_TABLES[shape][0]
    laptop.profile.write_bytes(laptop.profile.read_bytes() + added.encode())
    laptop.served["codex/REMOTE.md"] = REMOTE + "Name the gap.\n"
    _remote()
    _one_tui(laptop.profile.read_text(), shape)
    _remote()
    _one_tui(laptop.profile.read_text(), shape)
    assert "vhir would change" not in capsys.readouterr().out


# --- lines of the instructions are never tables ----------------------------------


def test_lines_of_the_instructions_are_neither_carried_nor_sections(box):
    _setup()
    text = box.profile.read_text()
    owned, tables = cs._client_tables(text)
    assert tables == [] and owned == text
    assert "fake" not in _servers(text)
    _instructions_intact(text)


def test_an_update_keeps_one_copy_of_bracket_lines_and_no_section_for_them(box):
    _setup()
    box.fd.write_text(FD + "Name the gap.\n")
    assert cs.deploy_codex_assets() == "updated"
    after = box.profile.read_text()
    assert after.count("[mcp_servers.fake]") == 1
    assert after.count("[Actual log entry") == 1
    assert "fake" not in _servers(after)
    _instructions_intact(after)


def test_one_line_instructions_split_after_that_line():
    text = (
        'sandbox_mode = "x"\n'
        'developer_instructions = "a\\n[tui]\\nb"\n'
        "\n[mcp_servers.a]\nurl = 1\n"
        "\n[tui]\nk = 1\n"
    )
    owned, tables = cs._client_tables(text)
    assert tables == ["[tui]\nk = 1\n"]
    assert owned == text[: text.index("\n[tui]\nk")]


def test_instructions_closed_on_the_opening_line_split_after_it():
    text = "developer_instructions = '''one line'''\n[tui]\nk = 1\n"
    assert cs._after_instructions(text) == (
        "developer_instructions = '''one line'''\n",
        "[tui]\nk = 1\n",
    )


# --- seed shapes -------------------------------------------------------------------


def test_an_unclosed_literal_carries_nothing_and_finds_no_sections():
    text = "developer_instructions = '''\nnever closed\n[tui]\n[mcp_servers.a]\nu=1\n"
    assert cs._after_instructions(text) == (text, "")
    assert cs._client_tables(text) == (text, [])
    assert cs._profile_sections(text) == {}


def test_an_unclosed_literal_profile_is_the_users_and_is_asked_about(
    box, capsys, monkeypatch
):
    _setup()
    broken = box.profile.read_text().replace("'''\n\n[mcp_servers", "\n\n[mcp_servers")
    assert broken.count("'''") == 1
    box.profile.write_text(broken + CODEX_TUI)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    assert cs.deploy_codex_assets() == "kept"
    assert box.profile.read_text() == broken + CODEX_TUI
    assert "vhir would change" in capsys.readouterr().out


def test_without_developer_instructions_every_table_after_the_head_is_seen():
    text = 'sandbox_mode = "x"\n\n[mcp_servers.a]\nurl = 1\n\n[tui]\nk = 1\n'
    assert cs._after_instructions(text) == ("", text)
    owned, tables = cs._client_tables(text)
    assert tables == ["[tui]\nk = 1\n"]
    assert owned == 'sandbox_mode = "x"\n\n[mcp_servers.a]\nurl = 1\n'


def test_a_profile_without_instructions_keeps_its_tables_in_the_proposed_text(
    box, capsys, monkeypatch
):
    box.profile.parent.mkdir(parents=True)
    box.profile.write_text('sandbox_mode = "x"\n' + CODEX_TUI)
    answers = []
    monkeypatch.setattr("builtins.input", lambda p="": answers.append(p) or "y")
    assert cs.deploy_codex_assets() == "written"
    assert len(answers) == 1  # the user's file: asked
    text = box.profile.read_text()
    assert text.endswith(CODEX_TUI) and "developer_instructions" in text
    assert len(_backups(box)) == 1


def test_a_non_utf8_profile_is_compared_whole_and_kept(box, capsys, monkeypatch):
    _setup()
    data = box.profile.read_bytes() + b"\n[tui]\nname = '\xff'\n"
    box.profile.write_bytes(data)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    assert cs.deploy_codex_assets() == "kept"
    assert box.profile.read_bytes() == data
    assert "can't be compared as text" in capsys.readouterr().out


def test_a_crlf_profile_is_compared_whole_and_asked_about(box, capsys, monkeypatch):
    _setup()
    crlf = (box.profile.read_text() + CODEX_TUI).replace("\n", "\r\n").encode()
    box.profile.write_bytes(crlf)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    assert cs.deploy_codex_assets() == "kept"
    assert box.profile.read_bytes() == crlf
    assert "vhir would change" in capsys.readouterr().out


@pytest.mark.parametrize("quote", ['"""', "'''"])
def test_a_table_holding_a_multi_line_string_is_asked_about(
    box, capsys, monkeypatch, quote
):
    """A [-line inside the string is text, not a header; the value is left as is."""
    _setup()
    edited = (
        box.profile.read_text() + f"\n[notice]\nmsg = {quote}\n[x]\nmore\n{quote}\n"
    )
    box.profile.write_text(edited)
    box.fd.write_text(FD + "Name the gap.\n")
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    assert cs.deploy_codex_assets() == "kept"
    assert box.profile.read_text() == edited
    assert "vhir would change" in capsys.readouterr().out


def test_an_indented_header_after_a_table_is_asked_about(box, capsys, monkeypatch):
    """The indented section is a server table of its own, never part of [tui];
    carrying it beside the section vhir adds would declare that server twice."""
    _setup()
    edited = (
        box.profile.read_text()
        + '\n[tui]\nfoo = 1\n  [mcp_servers.remnux-mcp]\n  url = "http://hand/mcp"\n'
    )
    box.profile.write_text(edited)
    box.started["remnux-mcp"] = True
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    assert cs.deploy_codex_assets() == "kept"
    assert box.profile.read_text() == edited
    assert "vhir would change" in capsys.readouterr().out


# --- consent: what is recorded ---------------------------------------------------


def test_a_users_edit_accepted_records_vhirs_part_and_keeps_codexs_tables(
    box, capsys, monkeypatch
):
    _setup()
    # at the top: a note after the last section would go with that section
    box.profile.write_text("# my note\n" + box.profile.read_text() + CODEX_TUI)
    answers = []
    monkeypatch.setattr("builtins.input", lambda p="": answers.append(p) or "y")
    assert cs.deploy_codex_assets() == "written"
    assert len(answers) == 1
    text = box.profile.read_text()
    assert "# my note" not in text and text.endswith(CODEX_TUI)
    assert _recorded(box) == _sha(text[: -len(CODEX_TUI)].encode())
    assert box.profile.stat().st_mode & 0o777 == 0o600
    monkeypatch.setattr("builtins.input", _no_prompt)
    assert cs.deploy_codex_assets() == "unchanged"  # settled: no second ask


# --- each caller carries [tui] -----------------------------------------------------


def test_local_setup_carries_codex_tui_with_no_prompt(box, capsys):
    _setup()
    box.profile.write_bytes(box.profile.read_bytes() + CODEX_TUI.encode())
    box.fd.write_text(FD + "Name the gap.\n")
    capsys.readouterr()
    _setup()
    out = capsys.readouterr().out
    assert f"Updated:   {box.profile}" in out and "vhir would change" not in out
    assert box.profile.read_text().endswith(CODEX_TUI)
    assert not _backups(box)


def test_local_setup_with_y_carries_codex_tui_without_a_backup(box, capsys):
    _setup()
    box.profile.write_bytes(box.profile.read_bytes() + CODEX_TUI.encode())
    box.fd.write_text(FD + "Name the gap.\n")
    _setup(ask_user_files=False)
    assert box.profile.read_text().endswith(CODEX_TUI)
    assert not _backups(box)
    assert "vhir CHANGED" not in capsys.readouterr().err


REMOTE = "## Codex on the examiner's machine\n\nNot in the case audit.\n"
SERVED = {
    "skills/MANIFEST": "# listed\nvhir-welcome/SKILL.md\n",
    "skills/vhir-welcome/SKILL.md": SKILL,
    "agents/finding-skeptic/codex.toml": CODEX_AGENT,
    "AGENTS.md": AGENTS,
    "claude-code/full/FORENSIC_DISCIPLINE.md": FD,
    "codex/OVERLAY.md": OVERLAY,
    "codex/REMOTE.md": REMOTE,
}


@pytest.fixture
def laptop(tmp_path, monkeypatch):
    home = tmp_path / "laptop"
    (home / ".vhir").mkdir(parents=True)
    manifest = home / ".vhir" / "manifest.json"
    manifest.write_text("{}")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(cs.Path, "home", staticmethod(lambda: home))
    monkeypatch.chdir(home)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("builtins.input", _no_prompt)
    served = dict(SERVED)
    monkeypatch.setattr(
        cs, "_fetch_raw", lambda rel: served[rel].encode() if rel in served else None
    )
    monkeypatch.setattr(cs, "_probe_health_with_auth", lambda u, t: {"status": "ok"})
    started = {"forensic-mcp": True, "sift-mcp": True, WIN: True}
    monkeypatch.setattr(
        cs,
        "_discover_services",
        lambda url, token: [{"name": n, "started": s} for n, s in started.items()],
    )
    return types.SimpleNamespace(
        home=home,
        manifest=manifest,
        served=served,
        started=started,
        profile=home / ".codex" / "valhuntir.config.toml",
    )


def _remote(**kw):
    _setup(remote=True, sift="https://sift.example:4508", token=TOKEN, **kw)


def test_remote_setup_carries_codex_tui_with_no_prompt(laptop, capsys):
    _remote()
    laptop.profile.write_bytes(laptop.profile.read_bytes() + CODEX_TUI.encode())
    _remote()
    assert laptop.profile.read_text().endswith(CODEX_TUI)  # unchanged: kept as is
    laptop.served["codex/REMOTE.md"] = REMOTE + "Name the gap.\n"
    capsys.readouterr()
    _remote()
    out = capsys.readouterr().out
    text = laptop.profile.read_text()
    assert f"Updated:   {laptop.profile}" in out and "vhir would change" not in out
    assert "Name the gap." in text and text.endswith(CODEX_TUI)
    assert not list(laptop.profile.parent.glob("*.vhir-backup-*"))


def test_remote_without_a_manifest_codex_tui_alone_gives_no_prompt(
    laptop, capsys, monkeypatch
):
    """With no manifest nothing is recorded, so a changed vhir part is asked
    about with or without [tui], as before; [tui] alone is no change."""
    laptop.manifest.unlink()
    _remote()
    laptop.profile.write_bytes(laptop.profile.read_bytes() + CODEX_TUI.encode())
    capsys.readouterr()
    _remote()
    assert laptop.profile.read_text().endswith(CODEX_TUI)
    assert "vhir would change" not in capsys.readouterr().out


def test_remote_setup_with_wintools_down_writes_its_section_and_names_it(
    laptop, capsys
):
    laptop.started[WIN] = False
    _remote()
    text = laptop.profile.read_text()
    assert 'url = "https://sift.example:4508/mcp/wintools-mcp"' in _servers(text)[WIN]
    assert "Not started now: wintools-mcp." in capsys.readouterr().out


# --- Claude Code: built as before (twin) -------------------------------------------


@pytest.fixture
def generated(monkeypatch):
    calls = []
    monkeypatch.setattr(
        cs, "_generate_config", lambda client, servers, ex: calls.append(servers)
    )
    monkeypatch.setattr(cs, "_record_client", lambda client: None)
    return calls


def test_claude_code_setup_still_leaves_out_a_backend_not_started(
    box, generated, capsys
):
    box.started[WIN] = False
    _setup(client="claude-code")
    (servers,) = generated
    assert _gateway(servers) == {"forensic-mcp", "sift-mcp"}
    out = capsys.readouterr()
    assert "1 backend(s) not started and excluded from config: wintools-mcp" in out.err
    assert "Not started now" not in out.out


def test_claude_code_setup_with_none_started_falls_back_to_the_aggregate(
    box, generated
):
    for name in box.started:
        box.started[name] = False
    _setup(client="claude-code")
    (servers,) = generated
    assert _gateway(servers) == {"vhir"}


def test_remote_claude_code_still_leaves_out_a_backend_not_started(
    laptop, generated, capsys, monkeypatch
):
    monkeypatch.setattr(cs, "_save_gateway_config", lambda url, token: None)
    laptop.started[WIN] = False
    _remote(client="claude-code")
    (servers,) = generated
    assert _gateway(servers) == {"forensic-mcp", "sift-mcp"}
    assert "Not started now" not in capsys.readouterr().out


def test_codex_profile_path_is_the_one_codex_reads(box):
    assert cs.codex_profile_path() == box.profile
    assert isinstance(box.profile, Path) and shutil.which  # imported names used
