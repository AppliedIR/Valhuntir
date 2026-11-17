"""`vhir update` on a box without OpenSearch says how to add it: with no
opensearch-mcp repo and no package, the steps block gives the clone, then
`vhir update`; a cloned repo is installed with the other packages before the
install offer; with the package installed the offer, or nothing, is as before.
Each state runs through cmd_update with the stand-ins of test_update_lock."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from tests import test_update_lock as lock
from tests.test_update import steps_block
from tests.test_update_lock import _asked, _steps, _update

box = lock.box  # the fixture: a scratch home with an install

PIN = "3.5.0"
COMPOSE = (
    f"services:\n  opensearch:\n    image: opensearchproject/opensearch:{PIN}\n"
    "    container_name: vhir-opensearch\n    environment:\n"
    "      - OPENSEARCH_JAVA_OPTS=-Xms4g -Xmx4g\n    mem_limit: 6g\n"
)
OFFER = "\n  Install OpenSearch now? [y/N] "


def _line(box):
    """The SPEC-2 entry, as the block prints it (each line unindented by two)."""
    clone = box.home / ".vhir" / "src" / "opensearch-mcp"
    return [
        "OpenSearch (evidence indexing, runs in Docker) isn't installed. To add it:",
        f"  git clone https://github.com/AppliedIR/opensearch-mcp.git {clone}",
        "then `vhir update`, which offers the install with its cost.",
    ]


def _has(block, lines):
    n = len(lines)
    return any(block[i : i + n] == lines for i in range(len(block) - n + 1))


def _clone(box):
    repo = box.home / "opensearch-mcp"
    (repo / "docker").mkdir(parents=True)
    (repo / "docker" / "docker-compose.yml").write_text(COMPOSE)
    (repo / "scripts").mkdir()
    (repo / "scripts" / "setup-opensearch.sh").write_text("#!/bin/sh\n")
    return repo


# state: (repo cloned, package installed, container)
STATES = {
    "i no package, no repo": (False, False, None),
    "ii repo, no package": (True, False, "absent"),
    "iii repo and package, no container": (True, True, "absent"),
    "iv repo, package and container": (True, True, PIN),
}


@pytest.mark.parametrize("state", list(STATES))
def test_each_opensearch_state_through_update(box, capsys, state):
    cloned, installed, container = STATES[state]
    repo = _clone(box) if cloned else box.home / "opensearch-mcp"
    calls, exited = _update(
        box, opensearch=installed, os_clone=cloned, os_container=container,
        tty=True, answers=["n"] * 8,
    )  # fmt: skip
    assert exited is None
    out, err = capsys.readouterr()
    block = steps_block(err)
    (locked,) = [c for kind, c in _steps(calls) if kind == "install"]
    asked = _asked(calls)
    said = _has(block, _line(box))
    # nothing runs at the line or at a declined offer
    assert not any(c[:1] == ["bash"] for c in calls)
    assert not any(c[:2] == ["git", "clone"] for c in calls)
    if state.startswith("i "):
        assert said, block
        assert str(repo) not in locked
        assert OFFER not in asked
        return
    assert not said and "isn't installed. To add it:" not in out + err
    assert locked.index(str(repo)) > locked.index("-c")  # with the others, locked
    if container == "absent":  # (ii), (iii): the existing offer, after the install
        assert f"OpenSearch {PIN} isn't installed on this box." in out
        assert asked.count(OFFER) == 1
        first_offer = next(i for i, c in enumerate(calls) if c == ["input", OFFER])
        assert calls.index(locked) < first_offer
    else:  # (iv): installed and running the pin: nothing to offer
        assert OFFER not in asked and "isn't installed" not in out + err


# clients, the install offer's answer, package installed before the run, whether the line for Codex is said
CODEX_ROWS = {
    "codex, Yes": (["codex"], "y", False, True),
    "claude-code and codex, Yes": (["claude-code", "codex"], "y", False, True),
    "claude-code, Yes": (["claude-code"], "y", False, False),
    "codex, No": (["codex"], "n", False, False),
    "iii package installed, codex, Yes": (["codex"], "y", True, False),
}
CODEX_LINE = "Run `vhir update` once more so Codex lists OpenSearch's tools."


@pytest.mark.parametrize("row", list(CODEX_ROWS))
def test_a_yes_in_state_ii_tells_a_codex_box_to_update_once_more(box, capsys, row):
    """Step 5 sets Codex's servers before the offer installs OpenSearch (the
    package this run installed isn't seen until a new process), and only
    Claude Code's are refreshed after it. In (iii) Step 5 saw the package."""
    clients, answer, installed, said = CODEX_ROWS[row]
    script = _clone(box) / "scripts" / "setup-opensearch.sh"
    with patch("vhir_cli.commands.update._redeploy_clients", return_value=clients):
        calls, exited = _update(
            box, opensearch=installed, os_clone=True, os_container="absent", tty=True,
            answers=[lambda p: answer if p == OFFER else "n"] * 8,
        )  # fmt: skip
    assert exited is None
    block = steps_block(capsys.readouterr().err)
    assert (["bash", str(script)] in calls) == (answer == "y")
    assert (CODEX_LINE in block) == said, block
