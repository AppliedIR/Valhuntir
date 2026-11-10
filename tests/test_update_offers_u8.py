"""U8 offers: on a terminal each offer is made once with its cost; a
decline is recorded in the install manifest under D11's key and not asked
again while its subject stays the same; with no terminal nothing is asked and
the U11 block lists each skipped offer by its text."""

from __future__ import annotations

import contextlib
import json
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from tests import test_update_lock as lock
from tests.test_update_lock import _asked, _update
from vhir_cli.commands import update

box = lock.box  # the fixture: a scratch home with an install

KEY = "declined_offers"  # D11's one manifest key: {offer: subject}
UPGRADE, INSTALL = "OpenSearch upgrade", "OpenSearch install"
SIFT, CUDA, OPENCTI = (
    "SIFT tools update",
    "CUDA package removal",
    "OpenCTI package removal",
)
# What this box's docker prints for a container that doesn't exist (measured
# 11-08 on docker here: "error: no such object: <name>", rc 1); older docker
# writes "Error: No such object:". Absent is matched without regard to case.
ABSENT_ERR = "error: no such object: vhir-opensearch\n"
DOWN_ERR = (
    "Cannot connect to the Docker daemon at unix:///var/run/docker.sock."
    " Is the docker daemon running?\n"
)
COMPOSE = (
    "services:\n  opensearch:\n    image: opensearchproject/opensearch:{pin}\n"
    "    container_name: vhir-opensearch\n    environment:\n"
    "      - discovery.type=single-node\n"
    "      - OPENSEARCH_JAVA_OPTS=-Xms{heap} -Xmx{heap}\n"
    "    mem_limit: {limit}\n    restart: unless-stopped\n"
)
VOL = "Volatility 3 2.26.0"


def _skipped(offer):
    return f"Not asked (no terminal): {offer}. Re-run `vhir update` in a terminal to be asked."


def _assumed(offer, taken=""):
    """The skip line; `taken` names the default the run took (batch 6 item 3: an
    informational offer, such as the OpenSearch install, keeps the short form)."""
    taken = f" {taken}" if taken else ""
    return (
        f"Not asked (VHIR_ASSUME_DEFAULTS is set): {offer}.{taken}"
        " Re-run `vhir update` without it to be asked."
    )


def _declined(offer, subject):
    return (
        f"Declined earlier: {offer} ({subject}). It is asked again when that changes."
    )


def _mem_gib():
    """The box's MemTotal in GiB, read here as the product must: kB / 1048576."""
    with open("/proc/meminfo") as fh:
        kb = next(int(ln.split()[1]) for ln in fh if ln.startswith("MemTotal:"))
    return f"{kb / 1048576:.1f} GiB"


# --- OpenSearch: the offer itself, called as update calls it at Step 7b ------


@pytest.fixture
def osb(tmp_path):
    """A home with sift-mcp at ~/.vhir/src and opensearch-mcp beside it."""
    home = tmp_path / "home"
    source = home / ".vhir" / "src" / "sift-mcp"
    source.mkdir(parents=True)
    repo = source.parent / "opensearch-mcp"
    (repo / ".git").mkdir(parents=True)
    (repo / "docker").mkdir()
    (repo / "scripts").mkdir()
    (repo / "scripts" / "setup-opensearch.sh").write_text("#!/bin/sh\n")
    manifest = home / ".vhir" / "manifest.json"
    manifest.write_text(json.dumps({"source": str(source)}))
    b = SimpleNamespace(home=home, source=source, repo=repo, manifest=manifest)
    _compose(b, "3.5.0")
    return b


def _compose(b, pin, heap="4g", limit="6g"):
    (b.repo / "docker" / "docker-compose.yml").write_text(
        COMPOSE.format(pin=pin, heap=heap, limit=limit)
    )


def _as_worktree(b):
    """opensearch-mcp as a git worktree: its .git is a file."""
    (b.repo / ".git").rmdir()
    (b.repo / ".git").write_text("gitdir: /elsewhere/.git/worktrees/opensearch-mcp\n")


def _os(b, capsys, monkeypatch, *, running="3.4.0", tty=True, answers=(), assume=False):
    """One _check_opensearch_version run. `running` is the image tag docker
    reports, "absent" for no container, "down" for a daemon that doesn't answer."""
    calls, replies = [], list(answers)
    if assume:
        monkeypatch.setenv("VHIR_ASSUME_DEFAULTS", "true")
    else:
        monkeypatch.delenv("VHIR_ASSUME_DEFAULTS", raising=False)

    def run(cmd, **kw):
        calls.append([str(c) for c in cmd])
        result = MagicMock(returncode=0, stdout="", stderr="")
        if cmd[:2] == ["docker", "inspect"]:
            if running == "absent":
                result.returncode, result.stderr = 1, ABSENT_ERR
            elif running == "down":
                result.returncode, result.stderr = 1, DOWN_ERR
            else:
                result.stdout = f"opensearchproject/opensearch:{running}\n"
        return result

    def ask(prompt=""):
        calls.append(["input", prompt])
        return replies.pop(0) if replies else ""

    stands = [
        patch("pathlib.Path.home", return_value=b.home),
        patch("subprocess.run", side_effect=run),
        patch("importlib.util.find_spec", return_value=None),
        patch("builtins.input", side_effect=ask),
        patch("sys.stdin.isatty", return_value=tty),
    ]
    with contextlib.ExitStack() as stack:
        for stand in stands:
            stack.enter_context(stand)
        update._check_opensearch_version(b.source)
    out, err = capsys.readouterr()
    return SimpleNamespace(
        calls=calls,
        reads=len(_asked(calls)),
        out=out,
        err=err,
        manifest=json.loads(b.manifest.read_text()),
    )


def _setup_ran(b, calls):
    return ["bash", str(b.repo / "scripts" / "setup-opensearch.sh")] in calls


def test_a_stale_opensearch_is_offered_once_with_its_cost(osb, capsys, monkeypatch):
    r = _os(osb, capsys, monkeypatch, answers=[""])
    assert r.reads == 1
    text = r.out + r.err
    assert "4 GiB heap" in text and "6 GiB container limit" in text
    assert _mem_gib() in text


def test_the_cost_is_read_from_the_compose_file(osb, capsys, monkeypatch):
    _compose(osb, "3.5.0", heap="2g", limit="3g")
    r = _os(osb, capsys, monkeypatch, answers=[""])
    text = r.out + r.err
    assert "2 GiB heap" in text and "3 GiB container limit" in text
    assert "4 GiB heap" not in text and "6 GiB container limit" not in text


def test_a_declined_upgrade_is_recorded_under_the_pin_and_running_pair(
    osb, capsys, monkeypatch
):
    r = _os(osb, capsys, monkeypatch, answers=[""])
    assert r.manifest.get(KEY, {}).get(UPGRADE) == ["3.5.0", "3.4.0"]


def test_a_declined_upgrade_is_not_asked_again_and_is_listed(osb, capsys, monkeypatch):
    _os(osb, capsys, monkeypatch, answers=["n"])
    r = _os(osb, capsys, monkeypatch, answers=["y"])
    assert r.reads == 0
    assert not _setup_ran(osb, r.calls)
    assert _declined(UPGRADE, "3.5.0, running 3.4.0") in r.err


def test_a_new_pin_asks_again(osb, capsys, monkeypatch):
    _os(osb, capsys, monkeypatch, answers=[""])
    _compose(osb, "3.6.0")
    assert _os(osb, capsys, monkeypatch, answers=[""]).reads == 1


def test_a_new_running_image_under_the_same_pin_asks_again_and_is_listed(
    osb, capsys, monkeypatch
):
    """K23: the subject is (pinned, running), not the pin alone."""
    _os(osb, capsys, monkeypatch, running="3.4.0", answers=[""])
    second = _os(osb, capsys, monkeypatch, running="3.3.0", answers=[""])
    assert second.reads == 1
    third = _os(osb, capsys, monkeypatch, running="3.3.0", answers=["y"])
    assert third.reads == 0
    assert _declined(UPGRADE, "3.5.0, running 3.3.0") in third.err


def test_with_no_terminal_the_upgrade_is_not_asked_and_is_listed_skipped(
    osb, capsys, monkeypatch
):
    r = _os(osb, capsys, monkeypatch, tty=False, answers=[""])
    assert r.reads == 0
    assert _skipped(UPGRADE) in r.err


def test_a_piped_yes_with_no_terminal_upgrades_nothing(osb, capsys, monkeypatch):
    r = _os(osb, capsys, monkeypatch, tty=False, answers=["y"])
    assert not _setup_ran(osb, r.calls)


def test_assume_defaults_on_a_terminal_takes_no_without_a_read(
    osb, capsys, monkeypatch
):
    r = _os(osb, capsys, monkeypatch, assume=True, answers=["y"])
    assert r.reads == 0
    assert _assumed(UPGRADE, "Kept OpenSearch 3.4.0.") in r.err
    assert KEY not in r.manifest
    assert not _setup_ran(osb, r.calls)


def test_yes_to_the_upgrade_runs_the_setup_script(osb, capsys, monkeypatch):
    r = _os(osb, capsys, monkeypatch, answers=["y"])
    assert _setup_ran(osb, r.calls)


def test_an_absent_opensearch_is_offered_once_with_its_cost(osb, capsys, monkeypatch):
    r = _os(osb, capsys, monkeypatch, running="absent", answers=[""])
    assert r.reads == 1
    text = r.out + r.err
    assert "4 GiB heap" in text and "6 GiB container limit" in text
    assert _mem_gib() in text


def test_a_declined_install_is_recorded_and_not_asked_again(osb, capsys, monkeypatch):
    first = _os(osb, capsys, monkeypatch, running="absent", answers=[""])
    assert first.manifest.get(KEY, {}).get(INSTALL) == ["3.5.0", "absent"]
    second = _os(osb, capsys, monkeypatch, running="absent", answers=["y"])
    assert second.reads == 0
    assert _declined(INSTALL, "3.5.0") in second.err


def test_yes_to_the_absent_offer_runs_the_setup_script(osb, capsys, monkeypatch):
    r = _os(osb, capsys, monkeypatch, running="absent", answers=["y"])
    assert _setup_ran(osb, r.calls)


def test_with_no_terminal_an_absent_opensearch_is_listed_skipped(
    osb, capsys, monkeypatch
):
    r = _os(osb, capsys, monkeypatch, running="absent", tty=False)
    assert r.reads == 0
    assert _skipped(INSTALL) in r.err


def test_no_checkout_means_no_offer(osb, capsys, monkeypatch):
    for p in sorted(osb.repo.rglob("*"), reverse=True):
        p.rmdir() if p.is_dir() else p.unlink()
    osb.repo.rmdir()
    r = _os(osb, capsys, monkeypatch, running="absent", answers=["y"])
    assert r.reads == 0
    assert "Not asked" not in r.err and "OpenSearch" not in r.out + r.err


def test_a_daemon_that_does_not_answer_makes_no_offer(osb, capsys, monkeypatch):
    r = _os(osb, capsys, monkeypatch, running="down", answers=["y"])
    assert r.reads == 0
    assert "Couldn't check whether OpenSearch is set up for snapshots" in r.out
    assert "Cannot connect to the Docker daemon" in r.out
    assert not _setup_ran(osb, r.calls)


def test_a_worktree_checkout_gets_the_version_check_and_the_offer(
    osb, capsys, monkeypatch
):
    """K9: opensearch-mcp's .git is a file; M-K9 dies here."""
    _as_worktree(osb)
    r = _os(osb, capsys, monkeypatch, answers=[""])
    assert r.reads == 1


def test_the_pull_list_holds_a_worktree_checkout(box):
    """K9 through update's pull list: the worktree at ~/.vhir/src comes first
    in the resolver's candidates; at cae198ba it is skipped for ~/opensearch-mcp."""
    wt = box.home / ".vhir" / "src" / "opensearch-mcp"
    wt.mkdir(parents=True)
    (wt / ".git").write_text("gitdir: /elsewhere/.git/worktrees/opensearch-mcp\n")
    calls, _ = _update(box, gpu=True)
    pulled = [
        os.path.realpath(c[2]) for c in calls if c[:2] == ["git", "-C"] and "pull" in c
    ]
    assert os.path.realpath(wt) in pulled


# --- SANS SIFT tools: offered at the end of a whole update -------------------


def _sift(box, *, vol=VOL, hayabusa=False, **kw):
    kw.setdefault("tty", True)
    kw.setdefault("gpu", True)  # the build is chosen: no PyTorch question
    with (
        patch("vhir_cli.sift_tools.volatility_problem", return_value=vol),
        patch("vhir_cli.sift_tools.hayabusa_missing", return_value=hayabusa),
    ):
        return _update(box, **kw)


def test_old_sans_sift_tools_are_offered_once_with_their_time(box, capsys):
    calls, _ = _sift(box, answers=[""])
    assert len(_asked(calls)) == 1
    out, err = capsys.readouterr()
    assert "sudo cast install teamdfir/sift" in out + err
    assert (out + err).count("15-20 minutes") == 1


def test_yes_runs_the_sans_installer(box):
    calls, _ = _sift(box, answers=["y"])
    assert ["sudo", "cast", "install", "teamdfir/sift"] in calls


def test_a_declined_sift_update_is_recorded_and_not_asked_again(box, capsys):
    _sift(box, answers=[""])
    assert lock._manifest(box).get(KEY, {}).get(SIFT) == [VOL]
    capsys.readouterr()
    calls, _ = _sift(box, answers=["y"])
    assert not _asked(calls)
    assert ["sudo", "cast", "install", "teamdfir/sift"] not in calls
    assert _declined(SIFT, VOL) in capsys.readouterr().err


def test_a_decline_is_written_by_the_manifest_owner(box):
    from vhir_cli.commands import client_setup

    with patch.object(
        client_setup, "_manifest_set", wraps=client_setup._manifest_set
    ) as owner:
        _sift(box, answers=[""])
    assert (KEY, {SIFT: [VOL]}) in [c.args for c in owner.call_args_list]
    assert lock._manifest(box)[KEY] == {SIFT: [VOL]}


def test_a_decline_that_cant_be_recorded_says_so(box, capsys):
    from vhir_cli.commands import client_setup

    with patch.object(client_setup, "_manifest_set", return_value=False):
        _sift(box, answers=[""])
    assert "The decline couldn't be recorded" in capsys.readouterr().err
    assert KEY not in lock._manifest(box)


def test_with_no_terminal_old_sift_tools_are_listed_skipped(box, capsys):
    calls, _ = _sift(box, tty=False, answers=["y"])
    assert not _asked(calls)
    assert _skipped(SIFT) in capsys.readouterr().err


def test_hayabusa_alone_stays_a_printed_warning(box, capsys):
    calls, _ = _sift(box, vol=None, hayabusa=True, answers=["y"])
    assert not _asked(calls)
    out, err = capsys.readouterr()
    assert "Hayabusa missing" in out + err
    assert "Not asked" not in err and "Declined earlier" not in err


# --- The CUDA and OpenCTI leftovers: the D11 rule on update's own offers -----

NEW_LEFTOVERS = lock.LEFTOVERS + "nvidia-nccl-cu12 210000000\n"


def test_a_declined_cuda_removal_is_not_asked_again_and_is_listed(box, capsys):
    """E15: leftovers on both runs, declined on run 1, not asked on run 2."""
    lock._cleanup(box, answers=[""])
    assert lock._manifest(box).get(KEY, {}).get(CUDA) == sorted(lock.NAMES)
    capsys.readouterr()
    calls, _ = lock._cleanup(box, answers=["y"])
    assert not any("Remove them now? [y/N]" in p for p in _asked(calls))
    assert not any(c[:3] == ["uv", "pip", "uninstall"] for c in calls)
    assert _declined(CUDA, ", ".join(sorted(lock.NAMES))) in capsys.readouterr().err


def test_a_new_cuda_package_set_asks_again(box):
    lock._cleanup(box, answers=[""])
    calls, _ = _update(box, leftovers=NEW_LEFTOVERS, cpu=True, tty=True, answers=[""])
    assert any("Remove them now? [y/N]" in p for p in _asked(calls))


def test_with_no_terminal_cuda_leftovers_are_listed_skipped(box, capsys):
    calls, _ = lock._cleanup(box, tty=False, answers=["y"])
    assert not _asked(calls)
    assert _skipped(CUDA) in capsys.readouterr().err


def test_assume_defaults_takes_no_at_the_cuda_offer(box, capsys, monkeypatch):
    monkeypatch.setenv("VHIR_ASSUME_DEFAULTS", "true")
    calls, _ = lock._cleanup(box, answers=["y"])
    assert not _asked(calls)
    assert (
        _assumed(CUDA, "Left the CUDA packages installed.") in capsys.readouterr().err
    )
    assert KEY not in lock._manifest(box)


def test_a_declined_opencti_removal_is_not_asked_again_and_is_listed(box, capsys):
    lock._opencti(box, answers=[""])
    assert lock._manifest(box).get(KEY, {}).get(OPENCTI) == sorted(lock.OPENCTI)
    capsys.readouterr()
    calls, _ = lock._opencti(box, answers=["y"])
    assert not _asked(calls)
    assert not any(c[:3] == ["uv", "pip", "uninstall"] for c in calls)
    assert (
        _declined(OPENCTI, ", ".join(sorted(lock.OPENCTI))) in capsys.readouterr().err
    )


def test_a_new_opencti_package_set_asks_again(box):
    lock._opencti(box, answers=[""])
    calls, _ = _update(
        box, opencti_leftovers="pycti\nstix2\n", tty=True, gpu=True, answers=[""]
    )
    assert any("Remove them now? [y/N]" in p for p in _asked(calls))


def test_with_no_terminal_opencti_leftovers_are_listed_skipped(box, capsys):
    calls, _ = lock._opencti(box, tty=False, answers=["y"])
    assert not _asked(calls)
    assert _skipped(OPENCTI) in capsys.readouterr().err


@pytest.mark.parametrize("reply", [EOFError, "", "n", "no", "yep", "ok", "y es"])
def test_confirm_takes_no_answer_and_anything_but_yes_as_no(reply):
    with (
        patch("builtins.input", side_effect=[reply]),
        patch.object(update, "_record_decline") as record,
    ):
        assert update._confirm("an offer", ["a"], "  Go? [y/N] ") is False
    record.assert_called_once_with("an offer", ["a"])


@pytest.mark.parametrize("reply", ["y", "yes", " Y ", "YES"])
def test_confirm_takes_y_or_yes_as_yes(reply):
    with (
        patch("builtins.input", side_effect=[reply]),
        patch.object(update, "_record_decline") as record,
    ):
        assert update._confirm("an offer", ["a"], "  Go? [y/N] ") is True
    assert not record.called
