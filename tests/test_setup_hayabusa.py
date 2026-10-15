"""`vhir setup hayabusa`: the current release, checked and installed for this user.

GitHub is replaced by a stub that serves a release answer and a zip built here:
a shell-script "hayabusa" that answers `help` with its banner, and a rules
folder beside it, laid out as the real zips are.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import zipfile
from pathlib import Path

import pytest

from vhir_cli import sift_tools
from vhir_cli.commands import hayabusa
from vhir_cli.main import main

VERSION = "4.2.0"
TAG = f"v{VERSION}"
BASE = f"https://github.com/Yamato-Security/hayabusa/releases/download/{TAG}/"


def _zip(build: str, banner: str = f"Hayabusa v{VERSION} - Autumn Release", extra=()):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            f"hayabusa-{VERSION}-{build}",
            f'#!/bin/sh\n[ "$1" = help ] && echo "{banner}"\n',
        )
        zf.writestr("rules/hayabusa/a.yml", "title: a\n")
        zf.writestr("config/level_tuning.txt", "")
        for info, data in extra:
            zf.writestr(info, data)
    return buf.getvalue()


def _release(zips: dict[str, bytes], **overrides) -> dict:
    assets = []
    for build, data in zips.items():
        name = f"hayabusa-{VERSION}-{build}.zip"
        assets.append(
            {
                "name": name,
                "browser_download_url": BASE + name,
                "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            }
        )
    return {"tag_name": TAG, "assets": assets, **overrides}


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


@pytest.fixture
def gh(tmp_path, monkeypatch):
    """A scratch HOME, a glibc 2.35 x86_64 box, and a stub GitHub."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(hayabusa, "_machine", lambda: "x86_64")
    monkeypatch.setattr(hayabusa, "_glibc", lambda: (2, 35))
    # Valhuntir's tool PATH: ~/.local/bin and nothing else that holds a hayabusa
    monkeypatch.setattr(
        sift_tools, "_search_path", lambda: str(home / ".local" / "bin")
    )

    class GH:
        zips = {b: _zip(b) for b in ("lin-x64-musl", "lin-x64-gnu")}
        release = None
        fetched: list[str] = []

        def get(self, url, accept):
            self.fetched.append(url)
            if url == hayabusa.API:
                rel = self.release or _release(self.zips)
                return _Resp(json.dumps(rel).encode())
            for build, data in self.zips.items():
                if url == f"{BASE}hayabusa-{VERSION}-{build}.zip":
                    return _Resp(data)
            raise OSError(f"no stub for {url}")

    g = GH()
    g.fetched = []
    g.home = home
    monkeypatch.setattr(hayabusa, "_get", g.get)
    return g


def _run(capsys):
    with pytest.raises(SystemExit) as e:
        hayabusa.cmd_setup_hayabusa(None, {})
    out = capsys.readouterr()
    return e.value.code, out.out + out.err


def _ok(capsys) -> str:
    hayabusa.cmd_setup_hayabusa(None, {})
    return capsys.readouterr().out


def _link(home: Path) -> Path:
    return home / ".local" / "bin" / "hayabusa"


def _folder(home: Path) -> Path:
    return home / ".local" / "share" / "hayabusa" / VERSION


@pytest.mark.parametrize(
    ("glibc", "build"),
    [((2, 35), "lin-x64-musl"), (None, "lin-x64-musl"), ((2, 38), "lin-x64-gnu"),
     ((2, 39), "lin-x64-gnu")],
)  # fmt: skip
def test_the_build_follows_glibc_and_lands_linked_with_its_rules(
    gh, capsys, monkeypatch, glibc, build
):
    monkeypatch.setattr(hayabusa, "_glibc", lambda: glibc)
    out = _ok(capsys)
    binary = _folder(gh.home) / f"hayabusa-{VERSION}-{build}"
    assert gh.fetched == [hayabusa.API, f"{BASE}hayabusa-{VERSION}-{build}.zip"]
    assert os.readlink(_link(gh.home)) == str(binary)
    assert os.access(binary, os.X_OK)
    assert (binary.parent / "rules" / "hayabusa" / "a.yml").is_file()
    assert (binary.parent / "config").is_dir()
    assert f"runs v{VERSION}" in out and "restart the gateway" in out
    # nothing left from the download
    assert sorted(p.name for p in _folder(gh.home).parent.iterdir()) == [VERSION]


def test_glibc_is_read_from_the_c_library(monkeypatch):
    monkeypatch.setattr(hayabusa.os, "confstr", lambda name: "glibc 2.35")
    assert hayabusa._glibc() == (2, 35)
    monkeypatch.setattr(hayabusa.os, "confstr", lambda name: "glibc 2.38.1")
    assert hayabusa._glibc() == (2, 38)

    def raises(name):
        raise ValueError(name)

    monkeypatch.setattr(hayabusa.os, "confstr", raises)
    assert hayabusa._glibc() is None


def test_another_machine_is_refused_before_any_download(gh, capsys, monkeypatch):
    monkeypatch.setattr(hayabusa, "_machine", lambda: "aarch64")
    rc, out = _run(capsys)
    assert rc == 1 and "aarch64" in out and "x86_64 build only" in out
    assert gh.fetched == [] and not _link(gh.home).exists()


def test_a_download_with_another_digest_is_refused(gh, capsys):
    gh.release = _release(gh.zips)
    gh.zips = {**gh.zips, "lin-x64-musl": _zip("lin-x64-musl", extra=[("x", "y")])}
    rc, out = _run(capsys)
    assert rc == 1 and "not the release's" in out
    assert not _folder(gh.home).exists() and not _link(gh.home).is_symlink()
    assert list(_folder(gh.home).parent.iterdir()) == []


@pytest.mark.parametrize(
    "digest", [None, "", "md5:abc", "sha256:" + "A" * 64, "sha256:12"]
)
def test_a_missing_or_malformed_digest_is_refused_before_the_download(
    gh, capsys, digest
):
    rel = _release(gh.zips)
    for a in rel["assets"]:
        a["digest"] = digest
    gh.release = rel
    rc, out = _run(capsys)
    assert rc == 1 and "no sha256 digest" in out
    assert gh.fetched == [hayabusa.API]


@pytest.mark.parametrize(
    "tag", ["4.2.0", "v4.2", "v4.2.0-rc1", "v4.2.0/../x", None, 420]
)
def test_a_tag_that_is_not_a_version_is_refused(gh, capsys, tag):
    gh.release = _release(gh.zips, tag_name=tag)
    rc, out = _run(capsys)
    assert rc == 1 and "isn't vX.Y.Z" in out and gh.fetched == [hayabusa.API]


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/hayabusa-4.2.0-lin-x64-musl.zip",
        "http://github.com/Yamato-Security/hayabusa/releases/download/v4.2.0/"
        "hayabusa-4.2.0-lin-x64-musl.zip",
        BASE + "hayabusa-4.2.0-lin-x64-gnu.zip",
        None,
    ],
)
def test_a_download_address_off_the_release_is_refused(gh, capsys, url):
    rel = _release(gh.zips)
    rel["assets"][0]["browser_download_url"] = url
    gh.release = rel
    rc, out = _run(capsys)
    assert rc == 1 and "download address" in out and gh.fetched == [hayabusa.API]


def test_a_release_without_the_build_is_refused(gh, capsys):
    gh.release = _release({"lin-x64-gnu": gh.zips["lin-x64-gnu"]})
    rc, out = _run(capsys)
    assert rc == 1 and f"no hayabusa-{VERSION}-lin-x64-musl.zip" in out


@pytest.mark.parametrize("body", [b"not json", b"[1, 2]", b"x" * (5 * 1024 * 1024 + 1)])
def test_a_release_answer_that_is_not_a_release_is_refused(
    gh, capsys, monkeypatch, body
):
    monkeypatch.setattr(hayabusa, "_get", lambda url, accept: _Resp(body))
    rc, out = _run(capsys)
    assert rc == 1 and "release answer" in out


def test_no_network_says_so(gh, capsys, monkeypatch):
    def offline(url, accept):
        raise hayabusa.urllib.error.URLError("Name or service not known")

    monkeypatch.setattr(hayabusa, "_get", offline)
    rc, out = _run(capsys)
    assert rc == 1 and "couldn't reach GitHub" in out


def _bad_member(name: str, link: bool = False):
    info = zipfile.ZipInfo(name)
    if link:
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
    return (info, "/etc/passwd" if link else "x")


@pytest.mark.parametrize(
    "member",
    [
        _bad_member("../escape"),
        _bad_member("rules/../../escape"),
        _bad_member("/abs"),
        _bad_member("..\\escape"),
        _bad_member("C:/x"),
        _bad_member("rules/link", link=True),
    ],
    ids=["parent", "nested-parent", "absolute", "backslash", "drive", "symlink"],
)
def test_a_zip_member_outside_its_folder_or_a_link_is_refused(gh, capsys, member):
    gh.zips = {"lin-x64-musl": _zip("lin-x64-musl", extra=[member])}
    gh.release = _release(gh.zips)
    rc, out = _run(capsys)
    assert rc == 1 and ("outside its folder" in out or "a link" in out)
    assert not _folder(gh.home).exists() and not _link(gh.home).is_symlink()
    assert not (gh.home / ".local" / "share" / "escape").exists()


def test_a_zip_without_the_binary_is_refused(gh, capsys):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("rules/a.yml", "")
    gh.zips = {"lin-x64-musl": buf.getvalue()}
    gh.release = _release(gh.zips)
    rc, out = _run(capsys)
    assert rc == 1 and f"no hayabusa-{VERSION}-lin-x64-musl" in out


def test_a_binary_that_answers_another_version_is_not_linked(gh, capsys):
    old = gh.home / "cast-hayabusa"
    old.write_text("")
    _link(gh.home).parent.mkdir(parents=True)
    _link(gh.home).symlink_to(old)
    gh.zips = {"lin-x64-musl": _zip("lin-x64-musl", banner="Hayabusa v3.8.1")}
    gh.release = _release(gh.zips)
    rc, out = _run(capsys)
    assert rc == 1 and "not Hayabusa v4.2.0" in out and "v3.8.1" in out
    assert os.readlink(_link(gh.home)) == str(old)  # the old link is kept
    # and nothing is left to be reused as 4.2.0 next time
    assert list(_folder(gh.home).parent.iterdir()) == []


def test_an_installed_binary_that_answers_another_version_is_not_linked(gh, capsys):
    _folder(gh.home).mkdir(parents=True)
    binary = _folder(gh.home) / f"hayabusa-{VERSION}-lin-x64-musl"
    binary.write_text('#!/bin/sh\necho "Hayabusa v3.8.1"\n')
    binary.chmod(0o755)
    rc, out = _run(capsys)
    assert rc == 1 and "not Hayabusa v4.2.0" in out
    assert not _link(gh.home).is_symlink() and gh.fetched == [hayabusa.API]


@pytest.mark.parametrize(
    "cap", ["_MAX_ZIP_BYTES", "_MAX_UNPACKED_BYTES", "_MAX_MEMBERS"]
)
def test_a_zip_over_a_cap_is_refused(gh, capsys, monkeypatch, cap):
    monkeypatch.setattr(hayabusa, cap, 2)
    rc, out = _run(capsys)
    assert rc == 1 and not _link(gh.home).is_symlink()
    assert list(_folder(gh.home).parent.iterdir()) == []


def test_an_existing_link_is_replaced_and_named(gh, capsys):
    old = gh.home / "cast-hayabusa"
    old.write_text("")
    _link(gh.home).parent.mkdir(parents=True)
    _link(gh.home).symlink_to(old)
    out = _ok(capsys)
    assert os.readlink(_link(gh.home)).endswith(f"hayabusa-{VERSION}-lin-x64-musl")
    assert f"it pointed at {old}" in out
    assert "restart the gateway" not in out  # ~/.local/bin was there already


def test_a_file_where_the_link_goes_is_never_replaced(gh, capsys):
    _link(gh.home).parent.mkdir(parents=True)
    _link(gh.home).write_text("mine")
    rc, out = _run(capsys)
    assert rc == 1 and "is a file, not a link" in out
    assert _link(gh.home).read_text() == "mine" and not _link(gh.home).is_symlink()


def test_a_rerun_uses_the_installed_version_without_downloading(gh, capsys):
    _ok(capsys)
    gh.fetched.clear()
    out = _ok(capsys)
    assert gh.fetched == [hayabusa.API]
    assert f"already in {_folder(gh.home)}" in out and "pointed at" not in out


def test_a_version_folder_without_the_binary_is_left_alone(gh, capsys):
    _folder(gh.home).mkdir(parents=True)
    (_folder(gh.home) / "notes").write_text("x")
    rc, out = _run(capsys)
    assert rc == 1 and "move it aside" in out
    assert (_folder(gh.home) / "notes").read_text() == "x"
    assert gh.fetched == [hayabusa.API]


def test_another_hayabusa_first_on_the_tools_path_is_named(gh, capsys, monkeypatch):
    other = gh.home / "opt" / "hayabusa"
    other.parent.mkdir()
    other.write_text("#!/bin/sh\n")
    other.chmod(0o755)
    monkeypatch.setattr(
        sift_tools,
        "_search_path",
        lambda: os.pathsep.join([str(other.parent), str(_link(gh.home).parent)]),
    )
    out = _ok(capsys)
    assert f"Note: {other} comes before" in out


def test_vhir_setup_hayabusa_runs_it(gh, capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["vhir", "setup", "hayabusa"])
    try:
        main()
    except SystemExit as e:
        assert e.code in (0, None)
    assert os.readlink(_link(gh.home)).endswith(f"hayabusa-{VERSION}-lin-x64-musl")
