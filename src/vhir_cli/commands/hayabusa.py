"""`vhir setup hayabusa`: install the current Hayabusa release for this user.

Opt-in. The current SIFT release doesn't install Hayabusa; this installs the
current Hayabusa release only:

- the Linux x86_64 build: musl when the C library is older than glibc 2.38
  (the gnu build fails on Ubuntu 22.04's 2.35), gnu from 2.38 on;
- checked against the sha256 digest GitHub's release API gives for that file;
- unpacked with its rules and config into ~/.local/share/hayabusa/<version>/
  and linked as ~/.local/bin/hayabusa. The gateway puts ~/.local/bin on its
  backends' PATH, and the evtx ingest uses the rules beside the binary the
  link points at.

Nothing outside those two places is changed, and nothing needs sudo.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
import zlib
from pathlib import Path

REPO = "Yamato-Security/hayabusa"
API = f"https://api.github.com/repos/{REPO}/releases/latest"
DOWNLOADS = f"https://github.com/{REPO}/releases/download/"

# The gnu build needs this glibc; older (and non-glibc) systems get musl
GNU_GLIBC = (2, 38)

_MAX_API_BYTES = 5 * 1024 * 1024
_MAX_ZIP_BYTES = 300 * 1024 * 1024
_MAX_UNPACKED_BYTES = 2 * 1024 * 1024 * 1024
_MAX_MEMBERS = 50_000


class InstallError(Exception):
    """Why Hayabusa wasn't installed, in a line the user can act on."""


def _machine() -> str:
    return platform.machine()


def _glibc() -> tuple[int, int] | None:
    """glibc's (major, minor), or None when the C library isn't glibc."""
    try:
        text = os.confstr("CS_GNU_LIBC_VERSION") or ""
    except (ValueError, OSError):
        return None
    m = re.fullmatch(r"glibc (\d+)\.(\d+)(?:\.\d+)*", text.strip())
    return (int(m.group(1)), int(m.group(2))) if m else None


def _build() -> str:
    """The build for this machine: lin-x64-musl or lin-x64-gnu."""
    machine = _machine()
    if machine != "x86_64":
        raise InstallError(
            f"this machine is {machine}; vhir setup hayabusa installs the "
            "Linux x86_64 build only. See https://github.com/"
            f"{REPO}/releases for other builds."
        )
    glibc = _glibc()
    return "lin-x64-gnu" if glibc and glibc >= GNU_GLIBC else "lin-x64-musl"


def _get(url: str, accept: str):
    req = urllib.request.Request(
        url, headers={"Accept": accept, "User-Agent": "vhir-setup-hayabusa"}
    )
    return urllib.request.urlopen(req, timeout=60)  # noqa: S310 — https only


def _latest_release() -> dict:
    try:
        with _get(API, "application/vnd.github+json") as resp:
            body = resp.read(_MAX_API_BYTES + 1)
    except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
        raise InstallError(f"couldn't reach GitHub ({e})") from e
    if len(body) > _MAX_API_BYTES:
        raise InstallError("GitHub's release answer was too large")
    try:
        release = json.loads(body)
    except ValueError as e:
        raise InstallError("GitHub's release answer wasn't JSON") from e
    if not isinstance(release, dict):
        raise InstallError("GitHub's release answer wasn't a release")
    return release


def _pick(release: dict, build: str) -> tuple[str, str, str, str]:
    """(version, asset name, url, sha256) for `build`, each checked."""
    tag = release.get("tag_name")
    m = re.fullmatch(r"v(\d+\.\d+\.\d+)", tag) if isinstance(tag, str) else None
    if not m:
        raise InstallError(f"the latest release's tag {tag!r} isn't vX.Y.Z")
    version = m.group(1)
    name = f"hayabusa-{version}-{build}.zip"
    assets = release.get("assets")
    asset = next(
        (
            a
            for a in (assets if isinstance(assets, list) else [])
            if isinstance(a, dict) and a.get("name") == name
        ),
        None,
    )
    if asset is None:
        raise InstallError(f"release {tag} has no {name}")
    url = asset.get("browser_download_url")
    if url != f"{DOWNLOADS}{tag}/{name}":
        raise InstallError(f"{name}'s download address isn't GitHub's: {url!r}")
    digest = asset.get("digest")
    d = (
        re.fullmatch(r"sha256:([0-9a-f]{64})", digest)
        if isinstance(digest, str)
        else None
    )
    if not d:
        raise InstallError(f"release {tag} gives no sha256 digest for {name}")
    return version, name, url, d.group(1)


def _download(url: str, sha256: str, dest: Path) -> None:
    """Save `url` to `dest`, refusing more than the size cap or another digest."""
    h = hashlib.sha256()
    size = 0
    try:
        with _get(url, "application/octet-stream") as resp, open(dest, "wb") as f:
            while chunk := resp.read(1024 * 1024):
                size += len(chunk)
                if size > _MAX_ZIP_BYTES:
                    raise InstallError(f"the download passed {_MAX_ZIP_BYTES} bytes")
                h.update(chunk)
                f.write(chunk)
    except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
        raise InstallError(f"the download failed ({e})") from e
    if h.hexdigest() != sha256:
        raise InstallError(
            f"the download's sha256 is {h.hexdigest()}, not the release's {sha256}"
        )


def _unpack(zip_path: Path, dest: Path, binary: str) -> None:
    """Unpack into `dest`, refusing any member that would land outside it,
    a link, or more than the size cap. The release's binary must be there."""
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as e:
        raise InstallError("the download isn't a zip") from e
    with zf:
        members = zf.infolist()
        if len(members) > _MAX_MEMBERS:
            raise InstallError(f"the zip has more than {_MAX_MEMBERS} files")
        total = 0
        for m in members:
            parts = m.filename.replace("\\", "/").split("/")
            if m.filename.startswith(("/", "\\")) or ".." in parts or ":" in parts[0]:
                raise InstallError(
                    f"the zip holds a path outside its folder: {m.filename!r}"
                )
            if stat.S_ISLNK(m.external_attr >> 16):
                raise InstallError(f"the zip holds a link: {m.filename!r}")
            total += m.file_size
            if total > _MAX_UNPACKED_BYTES:
                raise InstallError("the zip unpacks to more than the size cap")
        if binary not in {m.filename for m in members}:
            raise InstallError(f"the zip has no {binary}")
        try:
            zf.extractall(dest)
        except (zipfile.BadZipFile, NotImplementedError, zlib.error, EOFError) as e:
            raise InstallError(f"the zip didn't unpack ({e})") from e
    (dest / binary).chmod(0o755)


def _link(link: Path, target: Path) -> str | None:
    """Point `link` at `target` in one step; returns the old link's target.
    A file (not a link) already there is never replaced."""
    old = None
    if link.is_symlink():
        old = os.readlink(link)
    elif link.exists():
        raise InstallError(
            f"{link} is a file, not a link; move it aside and run this again"
        )
    tmp = link.with_name(f".hayabusa.{os.getpid()}.tmp")
    if tmp.is_symlink() or tmp.exists():
        tmp.unlink()
    tmp.symlink_to(target)
    os.replace(tmp, link)
    return old


def _check(binary: Path, version: str) -> None:
    """Run `hayabusa help`: its first line names the version."""
    try:
        out = subprocess.run(
            [str(binary), "help"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=60,
            cwd="/",
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise InstallError(f"{binary} help didn't run ({e})") from e
    first = (out.stdout + out.stderr).strip().splitlines()[:1]
    if out.returncode != 0 or not first or f"v{version}" not in first[0].split():
        raise InstallError(
            f"{binary} help gave rc {out.returncode} and {first[0] if first else 'no output'!r}, "
            f"not Hayabusa v{version}"
        )


def install() -> list[str]:
    """Install the current release; returns the lines to print."""
    build = _build()
    version, name, url, sha256 = _pick(_latest_release(), build)
    binary = f"hayabusa-{version}-{build}"
    home = Path.home()
    share = home / ".local" / "share" / "hayabusa"
    folder = share / version
    bin_dir = home / ".local" / "bin"
    lines = []
    if (folder / binary).is_file():
        _check(folder / binary, version)
        lines.append(f"Hayabusa {version} is already in {folder}; using it.")
    elif folder.exists() or folder.is_symlink():
        raise InstallError(
            f"{folder} is there without {binary}; move it aside and run this again"
        )
    else:
        share.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=share, prefix=".download-") as tmp:
            zip_path = Path(tmp) / name
            _download(url, sha256, zip_path)
            staged = Path(tmp) / "unpacked"
            staged.mkdir()
            _unpack(zip_path, staged, binary)
            _check(staged / binary, version)  # before it takes the version's place
            os.replace(staged, folder)
        lines.append(f"Hayabusa {version} ({name}, sha256 {sha256}) is in {folder}.")
    bin_dir.mkdir(parents=True, exist_ok=True)
    link = bin_dir / "hayabusa"
    old = _link(link, folder / binary)
    lines.append(
        f"Linked {link} -> {folder / binary}"
        + (f" (it pointed at {old})." if old and old != str(folder / binary) else ".")
    )
    lines.append(f"`hayabusa help` runs v{version}.")

    from vhir_cli.sift_tools import _which

    first = _which("hayabusa")
    if first and os.path.realpath(first) != os.path.realpath(link):
        lines.append(
            f"Note: {first} comes before {link} on the PATH Valhuntir's tools use, "
            "so the ingest runs that one. Remove it, or put ~/.local/bin first."
        )
    lines.append(
        f"If the gateway was started before {bin_dir} existed, restart it so "
        "ingest finds Hayabusa: systemctl --user restart vhir-gateway"
    )
    lines.append("Re-run the evtx ingest to add Hayabusa's detections.")
    return lines


def cmd_setup_hayabusa(args, identity: dict) -> None:
    try:
        lines = install()
    except (InstallError, OSError) as e:
        print(f"Hayabusa not installed: {e}", file=sys.stderr)
        sys.exit(1)
    for line in lines:
        print(line)
