"""Say when the SIFT tools Valhuntir runs are too old or missing.

A SANS SIFT image can predate the tool releases Valhuntir needs:

- Volatility 3 before 2.28 saves downloaded symbols only beside its own
  package. On SIFT that is /opt/volatility3, which a normal user can't write,
  so every Windows plugin fails with "Cannot write necessary symbol file".
  2.28 added a per-user symbols folder. An older Volatility in a folder the
  user owns (a pipx install, for one) works and isn't reported.
- Hayabusa missing means the event-log ingest runs no detections. The
  current SIFT release doesn't install it; `vhir setup hayabusa` installs the
  current release, so the warning names that.

SANS's own installer brings Volatility up to date, so the warning names it. This
module only reports: setup-sift.sh, `vhir setup test` and `vhir update` print
its warning and carry on.

Run as ``python -m vhir_cli.sift_tools``: prints the warning, or nothing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

# The first release that saves symbols in the user's own cache folder.
VOL_SYMBOLS_FIXED = (2, 28)

# What the ingest tries, in its order (opensearch-mcp parse_memory._find_vol3).
_VOL_NAMES = ("vol3", "vol")

# Read inside the Volatility interpreter: its version, then its symbol folders.
# (Importing the constants makes Volatility's own cache folder, as vol does.)
_VOL_PROBE = (
    "from volatility3.framework import constants as c\n"
    "print(c.VERSION_MAJOR, c.VERSION_MINOR, getattr(c, 'VERSION_PATCH', 0))\n"
    "print(*c.SYMBOL_BASEPATHS, sep='\\n')\n"
)


def _search_path() -> str:
    """PATH as the gateway gives it to its backends (sift_gateway's
    prepend_local_bin): ~/.local/bin first when it's missing, else as it is."""
    local_bin = str(Path.home() / ".local" / "bin")
    path = os.environ.get("PATH", "")
    if os.path.isdir(local_bin) and local_bin not in path.split(os.pathsep):
        return os.pathsep.join(p for p in (local_bin, path) if p)
    return path


def _which(name: str) -> str | None:
    return shutil.which(name, path=_search_path())


def _interpreter(script: str) -> list[str] | None:
    """The command a script's #! line runs it with, or None (no #!, not Python)."""
    try:
        with open(script, "rb") as f:
            first = f.readline(512)
    except OSError:
        return None
    if not first.startswith(b"#!"):
        return None
    words = first[2:].decode("utf-8", "replace").split()
    if not words:
        return None
    if Path(words[0]).name == "env":
        words = [w for w in words[1:] if not w.startswith("-")]
        if not words:
            return None
        found = _which(words[0])
        if found is None:
            return None
        words = [found, *words[1:]]
    if not Path(words[0]).name.startswith("python"):
        return None
    return words[:1]


def _is_volatility(cmd: list[str]) -> bool:
    """Does it print Volatility 3's banner? Run bare, as the ingest checks it."""
    try:
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            cwd="/",
            env={**os.environ, "PATH": _search_path()},
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return "Volatility 3" in out.stdout + out.stderr


def _volatility_interpreter() -> list[str] | None:
    """The Python the ingest's Volatility runs under, found as the ingest finds it:
    the first candidate that prints Volatility 3's banner."""
    for name in _VOL_NAMES:
        found = _which(name)
        if found and _is_volatility([found]):
            return _interpreter(found)
    python3 = _which("python3")
    if python3 and _is_volatility([python3, "-m", "volatility3"]):
        return [python3]
    return None


def _writable(folder: str) -> bool:
    """Can the user save a file there? A missing folder counts if it can be made."""
    path = Path(folder)
    while not path.exists():
        if path.parent == path:
            return False
        path = path.parent
    return path.is_dir() and os.access(path, os.W_OK | os.X_OK)


def volatility_problem() -> str | None:
    """'Volatility 3 <version>' when it can't save symbols, else None.

    None too when it can't be found or its version can't be read: this reports
    only what it measured.
    """
    interp = _volatility_interpreter()
    if interp is None:
        return None
    try:
        out = subprocess.run(
            [*interp, "-E", "-c", _VOL_PROBE],
            capture_output=True,
            text=True,
            timeout=30,
            cwd="/",
            env={**os.environ, "PATH": _search_path()},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    lines = out.stdout.splitlines()
    if out.returncode != 0 or not lines:
        return None
    try:
        major, minor, patch = (int(n) for n in lines[0].split())
    except ValueError:
        return None
    if (major, minor) >= VOL_SYMBOLS_FIXED:
        return None
    # Before 2.28 it saves a Windows kernel's symbols in <basepath>/windows/<pdb>/
    if any(
        _writable(os.path.join(folder, "windows")) for folder in lines[1:] if folder
    ):
        return None
    return f"Volatility 3 {major}.{minor}.{patch}"


# The current SIFT release doesn't install Hayabusa
HAYABUSA_CHOICE = (
    " For Hayabusa, run `vhir setup hayabusa` (installs the current Hayabusa "
    "release; the current SIFT release doesn't include it)."
)


def hayabusa_missing() -> bool:
    return _which("hayabusa") is None


def warning() -> str | None:
    """The one warning to print, or None when nothing is out of date."""
    problems = []
    vol = volatility_problem()
    if vol:
        problems.append(f"{vol}: memory analysis fails")
    hayabusa = hayabusa_missing()
    if hayabusa:
        problems.append("Hayabusa missing: no event-log detections")
    if not problems:
        return None
    return (
        "Some SIFT tools are out of date and parts of Valhuntir won't work with them "
        f"({'; '.join(problems)}). Update SIFT with: `sudo cast install teamdfir/sift` "
        "(about 5 minutes on the SANS OVA; if it reports failed states, run it again, "
        "since a download outage can cause them), then re-run `./setup-sift.sh` "
        "with the options you installed with (for example `--remote`)."
        + (HAYABUSA_CHOICE if hayabusa else "")
    )


def main() -> int:
    text = warning()
    if text:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
