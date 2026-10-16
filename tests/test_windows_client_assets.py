"""The Windows client fetches the same sift-mcp files the Linux client does.

sift-mcp moved claude-code/'s files into shared/ and full/; the Linux and macOS
scripts followed, the Windows one kept four old paths, which return 404, so a
Windows client never got CLAUDE.md, the discipline files or the audit hook.
Each script's map of destination file name -> sift-mcp path must match.
"""

import re
from pathlib import Path

ROOT = Path(__file__).parent.parent


def linux_assets(text: str) -> dict[str, str]:
    """curl -fsSL "…/sift-mcp/main/<path>" -o "<dest>": dest's file name -> path.
    The skills, fetched as skills/MANIFEST lists them, aren't fixed files, and
    the Codex section's files are Codex's."""
    text = re.sub(r"# ---- Codex:.*?(?=# ---- Phase 6)", "", text, flags=re.S)
    pairs = re.findall(r'sift-mcp/main/([^"\s]+)"\s+-o\s+"([^"]+)"', text)
    return {
        dest.rsplit("/", 1)[-1]: path
        for path, dest in pairs
        if not path.startswith("skills/")
    }


def windows_assets(text: str) -> dict[str, str]:
    """@{ Name = "<dest>"; Url = "…/sift-mcp/main/<path>"; … }: name -> path."""
    return dict(
        re.findall(r'Name = "([^"]+)"; Url = "[^"]*sift-mcp/main/([^"]+)"', text)
    )


def test_the_windows_client_fetches_what_the_linux_client_fetches():
    linux = linux_assets((ROOT / "setup-client-linux.sh").read_text())
    windows = windows_assets((ROOT / "setup-client-windows.ps1").read_text())
    assert len(linux) == 5, linux  # an empty match must not pass
    assert windows == linux
