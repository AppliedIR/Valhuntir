"""Codex's managed layer on a SIFT workstation.

`/etc/codex/requirements.toml` (root's, so every Codex session on the machine
follows it) keeps Codex's own sandbox on, keeps its shell off the signing
store, the gateway's tokens and the Valhuntir profile, and runs Valhuntir's
hooks: the case-data guard, the audit (with the text typed into a running
shell) and the start-up check. The hooks run from root-owned copies in
`/etc/codex/vhir-hooks/`.

The file is ours when it carries the marker line. An administrator's own
file is never changed: the block to merge is printed, and the controls are
reported as not in effect. Installing takes sudo and the examiner's consent;
otherwise the exact commands are printed. The documented opt-out moves the
file away, and `codex_controls_state` then reports CODEX CONTROLS OFF.
"""

from __future__ import annotations

import difflib
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

CODEX_ETC = Path("/etc/codex")
REQUIREMENTS = CODEX_ETC / "requirements.toml"
HOOKS_DIR = CODEX_ETC / "vhir-hooks"
MARKER = "# managed-by: valhuntir"
# (published name, where it is in sift-mcp/claude-code/)
HOOKS = (
    ("case-data-guard.sh", "shared/hooks/case-data-guard.sh"),
    ("forensic-audit.sh", "shared/hooks/forensic-audit.sh"),
    ("codex-stdin-capture.sh", "shared/hooks/codex-stdin-capture.sh"),
    ("case-dir-check.sh", "full/hooks/case-dir-check.sh"),
)
USERNS = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
USERNS_NOTICE = (
    "  NOTE: this kernel restricts unprivileged user namespaces "
    "(kernel.apparmor_restrict_unprivileged_userns=1), so Codex's sandbox "
    "can't start and its shell commands will fail. An administrator can allow "
    "it; see sift-mcp/docs/codex.md#sandbox."
)
OFF = "CODEX CONTROLS OFF"


def ours(text: str) -> bool:
    """Whether a requirements file is Valhuntir's (its marker line leads)."""
    return MARKER in text.splitlines()[:3]


def userns_restricted() -> bool:
    try:
        return USERNS.read_text().strip() == "1"
    except OSError:
        return False


def codex_controls_state(clients=()) -> str:
    """ "on" (our file in place), "admin-file" (someone else's), "off" (none,
    on a box set up for Codex: the opt-out) or "absent"."""
    try:
        text = REQUIREMENTS.read_text()
    except FileNotFoundError:
        return "off" if "codex" in clients else "absent"
    except OSError:
        return "admin-file"
    return "on" if ours(text) else "admin-file"


def _sources() -> tuple[str, list[tuple[str, Path]]] | None:
    """The requirements template and the hooks to install, from sift-mcp."""
    from vhir_cli.commands.client_setup import _find_claude_code_assets

    assets = _find_claude_code_assets()
    if assets is None:
        return None
    template = assets.parent / "codex" / "requirements.toml"
    hooks = [(name, assets / rel) for name, rel in HOOKS]
    if not template.is_file() or not all(p.is_file() for _, p in hooks):
        return None
    return template.read_text(), hooks


def render(template: str, home: Path) -> str:
    return template.replace("{home}", str(home)).replace("{hooks}", str(HOOKS_DIR))


def _commands(staged: Path, hooks) -> list[list[str]]:
    root = ["-o", "root", "-g", "root"]
    cmds = [["sudo", "install", "-d", "-m", "0755", *root, str(HOOKS_DIR)]]
    cmds += [["sudo", "install", "-m", "0755", *root, str(src), str(HOOKS_DIR / name)]
             for name, src in hooks]  # fmt: skip
    cmds.append(
        ["sudo", "install", "-m", "0644", *root, str(staged), str(REQUIREMENTS)]
    )
    return cmds


def _same(text: str, hooks) -> bool:
    try:
        if REQUIREMENTS.read_text() != text:
            return False
        return all((HOOKS_DIR / n).read_bytes() == s.read_bytes() for n, s in hooks)
    except OSError:
        return False


def deploy_codex_controls(consent: bool | None = None) -> str:
    """Install or update the managed layer. consent=None asks on a terminal
    (and prints the commands without one); True installs (sudo may ask for a
    password); False prints the commands. Returns "installed", "updated",
    "unchanged", "admin-file", "printed" or "missing" (no sift-mcp assets)."""
    if userns_restricted():
        print(USERNS_NOTICE)
    found = _sources()
    if found is None:
        print(
            "  Codex controls: sift-mcp's codex/ files weren't found; nothing installed."
        )
        return "missing"
    template, hooks = found
    text = render(template, Path.home())
    try:
        current = REQUIREMENTS.read_text()
    except FileNotFoundError:
        current = None
    except OSError as e:
        print(f"  Codex controls NOT in effect: {REQUIREMENTS} can't be read ({e}).")
        return "admin-file"
    if current is not None and not ours(current):
        print(
            f"  {REQUIREMENTS} is an administrator's own file; Valhuntir doesn't change it."
        )
        print(
            "  Codex controls NOT in effect. To have them, merge this block into it:\n"
        )
        print(text)
        return "admin-file"
    if current is not None and _same(text, hooks):
        return "unchanged"
    with tempfile.TemporaryDirectory(prefix="vhir-codex-") as tmp:
        staged = Path(tmp) / "requirements.toml"
        staged.write_text(text)
        cmds = _commands(staged, hooks)
        if consent is None and sys.stdin.isatty():
            if current is None:
                print(
                    f"  Codex's managed requirements, to install as {REQUIREMENTS}:\n"
                )
                print(text)
            else:
                diff = difflib.unified_diff(current.splitlines(), text.splitlines(),
                                            str(REQUIREMENTS), "new", lineterm="")  # fmt: skip
                print("\n".join(diff))
            print(
                "  This applies to every Codex session on this machine. To turn it "
                "off later, see sift-mcp/docs/codex.md#opt-out."
            )
            consent = input("  Install it (needs sudo)? [y/N] ").strip().lower() == "y"
        if consent:
            for cmd in cmds:
                try:
                    r = subprocess.run(cmd, timeout=120)
                except (OSError, subprocess.TimeoutExpired) as e:
                    r = None
                    print(f"  {shlex.join(cmd)} failed: {e}")
                if r is None or r.returncode != 0:
                    consent = False
                    break
            else:
                print(f"  Codex controls installed: {REQUIREMENTS}, {HOOKS_DIR}/")
                print(
                    "  Codex sessions already running (and the Codex app-server, if "
                    "it runs) keep the old rules until they're restarted."
                )
                return "installed" if current is None else "updated"
        print("  Codex controls NOT installed. To install them, run:")
        for cmd in _commands(Path("<this file>"), hooks)[:-1]:
            print(f"    {shlex.join(cmd)}")
        print(f"    sudo tee {REQUIREMENTS} >/dev/null <<'EOF'\n{text}EOF")
        return "printed"
