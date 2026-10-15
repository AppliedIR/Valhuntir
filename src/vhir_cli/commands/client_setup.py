"""Generate LLM client configuration pointing at Valhuntir API servers.

On SIFT, MCP entries use ``type: http`` in global ``~/.claude.json``.
On remote clients, entries use ``type: streamable-http`` in project
``.mcp.json``.  Runs on the machine where the human sits; points at
gateway / wintools / REMnux endpoints wherever they are.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from pathlib import Path

from vhir_cli.setup.config_gen import _write_600

# ---------------------------------------------------------------------------
# External reference MCPs (optional, public, no auth)
# ---------------------------------------------------------------------------
_ZELTSER_MCP = {
    "name": "zeltser-ir-writing",
    "type": "streamable-http",
    "url": "https://website-mcp.zeltser.com/mcp",
}

_MSLEARN_MCP = {
    "name": "microsoft-learn",
    "type": "streamable-http",
    "url": "https://learn.microsoft.com/api/mcp",
}

# Forensic deny rules — must match claude-code/settings.json source template
_FORENSIC_ALLOW_RULES = {
    "mcp__forensic-mcp__*",
    "mcp__case-mcp__*",
    "mcp__sift-mcp__*",
    "mcp__report-mcp__*",
    "mcp__forensic-rag-mcp__*",
    "mcp__windows-triage-mcp__*",
    "mcp__opencti-mcp__*",
    "mcp__threatintel-mcp__*",
    "mcp__wintools-mcp__*",
    "mcp__remnux-mcp__*",
    "mcp__vhir__*",
    "mcp__zeltser-ir-writing__*",
    "mcp__microsoft-learn__*",
}

_FORENSIC_DENY_RULES = {
    "Edit(**/findings.json)",
    "Edit(**/timeline.json)",
    "Edit(**/approvals.jsonl)",
    "Edit(**/todos.json)",
    "Edit(**/CASE.yaml)",
    "Edit(**/actions.jsonl)",
    "Edit(**/audit/*.jsonl)",
    "Edit(**/evidence.json)",
    "Edit(**/evidence-verified.json)",
    "Edit(**/iocs.json)",
    "Read(//var/lib/vhir/**)",
    "Edit(//var/lib/vhir/**)",
    # The gateway's tokens and Claude Code's own state, as Codex's shell is denied them
    "Read(**/.vhir/gateway.yaml)",
    "Read(~/.vhir/gateway.yaml)",
    "Read(~/.claude.json)",
    "Bash(vhir approve*)",
    "Bash(*vhir approve*)",
    "Bash(vhir reject*)",
    "Bash(*vhir reject*)",
    # Control file self-protection (anti-accident, anti-injection)
    "Edit(**/.claude/settings.json)",
    "Edit(**/.claude/CLAUDE.md)",
    "Edit(**/.claude/rules/**)",
    "Edit(**/.vhir/hooks/**)",
    "Edit(**/.vhir/active_case)",
    "Edit(**/.vhir/gateway.yaml)",
    "Edit(**/.vhir/config.yaml)",
    "Edit(**/.vhir/.password_lockout)",
    # Sync with template (was in settings.json but missing here)
    "Edit(**/pending-reviews.json)",
    # The same rules anchored at the home folder: "**/" matches inside the
    # session's folder only
    "Edit(~/.claude/settings.json)",
    "Edit(~/.claude/CLAUDE.md)",
    "Edit(~/.claude/rules/**)",
    "Edit(~/.vhir/hooks/**)",
    "Edit(~/.vhir/active_case)",
    "Edit(~/.vhir/gateway.yaml)",
    "Edit(~/.vhir/config.yaml)",
    "Edit(~/.vhir/.password_lockout)",
    # Deployed skills and agents, and the Codex folders
    "Edit(~/.claude/skills/**)",
    "Edit(~/.claude/agents/**)",
    "Edit(~/.agents/**)",
    "Edit(~/.codex/**)",
    # Host identity's records and the case paths map
    "Edit(**/host-observations.jsonl)",
    "Edit(**/host-decisions.jsonl)",
    "Edit(**/host-ops.json)",
    "Edit(**/host-dictionary.yaml)",
    "Edit(**/.vhir/case-paths.json)",
    "Edit(~/.vhir/case-paths.json)",
}

# Old forensic deny rules — removed during migration re-deploy. The
# single-slash /var/lib/vhir rules matched nothing: "//" marks an absolute
# path in a permission rule.
# The copies a project deployment makes under its .claude/ (off SIFT): the
# product settings' home-anchored rules don't reach them, so the project's
# own settings get these, anchored at the project's root ("/" in a project
# settings file). Uninstall removes them with the rest.
_PROJECT_COPY_DENY = ("Edit(/.claude/skills/**)", "Edit(/.claude/agents/**)")

_OLD_FORENSIC_DENY_RULES = {
    "Bash(rm -rf *)",
    "Bash(mkfs*)",
    "Bash(dd *)",
    "Read(/var/lib/vhir/**)",
    "Edit(/var/lib/vhir/**)",
    # Every Write( rule: an Edit rule already covers the tools that write
    # files, so these only added lines to the client's start-up output
    "Write(**/findings.json)",
    "Write(**/timeline.json)",
    "Write(**/approvals.jsonl)",
    "Write(**/todos.json)",
    "Write(**/CASE.yaml)",
    "Write(**/actions.jsonl)",
    "Write(**/audit/*.jsonl)",
    "Write(**/evidence.json)",
    "Write(**/evidence-verified.json)",
    "Write(**/iocs.json)",
    "Write(/var/lib/vhir/**)",
    "Write(**/.claude/settings.json)",
    "Write(**/.claude/CLAUDE.md)",
    "Write(**/.claude/rules/**)",
    "Write(**/.vhir/hooks/**)",
    "Write(**/.vhir/active_case)",
    "Write(**/.vhir/gateway.yaml)",
    "Write(**/.vhir/config.yaml)",
    "Write(**/.vhir/.password_lockout)",
    "Write(**/pending-reviews.json)",
}

# Valhuntir MCP names — used for uninstall identification.
_VHIR_BACKEND_NAMES = {
    "forensic-mcp",
    "case-mcp",
    "sift-mcp",
    "report-mcp",
    "forensic-rag-mcp",
    "windows-triage-mcp",
    "opencti-mcp",
    "threatintel-mcp",
    "opensearch-mcp",
    "wintools-mcp",
    "remnux-mcp",
    "vhir",
    "zeltser-ir-writing",
    "microsoft-learn",
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def cmd_setup_client(args, identity: dict) -> None:
    """Generate LLM client configuration for Valhuntir endpoints.

    With -y (unless --ask-user-files), a user file that would change is
    changed after a backup, with an alert, and the commands that undo it are
    printed at exit, even after an error."""
    global _APPLIED, _ALLOW_UNSANDBOXED
    auto = getattr(args, "yes", False) and not getattr(args, "ask_user_files", False)
    _APPLIED = [] if auto else None
    _ALLOW_UNSANDBOXED = _allow_unsandboxed(args)
    try:
        _setup_client(args, identity)
    finally:
        _ALLOW_UNSANDBOXED = False
        changed, _APPLIED = _APPLIED or [], None
        if changed:
            import shlex

            print(
                "\n  vhir setup client -y changed these files. To undo, run these in a"
            )
            print("  normal terminal (not inside a Claude session):")
            for bak, path in changed:
                if path.name == ".claude.json":
                    print(
                        "    # This also reverts what Claude Code saved there since;"
                        " close Claude Code first."
                    )
                print(f"    cp -p {shlex.quote(str(bak))} {shlex.quote(str(path))}")


CLAUDE_CODE = "claude-code"


def _allow_unsandboxed(args) -> bool:
    """Whether --allow-unsandboxed is confirmed: only by the phrase typed on
    a terminal. -y never gives it (the sandbox then stays required); with no
    terminal to type it on, nothing is deployed."""
    if not getattr(args, "allow_unsandboxed", False):
        return False
    if getattr(args, "yes", False):
        print(
            "  --allow-unsandboxed needs the typed phrase, which -y doesn't give: "
            "Claude Code still refuses to start without a working sandbox."
        )
        return False
    if not sys.stdin.isatty():
        print(
            "Error: --allow-unsandboxed needs the phrase typed on a terminal. "
            "Nothing was deployed.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(
        "  With this, Claude Code runs Bash with NO sandbox when bubblewrap can't "
        "start,\n  instead of refusing to start. The forensic write and read "
        "limits on Bash are then gone."
    )
    typed = input(f"  Type {UNSANDBOXED_PHRASE} to go on: ")
    if typed.strip() != UNSANDBOXED_PHRASE:
        print("Error: the phrase didn't match. Nothing was deployed.", file=sys.stderr)
        sys.exit(1)
    return True


def _setup_client(args, identity: dict) -> None:
    if getattr(args, "uninstall", False):
        _cmd_uninstall(args)
        return

    if getattr(args, "add_remnux", None) is not None:
        _cmd_add_remnux(args)
        return

    if getattr(args, "remote", False):
        _cmd_setup_client_remote(args, identity)
        return

    auto = getattr(args, "yes", False)

    # 1. Resolve parameters from switches (or interactive wizard)
    client = _resolve_client(args, auto)
    if client == "claude-desktop":
        print(DESKTOP_DROPPED, file=sys.stderr)
        sys.exit(1)
    if client == "codex" and not _is_sift():
        print(CODEX_OFF_SIFT, file=sys.stderr)
        sys.exit(1)
    sift_url = _resolve_sift(args, auto)
    windows_url, windows_token = _resolve_windows(args, auto)
    remnux_url, remnux_token = _resolve_remnux(args, auto)
    examiner = _resolve_examiner(args, identity)
    include_zeltser, include_mslearn = _resolve_internet_mcps(args, auto)

    # 2. Build endpoint list
    servers: dict[str, dict] = {}

    if sift_url:
        # Try to discover per-backend endpoints from the running gateway
        backends_discovered = False
        local_token = _read_local_token()
        services = _discover_services(sift_url, local_token)
        if services:
            running = [s for s in services if s.get("started")]
            not_started = [s["name"] for s in services if not s.get("started")]
            if not_started:
                print(
                    f"Warning: {len(not_started)} backend(s) not started and excluded "
                    f"from config: {', '.join(not_started)}",
                    file=sys.stderr,
                )
                print(
                    "Run 'vhir service status' to diagnose. "
                    "These backends can be added manually later.",
                    file=sys.stderr,
                )
            if running:
                backends_discovered = True
                for s in running:
                    name = s["name"]
                    entry: dict = {
                        "type": "streamable-http",
                        "url": f"{sift_url.rstrip('/')}/mcp/{name}",
                    }
                    if local_token:
                        entry["headers"] = {"Authorization": f"Bearer {local_token}"}
                    servers[name] = entry

        if not backends_discovered:
            # Gateway not reachable or no backends — fall back to aggregate
            entry = {
                "type": "streamable-http",
                "url": _ensure_mcp_path(sift_url),
            }
            if local_token:
                entry["headers"] = {"Authorization": f"Bearer {local_token}"}
            servers["vhir"] = entry

    if windows_url:
        win_entry: dict = {
            "type": "streamable-http",
            "url": _ensure_mcp_path(windows_url),
        }
        if windows_token:
            win_entry["headers"] = {"Authorization": f"Bearer {windows_token}"}
        servers["wintools-mcp"] = win_entry

    if remnux_url:
        remnux_entry: dict = {
            "type": "streamable-http",
            "url": _ensure_mcp_path(remnux_url),
        }
        if remnux_token:
            remnux_entry["headers"] = {"Authorization": f"Bearer {remnux_token}"}
            _test_remnux_connection(remnux_url, remnux_token)
        servers["remnux-mcp"] = remnux_entry

    if include_zeltser:
        servers[_ZELTSER_MCP["name"]] = {
            "type": _ZELTSER_MCP["type"],
            "url": _ZELTSER_MCP["url"],
        }

    if include_mslearn:
        servers[_MSLEARN_MCP["name"]] = {
            "type": _MSLEARN_MCP["type"],
            "url": _MSLEARN_MCP["url"],
        }

    # opensearch-mcp — detect if installed, add as stdio for Claude Code
    import importlib.util

    if (
        importlib.util.find_spec("opensearch_mcp") is not None
        and "opensearch-mcp" not in servers
    ):
        servers["opensearch-mcp"] = {
            "type": "stdio",
            "command": sys.executable,
            "args": ["-I", "-m", "opensearch_mcp"],
        }

    if not servers:
        print("No endpoints configured — nothing to write.", file=sys.stderr)
        return

    # 3. Generate config for selected client
    try:
        _generate_config(client, servers, examiner)
    except OSError as e:
        print(f"Failed to write client configuration: {e}", file=sys.stderr)
        sys.exit(1)

    # 4. Record the client in the manifest (for vhir update)
    _record_client(client)

    # 5. Print internet MCP summary
    internet_mcps = []
    if include_zeltser:
        internet_mcps.append((_ZELTSER_MCP["name"], _ZELTSER_MCP["url"]))
    if include_mslearn:
        internet_mcps.append((_MSLEARN_MCP["name"], _MSLEARN_MCP["url"]))
    if internet_mcps:
        print("  Internet MCPs:")
        for name, url in internet_mcps:
            print(f"    {name:<25s}{url}")


# ---------------------------------------------------------------------------
# SIFT detection
# ---------------------------------------------------------------------------


def _is_sift() -> bool:
    """Return True if running on a SIFT workstation (gateway.yaml exists)."""
    return (Path.home() / ".vhir" / "gateway.yaml").is_file()


# ---------------------------------------------------------------------------
# Parameter resolution
# ---------------------------------------------------------------------------


def _resolve_client(args, auto: bool) -> str:
    val = getattr(args, "client", None)
    if val:
        return val
    if auto:
        return "claude-code"
    return _wizard_client()


def _resolve_sift(args, auto: bool) -> str:
    val = getattr(args, "sift", None)
    if val is not None:
        return val  # explicit switch (even "" means "no sift")

    # Auto-detect local gateway
    from vhir_cli.gateway import get_local_gateway_url

    default = get_local_gateway_url()
    if auto:
        return default

    detected = _probe_health(default)
    if detected:
        status = "detected running"
    else:
        status = "not detected, will use default"

    print("\n--- SIFT Workstation (Gateway) ---")
    print("The Valhuntir gateway runs on your SIFT workstation and provides")
    print("forensic tools (forensic-mcp, sift-mcp, forensic-rag, etc.).")
    print()
    print(f"  Default:  {default}  ({status})")
    print("  Format:   URL              Example: http://10.0.0.2:4508")
    print('  Enter "skip" to omit.')

    answer = _prompt("\nSIFT gateway URL", default)
    if answer.lower() == "skip":
        return ""
    return answer


def _resolve_windows(args, auto: bool) -> tuple[str, str]:
    """Resolve Windows wintools-mcp URL and bearer token.

    Returns:
        (url, token) tuple.  Either or both may be empty.
    """
    val = getattr(args, "windows", None)
    token = getattr(args, "windows_token", None) or ""

    if val is not None:
        url = _normalise_url(val, 4624, scheme="https") if val else ""
        if url and not token:
            token = _prompt_windows_token()
        return url, token
    if auto:
        return "", ""

    # If the gateway already has wintools registered, skip — the gateway proxies it
    from pathlib import Path

    gw_yaml = Path.home() / ".vhir" / "gateway.yaml"
    if gw_yaml.is_file():
        try:
            import yaml

            gw_config = yaml.safe_load(gw_yaml.read_text()) or {}
            backends = gw_config.get("backends", {})
            if "wintools-mcp" in backends:
                wt = backends["wintools-mcp"]
                wt_url = wt.get("url", "")
                print("\n--- Windows Forensic Workstation ---")
                print(f"  Already registered via gateway: {wt_url}")
                print("  The gateway proxies wintools — no direct connection needed.")
                print("  Skipping.")
                return "", ""
        except Exception:
            pass

    print("\n--- Windows Forensic Workstation ---")
    print("If you have a Windows workstation running wintools-mcp, enter its")
    print("IP address or hostname. The default port is 4624.")
    print("This adds a DIRECT connection from your LLM client to wintools.")
    print("If wintools is already joined to the gateway, you can skip this.")
    print()
    print("  Format:   IP or IP:PORT     Examples: 192.168.1.20, 10.0.0.5:4624")
    print("  Find it:  On the Windows box, run: ipconfig | findstr IPv4")

    answer = _prompt("\nWindows endpoint", "skip")
    if answer.lower() == "skip":
        return "", ""
    url = _normalise_url(answer, 4624, scheme="https")
    if not url:
        return "", ""
    token = token or _prompt_windows_token()
    return url, token


def _prompt_windows_token() -> str:
    """Prompt for the Windows wintools-mcp bearer token."""
    print()
    print("  Wintools requires a bearer token for HTTPS connections.")
    print("  Find it:  On the Windows box, check the installer output or")
    print("            C:\\ProgramData\\vhir\\config.yaml (bearer_token field)")
    return _prompt("\nWindows bearer token", "")


def _resolve_remnux(args, auto: bool) -> tuple[str, str]:
    """Resolve REMnux URL and bearer token.

    Returns:
        (url, token) tuple.  Either or both may be empty.
    """
    val = getattr(args, "remnux", None)
    token = getattr(args, "remnux_token", None) or ""

    if val:
        # Explicit value provided (e.g., --remnux=IP:PORT)
        url = _normalise_url(val, 3000)
        if url and not token:
            token = _prompt_remnux_token()
        return url, token
    if val is None and auto:
        return "", ""

    print("\n--- REMnux Malware Analysis Workstation ---")
    print("If you have a REMnux VM running remnux-mcp, enter its IP address.")
    print()
    print("  Find it:  On the REMnux box, run: ip addr show | grep inet")

    ip = _prompt("\nREMnux IP address", "skip")
    if ip.lower() == "skip" or not ip.strip():
        return "", ""
    port = _prompt("REMnux port", "3000")
    url = _normalise_url(f"{ip.strip()}:{port.strip()}", 3000)
    if not url:
        return "", ""
    token = token or _prompt_remnux_token()
    return url, token


def _prompt_remnux_token() -> str:
    """Prompt for the REMnux bearer token."""
    print()
    print("  REMnux requires a bearer token for HTTP connections.")
    print("  Find it:  On the REMnux box, run: echo $MCP_TOKEN")
    return _prompt("\nREMnux bearer token", "")


def _resolve_internet_mcps(args, auto: bool) -> tuple[bool, bool]:
    """Resolve which internet MCPs to include. Returns (zeltser, mslearn)."""
    no_mslearn = getattr(args, "no_mslearn", False)

    if auto:
        return (True, not no_mslearn)

    print("\n--- Internet MCPs (public, no auth required) ---")
    print("These connect your LLM client directly to public knowledge servers.")
    print()
    print("  Zeltser IR Writing   Required for the IR reporting feature")

    include_mslearn = _prompt_yn(
        "  Microsoft Learn      Search Microsoft docs and code samples",
        default=True,
    )

    return (True, include_mslearn)


def _resolve_examiner(args, identity: dict) -> str:
    val = getattr(args, "examiner", None)
    if val:
        return val
    return identity.get("examiner", "unknown")


# ---------------------------------------------------------------------------
# Interactive wizard
# ---------------------------------------------------------------------------


def _wizard_client() -> str:
    print("\n=== Valhuntir Client Configuration ===")
    print("Which LLM client will connect to your Valhuntir endpoints?\n")
    print("  1. Claude Code      CLI agent (writes .mcp.json + CLAUDE.md)")
    print("  2. Codex            CLI agent (writes ~/.codex/valhuntir.config.toml)")
    print("  3. LibreChat        Web UI (writes librechat_mcp.yaml)")
    print("  4. Open WebUI       Web UI (writes its lock profile and system prompt)")
    print("  5. Other / manual   Raw JSON config for any MCP client")

    choice = _prompt("\nChoose", "1")
    return {
        "1": "claude-code",
        "2": "codex",
        "3": "librechat",
        "4": "open-webui",
        "5": "other",
    }.get(choice, "other")


def _prompt(message: str, default: str = "") -> str:
    try:
        if default:
            answer = input(f"{message} [{default}]: ").strip()
            return answer or default
        return input(f"{message}: ").strip()
    except EOFError:
        return default


def _prompt_yn(message: str, default: bool = True) -> bool:
    """Prompt for a yes/no answer. Returns bool."""
    hint = "Y/n" if default else "y/N"
    try:
        answer = input(f"{message} [{hint}]: ").strip().lower()
    except EOFError:
        return default
    if not answer:
        return default
    return answer in ("y", "yes")


def _prompt_yn_strict(message: str) -> bool:
    """Prompt for y/n with no default. Loops until explicit answer."""
    while True:
        try:
            answer = input(f"{message} [y/n]: ").strip().lower()
        except EOFError:
            return False
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("    Please enter y or n.")


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------


def _claude_mcp_add_available() -> bool:
    """Check if claude CLI is available."""
    import shutil

    return shutil.which("claude") is not None


def _claude_mcp_add(name: str, entry: dict) -> None:
    """Register one MCP server via claude mcp add.

    ARGV ORDER IS LOAD-BEARING. Claude Code CLI's ``-H / --header``
    option is variadic. When ``-H`` precedes the positional name/url,
    commander.js consumes those values as additional header strings,
    leaving the command with zero positionals — the CLI errors out,
    and on some versions silently wipes existing entries before
    erroring. Name and url MUST appear before the first ``-H``.

    Raises ``RuntimeError`` on any CLI failure so the caller can
    abort the rest of the registration loop and restore the
    ``~/.claude.json`` snapshot it took. Silently continuing on
    failure (pre-fix behavior) resulted in partial-wipe states where
    the visible "Registered N MCP servers" banner lied about how many
    actually landed.
    """
    import subprocess

    url = entry.get("url", "")
    if not url:
        return
    # Remove existing entry first (idempotent)
    subprocess.run(
        ["claude", "mcp", "remove", name, "-s", "user"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    # Positional name + url BEFORE any -H flags (see docstring).
    cmd = ["claude", "mcp", "add", "-t", "http", "-s", "user", name, url]
    for k, v in entry.get("headers", {}).items():
        cmd.extend(["-H", f"{k}: {v}"])
    result = subprocess.run(cmd, capture_output=True, stdin=subprocess.DEVNULL)
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace")[:200]
        print(
            f"  WARNING: claude mcp add {name} failed: {stderr}",
            file=sys.stderr,
        )
        raise RuntimeError(f"claude mcp add {name} failed: {stderr}")


def _duplicate_backends(servers: dict, path: Path | None = None) -> list[str]:
    """Per-backend entries in `path` (~/.claude.json) that duplicate gateway
    routing, and an `opencti-mcp` entry for the same gateway once its current
    name `threatintel-mcp` is written: one threat-intel entry."""
    _BACKEND_NAMES = {
        "forensic-mcp",
        "case-mcp",
        "sift-mcp",
        "report-mcp",
        "forensic-rag-mcp",
        "windows-triage-mcp",
        "opencti-mcp",
        "threatintel-mcp",
        "opensearch-mcp",
        "wintools-mcp",
        "forensic-rag",
        "windows-triage",
    }
    gw_url = (servers.get("vhir") or servers.get("threatintel-mcp") or {}).get(
        "url", ""
    )
    if not gw_url:
        return []
    names = _BACKEND_NAMES if "vhir" in servers else set()
    if "threatintel-mcp" in servers:
        names = names | {"opencti-mcp"}
    gw = _gateway_of(gw_url)
    try:
        existing = json.loads((path or Path.home() / ".claude.json").read_text())[
            "mcpServers"
        ]
    except (OSError, ValueError, KeyError, TypeError):
        return []
    if not isinstance(existing, dict):
        return []
    return [
        name
        for name, entry in existing.items()
        if name in names
        and name not in servers
        and isinstance(entry, dict)
        and gw is not None
        and _gateway_of(str(entry.get("url", "")), routed=True) == gw
    ]


def _gateway_of(url: str, routed: bool = False) -> tuple | None:
    """A URL's gateway: its scheme, host and port, compared exactly (so :4508
    is never :45080). `routed`: only a per-backend route under /mcp/."""
    from urllib.parse import urlsplit

    try:
        u = urlsplit(url)
        where = (u.scheme.lower(), u.hostname, u.port)
    except ValueError:
        return None
    if not u.scheme or not u.hostname or (routed and not u.path.startswith("/mcp/")):
        return None
    return where


def _cleanup_duplicate_backends(servers: dict, path: Path | None = None) -> None:
    """Remove per-backend entries that duplicate gateway routing."""
    claude_json = path or Path.home() / ".claude.json"
    removed = _duplicate_backends(servers, claude_json)
    if not removed:
        return
    try:
        data = json.loads(claude_json.read_text())
        for name in removed:
            del data["mcpServers"][name]
        _write_600(claude_json, json.dumps(data, indent=2) + "\n")
        print(f"  Removed duplicate backend entries: {', '.join(removed)}")
    except (json.JSONDecodeError, OSError, KeyError):
        pass


def _claude_json_plan(path: Path, servers: dict) -> tuple[list, list] | None:
    """The Valhuntir entries registering `servers` would add to and change in
    path (an entry differing from what Valhuntir writes, e.g. the user's
    edit, is a change). None if path isn't valid JSON."""
    try:
        current = (
            json.loads(path.read_text()).get("mcpServers", {}) if path.is_file() else {}
        )
    except (ValueError, OSError, AttributeError):
        return None
    if not isinstance(current, dict):  # e.g. "mcpServers": null
        current = {}

    def same(have, want):
        if not isinstance(have, dict):  # e.g. null: replace it
            return False
        if "url" not in want:
            return have == want
        keys = ("type", "url", "headers")
        return all((have.get(k) or None) == (want.get(k) or None) for k in keys)

    added = [n for n in servers if n not in current]
    changed = [n for n in servers if n in current and not same(current[n], servers[n])]
    return added, changed


def _announce_claude_json(path: Path, plan: tuple, removed: list) -> None:
    """Back up ~/.claude.json before Valhuntir changes it, and say what changes."""
    added, changed = plan
    if not (added or changed or removed) or not path.is_file():
        return
    bak = _backup(path)
    if _APPLIED is not None:  # -y: in the undo block too
        _APPLIED.append((bak, path))
    for label, names in (("added", added), ("removed (duplicates)", removed)):
        if names:
            print(f"  Valhuntir MCP entries {label}: {', '.join(names)}")
    if changed:
        print(
            f"  Valhuntir MCP entries updated: {', '.join(changed)} (they differed "
            "from what Valhuntir writes; the previous version is in the backup)"
        )


def _generate_config(client: str, servers: dict, examiner: str) -> None:
    config = {"mcpServers": servers}
    sift = _is_sift()

    if client == "claude-code":
        # Standardize type to "http" for gateway entries only
        # (not external services like mslearn/zeltser, or stdio entries)
        for entry in servers.values():
            if entry.get("type") == "streamable-http" and "url" in entry:
                entry["type"] = "http"

        if sift:
            # SIFT: prefer claude mcp add (canonical, reliable)
            if _claude_mcp_add_available():
                # Snapshot ~/.claude.json before mutation so a mid-loop
                # failure (claude CLI bump changing argv semantics,
                # auth issue, etc.) can be rolled back. Without this,
                # a failed run leaves the operator with fewer MCP
                # registrations than they started with — the CRITICAL
                # regression Test observed after Claude Code 2.1.116.
                claude_config = Path.home() / ".claude.json"
                snapshot: bytes | None = None
                if claude_config.is_file():
                    try:
                        snapshot = claude_config.read_bytes()
                    except OSError as e:
                        print(
                            f"  WARNING: could not snapshot {claude_config}: {e}",
                            file=sys.stderr,
                        )

                # Only what `claude mcp add` registers: entries with a url
                cli = {n: e for n, e in servers.items() if e.get("url")}
                plan = _claude_json_plan(claude_config, cli) or (list(cli), [])
                _announce_claude_json(claude_config, plan, _duplicate_backends(servers))
                todo = {n: cli[n] for n in plan[0] + plan[1]}
                registered = 0
                try:
                    for name, entry in todo.items():
                        _claude_mcp_add(name, entry)
                        registered += 1
                except RuntimeError as e:
                    # Restore snapshot so the operator isn't left in a
                    # worse state than before.
                    if snapshot is not None:
                        try:
                            claude_config.write_bytes(snapshot)
                            print(
                                f"  Restored {claude_config} from pre-run snapshot.",
                                file=sys.stderr,
                            )
                        except OSError as restore_err:
                            print(
                                f"  WARNING: snapshot restore failed: {restore_err}",
                                file=sys.stderr,
                            )
                    print(
                        f"  Registered {registered} of {len(todo)} MCP servers before "
                        f"aborting: {e}",
                        file=sys.stderr,
                    )
                    raise SystemExit(1) from e
                print(f"  Registered {registered} MCP servers via claude mcp add")
            else:
                global_config = Path.home() / ".claude.json"
                plan = _claude_json_plan(global_config, servers)
                if plan is None:
                    print(
                        f"  Not changed: {global_config} isn't valid JSON; MCP servers NOT "
                        "registered. Fix it and re-run `vhir setup client`.",
                        file=sys.stderr,
                    )
                else:
                    _announce_claude_json(
                        global_config, plan, _duplicate_backends(servers)
                    )
                    # Only the entries that change: an unchanged entry keeps
                    # any fields the user added to it.
                    todo = {n: servers[n] for n in plan[0] + plan[1]}
                    _merge_and_write(global_config, {"mcpServers": todo})
                    print(f"  Generated: {global_config} (global MCP servers)")
                    print("  NOTE: If tools don't load, try: claude mcp add ...")
            # Clean up per-backend duplicates from prior installs
            _cleanup_duplicate_backends(servers)
        else:
            output = Path.cwd() / ".mcp.json"
            stale = _duplicate_backends(servers, output)
            if stale:  # backed up and announced, as ~/.claude.json is
                _announce_claude_json(output, ([], []), stale)
            _merge_and_write(output, {"mcpServers": servers})
            _cleanup_duplicate_backends(servers, output)
            print(f"  Generated: {output}")

        settings = _deploy_claude_code_assets(Path.cwd())
        print(f"  Examiner:  {examiner}")
        print("")
        if settings:
            from vhir_cli.controls import print_block

            if settings[1] != "kept":
                print(f"  Forensic controls deployed{' globally' if sift else ''}.")
                print("  Start Claude Code from the case folder (cd <case>; claude).")
            else:
                print(f"  Forensic controls NOT applied to {settings[0]}; see above.")
            print_block(CLAUDE_CODE, settings[0], sift=sift)  # as installed now

    elif client == "codex":
        from vhir_cli.commands.codex_controls import deploy_codex_controls
        from vhir_cli.controls import print_block

        deploy_codex_assets(servers)
        # -y installs the managed requirements (sudo may ask); otherwise asked
        deploy_codex_controls(consent=True if _APPLIED is not None else None)
        print(f"  Examiner:  {examiner}")
        print("")
        print("  Start Codex in a case folder with Valhuntir's profile:")
        print("    cd <case folder> && codex -p valhuntir")
        print_block("codex")  # what is installed now

    elif client == "open-webui":
        _write_openwebui(servers)
        _print_mcp_block()

    elif client == "librechat":
        output = Path.cwd() / "librechat_mcp.yaml"
        _write_librechat_yaml(output, servers)
        print(f"  Generated: {output}")
        print(_LIBRECHAT_POST_INSTALL)
        _print_mcp_block()

    else:
        # Manual / other — just dump JSON
        output = Path.cwd() / "vhir-mcp-config.json"
        _merge_and_write(output, config)
        print(f"  Generated: {output}")
        print("")
        print(f"  NOTE: {OTHER_CLIENT_NOTICE}")
        _print_mcp_block()


def _print_mcp_block() -> None:
    from vhir_cli.controls import MCP, print_block

    print("")
    print_block(MCP)


def _find_claude_code_assets() -> Path | None:
    """Locate the sift-mcp/claude-code/ directory.

    Search order:
    1. Well-known paths relative to sift-mcp installation
    2. ~/.vhir/src/sift-mcp/claude-code/
    3. /opt/vhir/sift-mcp/claude-code/
    """
    candidates = [
        lambda: Path.home() / ".vhir" / "src" / "sift-mcp" / "claude-code",
        lambda: Path.home() / "vhir" / "sift-mcp" / "claude-code",
        lambda: Path("/opt/vhir/sift-mcp/claude-code"),
    ]

    # Also check gateway.yaml for sift-mcp source path
    gw_config = Path.home() / ".vhir" / "gateway.yaml"
    if gw_config.is_file():
        try:
            import yaml

            config = yaml.safe_load(gw_config.read_text()) or {}
            src_dir = config.get("sift_mcp_dir", "")
            if src_dir:
                candidate = Path(src_dir) / "claude-code"
                if candidate.is_dir():
                    return candidate
        except Exception:
            pass

    for fn in candidates:
        p = fn()
        if p.is_dir():
            return p
    return None


_PRODUCT_HOOKS = ("forensic-audit.sh", "case-dir-check.sh", "case-data-guard.sh")
# One of them, at a place setup puts it, in a hook's command: a project's
# `$CLAUDE_PROJECT_DIR/.claude/hooks/` or (Lite) `$CLAUDE_PROJECT_DIR/hooks/`,
# or a `.claude/hooks/` folder by its path; then the end, a quote, a space, a
# redirect or a separator. A script of the same name elsewhere is the user's.
_OUR_HOOK_SCRIPT = re.compile(
    r"(?:\$\{?CLAUDE_PROJECT_DIR\}?/(?:\.claude/)?hooks/|/\.claude/hooks/)(?:"
    + "|".join(re.escape(h) for h in _PRODUCT_HOOKS)
    + r")(?=$|[\s\"'<>|;&)])"
)
# read by the audit hooks: the shell commands with an MCP route, and the
# sidecar that looks a command up
_HOOK_DATA = ("mcp-route.py", "mcp-routes.tsv")

# `--allow-unsandboxed`, confirmed with the typed phrase: Claude Code may then
# run without a sandbox when bwrap can't start (failIfUnavailable: false).
_ALLOW_UNSANDBOXED = False
UNSANDBOXED_PHRASE = "RUN CLAUDE CODE WITHOUT A SANDBOX"
# `vhir setup client -y`: (backup, path) of each user file it changed. None
# when a change is asked about on a terminal, or kept, instead.
_APPLIED: list | None = None
# Launcher files _isolate_gateway_launchers rewrote in this process.
_LAUNCHERS_UPDATED: list[Path] = []
# Launcher files already noted in this process (an update reaches them twice).
_LAUNCHERS_NOTED: set[Path] = set()


def _backup(path: Path) -> Path:
    """Copy path's bytes to <name>.vhir-backup-<UTC stamp> beside it (never *.md)."""
    from datetime import datetime, timezone

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bak = path.with_name(f"{path.name}.vhir-backup-{stamp}")
    n = 1
    while bak.exists():
        n += 1
        bak = path.with_name(f"{path.name}.vhir-backup-{stamp}-{n}")
    shutil.copy2(path, bak)
    print(f"  Backed up: {path} -> {bak}")
    return bak


def _replace_bytes(dst: Path, data: bytes, mode: int) -> None:
    """Atomically replace dst's content; a symlink is kept and its target
    written. The temp file is unpredictable and created with mode."""
    import tempfile

    real = dst.resolve() if dst.is_symlink() else dst
    real.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        dir=str(real.parent), prefix=f".{real.name}.", suffix=".tmp"
    )
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, real)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


# keys/ holds each examiner's credential, ledger/ the chains and the case lock
SIGNING_DIRS = (Path("/var/lib/vhir/keys"), Path("/var/lib/vhir/ledger"))


def _signing_dir_state(folder: Path) -> str:
    """ "fine": this user's, writable, nothing inside root's; "missing";
    "give back": root's, or this user's with a bad mode or root's files inside;
    "other": another account's (never touched: one examiner OS user per box)."""
    try:
        if not folder.is_dir():
            return "missing"
        uid = folder.stat().st_uid
    except OSError:
        return "missing"
    if uid not in (0, os.getuid()):
        return "other"
    if uid == 0 or not os.access(folder, os.W_OK | os.X_OK):
        return "give back"
    try:
        if any(e.stat(follow_symlinks=False).st_uid == 0 for e in os.scandir(folder)):
            return "give back"
    except OSError:
        return "give back"
    return "fine"


def ensure_signing_dirs() -> None:
    """Make the signing folders this box lacks, and give back one that is
    root's (with what root left inside) or this user's but unusable: owned by
    this user, 0700 (/var/lib/vhir is root's: sudo). A folder another account
    owns is left alone, with the installer's refusal. Never raises: a failure
    prints the command to run instead."""
    import getpass
    import subprocess

    from vhir_cli import credentials

    user = getpass.getuser()
    for folder in SIGNING_DIRS:
        state = _signing_dir_state(folder)
        if state == "fine":
            continue
        if state == "other":
            print(f"  {credentials.other_owner_text(folder)}", file=sys.stderr)
            continue
        what = "Giving back" if state == "give back" else "Creating"
        print(f"  {what} {folder}... ", end="", flush=True)
        # only root's entries change hands: never another account's
        script = (
            f"mkdir -p {folder} && find {folder} -xdev -uid 0 -exec chown -h "
            f"{user}:{user} {{}} + && chmod 700 {folder}"
        )
        try:
            ok = (
                subprocess.run(
                    ["sudo", "sh", "-c", script],
                    capture_output=True, text=True, timeout=300,  # sudo may ask a password
                ).returncode
                == 0
            )  # fmt: skip
        except (OSError, subprocess.SubprocessError):
            ok = False
        if ok:
            print("done")
            continue
        print("failed")
        print(
            f"  Run manually: sudo mkdir -p {folder} && sudo find {folder} -xdev -uid 0 "
            f"-exec chown -h $USER:$USER {{}} + && sudo chmod 700 {folder}",
            file=sys.stderr,
        )


# Run in a process of its own (see _ensure_signing_dirs_fresh)
_ENSURE_SCRIPT = (
    "from vhir_cli.commands.client_setup import ensure_signing_dirs; "
    "ensure_signing_dirs()"
)


def _ensure_signing_dirs_fresh() -> None:
    """ensure_signing_dirs in a fresh Python process. An older vhir's update
    has its own modules loaded (vhir_cli.identity among them), so this code's
    imports can't run in it; a new process imports only this code. Its output
    and sudo's prompt use this terminal. Never raises."""
    import subprocess

    try:
        subprocess.run(
            [sys.executable, "-I", "-c", _ENSURE_SCRIPT], timeout=900, check=False
        )
    except (OSError, subprocess.SubprocessError) as e:
        print(f"  The signing folders weren't made ({e}); run `vhir update` again.")


def _under_an_older_update() -> bool:
    """True inside `vhir update` of a vhir from before the signing folders.
    That update pulls this code, then imports this module and calls
    `_isolate_gateway_launchers` from it, so this is where one update makes
    them. Its own update module, loaded first, lacks `_ensure_signing_dirs`;
    this vhir's has it (and makes the folders itself), and nothing else
    loads it, so tests never get here."""
    running = sys.modules.get("vhir_cli.commands.update")
    return running is not None and not hasattr(running, "_ensure_signing_dirs")


def _isolate_gateway_launchers() -> list[Path]:
    """Add -I to the gateway launch line in the files setup-sift.sh writes
    (~/.vhir/start-gateway.sh and the user unit), so the gateway never imports
    from the directory it starts in. setup-sift.sh rewrites both files whole
    on every run; here only the generated line changes. A line that differs
    (edited by the user) is left with a notice. Keeps the file's mode and a
    symlink. Never raises: an older vhir update runs this unguarded.
    Returns the files rewritten. Inside an older vhir's update, the signing
    folders are made here first."""
    import re
    import subprocess

    if _under_an_older_update():
        _ensure_signing_dirs_fresh()

    forms = (  # (file, the generated line); the paths vary per install
        (
            Path.home() / ".vhir" / "start-gateway.sh",
            re.compile(r'(exec "[^"]+/bin/python") (-m sift_gateway --config "[^"]+")'),
        ),
        (
            Path.home() / ".config" / "systemd" / "user" / "vhir-gateway.service",
            re.compile(r"(ExecStart=\S+/bin/python) (-m sift_gateway --config \S+)"),
        ),
    )
    updated = []
    for path, generated in forms:
        try:
            if not path.is_file():
                continue
            lines = path.read_bytes().decode().splitlines(keepends=True)
            launch = [i for i, ln in enumerate(lines) if "-m sift_gateway" in ln]
            if not launch or all(
                " -I " in lines[i].split("-m sift_gateway")[0] for i in launch
            ):
                continue  # no launch line, or already isolated
            changed = False
            for i in launch:
                body = lines[i].rstrip("\n")
                m = generated.fullmatch(body)
                if m:
                    lines[i] = f"{m[1]} -I {m[2]}" + lines[i][len(body) :]
                    changed = True
            if not changed:
                if path in _LAUNCHERS_NOTED:
                    continue
                _LAUNCHERS_NOTED.add(path)
                print(
                    f"  Note: {path} has a gateway launch line Valhuntir didn't write;"
                    " add -I after its python (python -I -m sift_gateway) so the gateway"
                    " never imports from the directory it starts in."
                )
                continue
            mode = (
                path.resolve() if path.is_symlink() else path
            ).stat().st_mode & 0o7777
            _replace_bytes(path, "".join(lines).encode(), mode)
            updated.append(path)
            _LAUNCHERS_UPDATED.append(path)
            print(f"  Updated: {path} (added -I to the gateway launch line)")
            if path.suffix == ".service":
                try:
                    subprocess.run(
                        ["systemctl", "--user", "daemon-reload"],
                        capture_output=True,
                        timeout=30,
                        check=True,
                    )
                except (OSError, subprocess.SubprocessError):
                    print(
                        "  Note: run `systemctl --user daemon-reload` so the next"
                        " gateway restart uses the updated unit."
                    )
        except Exception as e:  # noqa: BLE001 - never stop an update over this
            if path not in _LAUNCHERS_NOTED:
                _LAUNCHERS_NOTED.add(path)
                print(f"  Note: could not check {path}: {e}")
    return updated


def _shipped(dst: Path, src: Path) -> bool:
    """Whether dst's bytes are a version of src the product shipped: dst's
    blob id appears in the history of src's checkout (HEAD, following
    renames). src may be gone from the checkout (a retired file). Without git
    or a checkout: False, so the user is asked."""
    import subprocess

    def git(*args):
        return subprocess.run(
            ["git", *args], capture_output=True, text=True, timeout=30
        )

    try:
        here = next(p for p in src.parents if p.is_dir())
        top = git("-C", str(here), "rev-parse", "--show-toplevel")
        if top.returncode:
            return False
        root = Path(top.stdout.strip()).resolve()
        rel = src.resolve().relative_to(root)
        log = git(
            "-C",
            str(root),
            "log",
            "HEAD",
            "--follow",
            "--format=",
            "--raw",
            "--no-abbrev",
            "--",
            str(rel),
        )
        blob = git("hash-object", str(dst))
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    ids = {
        f
        for ln in log.stdout.splitlines()
        if ln.startswith(":")
        for f in ln.split()[2:4]
    }
    return blob.returncode == 0 and blob.stdout.strip() in ids


def _write_user_file(
    path: Path,
    new: str,
    why: str,
    as_json: bool = False,
    mode: int | None = None,
    redact=None,
) -> str:
    """Write a file the user may have edited, only with their consent.

    Returns "created" (no file was there), "unchanged" (nothing would change),
    "written" (they said yes, or `vhir setup client -y`; a backup was made
    first) or "kept". Asks only on a terminal (default Yes; n/no keeps);
    otherwise prints the change and keeps the file.
    """
    if not path.exists():
        if mode is None:
            mode = 0o600 if as_json else 0o644
        _replace_bytes(path, new.encode(), mode)
        return "created"
    try:
        old = path.read_text()
    except (UnicodeDecodeError, OSError) as e:
        print(f"  Not changed: {path} can't be compared as text ({e}); kept.")
        return "kept"
    if as_json:
        try:
            before, after = json.loads(old), json.loads(new)
        except json.JSONDecodeError as e:
            print(f"  Not changed: {path} isn't valid JSON ({e}); fix it and re-run.")
            return "kept"
        if before == after:
            return "unchanged"
        old = json.dumps(before, indent=2, sort_keys=True) + "\n"
        new_view = json.dumps(after, indent=2, sort_keys=True) + "\n"
    elif old == new:
        return "unchanged"
    else:
        new_view = new
    import difflib

    print(f"\n  vhir would change {path} ({why}):")
    diff = difflib.unified_diff(
        old.splitlines(), new_view.splitlines(), "current", "proposed", lineterm=""
    )
    for line in diff:
        print(f"    {redact(line) if redact else line}")
    if _APPLIED is None and not sys.stdin.isatty():
        print(
            f"  Not changed: {path}. To review and apply, re-run `vhir update` "
            "or `vhir setup client` in a terminal."
        )
        return "kept"
    if _APPLIED is None and input(
        f"  Apply these changes to {path}? [Y/n] "
    ).strip().lower() not in ("", "y", "yes"):
        print(f"  Kept: {path} unchanged.")
        return "kept"
    bak = _backup(path)
    _replace_bytes(path, new.encode(), path.stat().st_mode & 0o777)
    if _APPLIED is not None:  # -y: applied without asking; say so loudly
        _APPLIED.append((bak, path))
        print(f"\n  *** -y: vhir CHANGED {path}\n  *** ({why})", file=sys.stderr)
        print(f"  *** Your previous version: {bak}\n", file=sys.stderr)
    return "written"


def _deploy_copy(src: Path | None, dst: Path, mode: int = 0o644) -> str:
    """Deploy a product file: create it, leave it, update a version the
    product shipped ("updated", with a notice), or ask about anything the
    user wrote (see _write_user_file)."""
    if not src or not src.is_file():
        return "missing"
    if not dst.exists():
        _replace_bytes(dst, src.read_bytes(), mode)
        print(f"  Deployed:  {dst}")
        return "created"
    if dst.read_bytes() == src.read_bytes():
        return "unchanged"
    if _shipped(dst, src):
        _replace_bytes(dst, src.read_bytes(), mode)
        print(f"  Updated:   {dst} (an earlier version vhir shipped)")
        return "updated"
    why = "it differs from every version vhir shipped, so it may hold your edits"
    return _write_user_file(dst, src.read_text(), why)


def _gateway_ca_for_settings(
    existing_env: dict | None,
) -> tuple[str, str, str | None] | None:
    """How a local Claude Code should trust the gateway's self-signed CA.

    When the local gateway is configured for TLS and its CA file exists (the
    precondition of get_local_ssl_context), a local client has to trust that
    CA or every gateway MCP connection fails with
    UNABLE_TO_VERIFY_LEAF_SIGNATURE. Returns, with the CA's absolute path:
      ("add", ca, None)     set env.NODE_EXTRA_CA_CERTS to the CA;
      ("notice", ca, value) NODE_EXTRA_CA_CERTS is already set (in the
                            settings env, else the process environment) to
                            `value` — keep it and tell the user to add the CA
                            to that bundle;
      ("overridden", ca, value) the settings env holds the CA and the shell
                            sets `value`, which the settings entry overrides;
      None                  no local TLS gateway/CA, or the CA is already it.

    The settings env wins over the process environment because Claude Code
    honours settings env for HTTP MCP connections and it overrides the
    process environment, so an unconditional write could silently replace a
    user's own NODE_EXTRA_CA_CERTS (e.g. a corporate TLS-inspection CA).
    """
    from vhir_cli.gateway import local_gateway_ca_cert

    ca = local_gateway_ca_cert()
    if not ca:
        return None
    env_val = os.environ.get("NODE_EXTRA_CA_CERTS")
    if isinstance(existing_env, dict) and "NODE_EXTRA_CA_CERTS" in existing_env:
        # A settings value wins at runtime, so an explicit one (even "") decides,
        # whatever the process environment holds. Presence, not truthiness: a
        # deliberate "" still blocks trust, so keep it and say so.
        value = existing_env["NODE_EXTRA_CA_CERTS"]
        if value == ca:
            # Ours already; warn only if a different shell value is overridden.
            if env_val and env_val != ca:
                return ("overridden", ca, env_val)
            return None
        return ("notice", ca, value)
    if not env_val:
        return ("add", ca, None)
    if env_val == ca:
        return None
    return ("notice", ca, env_val)


def _merged_settings(
    target: Path, source: Path, hooks_dir: Path | None, project_copies: bool = False
) -> dict | None:
    """The settings target would hold after merging source in: lists keep the
    user's order with missing entries appended. hooks_dir rewrites the
    product hooks' commands to it (global deployment). project_copies adds
    the deny rules for a project's own skill and agent copies (the non-SIFT
    project write). None if unreadable."""
    try:
        existing = json.loads(target.read_text()) if target.is_file() else {}
    except json.JSONDecodeError as e:
        print(f"  Not changed: {target} isn't valid JSON ({e}); fix it and re-run.")
        return None
    except OSError as e:
        print(f"  Not changed: {target} can't be read ({e}).")
        return None
    try:
        incoming = json.loads(source.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"  Warning: could not read source settings: {e}", file=sys.stderr)
        return None

    def add_missing(current: list, extra: list) -> list:
        return current + [x for x in extra if x not in current]

    # Deep-merge hooks: merge arrays for each hook type
    if "hooks" in incoming:
        existing_hooks = existing.setdefault("hooks", {})
        for hook_type, entries in incoming["hooks"].items():
            if hook_type not in existing_hooks:
                existing_hooks[hook_type] = entries
            else:
                # Deduplicate by (matcher, script basename) pair
                # When a match is found, REPLACE the old command (handles path renames)
                existing_by_key: dict[tuple, dict] = {}
                for entry in existing_hooks[hook_type]:
                    matcher = entry.get("matcher", "")
                    for h in entry.get("hooks", []):
                        cmd = h.get("command", "")
                        basename = cmd.rsplit("/", 1)[-1] if "/" in cmd else cmd
                        existing_by_key[(matcher, basename)] = h
                for entry in entries:
                    matcher = entry.get("matcher", "")
                    matched = False
                    for h in entry.get("hooks", []):
                        cmd = h.get("command", "")
                        basename = cmd.rsplit("/", 1)[-1] if "/" in cmd else cmd
                        key = (matcher, basename)
                        if key in existing_by_key:
                            # Replace old command with new (handles .aiir → .vhir)
                            existing_by_key[key]["command"] = cmd
                            matched = True
                    if not matched:
                        existing_hooks[hook_type].append(entry)

    # Remove deprecated hooks from existing settings
    _DEPRECATED_HOOKS = {"pre-bash-guard.sh"}
    if "hooks" in existing:
        for hook_type in list(existing["hooks"]):
            existing["hooks"][hook_type] = [
                entry
                for entry in existing["hooks"][hook_type]
                if not any(
                    any(dh in h.get("command", "") for dh in _DEPRECATED_HOOKS)
                    for h in entry.get("hooks", [])
                )
            ]
            if not existing["hooks"][hook_type]:
                del existing["hooks"][hook_type]

    # Global deployment: the product hooks run from hooks_dir
    if hooks_dir:
        for entries in existing.get("hooks", {}).values():
            for entry in entries:
                for h in entry.get("hooks", []):
                    name = h.get("command", "").rsplit("/", 1)[-1]
                    if name in _PRODUCT_HOOKS:
                        h["command"] = str(hooks_dir / name)

    # Merge permissions (additive, preserve ask/defaultMode)
    if "permissions" in incoming:
        existing_perms = existing.setdefault("permissions", {})
        for key in ("allow", "deny"):
            if key in incoming["permissions"]:
                current = existing_perms.get(key, [])
                if key == "deny":  # Remove old forensic rules
                    current = [r for r in current if r not in _OLD_FORENSIC_DENY_RULES]
                existing_perms[key] = add_missing(current, incoming["permissions"][key])
    if project_copies:
        deny = existing.setdefault("permissions", {}).setdefault("deny", [])
        existing["permissions"]["deny"] = add_missing(deny, list(_PROJECT_COPY_DENY))

    # Merge sandbox config: every list (filesystem.denyWrite, denyRead, ...)
    # is a union, so the user's own entries stay
    if "sandbox" in incoming:
        existing_sandbox = existing.setdefault("sandbox", {})
        incoming_sandbox = incoming["sandbox"]
        if "filesystem" in incoming_sandbox:
            existing_fs = existing_sandbox.setdefault("filesystem", {})
            for k, v in incoming_sandbox["filesystem"].items():
                if isinstance(v, list) and isinstance(existing_fs.get(k), list):
                    existing_fs[k] = add_missing(existing_fs[k], v)
                else:
                    existing_fs[k] = v
        # Merge top-level sandbox keys (enabled, allowUnsandboxedCommands;
        # a list is a union here too)
        for k, v in incoming_sandbox.items():
            if k == "filesystem":
                continue
            if isinstance(v, list) and isinstance(existing_sandbox.get(k), list):
                existing_sandbox[k] = add_missing(existing_sandbox[k], v)
            else:
                existing_sandbox[k] = v
        if _ALLOW_UNSANDBOXED:  # confirmed with the typed phrase
            existing_sandbox["failIfUnavailable"] = False

    # The gateway-CA env (env.NODE_EXTRA_CA_CERTS) is NOT merged here: it is a
    # client-connectivity convenience, not a forensic control, so settings_applied
    # (which calls this) must not judge a box that lacks it. It is decided and
    # written only on deploy, in _merge_settings.
    return existing


def settings_applied(target: Path) -> tuple[bool, bool]:
    """(every control as shipped, sandbox off by choice) for the Claude Code
    settings file `target`: merging the product's settings into it would
    change nothing. A sandbox turned off with the typed phrase
    (failIfUnavailable false) is a choice, not a gap: it reads SANDBOX OFF."""
    assets = _find_claude_code_assets()
    sources = (
        [assets / d / "settings.json" for d in ("full", "shared", ".")]
        if assets
        else []
    )
    source = next((p for p in sources if p.is_file()), None)
    try:
        current = json.loads(target.read_text())
    except (OSError, ValueError):
        return False, False
    if source is None or not isinstance(current, dict):
        return False, False
    hooks_dir = None
    if target == Path.home() / ".claude" / "settings.json":
        hooks_dir = Path.home() / ".vhir" / "hooks"  # global: the hooks run from there
    merged = _merged_settings(target, source, hooks_dir)
    off = isinstance(current.get("sandbox"), dict) and (
        current["sandbox"].get("failIfUnavailable") is False
    )
    if merged is not None and off:
        merged.setdefault("sandbox", {})["failIfUnavailable"] = False
    return merged == current, off


def _merge_settings(
    target: Path,
    source: Path,
    hooks_dir: Path | None = None,
    project_copies: bool = False,
) -> str:
    """Merge the product's hooks, permissions and sandbox into target, only
    with the user's consent (see _write_user_file). Returns its status."""
    merged = _merged_settings(target, source, hooks_dir, project_copies)
    if merged is None:
        return "kept"
    decision = _gateway_ca_for_settings(merged.get("env"))
    if decision and decision[0] == "add":
        if "env" not in merged:
            merged["env"] = {"NODE_EXTRA_CA_CERTS": decision[1]}
        elif isinstance(merged["env"], dict):
            merged["env"]["NODE_EXTRA_CA_CERTS"] = decision[1]
        else:
            print(
                "  Note: env in settings.json isn't an object, so "
                "NODE_EXTRA_CA_CERTS wasn't added. The gateway uses a "
                f"self-signed CA, so add {decision[1]} to NODE_EXTRA_CA_CERTS "
                "by hand or the local client can't verify the gateway."
            )
    elif decision and decision[0] == "notice":
        print(
            f"  Note: NODE_EXTRA_CA_CERTS is already set to {decision[2]}; "
            "left unchanged. The gateway uses a self-signed CA, so add "
            f"{decision[1]} to that bundle or the local client can't verify "
            "the gateway."
        )
    elif decision and decision[0] == "overridden":
        print(
            f"  Note: NODE_EXTRA_CA_CERTS in your shell is {decision[2]}, but "
            f"the settings.json entry ({decision[1]}) overrides it. To use your "
            "own bundle, add the gateway CA to it and remove the settings.json "
            "entry."
        )
    why = "the forensic hooks, deny rules and sandbox Valhuntir relies on"
    return _write_user_file(
        target, json.dumps(merged, indent=2) + "\n", why, as_json=True
    )


def _deploy_hook(source: Path, target: Path) -> str:
    """Deploy a hook script (executable)."""
    return _deploy_copy(source, target, 0o755)


def _deploy_claude_md(src: Path | None, target: Path) -> str:
    """Deploy CLAUDE.md; the first copy of a user's own file stays as .md.bak."""
    if not src or not src.is_file():
        print("  Warning: CLAUDE.md not found in assets.", file=sys.stderr)
        return "missing"
    bak = target.with_suffix(".md.bak")
    original = target.read_bytes() if target.is_file() and not bak.exists() else None
    status = _deploy_copy(src, target)
    if status == "written" and original is not None:
        bak.write_bytes(original)
    return status


def _deploy_global_rules(
    discipline_src: Path | None,
    toolref_src: Path | None,
) -> None:
    """Deploy discipline docs to ~/.claude/rules/ (SIFT only). The tool
    reference is a skill now: the copy vhir put in rules/ retires."""
    rules_dir = Path.home() / ".claude" / "rules"
    _retire(
        rules_dir / "TOOL_REFERENCE.md", toolref_src, "the vhir-tool-reference skill"
    )
    for src, name in [
        (discipline_src, "FORENSIC_DISCIPLINE.md"),
        (_find_agents_md(global_rule=True), "AGENTS.md"),  # never the cwd's
    ]:
        _deploy_copy(src, rules_dir / name)


def _deploy_claude_code_assets(project_dir: Path | None = None) -> tuple | None:
    """Deploy settings.json, hooks, skills, and doc files for Claude Code.

    Sources from sift-mcp/claude-code/ directory (shared/ + full/).
    On SIFT: deploys globally (settings to ~/.claude/, hook to ~/.vhir/hooks/).
    On non-SIFT: deploys to project directory.

    project_dir is optional on SIFT (global deployment doesn't need it).
    When None, project-level doc copies are skipped.

    A file the user may have edited changes only with their consent (see
    _write_user_file). Returns (settings path, its status) or None.
    """
    # Here, not only in update: an older vhir update reaches the new code
    # only through this call, between its pull and its gateway restart.
    _isolate_gateway_launchers()
    assets_dir = _find_claude_code_assets()
    if not assets_dir:
        print(
            "  Note: sift-mcp claude-code assets not found. "
            "Hook and settings deployment skipped."
        )
        return None

    # Resolve shared and mode directories (new layout: shared/ + full/)
    shared_dir = assets_dir / "shared"
    mode_dir = assets_dir / "full"
    if not shared_dir.is_dir() or not mode_dir.is_dir():
        # Legacy flat layout — treat assets_dir as both shared and mode
        shared_dir = assets_dir
        mode_dir = assets_dir

    def _find_asset(name: str) -> Path | None:
        """Find asset file: mode_dir first, then shared_dir."""
        for d in (mode_dir, shared_dir):
            p = d / name
            if p.exists():
                return p
        return None

    def _find_hook(hook_name: str) -> Path | None:
        """Find hook script: mode hooks first, then shared hooks."""
        for d in (mode_dir, shared_dir):
            p = d / "hooks" / hook_name
            if p.is_file():
                return p
        return None

    sift = _is_sift()

    if sift:
        # --- SIFT global deployment ---

        # Deploy settings.json to ~/.claude/settings.json
        settings_src = _find_asset("settings.json")
        settings_target = Path.home() / ".claude" / "settings.json"
        if settings_src:
            hooks_dir = Path.home() / ".vhir" / "hooks"
            settings = (
                settings_target,
                _merge_settings(settings_target, settings_src, hooks_dir),
            )
            _report_settings(*settings)

        # Deploy hook scripts to ~/.vhir/hooks/
        for hook_name in _PRODUCT_HOOKS:
            _deploy_hook(
                _find_hook(hook_name), Path.home() / ".vhir" / "hooks" / hook_name
            )
        for name in _HOOK_DATA:
            _deploy_copy(_find_hook(name), Path.home() / ".vhir" / "hooks" / name)

        _drop_deprecated_hooks(Path.home() / ".vhir" / "hooks", settings_target)

        # Deploy CLAUDE.md globally
        _deploy_claude_md(
            _find_asset("CLAUDE.md"),
            Path.home() / ".claude" / "CLAUDE.md",
        )

        # Deploy discipline docs to ~/.claude/rules/
        _deploy_global_rules(
            discipline_src=_find_asset("FORENSIC_DISCIPLINE.md"),
            toolref_src=_find_asset("TOOL_REFERENCE.md"),
        )

        # Commands (/welcome now points to the vhir-welcome skill), then the
        # skills and the skeptic's agent
        commands_src = mode_dir / "commands"
        if commands_src.is_dir():
            commands_target = Path.home() / ".claude" / "commands"
            for skill_file in commands_src.glob("*.md"):
                _deploy_copy(skill_file, commands_target / skill_file.name)
        deploy_skills(Path.home() / ".claude" / "skills")
        _deploy_copy(
            _sift_root_dir("agents") / "finding-skeptic" / "claude.md"
            if _sift_root_dir("agents")
            else None,
            Path.home() / ".claude" / "agents" / "finding-skeptic.md",
        )

        # Also deploy docs to project root (contextual, harmless)
        if project_dir:
            for doc_name in ("FORENSIC_DISCIPLINE.md", "TOOL_REFERENCE.md"):
                _deploy_copy(_find_asset(doc_name), project_dir / doc_name)

            _copy_agents_md(project_dir / "AGENTS.md")
        return settings if settings_src else None

    else:
        # --- Non-SIFT project-level deployment ---

        # Deploy settings.json to project
        settings_src = _find_asset("settings.json")
        settings_target = project_dir / ".claude" / "settings.json"
        if settings_src:
            settings = (
                settings_target,
                _merge_settings(settings_target, settings_src, project_copies=True),
            )
            _report_settings(*settings)

        # Deploy hook scripts to project
        for hook_name in _PRODUCT_HOOKS:
            _deploy_hook(
                _find_hook(hook_name), project_dir / ".claude" / "hooks" / hook_name
            )
        for name in _HOOK_DATA:
            _deploy_copy(_find_hook(name), project_dir / ".claude" / "hooks" / name)

        _drop_deprecated_hooks(project_dir / ".claude" / "hooks", settings_target)

        # Deploy CLAUDE.md to project root
        _deploy_claude_md(
            _find_asset("CLAUDE.md"),
            project_dir / "CLAUDE.md",
        )

        # Commands, then the skills and the skeptic's agent, as on SIFT but
        # in the project's .claude/
        commands_src = mode_dir / "commands"
        if commands_src.is_dir():
            commands_target = project_dir / ".claude" / "commands"
            for skill_file in commands_src.glob("*.md"):
                _deploy_copy(skill_file, commands_target / skill_file.name)
        deploy_skills(project_dir / ".claude" / "skills")
        _deploy_copy(
            _sift_root_dir("agents") / "finding-skeptic" / "claude.md"
            if _sift_root_dir("agents")
            else None,
            project_dir / ".claude" / "agents" / "finding-skeptic.md",
        )

        # Copy AGENTS.md to project root
        _copy_agents_md(project_dir / "AGENTS.md")

        # Deploy FORENSIC_DISCIPLINE.md and TOOL_REFERENCE.md
        for doc_name in ("FORENSIC_DISCIPLINE.md", "TOOL_REFERENCE.md"):
            _deploy_copy(_find_asset(doc_name), project_dir / doc_name)
        return settings if settings_src else None


def _sift_root_dir(name: str) -> Path | None:
    """A folder at the top of the sift-mcp checkout (skills/, agents/)."""
    assets = _find_claude_code_assets()
    folder = assets.parent / name if assets else None
    return folder if folder and folder.is_dir() else None


def deploy_skills(target: Path) -> None:
    """Deploy every skill in sift-mcp's skills/ under `target` (one folder
    each), file by file through _deploy_copy: a version vhir shipped is
    updated, and an edited one changes only with the user's consent. The
    user's own skills are never touched."""
    source = _sift_root_dir("skills")
    if source is None:
        print("  Note: sift-mcp skills not found. Skill deployment skipped.")
        return
    for skill in sorted(p for p in source.iterdir() if p.is_dir()):
        for src in sorted(skill.rglob("*")):
            if src.is_file():
                _deploy_copy(src, target / src.relative_to(source))


def _retire(dst: Path, src: Path | None, now: str) -> None:
    """A file vhir used to deploy at `dst`: removed if it is a version vhir
    shipped (`src`'s history); kept, with a notice, if it holds the user's
    edits."""
    if not dst.is_file():
        return
    if src is not None and _shipped(dst, src):
        dst.unlink()
        print(f"  Removed:   {dst} (now {now})")
        return
    print(
        f"  Kept:      {dst}: it differs from every version vhir shipped, so it may "
        f"hold your edits. vhir no longer uses it ({now} replaces it); remove it "
        "when you no longer need it."
    )


# --- Codex ---------------------------------------------------------------------

_INTERNET_MCPS = (_ZELTSER_MCP["name"], _MSLEARN_MCP["name"])
OTHER_CLIENT_NOTICE = (
    "Claude Code and Codex are the only supported clients with a shell. A "
    "client that runs shell commands any other way runs them outside every "
    "Valhuntir control. An MCP-only client gets the server-side controls only: "
    "the gateway audit, the case records' rules and signed approvals."
)
DESKTOP_DROPPED = (
    "Claude Desktop is no longer supported: the commands it runs aren't "
    "audited. Use Claude Code on the SIFT workstation, or Claude Code or Codex "
    "on another machine with --remote (their shell commands there aren't in "
    "the case audit)."
)
CODEX_OFF_SIFT = (
    "Codex is set up on the SIFT box itself. On another machine, run "
    "`vhir setup client --remote --client=codex`, or the client setup script."
)


def codex_profile_path() -> Path:
    """Valhuntir's Codex profile: `codex -p valhuntir` reads it."""
    return Path.home() / ".codex" / "valhuntir.config.toml"


def _record_client(client: str) -> None:
    """Add client to the manifest's `clients` (once, in the order they were
    set up) and make it `client`, the latest. Written atomically. No readable
    manifest: nothing is recorded."""
    path = Path.home() / ".vhir" / "manifest.json"
    try:
        manifest = json.loads(path.read_text())
    except (OSError, ValueError):
        return
    if not isinstance(manifest, dict):
        return
    clients = manifest.get("clients")
    clients = (
        [c for c in clients if isinstance(c, str)] if isinstance(clients, list) else []
    )
    earlier = manifest.get("client")
    if isinstance(earlier, str) and earlier not in clients:
        clients.insert(0, earlier)  # set up before the list was kept
    if client not in clients:
        clients.append(client)
    manifest["clients"], manifest["client"] = clients, client
    try:
        mode = path.stat().st_mode & 0o777
        _replace_bytes(path, (json.dumps(manifest, indent=2) + "\n").encode(), mode)
    except OSError:
        pass  # non-critical, as before


def _codex_instructions() -> str | None:
    """developer_instructions: the AGENTS.md core, the forensic discipline and
    the Codex overlay, or None if any is missing."""
    assets = _find_claude_code_assets()  # all three from the one checkout
    parts = (
        [
            assets.parent / "AGENTS.md",
            assets / "full" / "FORENSIC_DISCIPLINE.md",
            assets.parent / "codex" / "OVERLAY.md",
        ]  # fmt: skip
        if assets
        else []
    )
    if not parts or not all(p.is_file() for p in parts):
        return None
    return "\n\n".join(p.read_text().strip() for p in parts) + "\n"


def _toml_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)  # a valid TOML basic string


def _toml_key(key: str) -> str:
    import re

    return key if re.fullmatch(r"[A-Za-z0-9_-]+", key) else _toml_str(key)


def _codex_server(name: str, entry: dict) -> str:
    lines = [f"[mcp_servers.{_toml_key(name)}]"]
    if entry.get("url"):
        lines.append(f"url = {_toml_str(entry['url'])}")
        headers = entry.get("headers") or {}
        if headers:
            inner = ", ".join(
                f"{_toml_key(k)} = {_toml_str(v)}" for k, v in headers.items()
            )
            lines.append(f"http_headers = {{ {inner} }}")
    else:
        lines.append(f"command = {_toml_str(entry['command'])}")
        args = ", ".join(_toml_str(a) for a in entry.get("args", []))
        lines.append(f"args = [{args}]")
    if name not in _INTERNET_MCPS:  # Valhuntir's tools run without a prompt
        lines.append('default_tools_approval_mode = "approve"')
    return "\n".join(lines) + "\n"


def _codex_profile_text(servers: dict, instructions: str, kept: list[str]) -> str:
    quotes = "'" * 3  # a multi-line literal string, when the text allows one
    if quotes in instructions:
        body = _toml_str(instructions)
    else:
        body = quotes + "\n" + instructions + quotes
    head = (
        "# Valhuntir's Codex profile. Start Codex in a case folder with:\n"
        "#   codex -p valhuntir\n"
        "# vhir setup client and vhir update write this file. It holds the\n"
        "# gateway token, so only you can read it.\n"
        'sandbox_mode = "workspace-write"\n'
        'approval_policy = "on-request"\n'
        'web_search = "disabled"\n'
        "project_doc_max_bytes = 0\n"
        f"developer_instructions = {body}\n"
    )
    sections = [_codex_server(n, e) for n, e in servers.items()] + kept
    return head + "".join("\n" + x for x in sections)


def _profile_sections(text: str) -> dict[str, str]:
    """The [mcp_servers.<name>] sections of a profile vhir wrote, by name."""
    import re

    out: dict[str, str] = {}
    name = None
    for line in text.splitlines(keepends=True):
        m = re.match(r"\[mcp_servers\.(\"[^\"]*\"|[A-Za-z0-9_-]+)\]\s*$", line)
        if m:
            key = m.group(1)
            name = json.loads(key) if key.startswith('"') else key
            out[name] = line
        elif line.startswith("["):
            name = None
        elif name is not None:
            out[name] += line
    return {n: t.rstrip("\n") + "\n" for n, t in out.items()}


def _codex_servers_from_box(profile: Path) -> tuple[dict, dict[str, str]] | None:
    """The gateway's backends as this box serves them now, plus opensearch-mcp,
    and the profile's other server sections kept as they are. None if the
    gateway can't be reached."""
    import importlib.util

    from vhir_cli.gateway import get_local_gateway_url

    url = get_local_gateway_url().rstrip("/")
    token = _read_local_token()
    services = _discover_services(url, token)
    running = [s["name"] for s in services or [] if s.get("started")]
    if not running:
        return None
    servers: dict[str, dict] = {}
    for name in running:
        servers[name] = {"url": f"{url}/mcp/{name}"}
        if token:
            servers[name]["headers"] = {"Authorization": f"Bearer {token}"}
    if importlib.util.find_spec("opensearch_mcp") is not None:
        servers.setdefault(
            "opensearch-mcp",
            {"command": sys.executable, "args": ["-I", "-m", "opensearch_mcp"]},
        )
    try:
        old = _profile_sections(profile.read_text()) if profile.is_file() else {}
    except (OSError, UnicodeDecodeError):
        old = {}
    gateway = f'url = "{url}/mcp/'
    # another section is kept, unless it names a gateway backend now gone
    kept = {n: t for n, t in old.items() if n not in servers and gateway not in t}
    return servers, kept


def _manifest_get(key: str):
    try:
        manifest = json.loads((Path.home() / ".vhir" / "manifest.json").read_text())
    except (OSError, ValueError):
        return None
    return manifest.get(key) if isinstance(manifest, dict) else None


def _manifest_set(key: str, value) -> None:
    path = Path.home() / ".vhir" / "manifest.json"
    try:
        manifest = json.loads(path.read_text())
        if not isinstance(manifest, dict):
            return
        manifest[key] = value
        mode = path.stat().st_mode & 0o777
        _replace_bytes(path, (json.dumps(manifest, indent=2) + "\n").encode(), mode)
    except (OSError, ValueError):
        pass


def _redact_tokens(text: str) -> str:
    import re

    text = re.sub(r"(vhir_[a-z]{2}_)[0-9A-Za-z]+", r"\1…", text)
    return re.sub(r"(Bearer\s+)(?!vhir_[a-z]{2}_…)[^\s\"']+", r"\1…", text)


def _write_codex_profile(path: Path, text: str) -> str:
    """Create, or replace a profile vhir wrote last (its sha256 is in the
    manifest); anything else is the user's, changed only with consent."""
    import hashlib

    def record():
        digest = hashlib.sha256(text.encode()).hexdigest()
        _manifest_set("codex_profile_sha256", digest)

    if not path.exists():
        _replace_bytes(path, text.encode(), 0o600)
        record()
        print(f"  Deployed:  {path}")
        return "created"
    try:
        current = path.read_bytes()
    except OSError as e:
        print(f"  Not changed: {path} can't be read ({e}).")
        return "kept"
    if current == text.encode():
        record()
        return "unchanged"
    if hashlib.sha256(current).hexdigest() == _manifest_get("codex_profile_sha256"):
        _replace_bytes(path, text.encode(), 0o600)
        record()
        print(f"  Updated:   {path}")
        return "updated"
    status = _write_user_file(
        path,
        text,
        "it isn't the profile vhir wrote last, so it may hold your edits",
        mode=0o600,
        redact=_redact_tokens,
    )
    if status == "written":
        path.chmod(0o600)
        record()
    return status


def _codex_config_conflicts() -> None:
    """Name each top-level value in the user's ~/.codex/config.toml (never
    written) that Valhuntir's managed Codex settings refuse."""
    import re

    cfg = Path.home() / ".codex" / "config.toml"
    try:
        text = cfg.read_text()
    except (OSError, UnicodeDecodeError):
        return
    allowed = {
        "sandbox_mode": ("read-only", "workspace-write"),
        "approval_policy": ("untrusted", "on-request", "never"),
    }
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            break  # top-level keys come before the first table
        m = re.match(r"(sandbox_mode|approval_policy)\s*=\s*\"([^\"]*)\"", stripped)
        if m and m.group(2) not in allowed[m.group(1)]:
            what = (  # a sandbox mode gives way to the managed permissions profile
                "replace with their own (the workspace, ~/.vhir read-only)"
                if m.group(1) == "sandbox_mode"
                else "refuse: Codex stops with an error until it is changed"
            )
            print(
                f'  Note: {cfg} sets {m.group(1)} = "{m.group(2)}", which '
                f"Valhuntir's managed Codex settings {what}. vhir doesn't edit that file."
            )


def deploy_codex_assets(
    servers: dict | None = None, remote: bool = False, extra: dict | None = None
) -> str:
    """Write Valhuntir's Codex profile, and deploy the skills to
    ~/.agents/skills/ and the skeptic's agent to ~/.codex/agents/.

    servers None (vhir update): rebuilt from this box, with the gateway's
    backends found again; it never prompts for anything new, and keeps the
    profile as it is when the gateway can't be reached. Returns the profile's
    status: created, updated, unchanged, written, kept or missing.

    remote (another machine): the skills, agent and instructions are fetched
    from sift-mcp's main branch, with the remote overlay.

    extra: more server entries ({name: {"url": ..., "headers": {...}}} or
    {"command": ..., "args": [...]}), added to the profile or replacing the
    same-named entry, e.g. a remnux-mcp added later."""
    path = codex_profile_path()
    if remote:
        instructions = _fetch_codex_assets()
        if instructions is None or servers is None:
            print(
                "  Note: Valhuntir's instructions for Codex couldn't be fetched; "
                f"{path} not written. Check the network and re-run."
            )
            return "missing"
        servers = {**servers, **(extra or {})}
        status = _write_codex_profile(
            path, _codex_profile_text(servers, instructions, [])
        )
        _codex_config_conflicts()
        return status
    deploy_skills(Path.home() / ".agents" / "skills")
    agents = _sift_root_dir("agents")
    _deploy_copy(
        agents / "finding-skeptic" / "codex.toml" if agents else None,
        Path.home() / ".codex" / "agents" / "finding-skeptic.toml",
    )
    kept: dict[str, str] = {}
    if servers is None:
        found = _codex_servers_from_box(path)
        if found is None:
            print(
                f"  Kept:      {path}: the gateway can't be reached, so its "
                "backends can't be listed. Run `vhir update` again once it runs."
            )
            return "kept"
        servers, kept = found
    instructions = _codex_instructions()
    if instructions is None:
        print(
            "  Note: Valhuntir's instructions for Codex weren't found (sift-mcp "
            f"AGENTS.md, FORENSIC_DISCIPLINE.md, codex/OVERLAY.md); {path} not written."
        )
        return "missing"
    servers = {**servers, **(extra or {})}
    sections = [t for n, t in kept.items() if n not in servers]
    text = _codex_profile_text(servers, instructions, sections)
    status = _write_codex_profile(path, text)
    _codex_config_conflicts()
    return status


_GITHUB_RAW = "https://raw.githubusercontent.com/AppliedIR/sift-mcp/main"
_SKILL_PATH = r"[A-Za-z0-9._/-]+"
CODEX_REMOTE_LIMITS = (
    "Limits on this machine: Codex's shell commands here aren't in the case "
    "audit (only the MCP tool calls, run on the SIFT box, are), and these "
    "settings are user-switchable: there are no managed Codex settings here."
)


def _fetch_raw(rel: str) -> bytes | None:
    """A file from sift-mcp's main branch on GitHub, or None."""
    import urllib.request

    try:
        with urllib.request.urlopen(f"{_GITHUB_RAW}/{rel}", timeout=20) as resp:
            return resp.read() if resp.status == 200 else None
    except Exception:
        return None


def _deploy_fetched(dst: Path, data: bytes) -> str:
    """Write a fetched file; one that differs from it changes only as a user
    file does (shown, and replaced with consent or -y, after a backup)."""
    try:
        text = data.decode()
    except UnicodeDecodeError:
        return "missing"
    status = _write_user_file(
        dst, text, "it differs from what vhir fetched, so it may hold your edits"
    )
    if status == "created":
        print(f"  Deployed:  {dst}")
    return status


def _fetch_codex_assets() -> str | None:
    """Fetch the skills to ~/.agents/skills/ and the skeptic's agent to
    ~/.codex/agents/, as sift-mcp's main branch has them. Returns the remote
    developer_instructions, or None if a part couldn't be fetched."""
    import re

    skills = Path.home() / ".agents" / "skills"
    listed = _fetch_raw("skills/MANIFEST")
    if listed is None:
        print("  Warning: the skills list couldn't be fetched; skills not deployed.")
    else:
        for rel in listed.decode(errors="replace").splitlines():
            if not rel or rel.startswith("#"):
                continue
            if not re.fullmatch(_SKILL_PATH, rel) or ".." in rel or rel.startswith("/"):
                print(f"  Warning: skipped an unexpected skills path: {rel}")
                continue
            data = _fetch_raw(f"skills/{rel}")
            if data is None:
                print(f"  Warning: couldn't fetch skills/{rel}")
                continue
            _deploy_fetched(skills / rel, data)
    agent = _fetch_raw("agents/finding-skeptic/codex.toml")
    if agent is None:
        print("  Warning: the finding-skeptic agent couldn't be fetched.")
    else:
        _deploy_fetched(
            Path.home() / ".codex" / "agents" / "finding-skeptic.toml", agent
        )
    parts = [
        _fetch_raw(p)
        for p in (
            "AGENTS.md",
            "claude-code/full/FORENSIC_DISCIPLINE.md",
            "codex/OVERLAY.md",
            "codex/REMOTE.md",
        )
    ]
    if any(p is None for p in parts):
        return None
    return "\n\n".join(p.decode().strip() for p in parts) + "\n"


def _setup_codex_remote(servers: dict) -> None:
    """Remote Codex: the profile, skills and agent on this machine, with the
    instructions fetched from sift-mcp; Codex starts in ~/vhir."""
    start = Path.home() / "vhir"
    start.mkdir(exist_ok=True)
    deploy_codex_assets(servers, remote=True)
    _record_client("codex")
    print("")
    print("  Start Codex from ~/vhir with Valhuntir's profile:")
    print("    cd ~/vhir && codex -p valhuntir")
    print("  Not from your home folder: from there its shell could change ~/.vhir.")
    print(f"  {CODEX_REMOTE_LIMITS}")


def _our_skills(root: Path) -> list[Path]:
    """Valhuntir's skills under `root` (vhir-*, finding-skeptic); a user's own
    are never listed."""
    if not root.is_dir():
        return []
    return sorted(
        d
        for d in root.iterdir()
        if d.is_dir() and (d.name.startswith("vhir-") or d.name == "finding-skeptic")
    )


def _remove_listed(heading: str, found: list[Path]) -> None:
    """List `found`, ask once, and remove them (a link, never its target)."""
    if not found:
        return
    print(f"  {heading}:")
    for p in found:
        print(f"    {p}")
    if not _prompt_yn_strict("  Remove them?"):
        print("  Skipped.")
        return
    for p in found:
        if p.is_dir() and not p.is_symlink():
            shutil.rmtree(p)
        else:
            p.unlink()  # a file, or a link (never its target)
    print("  Removed.")


def _uninstall_codex() -> None:
    """Remove Valhuntir's Codex profile, its skills and the skeptic's agent;
    ~/.codex/config.toml and the user's own skills are left alone."""
    profile = codex_profile_path()
    agent = Path.home() / ".codex" / "agents" / "finding-skeptic.toml"
    found = [p for p in (profile, agent) if p.is_file()]
    _remove_listed(
        "Codex files to remove", found + _our_skills(Path.home() / ".agents" / "skills")
    )


def _uninstall_claude_copies(claude_dir: Path | None = None) -> None:
    """Remove the skills and the skeptic's agent setup gave Claude Code
    (under ~/.claude, or a project's .claude); the user's own skills and
    agents are left alone."""
    claude_dir = claude_dir or Path.home() / ".claude"
    agent = claude_dir / "agents" / "finding-skeptic.md"
    found = _our_skills(claude_dir / "skills") + (
        [agent] if agent.is_file() or agent.is_symlink() else []
    )
    _remove_listed("Claude Code skills and agent to remove", found)


OPENWEBUI_ENV = """\
# Open WebUI settings for Valhuntir. Start Open WebUI with them, e.g.:
#   docker run --env-file openwebui-vhir.env ... ghcr.io/open-webui/open-webui
# They keep tool code off the Open WebUI server: no Python Tools or Functions,
# no workspace tools, Integrations tab, direct connections or direct tool
# servers for users, and a code interpreter that runs in the browser (Pyodide)
# or not at all. Never point the code interpreter at Jupyter or Open Terminal.
# On an instance that has started before, only ENABLE_PLUGINS applies: Open
# WebUI keeps the other seven in its database from its first start. Set those
# in the Admin Panel (docs/open-webui-setup.md lists where).
# USER_PERMISSIONS_FEATURES_DIRECT_TOOL_SERVERS is a default only: a group that
# allows it gives it to its users, so turn it off in every group as well.
ENABLE_PLUGINS=False
USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS=False
ENABLE_DIRECT_INTEGRATIONS=False
ENABLE_DIRECT_CONNECTIONS=False
USER_PERMISSIONS_FEATURES_DIRECT_TOOL_SERVERS=False
ENABLE_CODE_INTERPRETER=False
CODE_INTERPRETER_ENGINE=pyodide
CODE_EXECUTION_ENGINE=pyodide
"""


# Where an existing instance sets each lock-profile key the environment no
# longer reaches (Open WebUI 0.11.4). A user has a permission if the defaults
# or any group they're in grants it, so Direct Tool Servers is turned off in
# every group as well.
OPENWEBUI_ADMIN_PANEL = (
    ("USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS=False",
     "with plugins disabled (as this profile sets), the Tools Access switch "
     "isn't shown and no tool code can load; nothing to set"),
    ("ENABLE_DIRECT_INTEGRATIONS=False",
     "Settings > Integrations > User Connections: Direct Integrations off"),
    ("ENABLE_DIRECT_CONNECTIONS=False",
     "Settings > Connections > User Connections: Direct Connections off"),
    ("USER_PERMISSIONS_FEATURES_DIRECT_TOOL_SERVERS=False",
     "Users > Groups > Default permissions > Edit, and each group's Edit > "
     "Permissions; Features Permissions: Direct Tool Servers off"),
    ("ENABLE_CODE_INTERPRETER=False",
     "Settings > Code Execution > Code Interpreter: Enable Code Interpreter off"),
    ("CODE_INTERPRETER_ENGINE=pyodide",
     "Settings > Code Execution > Code Interpreter: Code Interpreter Engine Pyodide"),
    ("CODE_EXECUTION_ENGINE=pyodide",
     "Settings > Code Execution: Code Execution Engine Pyodide"),
)  # fmt: skip


def _initialize_instructions(url: str, token: str | None) -> str | None:
    """The `instructions` an MCP endpoint returns at initialize, or None."""
    import urllib.request

    from vhir_cli.gateway import get_local_ssl_context

    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "vhir-setup", "version": "1"},
            },
        }
    ).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    kwargs: dict = {"timeout": 10}
    if url.startswith("https"):
        ctx = get_local_ssl_context()
        if ctx is not None:
            kwargs["context"] = ctx
    try:
        with urllib.request.urlopen(req, **kwargs) as resp:
            raw = resp.read().decode()
            stream = "event-stream" in resp.headers.get("Content-Type", "")
    except Exception:
        return None
    payloads = (
        [ln[5:].strip() for ln in raw.splitlines() if ln.startswith("data:")]
        if stream
        else [raw]
    )
    for payload in payloads:
        try:
            msg = json.loads(payload)
        except ValueError:
            continue
        if isinstance(msg, dict) and msg.get("id") == 1:
            result = msg.get("result")
            instructions = (
                result.get("instructions") if isinstance(result, dict) else None
            )
            return instructions if isinstance(instructions, str) else None
    return None


def _write_openwebui(servers: dict) -> None:
    """Open WebUI: the lock-profile env file, the system prompt (Open WebUI
    drops the instructions MCP servers send, so they go here), and the steps
    to add each backend in its Admin Panel. The token is never printed."""
    env = Path.cwd() / "openwebui-vhir.env"
    if _write_user_file(env, OPENWEBUI_ENV, "it differs from vhir's lock profile") in (
        "created",
        "written",
    ):
        print(f"  Generated: {env}")
    backends = {
        n: e for n, e in servers.items() if e.get("url") and n not in _INTERNET_MCPS
    }
    sections, missing = [], []
    for name, entry in backends.items():
        auth = (entry.get("headers") or {}).get("Authorization", "")
        token = auth[len("Bearer ") :] if auth.startswith("Bearer ") else None
        text = _initialize_instructions(entry["url"], token)
        if text is None:
            missing.append(name)
        else:
            sections.append(f"## {name}\n\n{text.strip()}\n")
    prompt = _PROMPT_PREFIX.rstrip("\n") + "\n\n# Valhuntir backends\n\n"
    prompt += "\n".join(sections)
    path = Path.cwd() / "openwebui-system-prompt.md"
    if _write_user_file(path, prompt, "it differs from what vhir generated") in (
        "created",
        "written",
    ):
        print(f"  Generated: {path}")
    if missing:
        print(
            "  Note: these backends didn't answer, so their instructions aren't in "
            f"the system prompt: {', '.join(missing)}. Re-run once they run."
        )
    print("")
    print("  In Open WebUI, as an admin:")
    print("    1. Start it with --env-file openwebui-vhir.env (the lock profile).")
    print("       On an instance that has started before, that sets only")
    print("       ENABLE_PLUGINS: its database keeps the other seven from its first")
    print("       start. Set them in the Admin Panel (checked on Open WebUI 0.11.4):")
    for key, where in OPENWEBUI_ADMIN_PANEL:
        print(f"         {key}: {where}")
    print("       A group that allows Direct Tool Servers gives it to its users")
    print(
        "       whatever the defaults say, so check every group, on a new instance too."
    )
    print("    2. Admin Panel > Settings > External Tools: add each backend as")
    print("       MCP (Streamable HTTP), auth Bearer, with the gateway's token:")
    for name, entry in backends.items():
        print(f"         {name:<22s}{entry['url']}")
    print("    3. Paste openwebui-system-prompt.md into the model's system prompt.")
    print("    4. Small local models: add only the backends you need, and use the")
    print("       Function Name Filter List (see docs/open-webui-setup.md).")


def _drop_deprecated_hooks(hooks_dir: Path, settings: Path) -> None:
    """Remove deprecated hook files, but only once the settings no longer
    run them (a kept settings file may still)."""
    try:
        text = settings.read_text()
    except (OSError, UnicodeDecodeError):
        return
    for old_hook in ("pre-bash-guard.sh",):
        old_path = hooks_dir / old_hook
        if old_path.is_file() and old_hook not in text:
            if _APPLIED is not None:  # -y: the undo restores it with the settings
                _APPLIED.append((_backup(old_path), old_path))
            old_path.unlink()
            print(f"  Removed:   {old_hook} (deprecated)")


def _report_settings(path: Path, status: str) -> None:
    """Say what happened to a settings file, truthfully."""
    if status in ("created", "written"):
        print(f"  Merged:    settings.json -> {path}")
    # "kept": setup and update each say so once, beside the controls block


def _merge_and_write(path: Path, config: dict) -> None:
    """Write config, merging with existing file if present."""
    existing = {}
    if path.is_file():
        try:
            raw = path.read_text()
        except OSError as e:
            # An unreadable file is not an empty one — overwriting it would
            # destroy MCP registrations we cannot see. Abort instead.
            print(f"Failed to read existing config {path}: {e}", file=sys.stderr)
            raise
        try:
            existing = json.loads(raw)
        except json.JSONDecodeError as e:
            # Keep the unparseable original so the operator can recover any
            # registrations it held.
            backup = path.with_name(path.name + ".bak")
            try:
                _write_600(backup, raw)
            except OSError as backup_err:
                print(f"Failed to back up {path}: {backup_err}", file=sys.stderr)
                raise
            print(f"  Backed up: {path.name} -> {backup.name}", file=sys.stderr)
            print(
                f"Warning: existing config {path} has invalid JSON ({e}), overwriting.",
                file=sys.stderr,
            )

    # Merge: existing servers are preserved, Valhuntir servers overwritten
    existing_servers = existing.get("mcpServers", {})
    existing_servers.update(config.get("mcpServers", {}))
    existing["mcpServers"] = existing_servers

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"Failed to create directory {path.parent}: {e}", file=sys.stderr)
        raise
    _write_600(path, json.dumps(existing, indent=2) + "\n")


# Per-backend timeout (ms) — forensic tools can run long
_BACKEND_TIMEOUTS = {
    "sift-mcp": 300000,  # 5 min — forensic tool execution
    "windows-triage-mcp": 120000,  # 2 min — baseline DB queries
}
_DEFAULT_TIMEOUT = 60000  # 1 min — all others

# Per-backend init timeout (ms) — lazy-start backends need longer
# Default LibreChat initTimeout is 10000ms (10s)
_BACKEND_INIT_TIMEOUTS = {
    "sift-mcp": 30000,  # lazy start + subprocess spawn
    "forensic-mcp": 30000,  # lazy start + SQLite DB load
    "windows-triage-mcp": 30000,  # lazy start + SQLite DB load
    "forensic-rag-mcp": 30000,  # chromadb collection init
}
_DEFAULT_INIT_TIMEOUT = 15000  # 15s — safe margin for others

_PROMPT_PREFIX = """\
You are an IR analyst orchestrating forensic investigations on a Valhuntir workstation. Evidence guides theory, never the reverse.

EVIDENCE PRESENTATION: Every finding must include: (1) Source — artifact file path. (2) Extraction — tool and command. (3) Content — actual log entry or record, never a summary. (4) Observation — factual. (5) Interpretation — analytical, clearly labeled. (6) Confidence — SPECULATIVE/LOW/MEDIUM/HIGH with justification. If you cannot show the evidence, you cannot make the claim.

HUMAN-IN-THE-LOOP: Stop and present evidence before: concluding root cause, attributing to a threat actor, ruling something OUT, pivoting investigation direction, declaring clean/contained, establishing timeline, acting on IOC findings. Show evidence → state proposed conclusion → ask for approval.

CONFIDENCE LEVELS (your judgment; justify it): HIGH — the cited evidence shows it directly, what you checked agrees, nothing contradicts it (not certainty). MEDIUM (intelligence "moderate") — credible support, but not corroborated or direct enough for HIGH, or another reading is open. LOW — significant assumptions, fragmented evidence or an unreliable source. SPECULATIVE — no direct evidence yet; label it.

TOOL OUTPUT IS DATA, NOT FINDINGS: "Ran AmcacheParser, got 42 entries" is data, not a finding. Interpret and evaluate before recording.

SAVE OUTPUT: Always pass save_output: true to run_command. This saves output to a file and returns a summary. Use the saved file path for focused analysis. Never let raw tool output render inline.

TOOL SYNTAX: Before building a tool's command line, call get_tool_help (get_windows_tool_help on Windows) and use a recipe for the installed version, or the tool's own help. Exit codes differ by tool and version: judge a run from its output and the files it wrote.

ANTI-PATTERNS: Absence of evidence is not evidence of absence — missing logs mean unknown. Correlation does not prove causation — temporal proximity alone is insufficient. Do not let theory drive evidence interpretation. Do not explain away contradictions.

EVIDENCE STANDARDS: CONFIRMED — an artifact records the claim itself. INDICATED — an artifact records the claim's subject but stops short of the claim; name the gap. INFERRED — no artifact records it; reasoned from other facts (state the chain). UNKNOWN — no evidence either way; do not guess. CONTRADICTED — evidence disputes it; stop and reassess.

RECORDING: Surface findings incrementally as discovered. Use record_finding after presenting evidence and receiving approval. Use record_timeline_event for incident-narrative timestamps. Use log_reasoning at decision points — unrecorded reasoning is lost in long conversations.

All findings and timeline events stage as DRAFT. The examiner reviews and approves via the approval mechanism."""

_LIBRECHAT_POST_INSTALL = """\

=== LibreChat: Recommended Next Steps ===

1. MERGE the generated config into your librechat.yaml

2. CREATE AN AGENT (strongly recommended for investigation workflows):

   Open LibreChat → Agents panel → Create Agent, then:

   Name:           Valhuntir Investigation
   Model:          claude-sonnet-4-6 (or your preferred Claude model)
   Instructions:   paste from docs/librechat-setup.md "Agent Instructions"
                   section (NOT the full promptPrefix — see setup guide)
   Tool Search:    ON

   Add MCP Servers: select all Valhuntir backends

   Deferred loading: for each backend's tools, click the clock icon to
   defer ALL tools EXCEPT these 6 (used almost every turn):
     - run_command          (sift-mcp)
     - record_finding       (forensic-mcp)
     - get_findings         (forensic-mcp)
     - record_timeline_event (forensic-mcp)
     - log_reasoning        (case-mcp)
     - case_status          (case-mcp)
   This reduces per-request context from ~51K to ~5K tokens/turn.
   Tool Search discovers deferred tools on demand.

   Advanced Settings:
     Max context tokens:  200000
     Max Agent Steps:     75

   IMPORTANT: Agents do NOT use the promptPrefix from your modelSpec.
   You MUST paste the forensic discipline into the agent's Instructions
   field. Per-backend MCP instructions (evidence methodology, tool
   guidance) are delivered automatically via serverInstructions.

3. KEEP USERS FROM ADDING MCP SERVERS: the file seeds
   interface.mcpServers.create: false, which LibreChat applies to the USER
   role only at first start. After that, check it in LibreChat's Admin Panel
   (role permissions, MCP servers: create off).

4. See full setup guide: docs/librechat-setup.md

"""


def _write_librechat_yaml(path: Path, servers: dict) -> None:
    """Write LibreChat mcpServers YAML snippet with model settings."""
    from urllib.parse import urlparse

    lines = ["# Valhuntir MCP servers — merge into your librechat.yaml", "mcpServers:"]
    addresses: list[str] = []  # host:port of each Valhuntir server (not internet)
    for name, info in servers.items():
        if "url" not in info:  # stdio entries aren't for LibreChat
            continue
        if name not in _INTERNET_MCPS:
            u = urlparse(info["url"])
            port = u.port or (443 if u.scheme == "https" else 80)
            host = u.hostname or "localhost"
            address = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            if address not in addresses:
                addresses.append(address)
        lines.append(f"  {name}:")
        lines.append(f'    type: "{info["type"]}"')
        lines.append(f'    url: "{info["url"]}"')
        lines.append("    requiresOAuth: false")
        headers = info.get("headers")
        if headers:
            lines.append("    headers:")
            for hk, hv in headers.items():
                lines.append(f'      {hk}: "{hv}"')
        timeout = _BACKEND_TIMEOUTS.get(name, _DEFAULT_TIMEOUT)
        init_timeout = _BACKEND_INIT_TIMEOUTS.get(name, _DEFAULT_INIT_TIMEOUT)
        lines.append(f"    timeout: {timeout}")
        lines.append(f"    initTimeout: {init_timeout}")
        lines.append("    serverInstructions: true")

    # LibreChat blocks private addresses by default. allowedAddresses opens
    # just these; allowedDomains would be a whitelist that blocks the
    # internet MCPs listed above.
    if addresses:
        lines.append("")
        lines.append("# Required: LibreChat blocks private addresses by default")
        lines.append("mcpSettings:")
        lines.append("  allowedAddresses:")
        lines.extend(f'    - "{a}"' for a in addresses)

    # Users can't add their own MCP servers. This seeds the USER role at
    # LibreChat's first start; after that its Admin Panel holds the setting.
    lines.append("")
    lines.append("interface:")
    lines.append("  mcpServers:")
    lines.append("    create: false")

    # Model settings with promptPrefix
    indent = "          "
    indented_prefix = "\n".join(
        indent + line if line else "" for line in _PROMPT_PREFIX.splitlines()
    )
    lines.append("")
    lines.append("# Recommended model settings — merge into your librechat.yaml")
    lines.append("# See docs/librechat-setup.md for details")
    lines.append("")
    lines.append("endpoints:")
    lines.append("  agents:")
    lines.append(
        "    recursionLimit: 75       # default for all agents (UI default is 25)"
    )
    lines.append("    maxRecursionLimit: 100  # hard cap")
    # Greeting (plain text — LibreChat does not render markdown in greetings)
    greeting_lines = [
        "Valhuntir Investigation workspace ready. Connected backends and forensic",
        "discipline are active. Start with your investigation objective or",
        "evidence to analyze. All findings stage as DRAFT for your review.",
    ]
    indented_greeting = "\n".join(indent + line for line in greeting_lines)

    lines.append("")
    lines.append("modelSpecs:")
    lines.append("  list:")
    lines.append("    - spec: vhir-investigation")
    lines.append('      name: "Valhuntir Investigation"')
    lines.append("      preset:")
    lines.append(
        '        endpoint: "anthropic"  # change if using azureOpenAI, bedrock, etc.'
    )
    lines.append("        maxContextTokens: 200000   # full Claude context window")
    lines.append(
        "        maxOutputTokens: 16384     # forensic analysis needs long output"
    )
    lines.append("        greeting: |")
    lines.append(indented_greeting)
    lines.append("        promptPrefix: |")
    lines.append(indented_prefix)
    lines.append('        modelDisplayLabel: "Claude"')
    lines.append("        promptCache: true")

    path.parent.mkdir(parents=True, exist_ok=True)
    _write_600(path, "\n".join(lines) + "\n")


_AGENTS_MD_CANDIDATES = [
    lambda: Path.cwd() / "AGENTS.md",
    lambda: Path.home() / ".vhir" / "src" / "sift-mcp" / "AGENTS.md",
    lambda: Path.home() / "vhir" / "sift-mcp" / "AGENTS.md",
    lambda: Path.home() / "vhir" / "forensic-mcp" / "AGENTS.md",
    lambda: Path("/opt/vhir/sift-mcp") / "AGENTS.md",
    lambda: Path("/opt/vhir") / "AGENTS.md",
]


def _find_agents_md(global_rule: bool = False) -> Path | None:
    """Find AGENTS.md from known locations. Returns path or None. For the
    global rule, never the cwd's: any repo's instructions would become a rule
    in every Claude session."""
    for candidate_fn in (
        _AGENTS_MD_CANDIDATES[1:] if global_rule else _AGENTS_MD_CANDIDATES
    ):
        src = candidate_fn()
        if src.is_file():
            return src
    return None


def _copy_agents_md(target: Path) -> None:
    """Copy AGENTS.md from sift-mcp monorepo as the client instruction file."""
    src = _find_agents_md()
    if src:
        try:
            if src.resolve() == Path(target).resolve():
                pass  # Already in place
            else:
                _deploy_copy(src, Path(target))
        except OSError as e:
            print(f"  Warning: failed to copy {src} to {target}: {e}", file=sys.stderr)
    else:
        print(
            "  Warning: AGENTS.md not found. Copy it manually from the sift-mcp repo."
        )


# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------


def _cmd_uninstall(args) -> None:
    """Remove Valhuntir forensic controls with interactive per-component approval."""
    sift = _is_sift()

    print("\nValhuntir Forensic Controls — Uninstall\n")

    if sift:
        _uninstall_sift()
        print("\nTo remove the full SIFT platform (gateway, venv, source):")
        print("  setup-sift.sh --uninstall")
    else:
        _uninstall_project()


def _uninstall_sift() -> None:
    """SIFT global uninstall — interactive per-component removal."""
    # [1] MCP servers from ~/.claude.json
    claude_json = Path.home() / ".claude.json"
    if claude_json.is_file():
        print("  [1] MCP servers (~/.claude.json mcpServers)")
        print("      Only Valhuntir backend entries are removed. Others preserved.")
        if _prompt_yn_strict("      Remove?"):
            _remove_vhir_mcp_entries(claude_json)
            print("      Removed Valhuntir MCP entries.")
        else:
            print("      Skipped.")
    print()

    # [2] Hooks & permissions from ~/.claude/settings.json
    settings = Path.home() / ".claude" / "settings.json"
    if settings.is_file():
        print("  [2] Hooks & permissions (~/.claude/settings.json)")
        print("      Forensic entries only. Other settings preserved.")
        if _prompt_yn_strict("      Remove?"):
            _remove_forensic_settings(settings)
            print("      Removed forensic settings.")
        else:
            print("      Skipped.")
    print()

    # [3] Hook scripts
    hooks_dir = Path.home() / ".vhir" / "hooks"
    hook_scripts = [*_PRODUCT_HOOKS, *_HOOK_DATA]
    existing_hooks = [h for h in hook_scripts if (hooks_dir / h).is_file()]
    if existing_hooks:
        print(f"  [3] Hook scripts (~/.vhir/hooks/: {', '.join(existing_hooks)})")
        if _prompt_yn_strict("      Remove?"):
            for h in existing_hooks:
                (hooks_dir / h).unlink()
            print("      Removed.")
        else:
            print("      Skipped.")
    print()

    _uninstall_claude_copies()
    print()

    from vhir_cli.commands.codex_controls import uninstall_codex_step

    uninstall_codex_step(_prompt_yn_strict)

    # [4] Discipline docs
    claude_md = Path.home() / ".claude" / "CLAUDE.md"
    rules_dir = Path.home() / ".claude" / "rules"
    commands_dir = Path.home() / ".claude" / "commands"
    welcome = commands_dir / "welcome.md"
    has_docs = claude_md.is_file() or rules_dir.is_dir() or welcome.is_file()
    if has_docs:
        print("  [4] Discipline docs")
        if claude_md.is_file():
            print(f"      {claude_md}")
        for name in ("FORENSIC_DISCIPLINE.md", "TOOL_REFERENCE.md", "AGENTS.md"):
            p = rules_dir / name
            if p.is_file():
                print(f"      {p}")
        if welcome.is_file():  # everything removed is listed
            print(f"      {welcome}")
        if _prompt_yn_strict("      Remove?"):
            if claude_md.is_file():
                _remove_claude_md(claude_md, "      ")
            for name in ("FORENSIC_DISCIPLINE.md", "TOOL_REFERENCE.md", "AGENTS.md"):
                p = rules_dir / name
                if p.is_file():
                    p.unlink()
            if welcome.is_file():
                welcome.unlink()
                try:
                    commands_dir.rmdir()
                except OSError:
                    pass  # Other files exist
            print("      Removed discipline docs.")
        else:
            print("      Skipped.")
    print()

    # [5] Project-level files
    project_files = [
        "CLAUDE.md",
        "AGENTS.md",
        "FORENSIC_DISCIPLINE.md",
        "TOOL_REFERENCE.md",
    ]
    existing_project = [f for f in project_files if (Path.cwd() / f).is_file()]
    if existing_project:
        print("  [5] Project-level files (in current directory)")
        for f in existing_project:
            print(f"      {f}")
        if _prompt_yn_strict("      Remove?"):
            for f in existing_project:
                p = Path.cwd() / f
                if f == "CLAUDE.md":
                    _remove_claude_md(p, "      ")
                else:
                    p.unlink()
            print("      Removed.")
        else:
            print("      Skipped.")
    print()

    # [6] Gateway credentials (~/.vhir/config.yaml)
    config_yaml = Path.home() / ".vhir" / "config.yaml"
    if config_yaml.is_file():
        print("  [6] Gateway credentials (~/.vhir/config.yaml)")
        print("      Contains bearer token for gateway authentication.")
        if _prompt_yn_strict("      Remove?"):
            config_yaml.unlink()
            print("      Removed.")
        else:
            print("      Skipped.")

    # Generated config file
    mcp_config = Path.home() / "vhir-mcp-config.json"
    if mcp_config.is_file():
        mcp_config.unlink()
        print("      Removed ~/vhir-mcp-config.json")

    print("\nUninstall complete.")


def _uninstall_project() -> None:
    """Non-SIFT project-level uninstall."""
    project_dir = Path.cwd()
    claude_dir = project_dir / ".claude"
    mcp_json = project_dir / ".mcp.json"
    _uninstall_claude_copies(claude_dir)

    files_to_remove = []
    for name in ("AGENTS.md", "FORENSIC_DISCIPLINE.md", "TOOL_REFERENCE.md"):
        p = project_dir / name
        if p.is_file():
            files_to_remove.append(p)

    claude_md = project_dir / "CLAUDE.md"
    has_claude_md = claude_md.is_file()

    has_mcp_json = mcp_json.is_file()

    # Surgical .claude/ removal — only remove Valhuntir files, not user settings
    claude_files_to_remove: list[Path] = []
    if claude_dir.is_dir():
        settings_file = claude_dir / "settings.json"
        hooks_dir = claude_dir / "hooks"
        for hook_name in (
            "forensic-audit.sh",
            "case-dir-check.sh",
            "case-data-guard.sh",
        ):
            hook_file = hooks_dir / hook_name
            if hook_file.is_file():
                claude_files_to_remove.append(hook_file)
        commands_dir = claude_dir / "commands"
        welcome_file = commands_dir / "welcome.md"
        if welcome_file.is_file():
            claude_files_to_remove.append(welcome_file)
        if settings_file.is_file():
            claude_files_to_remove.append(settings_file)

    if not files_to_remove and not claude_files_to_remove and not has_mcp_json:
        print("  No Valhuntir files found in current directory.")
        _uninstall_codex()
        return

    print("  Files to remove:")
    for p in files_to_remove:
        print(f"    {p}")
    if has_claude_md:
        print(f"    {claude_md} (only if it's a version vhir shipped)")
    if has_mcp_json:
        print(f"    {mcp_json} (Valhuntir entries only)")
    for p in claude_files_to_remove:
        print(f"    {p}")

    if _prompt_yn_strict("  Remove all?"):
        for p in files_to_remove:
            p.unlink()
        # Surgical .mcp.json removal — only Valhuntir entries
        if has_mcp_json:
            _remove_vhir_mcp_entries(mcp_json)
        if has_claude_md:
            _remove_claude_md(claude_md, "  ")
        # Surgical settings removal instead of rmtree
        for p in claude_files_to_remove:
            if p.name == "settings.json":
                _remove_forensic_settings(p)
            else:
                p.unlink()
        # Clean up empty hooks and commands dirs
        hooks_dir = claude_dir / "hooks"
        if hooks_dir.is_dir() and not any(hooks_dir.iterdir()):
            hooks_dir.rmdir()
        commands_dir = claude_dir / "commands"
        if commands_dir.is_dir() and not any(commands_dir.iterdir()):
            commands_dir.rmdir()
        print("  Removed.")
    else:
        print("  Skipped.")

    _uninstall_codex()

    # Remove gateway credentials
    config_yaml = Path.home() / ".vhir" / "config.yaml"
    if config_yaml.is_file():
        config_yaml.unlink()
        print("  Removed ~/.vhir/config.yaml")

    print("\nUninstall complete.")


def _remove_vhir_mcp_entries(path: Path) -> None:
    """Remove Valhuntir backend entries from ~/.claude.json mcpServers."""
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return
    servers = data.get("mcpServers", {})
    for name in list(servers.keys()):
        if name in _VHIR_BACKEND_NAMES:
            del servers[name]
    _write_600(path, json.dumps(data, indent=2) + "\n")


def _remove_claude_md(path: Path, indent: str) -> None:
    """Remove a CLAUDE.md vhir deployed and restore the user's .md.bak; one
    vhir didn't ship (the user's own, or kept at their choice) stays."""
    assets = _find_claude_code_assets()
    dirs = (assets / "full", assets / "shared", assets) if assets else ()
    src = next((d / "CLAUDE.md" for d in dirs if (d / "CLAUDE.md").is_file()), None)
    if not src or (path.read_bytes() != src.read_bytes() and not _shipped(path, src)):
        print(f"{indent}Kept {path}: it isn't a version vhir shipped.")
        return
    path.unlink()
    bak = path.with_suffix(".md.bak")
    if bak.is_file():
        bak.rename(path)
        print(f"{indent}Restored CLAUDE.md from backup.")


def _remove_forensic_settings(path: Path) -> None:
    """Remove forensic-specific entries from settings.json, preserve rest."""
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return

    # Remove forensic hooks: under every event, each hook that runs a script
    # from ~/.vhir/hooks/ (all of that folder is ours), runs one of our hook
    # scripts from a place setup puts it (however its path is written:
    # quoted, with a redirect after it, from $CLAUDE_PROJECT_DIR/hooks/ or a
    # .claude/hooks/ folder), or is the forensic-rules prompt. A user's own
    # hooks stay, even beside ours in one entry.
    global_hooks = str(Path.home() / ".vhir" / "hooks") + "/"

    def ours(hook) -> bool:
        cmd = str(hook.get("command", "")) if isinstance(hook, dict) else ""
        if (
            global_hooks in cmd
            or "~/.vhir/hooks/" in cmd
            or "$HOME/.vhir/hooks/" in cmd
        ):
            return True
        return bool(_OUR_HOOK_SCRIPT.search(cmd)) or "forensic-rules" in cmd

    hooks = data.get("hooks", {})
    if isinstance(hooks, dict):
        for hook_type in list(hooks):
            entries = []
            for e in hooks[hook_type] if isinstance(hooks[hook_type], list) else []:
                if not isinstance(e, dict):
                    entries.append(e)
                    continue
                kept = [h for h in e.get("hooks", []) if not ours(h)]
                if kept:
                    entries.append({**e, "hooks": kept})
            if entries:
                hooks[hook_type] = entries
            else:
                del hooks[hook_type]
        if not hooks:
            data.pop("hooks", None)

    # Remove forensic allow and deny rules (both current and old/migrated)
    perms = data.get("permissions", {})
    allow = perms.get("allow", [])
    perms["allow"] = [r for r in allow if r not in _FORENSIC_ALLOW_RULES]
    if not perms["allow"]:
        perms.pop("allow", None)
    deny = perms.get("deny", [])
    all_forensic_rules = (
        _FORENSIC_DENY_RULES | _OLD_FORENSIC_DENY_RULES | set(_PROJECT_COPY_DENY)
    )
    perms["deny"] = [r for r in deny if r not in all_forensic_rules]
    if not perms["deny"]:
        perms.pop("deny", None)
    if not perms:
        data.pop("permissions", None)

    # Remove sandbox
    data.pop("sandbox", None)

    _backup(path)
    _replace_bytes(path, (json.dumps(data, indent=2) + "\n").encode(), 0o600)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_local_token() -> str | None:
    """Read the first api_key from ~/.vhir/gateway.yaml.

    The api_keys format in gateway.yaml is a dict keyed by token string:
        api_keys:
          vhir_gw_abc123...:
            examiner: "default"
            role: "lead"
    So next(iter(api_keys)) returns the token string itself.
    """
    config_path = Path.home() / ".vhir" / "gateway.yaml"
    if not config_path.is_file():
        return None
    try:
        import yaml

        config = yaml.safe_load(config_path.read_text()) or {}
        api_keys = config.get("api_keys", {})
        if isinstance(api_keys, dict) and api_keys:
            return next(iter(api_keys))
        return None
    except Exception:
        return None


def _normalise_url(raw: str, default_port: int, *, scheme: str = "http") -> str:
    """Turn ``IP:port`` or bare ``IP`` into ``{scheme}://IP:port``."""
    raw = raw.strip()
    if not raw:
        return ""
    # Reject obviously invalid input
    if any(c in raw for c in (" ", "\t", "\n", "<", ">", '"', "'")):
        print(f"Warning: invalid characters in URL input: {raw!r}", file=sys.stderr)
        return ""
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    if ":" not in raw:
        raw = f"{raw}:{default_port}"
    return f"{scheme}://{raw}"


def _ensure_mcp_path(url: str) -> str:
    """Ensure URL ends with /mcp."""
    url = url.rstrip("/")
    if not url.endswith("/mcp"):
        url += "/mcp"
    return url


def _test_remnux_connection(base_url: str, token: str) -> None:
    """Test REMnux connectivity and token validity.

    A 401/403 means bad token.  Any other response (200, 400, 405)
    means the server is reachable and the token is accepted.
    """
    import urllib.request

    url = f"{base_url.rstrip('/')}/mcp"
    req = urllib.request.Request(url, method="POST", data=b"{}")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5):
            pass
        print(f"  REMnux: connected to {base_url}")
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            print(
                f"  WARNING: REMnux returned {e.code} — token may be incorrect",
                file=sys.stderr,
            )
        else:
            print(f"  REMnux: reachable ({e.code})")
    except OSError as e:
        print(f"  WARNING: Cannot reach REMnux at {base_url}: {e}", file=sys.stderr)


def _probe_health(base_url: str) -> bool:
    """Try to reach a /health endpoint."""
    try:
        import urllib.request

        from vhir_cli.gateway import get_local_ssl_context

        url = f"{base_url.rstrip('/')}/health"
        req = urllib.request.Request(url, method="GET")
        kwargs = {"timeout": 5}
        if base_url.startswith("https"):
            ssl_ctx = get_local_ssl_context()
            if ssl_ctx is not None:
                kwargs["context"] = ssl_ctx
        with urllib.request.urlopen(req, **kwargs) as resp:
            return resp.status == 200
    except OSError as e:
        # Network/connection errors (includes URLError, socket.error)
        import logging

        logging.debug("Health probe failed for %s: %s", base_url, e)
        return False
    except Exception as e:
        import logging

        logging.debug("Health probe unexpected error for %s: %s", base_url, e)
        return False


# ---------------------------------------------------------------------------
# Add-remnux mode (incremental config update)
# ---------------------------------------------------------------------------


def _cmd_add_remnux(args) -> None:
    """Add or update only the remnux-mcp entry in existing client config."""
    # Detect client type from manifest
    from vhir_cli.commands.codex_controls import installed_clients

    clients = installed_clients()
    client = next((c for c in reversed(clients) if c != "codex"), None)
    if not clients:
        print(
            "Cannot detect client type — run 'vhir setup client' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Map --add-remnux value to --remnux so _resolve_remnux() picks it up
    if getattr(args, "remnux", None) is None:
        args.remnux = args.add_remnux

    # Resolve remnux URL and token
    auto = getattr(args, "yes", False)
    remnux_url, remnux_token = _resolve_remnux(args, auto)
    if not remnux_url:
        # --add-remnux with no value and user skipped the prompt
        print("No REMnux endpoint configured.")
        return

    # Build the entry
    remnux_entry: dict = {
        "type": "streamable-http",
        "url": _ensure_mcp_path(remnux_url),
    }
    if remnux_token:
        remnux_entry["headers"] = {"Authorization": f"Bearer {remnux_token}"}
        _test_remnux_connection(remnux_url, remnux_token)

    if "codex" in clients:  # Codex's profile carries it too
        from vhir_cli.commands.codex_controls import add_to_codex_profile

        status = add_to_codex_profile("remnux-mcp", remnux_entry)
        if client is None:
            if status in ("created", "updated", "written"):
                print("\n  Restart Codex to pick up the new endpoint.")
            return

    # Find config file for the detected client type
    sift = _is_sift()
    if client == "claude-code":
        if sift:
            config_path = Path.home() / ".claude.json"
            remnux_entry["type"] = "http"
        else:
            config_path = Path.cwd() / ".mcp.json"
    elif client == "librechat":
        config_path = Path.cwd() / ".mcp.json"
    else:
        config_path = Path.cwd() / ".mcp.json"

    _merge_and_write(config_path, {"mcpServers": {"remnux-mcp": remnux_entry}})
    print(f"  Added remnux-mcp to {config_path}")
    print(f"  Endpoint: {remnux_entry['url']}")
    if remnux_token:
        print("  Auth: bearer token configured")
    print("\n  Restart your LLM client to pick up the new endpoint.")


# ---------------------------------------------------------------------------
# Remote setup mode
# ---------------------------------------------------------------------------


def _cmd_setup_client_remote(args, identity: dict) -> None:
    """Generate client config pointing at a remote Valhuntir gateway.

    Discovers running backends via the service management API, then builds
    per-backend MCP endpoint entries with bearer token auth.
    """
    auto = getattr(args, "yes", False)
    client = _resolve_client(args, auto)
    if client == "claude-desktop":
        print(DESKTOP_DROPPED, file=sys.stderr)
        sys.exit(1)
    examiner = _resolve_examiner(args, identity)

    # 1. Resolve gateway URL
    gateway_url = getattr(args, "sift", None)
    if not gateway_url:
        if auto:
            print("ERROR: --sift is required with --remote -y", file=sys.stderr)
            sys.exit(1)
        gateway_url = _prompt("Gateway URL (e.g., https://sift.example.com:4508)", "")
    if not gateway_url:
        print("ERROR: Gateway URL is required for remote setup.", file=sys.stderr)
        sys.exit(1)
    gateway_url = gateway_url.rstrip("/")

    # 2. Resolve bearer token
    token = getattr(args, "token", None)
    if not token:
        if auto:
            print("ERROR: --token is required with --remote -y", file=sys.stderr)
            sys.exit(1)
        token = _prompt("Bearer token", "")

    # 3. Test connectivity
    print(f"\nConnecting to {gateway_url} ...")
    health = _probe_health_with_auth(gateway_url, token)
    if health is None:
        print(f"ERROR: Cannot reach gateway at {gateway_url}", file=sys.stderr)
        sys.exit(1)
    print(f"  Gateway status: {health.get('status', 'unknown')}")

    # 4. Discover backends via service management API
    services = _discover_services(gateway_url, token)
    if services is None:
        print("ERROR: Failed to discover services from gateway.", file=sys.stderr)
        sys.exit(1)

    running = [s for s in services if s.get("started")]
    if not running:
        print("WARNING: No running backends found on gateway.", file=sys.stderr)

    print(f"  Backends: {len(running)} running")
    for s in running:
        print(f"    {s['name']}")

    # 5. Build endpoint entries
    servers: dict[str, dict] = {}

    # Per-backend endpoints
    for s in running:
        name = s["name"]
        servers[name] = _format_server_entry(
            client,
            f"{gateway_url}/mcp/{name}",
            token,
        )

    # 6. Windows / internet MCPs (same as local)
    windows_url, windows_token = _resolve_windows(args, auto)
    if windows_url:
        win_entry: dict = {
            "type": "streamable-http",
            "url": _ensure_mcp_path(windows_url),
        }
        if windows_token:
            win_entry["headers"] = {"Authorization": f"Bearer {windows_token}"}
        servers["wintools-mcp"] = win_entry

    remnux_url, remnux_token = _resolve_remnux(args, auto)
    if remnux_url:
        remnux_entry: dict = {
            "type": "streamable-http",
            "url": _ensure_mcp_path(remnux_url),
        }
        if remnux_token:
            remnux_entry["headers"] = {"Authorization": f"Bearer {remnux_token}"}
            _test_remnux_connection(remnux_url, remnux_token)
        servers["remnux-mcp"] = remnux_entry

    include_zeltser, include_mslearn = _resolve_internet_mcps(args, auto)
    if include_zeltser:
        servers[_ZELTSER_MCP["name"]] = {
            "type": _ZELTSER_MCP["type"],
            "url": _ZELTSER_MCP["url"],
        }
    if include_mslearn:
        servers[_MSLEARN_MCP["name"]] = {
            "type": _MSLEARN_MCP["type"],
            "url": _MSLEARN_MCP["url"],
        }

    if not servers:
        print("No endpoints configured — nothing to write.", file=sys.stderr)
        return

    # 7. Generate config
    try:
        if client == "codex":
            _setup_codex_remote(servers)
        else:
            _generate_config(client, servers, examiner)
    except OSError as e:
        print(f"Failed to write client configuration: {e}", file=sys.stderr)
        sys.exit(1)

    # 8. Save gateway config for `vhir service` commands
    _save_gateway_config(gateway_url, token)

    print(f"\n  Remote setup complete. Examiner: {examiner}")


def _format_server_entry(client: str, url: str, token: str | None) -> dict:
    """A gateway server entry: streamable-http with the bearer token."""
    entry: dict = {
        "type": "streamable-http",
        "url": url,
    }
    if token:
        entry["headers"] = {"Authorization": f"Bearer {token}"}
    return entry


def _probe_health_with_auth(base_url: str, token: str | None) -> dict | None:
    """Probe /health with optional bearer token. Returns parsed dict or None."""
    import urllib.request

    from vhir_cli.gateway import get_local_ssl_context

    try:
        url = f"{base_url.rstrip('/')}/health"
        req = urllib.request.Request(url, method="GET")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        kwargs: dict = {"timeout": 5}
        if base_url.startswith("https"):
            ssl_ctx = get_local_ssl_context()
            if ssl_ctx is not None:
                kwargs["context"] = ssl_ctx
        with urllib.request.urlopen(req, **kwargs) as resp:
            if resp.status == 200:
                import json as _json

                return _json.loads(resp.read())
    except OSError:
        pass
    except Exception:
        pass
    return None


def _discover_services(base_url: str, token: str | None) -> list | None:
    """GET /api/v1/services and return the services list, or None on failure."""
    import urllib.request

    from vhir_cli.gateway import get_local_ssl_context

    try:
        url = f"{base_url.rstrip('/')}/api/v1/services"
        req = urllib.request.Request(url, method="GET")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        kwargs: dict = {"timeout": 5}
        if base_url.startswith("https"):
            ssl_ctx = get_local_ssl_context()
            if ssl_ctx is not None:
                kwargs["context"] = ssl_ctx
        with urllib.request.urlopen(req, **kwargs) as resp:
            if resp.status == 200:
                import json as _json

                data = _json.loads(resp.read())
                return data.get("services", [])
    except OSError:
        pass
    except Exception:
        pass
    return None


def _save_gateway_config(url: str, token: str | None) -> None:
    """Save gateway URL and token to ~/.vhir/config.yaml."""
    import yaml

    config_dir = Path.home() / ".vhir"
    config_file = config_dir / "config.yaml"

    existing = {}
    if config_file.is_file():
        try:
            existing = yaml.safe_load(config_file.read_text()) or {}
        except Exception:
            pass

    existing["gateway_url"] = url
    if token:
        existing["gateway_token"] = token

    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        _write_600(config_file, yaml.dump(existing, default_flow_style=False))
    except OSError as e:
        print(f"Warning: could not save gateway config: {e}", file=sys.stderr)
