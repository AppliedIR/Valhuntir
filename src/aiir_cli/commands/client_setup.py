"""Generate LLM client configuration pointing at AIIR API servers.

On SIFT, MCP entries use ``type: http`` in global ``~/.claude.json``.
On remote clients, entries use ``type: streamable-http`` in project
``.mcp.json``.  Runs on the machine where the human sits; points at
gateway / wintools / REMnux endpoints wherever they are.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from aiir_cli.setup.config_gen import _write_600

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
    "mcp__wintools-mcp__*",
    "mcp__remnux-mcp__*",
    "mcp__aiir__*",
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
    "Write(**/findings.json)",
    "Write(**/timeline.json)",
    "Write(**/approvals.jsonl)",
    "Write(**/todos.json)",
    "Write(**/CASE.yaml)",
    "Write(**/actions.jsonl)",
    "Write(**/audit/*.jsonl)",
    "Edit(**/evidence.json)",
    "Write(**/evidence.json)",
    "Read(/var/lib/aiir/**)",
    "Edit(/var/lib/aiir/**)",
    "Write(/var/lib/aiir/**)",
    "Bash(aiir approve*)",
    "Bash(*aiir approve*)",
    "Bash(aiir reject*)",
    "Bash(*aiir reject*)",
    # Control file self-protection (anti-accident, anti-injection)
    "Edit(**/.claude/settings.json)",
    "Write(**/.claude/settings.json)",
    "Edit(**/.claude/CLAUDE.md)",
    "Write(**/.claude/CLAUDE.md)",
    "Edit(**/.claude/rules/**)",
    "Write(**/.claude/rules/**)",
    "Edit(**/.aiir/hooks/**)",
    "Write(**/.aiir/hooks/**)",
    "Edit(**/.aiir/active_case)",
    "Write(**/.aiir/active_case)",
    "Edit(**/.aiir/gateway.yaml)",
    "Write(**/.aiir/gateway.yaml)",
    "Edit(**/.aiir/config.yaml)",
    "Write(**/.aiir/config.yaml)",
    "Edit(**/.aiir/.password_lockout)",
    "Write(**/.aiir/.password_lockout)",
    # Sync with template (was in settings.json but missing here)
    "Edit(**/pending-reviews.json)",
    "Write(**/pending-reviews.json)",
}

# Old forensic deny rules — removed during migration re-deploy
_OLD_FORENSIC_DENY_RULES = {"Bash(rm -rf *)", "Bash(mkfs*)", "Bash(dd *)"}

# AIIR MCP names — used for uninstall identification.
_AIIR_BACKEND_NAMES = {
    "forensic-mcp",
    "case-mcp",
    "sift-mcp",
    "report-mcp",
    "forensic-rag-mcp",
    "windows-triage-mcp",
    "opencti-mcp",
    "wintools-mcp",
    "remnux-mcp",
    "aiir",
    "zeltser-ir-writing",
    "microsoft-learn",
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def cmd_setup_client(args, identity: dict) -> None:
    """Generate LLM client configuration for AIIR endpoints."""
    if getattr(args, "uninstall", False):
        _cmd_uninstall(args)
        return

    if getattr(args, "remote", False):
        _cmd_setup_client_remote(args, identity)
        return

    auto = getattr(args, "yes", False)

    # 1. Resolve parameters from switches (or interactive wizard)
    client = _resolve_client(args, auto)
    sift_url = _resolve_sift(args, auto)
    windows_url = _resolve_windows(args, auto)
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
                    "Run 'aiir service status' to diagnose. "
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
            servers["aiir"] = entry

    if windows_url:
        servers["wintools-mcp"] = {
            "type": "streamable-http",
            "url": _ensure_mcp_path(windows_url),
        }

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

    if not servers:
        print("No endpoints configured — nothing to write.", file=sys.stderr)
        return

    # 3. Generate config for selected client
    try:
        _generate_config(client, servers, examiner)
    except OSError as e:
        print(f"Failed to write client configuration: {e}", file=sys.stderr)
        sys.exit(1)

    # 4. Record client type in manifest (for aiir update)
    manifest_path = Path.home() / ".aiir" / "manifest.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text())
            manifest["client"] = client
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        except (json.JSONDecodeError, OSError):
            pass  # Non-critical

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
    return (Path.home() / ".aiir" / "gateway.yaml").is_file()


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
    from aiir_cli.gateway import get_local_gateway_url

    default = get_local_gateway_url()
    if auto:
        return default

    detected = _probe_health(default)
    if detected:
        status = "detected running"
    else:
        status = "not detected, will use default"

    print("\n--- SIFT Workstation (Gateway) ---")
    print("The AIIR gateway runs on your SIFT workstation and provides")
    print("forensic tools (forensic-mcp, sift-mcp, forensic-rag, etc.).")
    print()
    print(f"  Default:  {default}  ({status})")
    print("  Format:   URL              Example: http://10.0.0.2:4508")
    print('  Enter "skip" to omit.')

    answer = _prompt("\nSIFT gateway URL", default)
    if answer.lower() == "skip":
        return ""
    return answer


def _resolve_windows(args, auto: bool) -> str:
    val = getattr(args, "windows", None)
    if val is not None:
        return _normalise_url(val, 4624) if val else ""
    if auto:
        return ""

    print("\n--- Windows Forensic Workstation ---")
    print("If you have a Windows workstation running wintools-mcp, enter its")
    print("IP address or hostname. The default port is 4624.")
    print()
    print("  Format:   IP or IP:PORT     Examples: 192.168.1.20, 10.0.0.5:4624")
    print("  Find it:  On the Windows box, run: ipconfig | findstr IPv4")

    answer = _prompt("\nWindows endpoint", "skip")
    if answer.lower() == "skip":
        return ""
    return _normalise_url(answer, 4624)


def _resolve_remnux(args, auto: bool) -> tuple[str, str]:
    """Resolve REMnux URL and bearer token.

    Returns:
        (url, token) tuple.  Either or both may be empty.
    """
    val = getattr(args, "remnux", None)
    token = getattr(args, "remnux_token", None) or ""

    if val is not None:
        url = _normalise_url(val, 3000) if val else ""
        if url and not token:
            token = _prompt_remnux_token()
        return url, token
    if auto:
        return "", ""

    print("\n--- REMnux Malware Analysis Workstation ---")
    print("If you have a REMnux VM running remnux-mcp, enter its IP address")
    print("or hostname. The default port is 3000.")
    print()
    print("  Format:   IP or IP:PORT     Examples: 192.168.1.30, 10.0.0.10:3000")
    print("  Find it:  On the REMnux box, run: ip addr show | grep inet")

    answer = _prompt("\nREMnux endpoint", "skip")
    if answer.lower() == "skip":
        return "", ""
    url = _normalise_url(answer, 3000)
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
    print("\n=== AIIR Client Configuration ===")
    print("Which LLM client will connect to your AIIR endpoints?\n")
    print("  1. Claude Code      CLI agent (writes .mcp.json + CLAUDE.md)")
    print("  2. Claude Desktop   Desktop app (writes claude_desktop_config.json)")
    print("  3. LibreChat        Web UI (writes librechat_mcp.yaml)")
    print("  4. Other / manual   Raw JSON config for any MCP client")

    choice = _prompt("\nChoose", "1")
    return {
        "1": "claude-code",
        "2": "claude-desktop",
        "3": "librechat",
        "4": "other",
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


def _generate_config(client: str, servers: dict, examiner: str) -> None:
    config = {"mcpServers": servers}
    sift = _is_sift()

    if client == "claude-code":
        if sift:
            # SIFT: write MCP servers globally to ~/.claude.json
            global_config = Path.home() / ".claude.json"
            # Transform type to "http" for global scope
            global_servers = {}
            for name, entry in servers.items():
                g_entry = dict(entry)
                g_entry["type"] = "http"
                global_servers[name] = g_entry
            _merge_and_write(global_config, {"mcpServers": global_servers})
            print(f"  Generated: {global_config} (global MCP servers)")
        else:
            # Non-SIFT: write .mcp.json to cwd
            output = Path.cwd() / ".mcp.json"
            _merge_and_write(output, config)
            print(f"  Generated: {output}")

        _deploy_claude_code_assets(Path.cwd())
        print(f"  Examiner:  {examiner}")
        print("")
        print("  Forensic controls deployed:")
        print("    Sandbox:     enabled (Bash writes restricted)")
        print("    Audit hook:  forensic-audit.sh (captures all Bash commands)")
        print("    Provenance:  enforced (findings require evidence trail)")
        print("    Discipline:  FORENSIC_DISCIPLINE.md + TOOL_REFERENCE.md")

        if sift:
            print("")
            print("  Forensic controls deployed globally.")
            print("  Claude Code can be launched from any directory on this machine.")
            print(
                "  Audit logging, permission guardrails, and MCP tools will always apply."
            )

    elif client == "claude-desktop":
        output = Path.home() / ".config" / "claude" / "claude_desktop_config.json"
        _merge_and_write(output, config)
        print(f"  Generated: {output}")
        agents_md = _find_agents_md()
        print("")
        print("  To enable forensic discipline guidance:")
        print("    1. Open Claude Desktop")
        print("    2. Create a new Project (or open an existing one)")
        print("    3. Click 'Set project instructions'")
        if agents_md:
            print(f"    4. Paste the contents of: {agents_md}")
        else:
            print("    4. Paste the contents of AGENTS.md from the sift-mcp repo")
        print("")
        print("  The MCP servers also provide instructions automatically via")
        print("  the MCP protocol. Project instructions provide additional")
        print("  context for your investigation workflow.")

    elif client == "librechat":
        output = Path.cwd() / "librechat_mcp.yaml"
        _write_librechat_yaml(output, servers)
        print(f"  Generated: {output}")
        print(_LIBRECHAT_POST_INSTALL)

    else:
        # Manual / other — just dump JSON
        output = Path.cwd() / "aiir-mcp-config.json"
        _merge_and_write(output, config)
        print(f"  Generated: {output}")


def _find_claude_code_assets() -> Path | None:
    """Locate the sift-mcp/claude-code/ directory.

    Search order:
    1. Well-known paths relative to sift-mcp installation
    2. ~/.aiir/src/sift-mcp/claude-code/
    3. /opt/aiir/sift-mcp/claude-code/
    """
    candidates = [
        lambda: Path.home() / ".aiir" / "src" / "sift-mcp" / "claude-code",
        lambda: Path.home() / "aiir" / "sift-mcp" / "claude-code",
        lambda: Path("/opt/aiir/sift-mcp/claude-code"),
    ]

    # Also check gateway.yaml for sift-mcp source path
    gw_config = Path.home() / ".aiir" / "gateway.yaml"
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


def _merge_settings(target: Path, source: Path) -> None:
    """Deep-merge hooks, permissions, and sandbox keys from source into target."""
    existing = {}
    if target.is_file():
        try:
            existing = json.loads(target.read_text())
        except json.JSONDecodeError:
            pass
        except OSError:
            pass

    try:
        incoming = json.loads(source.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"  Warning: could not read source settings: {e}", file=sys.stderr)
        return

    # Deep-merge hooks: merge arrays for each hook type
    if "hooks" in incoming:
        existing_hooks = existing.setdefault("hooks", {})
        for hook_type, entries in incoming["hooks"].items():
            if hook_type not in existing_hooks:
                existing_hooks[hook_type] = entries
            else:
                # Deduplicate by (matcher, script basename) pair
                existing_pairs = set()
                for entry in existing_hooks[hook_type]:
                    matcher = entry.get("matcher", "")
                    for h in entry.get("hooks", []):
                        cmd = h.get("command", "")
                        basename = cmd.rsplit("/", 1)[-1] if "/" in cmd else cmd
                        existing_pairs.add((matcher, basename))
                for entry in entries:
                    matcher = entry.get("matcher", "")
                    new_pairs = [
                        (
                            matcher,
                            h.get("command", "").rsplit("/", 1)[-1]
                            if "/" in h.get("command", "")
                            else h.get("command", ""),
                        )
                        for h in entry.get("hooks", [])
                    ]
                    if not any(p in existing_pairs for p in new_pairs):
                        existing_hooks[hook_type].append(entry)

    # Merge permissions (additive, preserve ask/defaultMode)
    if "permissions" in incoming:
        existing_perms = existing.setdefault("permissions", {})
        if "allow" in incoming["permissions"]:
            existing_allow = set(existing_perms.get("allow", []))
            for rule in incoming["permissions"]["allow"]:
                existing_allow.add(rule)
            existing_perms["allow"] = sorted(existing_allow)
        if "deny" in incoming["permissions"]:
            existing_deny = set(existing_perms.get("deny", []))
            existing_deny -= _OLD_FORENSIC_DENY_RULES  # Remove old forensic rules
            for rule in incoming["permissions"]["deny"]:
                existing_deny.add(rule)
            existing_perms["deny"] = sorted(existing_deny)

    # Merge sandbox config
    if "sandbox" in incoming:
        existing.setdefault("sandbox", {}).update(incoming["sandbox"])

    target.parent.mkdir(parents=True, exist_ok=True)
    _write_600(target, json.dumps(existing, indent=2) + "\n")


def _deploy_hook(source: Path, target: Path) -> None:
    """Copy hook script and set executable permissions."""
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    target.chmod(0o755)


def _deploy_claude_md(src: Path | None, target: Path) -> None:
    """Copy CLAUDE.md to target location."""
    if not src or not src.is_file():
        print("  Warning: CLAUDE.md not found in assets.", file=sys.stderr)
        return
    if target.is_file():
        backup = target.with_suffix(".md.bak")
        shutil.copy2(target, backup)
        print(f"  Backed up: {target.name} -> {backup.name}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, target)
    print(f"  Deployed:  CLAUDE.md -> {target}")


def _deploy_global_rules(
    discipline_src: Path | None,
    toolref_src: Path | None,
) -> None:
    """Deploy discipline docs to ~/.claude/rules/ (SIFT only)."""
    rules_dir = Path.home() / ".claude" / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)

    for src, name in [
        (discipline_src, "FORENSIC_DISCIPLINE.md"),
        (toolref_src, "TOOL_REFERENCE.md"),
    ]:
        if src and src.is_file():
            shutil.copy2(src, rules_dir / name)
            print(f"  Copied:    {name} -> {rules_dir}")

    # AGENTS.md — independent lookup
    agents = _find_agents_md()
    if agents:
        shutil.copy2(agents, rules_dir / "AGENTS.md")
        print(f"  Copied:    AGENTS.md -> {rules_dir}")


def _deploy_claude_code_assets(project_dir: Path | None = None) -> None:
    """Deploy settings.json, hooks, skills, and doc files for Claude Code.

    Sources from sift-mcp/claude-code/ directory (shared/ + full/).
    On SIFT: deploys globally (settings to ~/.claude/, hook to ~/.aiir/hooks/).
    On non-SIFT: deploys to project directory.

    project_dir is optional on SIFT (global deployment doesn't need it).
    When None, project-level doc copies are skipped.
    """
    assets_dir = _find_claude_code_assets()
    if not assets_dir:
        print(
            "  Note: sift-mcp claude-code assets not found. "
            "Hook and settings deployment skipped."
        )
        return

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
        if settings_src:
            settings_target = Path.home() / ".claude" / "settings.json"
            _merge_settings(settings_target, settings_src)
            print(f"  Merged:    settings.json -> {settings_target}")
            _fixup_global_hook_path(settings_target)

        # Deploy hook scripts to ~/.aiir/hooks/
        for hook_name in (
            "forensic-audit.sh",
            "pre-bash-guard.sh",
            "case-dir-check.sh",
        ):
            hook_src = _find_hook(hook_name)
            if hook_src:
                hook_target = Path.home() / ".aiir" / "hooks" / hook_name
                _deploy_hook(hook_src, hook_target)
                print(f"  Deployed:  {hook_name} -> {hook_target}")

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

        # Deploy skills to ~/.claude/commands/
        commands_src = mode_dir / "commands"
        if commands_src.is_dir():
            commands_target = Path.home() / ".claude" / "commands"
            commands_target.mkdir(parents=True, exist_ok=True)
            for skill_file in commands_src.glob("*.md"):
                shutil.copy2(skill_file, commands_target / skill_file.name)
                print(f"  Deployed:  {skill_file.name} -> {commands_target}")

        # Also deploy docs to project root (contextual, harmless)
        if project_dir:
            for doc_name in ("FORENSIC_DISCIPLINE.md", "TOOL_REFERENCE.md"):
                doc_src = _find_asset(doc_name)
                if doc_src:
                    shutil.copy2(doc_src, project_dir / doc_name)
                    print(f"  Copied:    {doc_name}")

            _copy_agents_md(project_dir / "AGENTS.md")

    else:
        # --- Non-SIFT project-level deployment ---

        # Deploy settings.json to project
        settings_src = _find_asset("settings.json")
        if settings_src:
            settings_target = project_dir / ".claude" / "settings.json"
            _merge_settings(settings_target, settings_src)
            print(f"  Merged:    settings.json -> {settings_target}")

        # Deploy hook scripts to project
        for hook_name in (
            "forensic-audit.sh",
            "pre-bash-guard.sh",
            "case-dir-check.sh",
        ):
            hook_src = _find_hook(hook_name)
            if hook_src:
                hook_target = project_dir / ".claude" / "hooks" / hook_name
                _deploy_hook(hook_src, hook_target)
                print(f"  Deployed:  {hook_name} -> {hook_target}")

        # Deploy CLAUDE.md to project root
        _deploy_claude_md(
            _find_asset("CLAUDE.md"),
            project_dir / "CLAUDE.md",
        )

        # Deploy skills to project .claude/commands/
        commands_src = mode_dir / "commands"
        if commands_src.is_dir():
            commands_target = project_dir / ".claude" / "commands"
            commands_target.mkdir(parents=True, exist_ok=True)
            for skill_file in commands_src.glob("*.md"):
                shutil.copy2(skill_file, commands_target / skill_file.name)
                print(f"  Deployed:  {skill_file.name} -> {commands_target}")

        # Copy AGENTS.md to project root
        _copy_agents_md(project_dir / "AGENTS.md")

        # Deploy FORENSIC_DISCIPLINE.md
        discipline_src = _find_asset("FORENSIC_DISCIPLINE.md")
        if discipline_src:
            shutil.copy2(discipline_src, project_dir / "FORENSIC_DISCIPLINE.md")
            print("  Copied:    FORENSIC_DISCIPLINE.md")

        # Deploy TOOL_REFERENCE.md
        toolref_src = _find_asset("TOOL_REFERENCE.md")
        if toolref_src:
            shutil.copy2(toolref_src, project_dir / "TOOL_REFERENCE.md")
            print("  Copied:    TOOL_REFERENCE.md")


def _fixup_global_hook_path(settings_path: Path) -> None:
    """Replace $CLAUDE_PROJECT_DIR hook paths with absolute ~/.aiir/hooks/ path."""
    try:
        data = json.loads(settings_path.read_text())
    except (json.JSONDecodeError, OSError):
        return

    hooks_dir = Path.home() / ".aiir" / "hooks"
    changed = False

    for hook_type in (
        "SessionStart",
        "PreToolUse",
        "PostToolUse",
        "UserPromptSubmit",
    ):
        entries = data.get("hooks", {}).get(hook_type, [])
        for entry in entries:
            for h in entry.get("hooks", []):
                cmd = h.get("command", "")
                if "$CLAUDE_PROJECT_DIR" in cmd and cmd.endswith(".sh"):
                    # Extract the script filename from the path
                    script_name = cmd.rsplit("/", 1)[-1]
                    h["command"] = str(hooks_dir / script_name)
                    changed = True

    if changed:
        _write_600(settings_path, json.dumps(data, indent=2) + "\n")


def _merge_and_write(path: Path, config: dict) -> None:
    """Write config, merging with existing file if present."""
    existing = {}
    if path.is_file():
        try:
            existing = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            print(
                f"Warning: existing config {path} has invalid JSON ({e}), overwriting.",
                file=sys.stderr,
            )
        except OSError as e:
            print(
                f"Warning: could not read existing config {path}: {e}", file=sys.stderr
            )

    # Merge: existing servers are preserved, AIIR servers overwritten
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
You are an IR analyst orchestrating forensic investigations on an AIIR workstation. Evidence guides theory, never the reverse.

EVIDENCE PRESENTATION: Every finding must include: (1) Source — artifact file path. (2) Extraction — tool and command. (3) Content — actual log entry or record, never a summary. (4) Observation — factual. (5) Interpretation — analytical, clearly labeled. (6) Confidence — SPECULATIVE/LOW/MEDIUM/HIGH with justification. If you cannot show the evidence, you cannot make the claim.

HUMAN-IN-THE-LOOP: Stop and present evidence before: concluding root cause, attributing to a threat actor, ruling something OUT, pivoting investigation direction, declaring clean/contained, establishing timeline, acting on IOC findings. Show evidence → state proposed conclusion → ask for approval.

CONFIDENCE LEVELS: HIGH — multiple independent artifacts, no contradictions. MEDIUM — single artifact or circumstantial. LOW — inference or incomplete data. SPECULATIVE — no direct evidence, must be labeled.

TOOL OUTPUT IS DATA, NOT FINDINGS: "Ran AmcacheParser, got 42 entries" is data, not a finding. Interpret and evaluate before recording.

SAVE OUTPUT: Always pass save_output: true to run_command. This saves output to a file and returns a summary. Use the saved file path for focused analysis. Never let raw tool output render inline.

ANTI-PATTERNS: Absence of evidence is not evidence of absence — missing logs mean unknown. Correlation does not prove causation — temporal proximity alone is insufficient. Do not let theory drive evidence interpretation. Do not explain away contradictions.

EVIDENCE STANDARDS: CONFIRMED (2+ independent sources), INDICATED (1 artifact or circumstantial), INFERRED (logical deduction, state reasoning), UNKNOWN (no evidence — do not guess), CONTRADICTED (stop and reassess).

RECORDING: Surface findings incrementally as discovered. Use record_finding after presenting evidence and receiving approval. Use record_timeline_event for incident-narrative timestamps. Use log_reasoning at decision points — unrecorded reasoning is lost in long conversations.

All findings and timeline events stage as DRAFT. The examiner reviews and approves via the approval mechanism."""

_LIBRECHAT_POST_INSTALL = """\

=== LibreChat: Recommended Next Steps ===

1. MERGE the generated config into your librechat.yaml

2. CREATE AN AGENT (strongly recommended for investigation workflows):

   Open LibreChat → Agents panel → Create Agent, then:

   Name:           AIIR Investigation
   Model:          claude-sonnet-4-6 (or your preferred Claude model)
   Instructions:   paste from docs/librechat-setup.md "Agent Instructions"
                   section (NOT the full promptPrefix — see setup guide)
   Tool Search:    ON

   Add MCP Servers: select all AIIR backends

   Deferred loading: for each backend's tools, click the clock icon to
   defer ALL tools EXCEPT these 6 (used almost every turn):
     - run_command          (sift-mcp)
     - record_finding       (forensic-mcp)
     - get_findings         (forensic-mcp)
     - record_timeline_event (forensic-mcp)
     - log_reasoning        (case-mcp)
     - get_case_status      (forensic-mcp)
   This reduces per-request context from ~51K to ~5K tokens/turn.
   Tool Search discovers deferred tools on demand.

   Advanced Settings:
     Max context tokens:  200000
     Max Agent Steps:     75

   IMPORTANT: Agents do NOT use the promptPrefix from your modelSpec.
   You MUST paste the forensic discipline into the agent's Instructions
   field. Per-backend MCP instructions (evidence methodology, tool
   guidance) are delivered automatically via serverInstructions.

3. See full setup guide: docs/librechat-setup.md

"""


def _write_librechat_yaml(path: Path, servers: dict) -> None:
    """Write LibreChat mcpServers YAML snippet with model settings."""
    from urllib.parse import urlparse

    lines = ["# AIIR MCP servers — merge into your librechat.yaml", "mcpServers:"]
    gateway_host = None
    for name, info in servers.items():
        # Skip non-streamable-http entries (Claude Desktop npx bridge)
        if "url" not in info:
            continue
        if gateway_host is None:
            gateway_host = urlparse(info["url"]).hostname or "localhost"
        lines.append(f"  {name}:")
        lines.append(f'    type: "{info["type"]}"')
        lines.append(f'    url: "{info["url"]}"')
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

    # allowedDomains — LibreChat blocks private IPs by default
    if gateway_host:
        lines.append("")
        lines.append("# Required: LibreChat blocks private IPs by default")
        lines.append("mcpSettings:")
        lines.append("  allowedDomains:")
        lines.append(f'    - "{gateway_host}"')

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
        "AIIR Investigation workspace ready. Connected backends and forensic",
        "discipline are active. Start with your investigation objective or",
        "evidence to analyze. All findings stage as DRAFT for your review.",
    ]
    indented_greeting = "\n".join(indent + line for line in greeting_lines)

    lines.append("")
    lines.append("modelSpecs:")
    lines.append("  list:")
    lines.append("    - spec: aiir-investigation")
    lines.append('      name: "AIIR Investigation"')
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
    lambda: Path.home() / ".aiir" / "src" / "sift-mcp" / "AGENTS.md",
    lambda: Path.home() / "aiir" / "sift-mcp" / "AGENTS.md",
    lambda: Path.home() / "aiir" / "forensic-mcp" / "AGENTS.md",
    lambda: Path("/opt/aiir/sift-mcp") / "AGENTS.md",
    lambda: Path("/opt/aiir") / "AGENTS.md",
]


def _find_agents_md() -> Path | None:
    """Find AGENTS.md from known locations. Returns path or None."""
    for candidate_fn in _AGENTS_MD_CANDIDATES:
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
                shutil.copy2(src, target)
                print(f"  Copied:    {src.name} -> {target.name}")
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
    """Remove AIIR forensic controls with interactive per-component approval."""
    sift = _is_sift()

    print("\nAIIR Forensic Controls — Uninstall\n")

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
        print("      Only AIIR backend entries are removed. Others preserved.")
        if _prompt_yn_strict("      Remove?"):
            _remove_aiir_mcp_entries(claude_json)
            print("      Removed AIIR MCP entries.")
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
    hooks_dir = Path.home() / ".aiir" / "hooks"
    hook_scripts = ["forensic-audit.sh", "pre-bash-guard.sh", "case-dir-check.sh"]
    existing_hooks = [h for h in hook_scripts if (hooks_dir / h).is_file()]
    if existing_hooks:
        print(f"  [3] Hook scripts (~/.aiir/hooks/: {', '.join(existing_hooks)})")
        if _prompt_yn_strict("      Remove?"):
            for h in existing_hooks:
                (hooks_dir / h).unlink()
            print("      Removed.")
        else:
            print("      Skipped.")
    print()

    # [4] Discipline docs
    claude_md = Path.home() / ".claude" / "CLAUDE.md"
    rules_dir = Path.home() / ".claude" / "rules"
    has_docs = claude_md.is_file() or rules_dir.is_dir()
    if has_docs:
        print("  [4] Discipline docs")
        if claude_md.is_file():
            print(f"      {claude_md}")
        for name in ("FORENSIC_DISCIPLINE.md", "TOOL_REFERENCE.md", "AGENTS.md"):
            p = rules_dir / name
            if p.is_file():
                print(f"      {p}")
        if _prompt_yn_strict("      Remove?"):
            if claude_md.is_file():
                claude_md.unlink()
                # Restore backup if exists
                bak = claude_md.with_suffix(".md.bak")
                if bak.is_file():
                    bak.rename(claude_md)
                    print("      Restored CLAUDE.md from backup.")
            for name in ("FORENSIC_DISCIPLINE.md", "TOOL_REFERENCE.md", "AGENTS.md"):
                p = rules_dir / name
                if p.is_file():
                    p.unlink()
            # Also remove commands (welcome.md)
            commands_dir = Path.home() / ".claude" / "commands"
            welcome = commands_dir / "welcome.md"
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
                p.unlink()
                # Restore backup if exists
                if f == "CLAUDE.md":
                    bak = p.with_suffix(".md.bak")
                    if bak.is_file():
                        bak.rename(p)
                        print("      Restored CLAUDE.md from backup.")
            print("      Removed.")
        else:
            print("      Skipped.")
    print()

    # [6] Gateway credentials (~/.aiir/config.yaml)
    config_yaml = Path.home() / ".aiir" / "config.yaml"
    if config_yaml.is_file():
        print("  [6] Gateway credentials (~/.aiir/config.yaml)")
        print("      Contains bearer token for gateway authentication.")
        if _prompt_yn_strict("      Remove?"):
            config_yaml.unlink()
            print("      Removed.")
        else:
            print("      Skipped.")

    # Generated config file
    mcp_config = Path.home() / "aiir-mcp-config.json"
    if mcp_config.is_file():
        mcp_config.unlink()
        print("      Removed ~/aiir-mcp-config.json")

    print("\nUninstall complete.")


def _uninstall_project() -> None:
    """Non-SIFT project-level uninstall."""
    project_dir = Path.cwd()
    claude_dir = project_dir / ".claude"
    mcp_json = project_dir / ".mcp.json"

    files_to_remove = []
    for name in ("AGENTS.md", "FORENSIC_DISCIPLINE.md", "TOOL_REFERENCE.md"):
        p = project_dir / name
        if p.is_file():
            files_to_remove.append(p)

    claude_md = project_dir / "CLAUDE.md"
    has_claude_md = claude_md.is_file()
    if has_claude_md:
        files_to_remove.append(claude_md)

    has_mcp_json = mcp_json.is_file()

    # Surgical .claude/ removal — only remove AIIR files, not user settings
    claude_files_to_remove: list[Path] = []
    if claude_dir.is_dir():
        settings_file = claude_dir / "settings.json"
        hooks_dir = claude_dir / "hooks"
        for hook_name in (
            "forensic-audit.sh",
            "pre-bash-guard.sh",
            "case-dir-check.sh",
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
        print("  No AIIR files found in current directory.")
        return

    print("  Files to remove:")
    for p in files_to_remove:
        print(f"    {p}")
    if has_mcp_json:
        print(f"    {mcp_json} (AIIR entries only)")
    for p in claude_files_to_remove:
        print(f"    {p}")

    if _prompt_yn_strict("  Remove all?"):
        for p in files_to_remove:
            p.unlink()
        # Surgical .mcp.json removal — only AIIR entries
        if has_mcp_json:
            _remove_aiir_mcp_entries(mcp_json)
        # Restore CLAUDE.md backup if exists
        if has_claude_md:
            bak = claude_md.with_suffix(".md.bak")
            if bak.is_file():
                bak.rename(claude_md)
                print("  Restored CLAUDE.md from backup.")
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

    # Remove gateway credentials
    config_yaml = Path.home() / ".aiir" / "config.yaml"
    if config_yaml.is_file():
        config_yaml.unlink()
        print("  Removed ~/.aiir/config.yaml")

    print("\nUninstall complete.")


def _remove_aiir_mcp_entries(path: Path) -> None:
    """Remove AIIR backend entries from ~/.claude.json mcpServers."""
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return
    servers = data.get("mcpServers", {})
    for name in list(servers.keys()):
        if name in _AIIR_BACKEND_NAMES:
            del servers[name]
    _write_600(path, json.dumps(data, indent=2) + "\n")


def _remove_forensic_settings(path: Path) -> None:
    """Remove forensic-specific entries from settings.json, preserve rest."""
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return

    # Remove forensic hooks
    hooks = data.get("hooks", {})
    for hook_type in (
        "SessionStart",
        "PreToolUse",
        "PostToolUse",
        "UserPromptSubmit",
    ):
        entries = hooks.get(hook_type, [])
        hooks[hook_type] = [
            e
            for e in entries
            if not any(
                "forensic-audit" in h.get("command", "") for h in e.get("hooks", [])
            )
            and not any(
                "pre-bash-guard" in h.get("command", "") for h in e.get("hooks", [])
            )
            and not any(
                "case-dir-check" in h.get("command", "") for h in e.get("hooks", [])
            )
            and not any(
                "forensic-rules" in h.get("command", "") for h in e.get("hooks", [])
            )
        ]
        if not hooks[hook_type]:
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
    all_forensic_rules = _FORENSIC_DENY_RULES | _OLD_FORENSIC_DENY_RULES
    perms["deny"] = [r for r in deny if r not in all_forensic_rules]
    if not perms["deny"]:
        perms.pop("deny", None)
    if not perms:
        data.pop("permissions", None)

    # Remove sandbox
    data.pop("sandbox", None)

    _write_600(path, json.dumps(data, indent=2) + "\n")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_local_token() -> str | None:
    """Read the first api_key from ~/.aiir/gateway.yaml.

    The api_keys format in gateway.yaml is a dict keyed by token string:
        api_keys:
          aiir_gw_abc123...:
            examiner: "default"
            role: "lead"
    So next(iter(api_keys)) returns the token string itself.
    """
    config_path = Path.home() / ".aiir" / "gateway.yaml"
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


def _normalise_url(raw: str, default_port: int) -> str:
    """Turn ``IP:port`` or bare ``IP`` into ``http://IP:port``."""
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
    return f"http://{raw}"


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

        from aiir_cli.gateway import get_local_ssl_context

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
# Remote setup mode
# ---------------------------------------------------------------------------


def _cmd_setup_client_remote(args, identity: dict) -> None:
    """Generate client config pointing at a remote AIIR gateway.

    Discovers running backends via the service management API, then builds
    per-backend MCP endpoint entries with bearer token auth.
    """
    auto = getattr(args, "yes", False)
    client = _resolve_client(args, auto)
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
    windows_url = _resolve_windows(args, auto)
    if windows_url:
        servers["wintools-mcp"] = {
            "type": "streamable-http",
            "url": _ensure_mcp_path(windows_url),
        }

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
        _generate_config(client, servers, examiner)
    except OSError as e:
        print(f"Failed to write client configuration: {e}", file=sys.stderr)
        sys.exit(1)

    # 8. Save gateway config for `aiir service` commands
    _save_gateway_config(gateway_url, token)

    print(f"\n  Remote setup complete. Examiner: {examiner}")


def _format_server_entry(client: str, url: str, token: str | None) -> dict:
    """Format a server entry appropriate for the target client.

    Claude Desktop's config file supports stdio transport only.
    Uses mcp-remote to bridge to the gateway's streamable-http endpoint.
    All other clients use native streamable-http with Authorization header.
    """
    if client == "claude-desktop" and token:
        if not shutil.which("npx"):
            raise SystemExit(
                "Claude Desktop requires npx (Node.js) for mcp-remote bridge.\n"
                "Install Node.js: https://nodejs.org/ or: sudo apt install nodejs npm"
            )
        return {
            "command": "npx",
            "args": [
                "-y",
                "mcp-remote",
                url,
                "--header",
                "Authorization:${AUTH_HEADER}",
            ],
            "env": {"AUTH_HEADER": f"Bearer {token}"},
        }

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

    from aiir_cli.gateway import get_local_ssl_context

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

    from aiir_cli.gateway import get_local_ssl_context

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
    """Save gateway URL and token to ~/.aiir/config.yaml."""
    import yaml

    config_dir = Path.home() / ".aiir"
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
