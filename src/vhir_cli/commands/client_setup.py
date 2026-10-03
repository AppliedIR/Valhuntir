"""Generate LLM client configuration pointing at Valhuntir API servers.

On SIFT, MCP entries use ``type: http`` in global ``~/.claude.json``.
On remote clients, entries use ``type: streamable-http`` in project
``.mcp.json``.  Runs on the machine where the human sits; points at
gateway / wintools / REMnux endpoints wherever they are.
"""

from __future__ import annotations

import json
import os
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
    "Write(**/findings.json)",
    "Write(**/timeline.json)",
    "Write(**/approvals.jsonl)",
    "Write(**/todos.json)",
    "Write(**/CASE.yaml)",
    "Write(**/actions.jsonl)",
    "Write(**/audit/*.jsonl)",
    "Edit(**/evidence.json)",
    "Write(**/evidence.json)",
    "Edit(**/iocs.json)",
    "Write(**/iocs.json)",
    "Read(/var/lib/vhir/**)",
    "Edit(/var/lib/vhir/**)",
    "Write(/var/lib/vhir/**)",
    "Bash(vhir approve*)",
    "Bash(*vhir approve*)",
    "Bash(vhir reject*)",
    "Bash(*vhir reject*)",
    # Control file self-protection (anti-accident, anti-injection)
    "Edit(**/.claude/settings.json)",
    "Write(**/.claude/settings.json)",
    "Edit(**/.claude/CLAUDE.md)",
    "Write(**/.claude/CLAUDE.md)",
    "Edit(**/.claude/rules/**)",
    "Write(**/.claude/rules/**)",
    "Edit(**/.vhir/hooks/**)",
    "Write(**/.vhir/hooks/**)",
    "Edit(**/.vhir/active_case)",
    "Write(**/.vhir/active_case)",
    "Edit(**/.vhir/gateway.yaml)",
    "Write(**/.vhir/gateway.yaml)",
    "Edit(**/.vhir/config.yaml)",
    "Write(**/.vhir/config.yaml)",
    "Edit(**/.vhir/.password_lockout)",
    "Write(**/.vhir/.password_lockout)",
    # Sync with template (was in settings.json but missing here)
    "Edit(**/pending-reviews.json)",
    "Write(**/pending-reviews.json)",
}

# Old forensic deny rules — removed during migration re-deploy
_OLD_FORENSIC_DENY_RULES = {"Bash(rm -rf *)", "Bash(mkfs*)", "Bash(dd *)"}

# Valhuntir MCP names — used for uninstall identification.
_VHIR_BACKEND_NAMES = {
    "forensic-mcp",
    "case-mcp",
    "sift-mcp",
    "report-mcp",
    "forensic-rag-mcp",
    "windows-triage-mcp",
    "opencti-mcp",
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
    global _APPLIED
    auto = getattr(args, "yes", False) and not getattr(args, "ask_user_files", False)
    _APPLIED = [] if auto else None
    try:
        _setup_client(args, identity)
    finally:
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

    # 4. Record client type in manifest (for vhir update)
    manifest_path = Path.home() / ".vhir" / "manifest.json"
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


def _duplicate_backends(servers: dict) -> list[str]:
    """Per-backend ~/.claude.json entries that duplicate gateway routing."""
    _BACKEND_NAMES = {
        "forensic-mcp",
        "case-mcp",
        "sift-mcp",
        "report-mcp",
        "forensic-rag-mcp",
        "windows-triage-mcp",
        "opencti-mcp",
        "opensearch-mcp",
        "wintools-mcp",
        "forensic-rag",
        "windows-triage",
    }
    gw_url = servers.get("vhir", {}).get("url", "")
    if not gw_url:
        return []
    gw_base = gw_url.rsplit("/mcp/", 1)[0]
    try:
        existing = json.loads((Path.home() / ".claude.json").read_text())["mcpServers"]
    except (OSError, ValueError, KeyError, TypeError):
        return []
    if not isinstance(existing, dict):
        return []
    return [
        name
        for name, entry in existing.items()
        if name in _BACKEND_NAMES
        and isinstance(entry, dict)
        and entry.get("url", "").startswith(gw_base)
    ]


def _cleanup_duplicate_backends(servers: dict) -> None:
    """Remove per-backend entries that duplicate gateway routing."""
    claude_json = Path.home() / ".claude.json"
    removed = _duplicate_backends(servers)
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
            _merge_and_write(output, {"mcpServers": servers})
            print(f"  Generated: {output}")

        settings = _deploy_claude_code_assets(Path.cwd())
        print(f"  Examiner:  {examiner}")
        print("")
        if settings and settings[1] != "kept":
            print("  Forensic controls deployed:")
            print("    Sandbox:     enabled (Bash writes restricted)")
            print("    Audit hook:  forensic-audit.sh (captures all Bash commands)")
            print("    Provenance:  enforced (findings require evidence trail)")
            print("    Discipline:  FORENSIC_DISCIPLINE.md + TOOL_REFERENCE.md")
        elif settings:
            print(f"  Forensic controls NOT applied to {settings[0]}; see above.")

        if sift and settings and settings[1] != "kept":
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
        output = Path.cwd() / "vhir-mcp-config.json"
        _merge_and_write(output, config)
        print(f"  Generated: {output}")


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
# `vhir setup client -y`: (backup, path) of each user file it changed. None
# when a change is asked about on a terminal, or kept, instead.
_APPLIED: list | None = None
# Launcher files _isolate_gateway_launchers rewrote in this process.
_LAUNCHERS_UPDATED: list[Path] = []


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


def _isolate_gateway_launchers() -> list[Path]:
    """Add -I to the gateway launch line in the files setup-sift.sh writes
    (~/.vhir/start-gateway.sh and the user unit), so the gateway never imports
    from the directory it starts in. setup-sift.sh rewrites both files whole
    on every run; here only the generated line changes. A line that differs
    (edited by the user) is left with a notice. Keeps the file's mode and a
    symlink. Never raises: an older vhir update runs this unguarded.
    Returns the files rewritten."""
    import re
    import subprocess

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
            print(f"  Note: could not check {path}: {e}")
    return updated


def _shipped(dst: Path, src: Path) -> bool:
    """Whether dst's bytes are a version of src the product shipped: dst's
    blob id appears in the history of src's checkout (HEAD, following
    renames). Without git or a checkout: False, so the user is asked."""
    import subprocess

    def git(*args):
        return subprocess.run(
            ["git", *args], capture_output=True, text=True, timeout=30
        )

    try:
        top = git("-C", str(src.parent), "rev-parse", "--show-toplevel")
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


def _write_user_file(path: Path, new: str, why: str, as_json: bool = False) -> str:
    """Write a file the user may have edited, only with their consent.

    Returns "created" (no file was there), "unchanged" (nothing would change),
    "written" (they said yes, or `vhir setup client -y`; a backup was made
    first) or "kept". Asks only on a terminal (default No); otherwise prints
    the change and keeps the file.
    """
    if not path.exists():
        _replace_bytes(path, new.encode(), 0o600 if as_json else 0o644)
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
        print(f"    {line}")
    if _APPLIED is None and not sys.stdin.isatty():
        print(
            f"  Not changed: {path}. To review and apply, re-run `vhir update` "
            "or `vhir setup client` in a terminal."
        )
        return "kept"
    if _APPLIED is None and input(
        f"  Apply these changes to {path}? [y/N] "
    ).strip().lower() not in ("y", "yes"):
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


def _merged_settings(target: Path, source: Path, hooks_dir: Path | None) -> dict | None:
    """The settings target would hold after merging source in: lists keep the
    user's order with missing entries appended. hooks_dir rewrites the
    product hooks' commands to it (global deployment). None if unreadable."""
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

    # Merge sandbox config (deep-merge filesystem.denyWrite)
    if "sandbox" in incoming:
        existing_sandbox = existing.setdefault("sandbox", {})
        incoming_sandbox = incoming["sandbox"]
        if "filesystem" in incoming_sandbox:
            existing_fs = existing_sandbox.setdefault("filesystem", {})
            for k, v in incoming_sandbox["filesystem"].items():
                if k == "denyWrite":
                    existing_fs[k] = add_missing(existing_fs.get(k, []), v)
                else:
                    existing_fs[k] = v
        # Merge top-level sandbox keys (enabled, allowUnsandboxedCommands)
        for k, v in incoming_sandbox.items():
            if k != "filesystem":
                existing_sandbox[k] = v
    return existing


def _merge_settings(target: Path, source: Path, hooks_dir: Path | None = None) -> str:
    """Merge the product's hooks, permissions and sandbox into target, only
    with the user's consent (see _write_user_file). Returns its status."""
    merged = _merged_settings(target, source, hooks_dir)
    if merged is None:
        return "kept"
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
    """Deploy discipline docs to ~/.claude/rules/ (SIFT only)."""
    rules_dir = Path.home() / ".claude" / "rules"
    for src, name in [
        (discipline_src, "FORENSIC_DISCIPLINE.md"),
        (toolref_src, "TOOL_REFERENCE.md"),
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

        # Deploy skills to ~/.claude/commands/
        commands_src = mode_dir / "commands"
        if commands_src.is_dir():
            commands_target = Path.home() / ".claude" / "commands"
            for skill_file in commands_src.glob("*.md"):
                _deploy_copy(skill_file, commands_target / skill_file.name)

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
            settings = (settings_target, _merge_settings(settings_target, settings_src))
            _report_settings(*settings)

        # Deploy hook scripts to project
        for hook_name in _PRODUCT_HOOKS:
            _deploy_hook(
                _find_hook(hook_name), project_dir / ".claude" / "hooks" / hook_name
            )

        _drop_deprecated_hooks(project_dir / ".claude" / "hooks", settings_target)

        # Deploy CLAUDE.md to project root
        _deploy_claude_md(
            _find_asset("CLAUDE.md"),
            project_dir / "CLAUDE.md",
        )

        # Deploy skills to project .claude/commands/
        commands_src = mode_dir / "commands"
        if commands_src.is_dir():
            commands_target = project_dir / ".claude" / "commands"
            for skill_file in commands_src.glob("*.md"):
                _deploy_copy(skill_file, commands_target / skill_file.name)

        # Copy AGENTS.md to project root
        _copy_agents_md(project_dir / "AGENTS.md")

        # Deploy FORENSIC_DISCIPLINE.md and TOOL_REFERENCE.md
        for doc_name in ("FORENSIC_DISCIPLINE.md", "TOOL_REFERENCE.md"):
            _deploy_copy(_find_asset(doc_name), project_dir / doc_name)
        return settings if settings_src else None


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
            old_path.unlink()
            print(f"  Removed:   {old_hook} (deprecated)")


def _report_settings(path: Path, status: str) -> None:
    """Say what happened to a settings file, truthfully."""
    if status in ("created", "written"):
        print(f"  Merged:    settings.json -> {path}")
    elif status == "kept":
        print(f"  Forensic controls NOT applied to {path}; see above.")


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

    lines = ["# Valhuntir MCP servers — merge into your librechat.yaml", "mcpServers:"]
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
    hook_scripts = ["forensic-audit.sh", "case-dir-check.sh", "case-data-guard.sh"]
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
                _remove_claude_md(claude_md, "      ")
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
    manifest_path = Path.home() / ".vhir" / "manifest.json"
    client = None
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text())
            client = manifest.get("client")
        except (json.JSONDecodeError, OSError):
            pass
    if not client:
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

    # Find config file for the detected client type
    sift = _is_sift()
    if client == "claude-code":
        if sift:
            config_path = Path.home() / ".claude.json"
            remnux_entry["type"] = "http"
        else:
            config_path = Path.cwd() / ".mcp.json"
    elif client == "claude-desktop":
        config_path = Path.home() / ".config" / "claude" / "claude_desktop_config.json"
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
        _generate_config(client, servers, examiner)
    except OSError as e:
        print(f"Failed to write client configuration: {e}", file=sys.stderr)
        sys.exit(1)

    # 8. Save gateway config for `vhir service` commands
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
