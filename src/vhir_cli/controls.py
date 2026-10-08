"""What each client's controls protect, and what they don't.

One table drives the block `vhir setup client` and `vhir update` print for
each client, and the table in docs/security.md (a test keeps them equal).
The block describes the files as deployed when it's printed. The AI keeps
sudo through run_command, so client-side controls prevent accidents and
record what happened; the approved findings' signatures are what catch a
change after the fact.
"""

from __future__ import annotations

CLAUDE, CODEX, MCP = "claude-code", "codex", "mcp-only"
ALL = (CLAUDE, CODEX, MCP)

# (control, clients, protects, doesn't protect)
ROWS = (
    (
        "run_command",
        ALL,
        "nothing: it's the one tool that runs outside every client sandbox",
        "it runs as the examiner, with sudo, and can rewrite or remove every "
        "client-side control below; the gateway's audit of the call is the only trace",
    ),
    (
        "Signed approvals",
        ALL,
        "an approved finding or timeline event: a later change fails verification",
        "drafts, which the AI's shell can still change before the examiner approves them",
    ),
    (
        "Deny rules",
        (CLAUDE,),
        "the Edit and Read tools on the case records, the signing store, the "
        "settings, hooks and deployed skills",
        "Bash (the sandbox's job), MCP tools, and refusals, which no hook records",
    ),
    (
        "Sandbox",
        (CLAUDE,),
        "Bash: it can't write the controls or read the signing store, and Claude "
        "Code won't start without it",
        "MCP tools, and the case folder: Bash can write in it, drafts and audit files included",
    ),
    (
        "Managed requirements",
        (CODEX,),
        "Codex's shell: its sandbox stays on, it can't read the signing store, the "
        "gateway's tokens or the profile, and ~/.codex and ~/.agents are read-only to it",
        "every Codex session on the machine follows them; anyone with sudo (the AI "
        "too, through run_command) can move them away; sessions already running keep "
        "the old rules until restarted; a kernel that restricts user namespaces stops "
        "Codex's sandbox, and its shell commands then fail",
    ),
    (
        "Audit",
        (CLAUDE, CODEX),
        "each shell command, recorded in the active case, failed ones and the "
        "case-data guard's refusals too",
        "a deny rule's refusal (no hook runs for it); another OS user's sessions; "
        "a session after the active case was switched "
        "through MCP; two sessions at once can share an audit id; Codex's typed shell "
        "input is recorded at its next hooked call or when the turn ends; a command "
        "with an MCP route is marked only when it's the first one (not later in a "
        "pipe or chain, or inside a script)",
    ),
    (
        "Case-data guard",
        (CLAUDE, CODEX),
        "the listed ways to delete or overwrite case records with a shell command",
        "interpreters, editors, tee and scripts: a best-effort check, not a boundary; "
        "for Codex, apply_patch edits aren't checked, and a relative path is read "
        "against the session's folder, so a command run in another folder isn't "
        "checked correctly",
    ),
    (
        "Start-up check",
        (CLAUDE, CODEX),
        "a warning when the session starts outside a case folder",
        "it never stops the session",
    ),
    (
        "MCP-only",
        (MCP,),
        "the server-side controls only: tools, audit and approvals on the gateway",
        "whether the client follows the forensic discipline can't be checked",
    ),
)


def rows_for(client: str):
    return [r for r in ROWS if client in r[1]]


def block_lines(
    client: str,
    sandbox_off: bool = False,
    codex_state: str = "",
    overrides: dict | None = None,
) -> list[str]:
    """The controls block for `client` (claude-code, codex, or anything else
    as MCP-only). `overrides` replaces a row's "protects" text with what is
    installed instead (see installed_overrides); `sandbox_off` and
    `codex_state` are its two commonest cases."""
    kind = client if client in (CLAUDE, CODEX) else MCP
    over = dict(overrides or {})
    if sandbox_off:
        over.setdefault("Sandbox", SANDBOX_OFF)
    if kind == CODEX and codex_state in ("off", "admin-file"):
        over = {**_codex_overrides(codex_state, ""), **over}
    lines = ["  Controls (as deployed now):"]
    for name, _, protects, gaps in rows_for(kind):
        lines.append(f"    {name}: {over.get(name, protects)}.")
        lines.append(f"      Doesn't cover: {gaps}.")
    return lines


SANDBOX_OFF = "SANDBOX OFF: Bash runs unconfined when the sandbox can't start"
# A row that is a hook: the hook's file name (in Claude Code's settings, or
# run by Codex's requirements)
HOOKED = {
    "Audit": "forensic-audit.sh",
    "Case-data guard": "case-data-guard.sh",
    "Start-up check": "case-dir-check.sh",
}
_HOOK_EVENT = {"Audit": "PostToolUse", "Case-data guard": "PreToolUse",
               "Start-up check": "SessionStart"}  # fmt: skip


def _claude_overrides(settings_path) -> dict:
    """What Claude Code's settings file holds now, row by row."""
    import json
    from pathlib import Path

    path = Path(settings_path)
    try:
        settings = json.loads(path.read_text())
        if not isinstance(settings, dict):
            raise ValueError
    except (OSError, ValueError):
        missing = f"NOT in effect: {path} can't be read"
        return {n: missing for n in ("Deny rules", "Sandbox", *HOOKED)}
    over = {}
    deny = (settings.get("permissions") or {}).get("deny") or []
    if not any("findings.json" in str(r) for r in deny):
        over["Deny rules"] = f"NOT in effect: {path} has none of Valhuntir's deny rules"
    sandbox = settings.get("sandbox") or {}
    if sandbox.get("enabled") is not True:
        over["Sandbox"] = f"SANDBOX OFF: {path} doesn't turn it on"
    elif sandbox.get("failIfUnavailable") is False:
        over["Sandbox"] = SANDBOX_OFF
    hooks = settings.get("hooks") or {}
    for name, script in HOOKED.items():
        commands = [h.get("command", "") for m in hooks.get(_HOOK_EVENT[name]) or []
                    if isinstance(m, dict) for h in m.get("hooks") or [] if isinstance(h, dict)]  # fmt: skip
        if not any(script in str(c) for c in commands):
            over[name] = f"NOT in effect: {path} doesn't run {script}"
    return over


def _codex_overrides(state: str, text: str) -> dict:
    """What Codex's managed layer holds now: our file (nothing to say), none
    (every control it carries is off), or an administrator's own file (only
    the hooks it names that are installed run)."""
    from vhir_cli.commands.codex_controls import HOOKS_DIR, REQUIREMENTS

    if state == "off":
        off = f"NOT in effect: {REQUIREMENTS}, which runs it, isn't installed"
        return {
            "Managed requirements": f"CODEX CONTROLS OFF: {REQUIREMENTS} isn't installed",
            **{n: off for n in HOOKED},
        }
    if state != "admin-file":
        return {}
    over = {
        "Managed requirements": "NOT ours: an administrator's own requirements file; "
        "what it requires is theirs, and Valhuntir doesn't check it"
    }
    for name, script in HOOKED.items():
        hook = HOOKS_DIR / script
        if str(hook) not in text:
            over[name] = (
                f"NOT in effect: the administrator's {REQUIREMENTS} doesn't run it"
            )
        elif not hook.is_file():
            over[name] = f"NOT in effect: {hook}, which the file runs, isn't installed"
    return over


def installed_overrides(client: str, settings_path=None) -> dict:
    """Each row's state as installed now, read from the files themselves
    (Claude Code's settings; Codex's requirements and hooks), never from
    what setup meant to install."""
    if client == CLAUDE:
        from pathlib import Path

        return _claude_overrides(
            settings_path or Path.home() / ".claude" / "settings.json"
        )
    if client == CODEX:
        from vhir_cli.commands.codex_controls import REQUIREMENTS, codex_controls_state

        state = codex_controls_state([CODEX])
        try:
            text = REQUIREMENTS.read_text() if state == "admin-file" else ""
        except OSError:
            text = ""
        return _codex_overrides(state, text)
    return {}


def print_block(client: str, settings_path=None) -> None:
    """Print `client`'s controls block as installed now."""
    for line in block_lines(
        client, overrides=installed_overrides(client, settings_path)
    ):
        print(line)


def markdown() -> str:
    """The docs table: one row per control and client set."""
    names = {CLAUDE: "Claude Code", CODEX: "Codex", MCP: "MCP-only clients"}
    out = [
        "| Control | Clients | Protects | Doesn't protect |",
        "|---|---|---|---|",
    ]
    for name, clients, protects, gaps in ROWS:
        who = ", ".join(names[c] for c in clients)
        out.append(f"| {name} | {who} | {protects} | {gaps} |")
    return "\n".join(out) + "\n"
