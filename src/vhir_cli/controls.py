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
        "for Codex, an apply_patch is checked by the paths its headers name, and a "
        "relative path is read against the session's folder, so a command run in "
        "another folder isn't checked correctly",
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


SANDBOX_OFF = "SANDBOX OFF: Bash runs unconfined when the sandbox can't start"


def block_lines(
    client: str, sandbox_off: bool = False, not_applied: str = ""
) -> list[str]:
    """The controls block for `client` (claude-code, codex, or anything else
    as MCP-only). `not_applied` says why the client's own controls aren't
    in effect as shipped: the block then claims none of them, only the
    server-side rows."""
    kind = client if client in (CLAUDE, CODEX) else MCP
    lines = ["  Controls (as deployed now):"]
    for name, clients, protects, gaps in rows_for(kind):
        if not_applied and clients != ALL:
            continue
        if name == "Sandbox" and sandbox_off:
            protects = SANDBOX_OFF
        lines.append(f"    {name}: {protects}.")
        lines.append(f"      Doesn't cover: {gaps}.")
    if not_applied:
        lines.append(f"    NOT in effect: {not_applied}.")
    return lines


def _codex_not_applied() -> str:
    """Why Codex's controls aren't in effect as shipped, or "" when they are:
    our requirements file, exactly as setup writes it, with its hooks."""
    from pathlib import Path

    from vhir_cli.commands import codex_controls as cc

    state = cc.codex_controls_state([CODEX])
    setup = "run vhir setup client --client=codex"
    if state == "off":
        return f"CODEX CONTROLS OFF: {cc.REQUIREMENTS} isn't installed; {setup} to turn them on"
    if state == "admin-file":
        return (
            f"{cc.REQUIREMENTS} is an administrator's own file; Valhuntir doesn't "
            "check what it requires (merge the block setup prints to have its controls)"
        )
    found = cc._sources()
    if found is None or not cc._same(cc.render(found[0], Path.home()), found[1]):
        return (
            f"Valhuntir's controls aren't fully applied in {cc.REQUIREMENTS} "
            f"(declined or edited); {setup} to apply them"
        )
    return ""


def applied(client: str, settings_path=None) -> tuple[bool, str]:
    """(sandbox off, why not applied) for `client` as installed now, read
    from the files themselves, never from what setup meant to install. The
    controls are on only when the file holds every control as shipped."""
    if client == CLAUDE:
        from pathlib import Path

        from vhir_cli.commands.client_setup import settings_applied

        path = Path(settings_path or Path.home() / ".claude" / "settings.json")
        on, sandbox_off = settings_applied(path)
        if not on:
            return False, (
                f"Valhuntir's controls aren't fully applied in {path} (declined or "
                "edited); run vhir setup client to apply them"
            )
        return sandbox_off, ""
    if client == CODEX:
        return False, _codex_not_applied()
    return False, ""


# Off the SIFT box there is no case: no row of Claude Code's holds there
OFF_SIFT = (
    "this machine has no case, and its local controls guard no case records: "
    "Claude Code's shell commands here aren't in the case audit; these settings "
    "are user-switchable"
)


def print_block(client: str, settings_path=None, sift: bool = True) -> None:
    """Print `client`'s controls block as installed now. Off the SIFT box
    (Claude Code on a laptop), only the gateway's rows and why."""
    if client == CLAUDE and not sift:
        sandbox_off, why = False, OFF_SIFT
    else:
        sandbox_off, why = applied(client, settings_path)
    for line in block_lines(client, sandbox_off, why):
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
