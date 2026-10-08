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
        "each shell command, failed and refused ones too, recorded in the active case",
        "another OS user's sessions; a session after the active case was switched "
        "through MCP; two sessions at once can share an audit id; Codex's typed shell "
        "input is recorded at its next hooked call or when the turn ends; a command "
        "with an MCP route is marked only when it's the first one (not later in a "
        "pipe or chain, or inside a script)",
    ),
    (
        "Case-data guard",
        (CLAUDE, CODEX),
        "the listed ways to delete or overwrite case records (for Codex, a relative "
        "path is refused: it doesn't say which folder a command runs in)",
        "interpreters, editors, tee and scripts: a best-effort check, not a boundary",
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
    client: str, sandbox_off: bool = False, codex_state: str = ""
) -> list[str]:
    """The controls block for `client` (claude-code, codex, or anything else
    as MCP-only), with the deployed state: SANDBOX OFF, or Codex's
    requirements off or not in effect."""
    kind = client if client in (CLAUDE, CODEX) else MCP
    lines = ["  Controls (as deployed now):"]
    for name, _, protects, gaps in rows_for(kind):
        if name == "Sandbox" and sandbox_off:
            protects = "SANDBOX OFF: Bash runs unconfined when the sandbox can't start"
        if name == "Managed requirements" and codex_state in ("off", "admin-file"):
            protects = {
                "off": "CODEX CONTROLS OFF: the requirements were moved away",
                "admin-file": "NOT in effect: an administrator's own requirements file",
            }[codex_state]
        lines.append(f"    {name}: {protects}.")
        lines.append(f"      Doesn't cover: {gaps}.")
    return lines


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
