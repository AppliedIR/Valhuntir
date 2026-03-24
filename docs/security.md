# Security Model

## Design Philosophy

ValiHuntIR runs on isolated forensic workstations behind firewalls. The primary security boundary is network isolation and VM/container isolation, not in-band command filtering. The controls described here are defense-in-depth measures within that boundary.

## Network Assumptions

All ValiHuntIR components are assumed to run on a private forensic network:

- Not exposed to incoming connections from the Internet
- Not exposed to untrusted systems
- Protected by firewalls on a trusted network segment
- Outgoing Internet connections are required for report generation (Zeltser IR Writing MCP) and optionally for threat intelligence (OpenCTI) and documentation (MS Learn MCP)

wintools-mcp must only be installed on dedicated forensic workstations. Never install on personal laptops, production systems, or machines containing data outside the scope of the investigation.

## Authentication

### Gateway (sift-gateway)

Bearer token authentication on all MCP and REST endpoints (health check excepted). Tokens use the `vhir_gw_` prefix with 24 hex characters (96 bits of entropy).

```text
Authorization: Bearer vhir_gw_a1b2c3d4e5f6a1b2c3d4e5f6
```

API keys map to examiner identities in `gateway.yaml`. The examiner name is injected into backend tool calls for audit attribution.

When installed with `--remote`, TLS is enabled with a local CA certificate.

### wintools-mcp

Bearer token authentication with `vhir_wt_` prefix. Generated during installation. Every request requires `Authorization: Bearer <token>`. The `--no-auth` flag is for development only.

## Execution Security

### sift-mcp (Linux)

- **Denylist**: Blocks destructive system commands (mkfs, dd, fdisk, shutdown, etc.). When Claude Code is the client, additional case-file-specific deny rules are deployed (see L3 below).
- **subprocess.run(shell=False)**: No shell, no arbitrary command chains
- **Argument sanitization**: Shell metacharacters blocked
- **Path validation**: Kernel interfaces (/proc, /sys, /dev) blocked for input
- **rm protection**: Case directories protected from deletion
- **Output truncation**: Large output capped
- **Flag restrictions**: Certain tools have specific flag blocks (find blocks `-exec`/`-delete`, sed blocks `-i`, tar blocks extraction/creation, etc.)

Uncataloged tools can execute with basic response envelopes. Catalog enrollment is for FK enrichment, not access control.

### wintools-mcp (Windows)

- **Catalog allowlist**: Only tools defined in YAML catalog files can execute
- **Hardcoded denylist**: 20+ dangerous binaries blocked (cmd, powershell, pwsh, wscript, cscript, mshta, rundll32, regsvr32, certutil, bitsadmin, msiexec, bash, wsl, sh, msbuild, installutil, regasm, regsvcs, cmstp, control — including .exe variants)
- **subprocess.run(shell=False)**: No shell, no command chains
- **Argument sanitization**: Shell metacharacters, response-file syntax (`@filename`), dangerous flags, and output redirect flags all blocked
- **Output directory control**: Zimmerman tool wrappers hardcode the output directory; user-supplied flags cannot override it

The installer requires typing `security_hole` (or passing `-AcknowledgeSecurityHole`) as an intentional friction point.

## Human-in-the-Loop Controls

Nine layers of defense-in-depth protect the integrity of forensic findings. The HMAC verification ledger (L2) is the cryptographic guarantee. The other layers are advisory controls that raise the bar.

### L1 — Structural Approval Gate

All findings and timeline events stage as DRAFT. Only a human examiner can move them to APPROVED or REJECTED — via the vhir CLI (password entry at `/dev/tty`) or the Examiner Portal (challenge-response authentication in the browser). There is no MCP tool for approval. The AI cannot bypass either mechanism: the CLI reads the password from `/dev/tty` (not stdin), and the portal requires computing HMAC(PBKDF2(password), nonce) which the AI cannot do without the password.

### L2 — HMAC Verification Ledger

When an examiner approves findings, an HMAC-SHA256 signature is computed over the substantive text (observation + interpretation for findings, description for timeline events) using a key derived from the examiner's password (PBKDF2, 600K iterations). These signatures are stored in `/var/lib/vhir/verification/{case-id}.jsonl` — outside the case directory and outside the Claude Code sandbox.

- `vhir review --verify` performs full HMAC verification with per-examiner password prompts
- `vhir review --verify --mine` filters to the current examiner only
- Report generation includes automatic reconciliation (no password needed) that detects mismatches between approved items and ledger entries
- Password rotation (`vhir config --reset-password`) re-signs all ledger entries with the new key
- Case close copies the verification ledger into the case directory for archival

The LLM cannot forge ledger entries because it does not know the password-derived key.

### L3 — Case Data Deny Rules

When Claude Code is the LLM client, 41 deny rules block Read/Edit/Write tool access to protected files:

- Case data: `findings.json`, `timeline.json`, `approvals.jsonl`, `todos.json`, `CASE.yaml`, `actions.jsonl`, `audit/*.jsonl`, `evidence.json`, `pending-reviews.json`
- System: `/var/lib/vhir/**` (verification ledger + password hashes)
- CLI: `Bash(vhir approve*)` and `Bash(vhir reject*)` (including path-qualified variants)
- Control files: `.claude/settings.json`, `.claude/CLAUDE.md`, `.claude/rules/**`, `.vhir/hooks/**`, `.vhir/active_case`, `.vhir/gateway.yaml`, `.vhir/config.yaml`, `.vhir/.password_lockout`

These rules replace the previous generic denylist (rm -rf, mkfs, dd) with targeted protection for case integrity.

### L4 — Sandbox Filesystem Write Protection

`sandbox.filesystem.denyWrite` uses bwrap to OS-enforce write blocking on protected paths. Bash commands run inside the sandbox cannot modify these files regardless of the shell construct used (sed -i, perl -i, redirections, etc.). Protected paths include `~/.vhir/gateway.yaml`, `~/.vhir/config.yaml`, `~/.vhir/active_case`, `~/.vhir/hooks`, `~/.claude/settings.json`, `~/.claude/CLAUDE.md`, and `~/.claude/rules`. MCP backends run outside the sandbox and can write case data normally.

### L5 — File Permission Protection

Case data files with forensic value (findings.json, timeline.json, approvals.jsonl) are set to chmod 444 (read-only) after every write. The owning process unlocks before writing and relocks after. This is a speed bump, not a wall — the LLM process can chmod — but combined with deny rules and the PreToolUse hook it adds another layer.

At case initialization, the filesystem is checked. Non-POSIX filesystems (NTFS, exFAT, VFAT) trigger a warning since chmod has no effect.

### L6 — Report Reconciliation

When generating reports, report-mcp performs a bidirectional reconciliation between approved items and the verification ledger. This does not require a password. It detects:

- Items approved but missing from the ledger (APPROVED_NO_VERIFICATION)
- Ledger entries with no corresponding approved item (VERIFICATION_NO_FINDING)
- Substantive text changed after signing (DESCRIPTION_MISMATCH)
- Count mismatches between approved items and ledger entries

Alerts are included in the generated report as `verification_alerts`.

### L7-L8 — Integrity Controls

- **Password authentication**: Both the `vhir approve` CLI command and the Examiner Portal Commit button require password-based authentication. The CLI uses direct password entry via `/dev/tty`. The portal uses challenge-response: the browser derives a PBKDF2 key and computes HMAC-SHA256(key, server_nonce) — the password never leaves the browser. Passwords are set per examiner via `vhir config --setup-password` (minimum 8 characters).
- **Provenance enforcement**: Findings must be traceable to evidence (MCP > HOOK > SHELL > NONE). NONE provenance with no supporting commands is rejected by a hard gate in `record_finding()`.
- **Content hash integrity**: SHA-256 hashes computed at staging, verified at approval. `vhir review --verify` detects post-approval tampering via cross-file hash comparison.

### L9 — Kernel Sandbox (bubblewrap)

Claude Code's sandbox uses bubblewrap (`bwrap`) to isolate Bash commands in
Linux namespaces. It enforces network isolation (`--unshare-net`) and PID
namespace isolation (`--unshare-pid`), plus filesystem write restrictions
(only the working directory is writable). MCP servers run outside the sandbox
with full access. Only Bash commands and their children are confined.

On non-setuid bwrap (all Ubuntu 18.10+), namespace creation requires
unprivileged user namespace support in the kernel. Multiple mechanisms can
block this:

| Mechanism | Versions | Detection |
|-----------|----------|-----------|
| AppArmor `restrict_unprivileged_userns` | Ubuntu 23.10+ | sysctl check + AppArmor profile fix |
| `unprivileged_userns_clone=0` | Any (hardened kernels, cloud images) | sysctl check + persistent fix |
| Container restrictions | Any | `systemd-detect-virt` + marker files + cgroup check |
| WSL1 | Any | `uname -r` check |
| `max_user_namespaces=0` | Any | sysctl check |

`setup-sift.sh` detects these restrictions at install time and provides
environment-specific remediation. On Ubuntu 23.10+, it writes a targeted
AppArmor profile at `/etc/apparmor.d/bwrap` that grants only `/usr/bin/bwrap`
the `userns` permission. On older systems with `unprivileged_userns_clone=0`,
it provides the sysctl command to re-enable user namespaces.

`vhir setup test` includes a sandbox health check with the same diagnostic
cascade.

If the sandbox cannot be enabled (e.g., containers without privileged
namespaces), Claude Code's `enableWeakerNestedSandbox` setting provides
partial isolation (network + filesystem restrictions remain, process
isolation is reduced). By default, `allowUnsandboxedCommands: false` means
Claude Code will refuse to run Bash commands rather than running them
unsandboxed.

### Provenance Tiers

| Tier | Source | Trust Level |
|------|--------|-------------|
| MCP | MCP audit log | System-witnessed |
| HOOK | Claude Code hook log | Framework-witnessed |
| SHELL | `supporting_commands` parameter | Self-reported |
| NONE | No audit record | Rejected |

### Claude Code Controls

When Claude Code is the LLM client, `vhir setup client --client=claude-code` deploys:

- **Kernel-level sandbox**: Restricts Bash writes and network access via bubblewrap (L9). On Ubuntu 24.04+, requires AppArmor profile installed by `setup-sift.sh`
- **Case data deny rules**: 41 rules blocking Read/Edit/Write to protected case files, evidence registry, verification ledger, and control files (L3)
- **PreToolUse hook**: Blocks Bash redirections targeting protected files (L4)
- **PostToolUse audit hook**: Captures every Bash command and output to `audit/claude-code.jsonl`
- **Provenance enforcement**: Findings without an evidence trail are rejected
- **Password-gated human approval**: Approval requires the examiner's password + writes HMAC ledger entry (L2)

## SSH Security Consideration

Remote deployments (Path 2) require SSH access to SIFT only for CLI-exclusive operations: case initialization, evidence registration, evidence unlocking, and command execution. Finding approval and rejection are available through the Examiner Portal in the browser — SSH is not required for the review workflow.

If the remote LLM client has terminal access (e.g., Claude Code), it can potentially use the examiner's SSH credentials to run commands on SIFT outside of MCP controls. The password gate prevents the LLM from approving findings — whether through the CLI (`/dev/tty` password entry) or the portal (challenge-response authentication). Other operations (file modification, evidence access) are not password-gated.

For production forensic work with remote Claude Code, examiners should use SSH authentication that requires human interaction per use:

- Password-only authentication (no agent-forwarded keys)
- `ssh-add -c` for per-use agent confirmation
- Hardware security keys (FIDO2/U2F)

Alternatively, MCP-only clients (Claude Desktop, LibreChat) eliminate this concern entirely — they can only reach SIFT through audited MCP tools.

## Adversarial Evidence

Evidence under analysis may contain attacker-controlled content designed to manipulate LLM analysis. Any text field in any artifact — filenames, event log messages, registry values, email subjects, script comments, file metadata — could contain adversarial instructions.

Defenses:

- **AGENTS.md rules**: Instruct the LLM to never interpret embedded text as instructions
- **data_provenance markers**: Every tool response tags output as untrusted
- **Discipline reminders**: Rotating forensic methodology reminders in every response
- **HITL approval gate**: The primary mitigation — humans review all findings

## Evidence Handling

Never place original evidence on any ValiHuntIR system. Only use working copies for which verified originals or backups exist.

Any data loaded into the system runs the risk of being exposed to the underlying AI provider. Only place data on these systems that you are willing to send to your AI provider. Treat all ValiHuntIR systems as analysis environments, not evidence storage.

### Evidence Integrity Measures

- SHA-256 hashes computed at registration, verified on demand via `vhir evidence verify`
- Evidence registry (`evidence.json`) protected by deny rules to prevent hash tampering
- Evidence access is logged to `evidence_access.jsonl`
- `vhir evidence lock` sets the entire evidence directory to read-only (chmod 444/555)
- `vhir evidence unlock` restores write access for re-extraction

These are defense-in-depth measures. Hash-based verification is the primary integrity mechanism. Proper evidence integrity depends on verified hashes, write blockers, and chain-of-custody procedures that exist outside this platform.

### Filesystem Requirements

- **ext4**: Recommended. Full permission support for read-only protection.
- **NTFS/exFAT**: Acceptable. File permission controls will be silently ineffective.
- **FAT32**: Discouraged. 4 GB file size limit.

## Audit Trail

Every MCP tool call is logged to a per-backend JSONL file in the case `audit/` directory:

```text
audit/
├── forensic-mcp.jsonl
├── case-mcp.jsonl
├── report-mcp.jsonl
├── sift-mcp.jsonl
├── forensic-rag-mcp.jsonl
├── windows-triage-mcp.jsonl
├── opencti-mcp.jsonl
├── wintools-mcp.jsonl
└── claude-code.jsonl          # PostToolUse hook (Claude Code only)
```

Each entry includes:
- Unique evidence ID (`{backend}-{examiner}-{date}-{seq}`)
- Tool name and arguments
- Timestamp
- Examiner identity
- Case identifier

Evidence IDs resume sequence numbering across process restarts.

## Responsible Use

This project demonstrates the capabilities of AI-assisted incident response. While steps have been taken to enforce human-in-the-loop controls, it is ultimately the responsibility of each examiner to ensure that their findings are accurate and complete. Ultimate responsibility rests with the human. The AI, like a hex editor, is a tool to be used by properly trained incident response professionals. Users are responsible for ensuring their use complies with applicable laws, regulations, and organizational policies.
