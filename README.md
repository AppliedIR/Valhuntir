# AIIR
[![CI](https://github.com/AppliedIR/aiir/actions/workflows/ci.yml/badge.svg)](https://github.com/AppliedIR/aiir/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-appliedir.github.io-blue)](https://appliedir.github.io/aiir/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/AppliedIR/aiir/blob/main/LICENSE)

AI Incident Response platform with varying levels of human-in-the-loop review and control based on your deployment needs. CLI and architecture reference.

**[Platform Documentation](https://appliedir.github.io/aiir/)** ·
[CLI Reference](https://appliedir.github.io/aiir/cli-reference/)

> **Public Beta** — This project is undergoing active feature development.
> Backward compatibility with future releases is not guaranteed. Consider
> this a public beta for feature testing and evaluation rather than a
> production-ready tool for real case data.

## AIIR Lite — Get Started in Minutes

In its simplest form, AIIR Lite provides Claude Code with forensic knowledge and instructions on how to enforce forensic rigor, present findings for human review, and audit actions taken. MCP servers enhance accuracy by providing authoritative information — a forensic knowledge RAG and a Windows triage database — plus optional OpenCTI threat intelligence and REMnux malware analysis.

**Quick** — Forensic discipline, MCP packages, and config. No databases (<70 MB):

```
git clone https://github.com/AppliedIR/sift-mcp.git
cd sift-mcp
./quickstart-lite.sh --quick
```

**Recommended** — Adds the RAG knowledge base (22,000+ records from 23 security sources) and Windows triage databases (2.6M baseline records). Requires ~14 GB disk space:

- ~7 GB — ML dependencies (PyTorch, CUDA) required by the RAG embedding model
- ~6 GB — Windows triage baseline databases (2.6M rows, decompressed)
- ~1 GB — RAG index, source code, and everything else

```
git clone https://github.com/AppliedIR/sift-mcp.git
cd sift-mcp
./quickstart-lite.sh
```

This one-time setup takes approximately 15-30 minutes depending on
internet speed and CPU. Subsequent runs reuse existing databases and index.

```
claude
/welcome
```

To update an existing AIIR Lite installation, re-run the installer from an updated clone (first step changes into wherever you installed the sift-mcp repo on initial installation):

```
cd sift-mcp
git pull
./quickstart-lite.sh
```

The installer is idempotent — it reuses the existing venv, skips databases
and RAG index if already present, and redeploys config files.

#### AIIR Lite

```mermaid
graph LR
    subgraph analyst ["Analyst Machine"]
        CC["Claude Code<br/>(human interface)"]
        FR["forensic-rag-mcp<br/>Knowledge search"]
        WTR["windows-triage-mcp<br/>Baseline validation"]

        CC -->|stdio| FR
        CC -->|stdio| WTR
    end
```

#### AIIR Lite with Optional Add-ons

```mermaid
graph LR
    subgraph analyst ["Analyst Machine"]
        CC["Claude Code<br/>(human interface)"]
        FR["forensic-rag-mcp<br/>Knowledge search"]
        WTR["windows-triage-mcp<br/>Baseline validation"]
        OC["opencti-mcp<br/>Threat intelligence"]

        CC -->|stdio| FR
        CC -->|stdio| WTR
        CC -->|stdio| OC
    end

    subgraph octi ["OpenCTI Instance"]
        OCTI[OpenCTI]
    end

    subgraph remnux ["REMnux Workstation"]
        RAPI["remnux-mcp API<br/>:3000"]
        RMX["remnux-mcp<br/>Malware analysis"]
        RAPI --> RMX
    end

    subgraph internet ["Internet"]
        ML["MS Learn MCP<br/>(HTTPS)"]
        ZE["Zeltser IR Writing MCP<br/>(HTTPS)"]
    end

    CC -->|"streamable-http"| RAPI
    CC -->|"HTTPS"| ML
    CC -->|"HTTPS"| ZE
    OC -->|"HTTP(S)"| OCTI
```

| Connection | Protocol | Notes |
|-----------|----------|-------|
| Claude Code → forensic-rag-mcp | stdio | Local Python process, always present |
| Claude Code → windows-triage-mcp | stdio | Local Python process, always present |
| Claude Code → opencti-mcp | stdio | Local Python process, connects out to OpenCTI via HTTP(S) |
| opencti-mcp → OpenCTI Instance | HTTP(S) | opencti-mcp runs locally, calls out to the OpenCTI server |
| Claude Code → remnux-mcp | streamable-http | Remote, on its own REMnux workstation |
| Claude Code → MS Learn MCP | HTTPS | `https://learn.microsoft.com/api/mcp` — streamable-http type in .mcp.json |
| Claude Code → Zeltser IR Writing MCP | HTTPS | `https://website-mcp.zeltser.com/mcp` — streamable-http type in .mcp.json |

No gateway, no sandbox, no deny rules. Claude runs forensic tools directly via Bash. Forensic discipline is suggested and reinforced via prompt hooks and reference documents, but Claude Code can choose to ignore them. See the [sift-mcp README](https://github.com/AppliedIR/sift-mcp#aiir-lite--get-started-in-minutes) for details and optional add-ons.

## Full AIIR — Structural Enforcement

For use cases where more definitive human-in-the-loop approval is desired, the full AIIR suite ensures accountability and enforces human review of findings through cryptographic signing, password-gated approvals, and multiple layered controls.

Full AIIR is **LLM client agnostic** — connect any MCP-compatible client through the gateway. Supported clients include Claude Code, Claude Desktop, LibreChat, Cherry Studio, and any MCP-only client that supports Streamable HTTP transport with Bearer token authentication. Forensic discipline is provided structurally at the gateway and MCP layer, not through client-specific prompt engineering, so the same rigor applies regardless of which AI model or client drives the investigation.

## Platform Architecture

The examiner interacts with AIIR through three interfaces: the **LLM client** (AI-assisted investigation), the **case dashboard** (browser-based review and approval), and the **aiir CLI** (case management, evidence handling, and verification).

### Deployment Overview

The typical deployment runs three VMs on a single host: SIFT (primary workstation), REMnux (malware analysis), and Windows (forensic tool execution). The examiner works on the SIFT VM — running the LLM client, the case dashboard in a browser, and the aiir CLI. REMnux and Windows are headless worker VMs. All three communicate over a VM-local network. Internet access is through NAT for external MCP services.

```mermaid
graph TB
    subgraph host ["Host Machine"]
        subgraph sift ["SIFT VM"]
            CC["LLM Client<br/>(human interface)"]
            BR["Browser<br/>(dashboard)"]
            CLI["aiir CLI"]
            GW["sift-gateway :4508"]
            CASE["Case Directory"]

            CC -->|"streamable-http"| GW
            BR -->|"HTTP"| GW
            CLI --> CASE
        end

        subgraph remnux ["REMnux VM (optional)"]
            RAPI["remnux-mcp :3000"]
        end

        subgraph winbox ["Windows VM (optional)"]
            WAPI["wintools-mcp :4624"]
        end

        CC -->|"streamable-http"| RAPI
        CC -->|"streamable-http"| WAPI
        WAPI -->|"SMB"| CASE
    end

    subgraph internet ["Internet"]
        ML["MS Learn MCP"]
        ZE["Zeltser IR Writing MCP"]
        OCTI["OpenCTI (if external)"]
    end

    CC -->|"HTTPS"| ML
    CC -->|"HTTPS"| ZE
    GW -.->|"HTTP(S)"| OCTI
```

REMnux and Windows VMs are optional. SIFT alone provides 64 MCP tools across 7 backends, the case dashboard, and full case management.

### SIFT Platform Components

The sift-gateway aggregates 7 MCP backends as stdio subprocesses behind a single HTTP endpoint. Each backend is also available individually. The case dashboard is served by the gateway for browser-based review and approval.

```mermaid
graph LR
    GW["sift-gateway :4508"]

    FM["forensic-mcp<br/>12 tools · findings, timeline,<br/>evidence, discipline"]
    CM["case-mcp<br/>14 tools · case management,<br/>audit queries"]
    RM["report-mcp<br/>6 tools · report generation,<br/>IOC aggregation"]
    SM["sift-mcp<br/>6 tools · Linux forensic<br/>tool execution"]
    RAG["forensic-rag<br/>3 tools · semantic search<br/>23K records"]
    WT["windows-triage<br/>13 tools · offline baseline<br/>validation"]
    OC["opencti<br/>10 tools · threat<br/>intelligence"]
    CD["case-dashboard<br/>browser review + commit"]
    FK["forensic-knowledge<br/>shared YAML data"]
    CASE["Case Directory"]

    GW -->|stdio| FM
    GW -->|stdio| CM
    GW -->|stdio| RM
    GW -->|stdio| SM
    GW -->|stdio| RAG
    GW -->|stdio| WT
    GW -->|stdio| OC
    GW --> CD
    FM --> FK
    SM --> FK
    FM --> CASE
    CM --> CASE
    RM --> CASE
    CD --> CASE
```

### Human-in-the-Loop Workflow

All findings and timeline events are staged as DRAFT by the AI. Only a human examiner can approve or reject them — via the case dashboard (browser) or the aiir CLI. Both paths produce identical HMAC-signed approval records. The AI cannot approve its own findings.

```mermaid
sequenceDiagram
    participant AI as LLM + MCP Tools
    participant Case as Case Directory
    participant Human as Examiner<br/>(Dashboard or CLI)

    AI->>Case: record_finding() → DRAFT
    AI->>Case: record_timeline_event() → DRAFT
    Note over Case: Staged for review

    Human->>Case: Review, edit, approve/reject
    Human->>Case: Commit (password + HMAC signing)

    Note over Case: Only APPROVED items<br/>appear in reports
    Human->>Case: aiir report --full
```

The **case dashboard** is the primary review interface. Examiners review findings and timeline events, edit fields (confidence, justification, observation, interpretation, MITRE IDs, IOCs), approve or reject items, and commit decisions — all in the browser. The Commit button (Shift+C) uses challenge-response authentication: the browser derives a PBKDF2 key from the examiner's password and proves knowledge via HMAC — the password never leaves the browser. The CLI's `aiir approve` provides the same functionality from the terminal.

![Dashboard — Findings](docs/images/dashboard.png)

![Dashboard — Timeline](docs/images/timeline.png)

### Where Things Run

| Component | Runs on | Port | Purpose |
|-----------|---------|------|---------|
| sift-gateway | SIFT | 4508 | Aggregates SIFT-local MCPs behind one HTTP endpoint |
| forensic-mcp | SIFT | (via gateway) | Findings, timeline, evidence, TODOs, discipline (12 tools + 14 resources) |
| case-mcp | SIFT | (via gateway) | Case management, audit queries, evidence registration (14 tools) |
| report-mcp | SIFT | (via gateway) | Report generation with profiles, IOC aggregation, MITRE mapping (6 tools) |
| sift-mcp | SIFT | (via gateway) | Denylist-protected forensic tool execution on Linux/SIFT (6 tools) |
| forensic-rag-mcp | SIFT | (via gateway) | Semantic search across Sigma, MITRE ATT&CK, Atomic Red Team, and more |
| windows-triage-mcp | SIFT | (via gateway) | Offline Windows baseline validation |
| opencti-mcp | SIFT | (via gateway) | Threat intelligence from OpenCTI (10 tools) |
| case-dashboard | SIFT | (via gateway) | Browser-based review, approval, and commit interface. Primary review UI — no SSH needed. |
| wintools-mcp | Windows | 4624 | Catalog-gated forensic tool execution on Windows (7 tools) |
| aiir CLI | SIFT | -- | Human-only: case init, evidence management, verification, exec. Approval also available via dashboard. Remote examiners need SSH only for CLI-exclusive operations. |
| forensic-knowledge | anywhere | -- | Shared YAML data package (tools, artifacts, discipline) |

The gateway exposes each backend as a separate MCP endpoint. Clients can connect to the aggregate endpoint or to individual backends:

```
http://localhost:4508/mcp              # Aggregate (all tools)
http://localhost:4508/mcp/forensic-mcp
http://localhost:4508/mcp/case-mcp
http://localhost:4508/mcp/report-mcp
http://localhost:4508/mcp/sift-mcp
http://localhost:4508/mcp/windows-triage-mcp
http://localhost:4508/mcp/forensic-rag-mcp
http://localhost:4508/mcp/opencti-mcp
```

#### Multi-Examiner Team

```mermaid
graph LR
    subgraph e1 ["Examiner 1 — SIFT Workstation"]
        CC1["LLM Client<br/>(human interface)"]
        BR1["Browser<br/>(human interface)"]
        CLI1["aiir CLI"]
        GW1["sift-gateway<br/>:4508"]
        MCPs1["forensic-mcp · case-mcp · report-mcp<br/>sift-mcp · forensic-rag-mcp<br/>windows-triage-mcp · opencti-mcp"]
        CASE1["Case Directory"]

        CC1 -->|"streamable-http"| GW1
        BR1 -->|"HTTPS"| GW1
        GW1 -->|stdio| MCPs1
        MCPs1 --> CASE1
        CLI1 --> CASE1
    end

    subgraph e2 ["Examiner 2 — SIFT Workstation"]
        CC2["LLM Client<br/>(human interface)"]
        BR2["Browser<br/>(human interface)"]
        CLI2["aiir CLI"]
        GW2["sift-gateway<br/>:4508"]
        MCPs2["forensic-mcp · case-mcp · report-mcp<br/>sift-mcp · forensic-rag-mcp<br/>windows-triage-mcp · opencti-mcp"]
        CASE2["Case Directory"]

        CC2 -->|"streamable-http"| GW2
        BR2 -->|"HTTPS"| GW2
        GW2 -->|stdio| MCPs2
        MCPs2 --> CASE2
        CLI2 --> CASE2
    end

    CASE1 <-->|"export / merge"| CASE2
```

### Case Directory Structure

```
cases/INC-2026-0219/
├── CASE.yaml                    # Case metadata (name, status, examiner)
├── evidence/                    # Original evidence (read-only after registration)
├── extractions/                 # Extracted artifacts
├── reports/                     # Generated reports
├── findings.json                # F-alice-001, F-alice-002, ...
├── timeline.json                # T-alice-001, ...
├── todos.json                   # TODO-alice-001, ...
├── evidence.json                # Evidence registry
├── actions.jsonl                # Investigative actions (append-only)
├── evidence_access.jsonl        # Chain-of-custody log
├── approvals.jsonl              # Approval audit trail
├── pending-reviews.json         # Dashboard edits awaiting approval
└── audit/
    ├── forensic-mcp.jsonl
    ├── sift-mcp.jsonl
    ├── claude-code.jsonl       # PostToolUse hook captures (Claude Code only)
    └── ...
```

### External Dependencies

- **Zeltser IR Writing MCP** — Required for report generation. Configured automatically by `aiir setup client`. URL: https://website-mcp.zeltser.com/mcp (HTTPS, no auth)

## Quick Start

### SIFT Workstation

Requires Python 3.10+ and sudo access. The installer handles everything: MCP servers, gateway, aiir CLI, HMAC verification ledger, examiner identity, and LLM client configuration. When you select Claude Code, additional forensic controls are deployed (kernel-level sandbox, case data deny rules, PreToolUse guard hook, PostToolUse audit hook, provenance enforcement, password-gated human approval with HMAC signing). Other clients get MCP config only.

**Quick** — Core platform only, no databases (~70 MB):

```
curl -fsSL https://raw.githubusercontent.com/AppliedIR/sift-mcp/main/quickstart.sh -o /tmp/aiir-quickstart.sh && bash /tmp/aiir-quickstart.sh
```

**Recommended** — Adds the RAG knowledge base (22,000+ records from 23 security sources) and Windows triage databases (2.6M baseline records), downloaded as pre-built snapshots. Requires ~14 GB disk space:

- ~7 GB — ML dependencies (PyTorch, CUDA) required by the RAG embedding model
- ~6 GB — Windows triage baseline databases (2.6M rows, decompressed)
- ~1 GB — RAG index, source code, and everything else

```
curl -fsSL https://raw.githubusercontent.com/AppliedIR/sift-mcp/main/quickstart.sh -o /tmp/aiir-quickstart.sh && bash /tmp/aiir-quickstart.sh --recommended
```

**Custom** — Individual package selection, OpenCTI integration, or remote access with TLS:

```
git clone https://github.com/AppliedIR/sift-mcp.git
cd sift-mcp
./setup-sift.sh
```

### Windows Forensic Workstation (optional)

```
# Option 1: git clone
git clone https://github.com/AppliedIR/wintools-mcp.git; cd wintools-mcp

# Option 2: download ZIP (no git required)
Invoke-WebRequest https://github.com/AppliedIR/wintools-mcp/archive/refs/heads/main.zip -OutFile wintools.zip
Expand-Archive wintools.zip -DestinationPath .; cd wintools-mcp-main
```

Then run the installer:

```
.\scripts\setup-windows.ps1
```

## Security Considerations

All AIIR components are assumed to run on a private forensic network, protected by firewalls, and not exposed to incoming connections from the Internet or potentially hostile systems. The design assumes dedicated, isolated systems are used throughout.

Any data loaded into the system or its component VMs, computers, or instances runs the risk of being exposed to the underlying AI. Only place data on these systems that you are willing to send to your AI provider.

Outgoing Internet connections are required for report generation (Zeltser IR Writing MCP) and optionally used for threat intelligence (OpenCTI) and documentation (MS Learn MCP). No incoming connections from external systems should be allowed.

AIIR is designed so that AI interactions flow through MCP tools, enabling security controls and audit trails. Clients with direct shell access (like Claude Code) can also operate outside MCP, but `aiir setup client` deploys forensic controls for Claude Code: a kernel-level sandbox restricts Bash writes, deny rules block Edit/Write to case data files, a PreToolUse hook guards against Bash redirections to protected files, a PostToolUse hook captures every Bash command to the audit trail, provenance enforcement ensures findings are traceable to evidence, and an HMAC verification ledger provides cryptographic proof that approved findings haven't been tampered with. AIIR is not designed to defend against a malicious AI or to constrain the AI client that you deploy.

## Commands

Most `aiir` CLI operations have MCP equivalents via case-mcp, forensic-mcp, and report-mcp. When working with an MCP-connected client, you can ask the AI to handle case management, evidence registration, report generation, and more — the AI operates through audited MCP tools rather than direct CLI invocation.

The commands below that require human interaction at the terminal (`/dev/tty`) **cannot** be delegated to the AI. These are intentional human-in-the-loop checkpoints — they use password entry, interactive review, or terminal confirmation to ensure the human examiner retains control over approval, rejection, and security-sensitive operations.

### Human-Only Commands (require terminal)

These commands read from `/dev/tty` directly and cannot be run by an AI client, even via Bash. This is by design — they are the human-in-the-loop controls that ensure the examiner reviews and approves all findings.

#### approve

```
aiir approve                                             # Interactive review of all DRAFT items
aiir approve F-alice-001 F-alice-002 T-alice-001         # Approve specific IDs
aiir approve F-alice-001 --edit                          # Edit in $EDITOR before approving
aiir approve F-alice-001 --note "Malware family unconfirmed"  # Approve with examiner note
aiir approve --by jane                                   # Filter to IDs with jane's examiner prefix
aiir approve --findings-only                             # Skip timeline events
aiir approve --timeline-only                             # Skip findings
aiir approve --review                                    # Apply pending dashboard edits
```

Requires password entry via `/dev/tty`. Approved findings are HMAC-signed with a PBKDF2-derived key. The `--review` flag applies edits made in the dashboard (stored in `pending-reviews.json`), recomputes content hashes and HMAC signatures, then removes the pending file. Alternatively, use the dashboard's Commit button (Shift+C) which performs the same operation via challenge-response authentication — the password never leaves the browser.

#### reject

```
aiir reject F-alice-003 --reason "Insufficient evidence for attribution"
aiir reject F-alice-003 T-alice-002 --reason "Contradicted by memory analysis"
```

Requires password confirmation via `/dev/tty`.

#### exec

```
aiir exec --purpose "Extract MFT from image" -- fls -r -m / image.E01
```

Requires `/dev/tty` confirmation. Logged to `audit/cli-exec.jsonl`. Use this for manual tool execution with audit trail when not operating through MCP.

#### evidence unlock

```
aiir unlock-evidence                       # Directory chmod 755, files remain 444
aiir evidence unlock
```

Requires `/dev/tty` confirmation. Unlocking evidence allows writes to the evidence directory.

#### Password management

```
aiir config --setup-password               # Set approval password (PBKDF2-hashed, min 8 chars)
aiir config --reset-password               # Reset password (requires current, re-signs ledger)
```

Password entry uses masked input via `/dev/tty` with termios. No echo, no stdin — the AI cannot read or supply the password.

#### HMAC verification

```
aiir review --findings --verify            # Cross-check content hashes + HMAC verification
aiir review --findings --verify --mine    # HMAC verification for current examiner only
```

Verification requires the examiner's password to derive the HMAC key and confirm integrity.

### All Commands

The remaining commands can also be performed through MCP tools (case-mcp, forensic-mcp, report-mcp) when working with an MCP-connected client. The CLI equivalents are listed here for reference and for use outside MCP sessions.

#### dashboard

```
aiir dashboard                                           # Open case review dashboard in browser
```

Opens the case-dashboard web UI for the active case. The dashboard is the primary review interface — examiners can review, edit, approve, reject, and commit findings entirely in the browser. Use the Commit button (Shift+C) to apply decisions with challenge-response authentication. Alternatively, `aiir approve --review` applies pending edits from the CLI.

#### case

```
aiir case init "Ransomware Investigation"                # Create a new case
aiir case close INC-2026-02191200                        # Close a case by ID
aiir case activate INC-2026-02191200                     # Set active case
aiir case migrate                                        # Migrate to flat layout (see below)
```

#### review

```
aiir review                                # Case summary (counts by status)
aiir review --findings                     # Findings table
aiir review --findings --detail            # Full finding detail
aiir review --iocs                         # IOCs grouped by approval status
aiir review --timeline                     # Timeline events
aiir review --timeline --status APPROVED   # Filter timeline by status
aiir review --timeline --start 2026-01-01 --end 2026-01-31   # Filter by date range
aiir review --timeline --type execution    # Filter by event type
aiir review --evidence                     # Evidence registry and access log
aiir review --audit --limit 100            # Audit trail (last N entries)
aiir review --todos --open                 # Open TODOs
```

#### todo

```
aiir todo                                                          # List open TODOs
aiir todo --all                                                    # Include completed
aiir todo add "Run volatility on server-04" --assignee jane --priority high --finding F-alice-003
aiir todo complete TODO-alice-001
aiir todo update TODO-alice-002 --note "Waiting on third party" --priority low
```

#### evidence

```
aiir register-evidence /path/to/image.E01 --description "Disk image from workstation"
aiir lock-evidence                         # All files chmod 444, directory chmod 555

aiir evidence register /path/to/image.E01 --description "Disk image"
aiir evidence list
aiir evidence verify
aiir evidence log [--path <filter>]
aiir evidence lock
```

#### export / merge

```
aiir export --file steve-findings.json      # Export findings for sharing
aiir merge --file jane-findings.json        # Merge another examiner's findings
```

#### report

```
aiir report --full [--save <path>]
aiir report --executive-summary [--save <path>]
aiir report --timeline [--from <date> --to <date>] [--save <path>]
aiir report --ioc [--save <path>]
aiir report --findings F-alice-001,F-alice-002 [--save <path>]
aiir report --status-brief [--save <path>]
```

#### audit

```
aiir audit log [--limit 100] [--mcp sift-mcp] [--tool run_command]
aiir audit summary
```

#### service

```
aiir service status                    # Show running backends + health
aiir service start forensic-rag        # Start a backend
aiir service stop windows-triage       # Stop a backend
aiir service restart sift-mcp          # Restart a backend
```

#### case migrate

```
aiir case migrate                                      # Migrate primary examiner data to flat layout
aiir case migrate --examiner alice                     # Specify examiner
aiir case migrate --import-all                         # Merge all examiners' data
```

#### config

```
aiir config --examiner "jane.doe"          # Set examiner identity
aiir config --show                         # Show current configuration
```

#### update

```
aiir update                       # Pull latest, reinstall, redeploy, restart
aiir update --check               # Check for updates without applying
aiir update --no-restart          # Skip gateway restart after update
```

#### join

```
aiir join --sift SIFT_URL --code CODE                            # Join from remote machine using join code
aiir join --sift SIFT_URL --code CODE --wintools                 # Join as wintools machine (registers backend)
```

Exchange a one-time join code for gateway credentials. Run on the remote machine (analyst laptop or Windows forensic workstation). The join code is generated on SIFT via `aiir setup join-code`. Credentials are saved to `~/.aiir/config.yaml` with restricted permissions (0600).

#### setup

```
aiir setup client                          # Interactive client configuration (recommended)
aiir setup test                            # Test MCP server connectivity
```

#### setup client

Generate Streamable HTTP config for your LLM client:

```
aiir setup client                                                          # Interactive wizard
aiir setup client --client=claude-code --sift=http://127.0.0.1:4508 -y    # Local solo
aiir setup client --sift=SIFT_IP:4508 --windows=WIN_IP:4624               # SIFT + Windows
```

For remote orchestrator setups (Path 2), remote examiners run a platform-specific setup script that creates a `~/aiir/` workspace with MCP config, forensic controls, and discipline docs:

```
# Linux
curl -sSL https://raw.githubusercontent.com/AppliedIR/aiir/main/setup-client-linux.sh \
  | bash -s -- --sift=https://SIFT_IP:4508 --code=XXXX-XXXX

# macOS
curl -sSL https://raw.githubusercontent.com/AppliedIR/aiir/main/setup-client-macos.sh \
  | bash -s -- --sift=https://SIFT_IP:4508 --code=XXXX-XXXX
```

```
# Windows
Invoke-WebRequest -Uri https://raw.githubusercontent.com/AppliedIR/aiir/main/setup-client-windows.ps1 -OutFile setup-client-windows.ps1
.\setup-client-windows.ps1 -Sift https://SIFT_IP:4508 -Code XXXX-XXXX
```

Always launch your LLM client from `~/aiir/` or a subdirectory. Forensic controls only apply when started from within the workspace. To uninstall, re-run the setup script with `--uninstall` (Linux/macOS) or `-Uninstall` (Windows).

Claude Desktop's config file supports stdio transport only. The [mcp-remote](https://www.npmjs.com/package/mcp-remote) bridge is used to connect to the gateway. `aiir setup client --client=claude-desktop` generates the correct mcp-remote config automatically.

| Client | Platforms | Config file | Extras |
|--------|-----------|-------------|--------|
| Claude Code | Linux, macOS, Windows | `~/aiir/.mcp.json` or `~/.claude.json` (SIFT) | `CLAUDE.md`, `settings.json`, sandbox, audit hooks |
| Claude Desktop | macOS, Windows | `claude_desktop_config.json` (see note) | Requires mcp-remote bridge. Project instructions from AGENTS.md |
| Cherry Studio | Linux, macOS, Windows | JSON import (manual) | `baseUrl` field, `streamableHttp` type (camelCase) |
| LibreChat | Any (browser) | `librechat.yaml` (`mcpServers` section) | AIIR generates `librechat_mcp.yaml` reference to merge |
| Other | Any | `aiir-mcp-config.json` | Manual integration |

Claude Code on Windows requires Git for Windows (provides Git Bash) or WSL. Claude Desktop is not available on Linux. Claude Desktop's config file supports stdio transport only — the `aiir setup client` wizard generates mcp-remote bridge configs automatically. Config path is platform-specific: `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows. Any MCP client that supports Streamable HTTP transport with Bearer token authentication headers will work — the gateway is not client-specific.

## Examiner Identity

Every approval, rejection, and command execution is logged with examiner identity. Resolution order:

| Priority | Source | Example |
|----------|--------|---------|
| 1 | `--examiner` flag | `aiir approve --examiner jane.doe F-jane-001` |
| 2 | `AIIR_EXAMINER` env var | `export AIIR_EXAMINER=jane.doe` |
| 3 | `~/.aiir/config.yaml` | `examiner: jane.doe` |
| 4 | `AIIR_ANALYST` env var | Deprecated fallback |
| 5 | OS username | Warns if unconfigured |

## Repo Map

| Repo | Purpose |
|------|---------|
| [sift-mcp](https://github.com/AppliedIR/sift-mcp) | Monorepo: 11 SIFT packages (forensic-mcp, case-mcp, report-mcp, sift-mcp, sift-gateway, case-dashboard, forensic-knowledge, forensic-rag, windows-triage, opencti, sift-common) |
| [wintools-mcp](https://github.com/AppliedIR/wintools-mcp) | Windows forensic tool execution (7 tools, 22 catalog entries) |
| [aiir](https://github.com/AppliedIR/aiir) | CLI, architecture reference |

## Updating

### Full AIIR

```
aiir update              # Pull latest code, reinstall packages, redeploy controls, restart gateway
aiir update --check      # Check for updates without applying
aiir update --no-restart # Update without restarting the gateway
```

The update command pulls the latest code from both repos (sift-mcp and aiir),
reinstalls all packages, redeploys forensic controls, restarts the gateway,
and runs a connectivity smoke test.

## Upgrading from Lite to Full

Both modes share the same Python venv, triage databases, and RAG index. Full
AIIR adds the gateway (7 MCP backends behind one HTTP endpoint), 4 additional
MCP servers (forensic-mcp, case-mcp, report-mcp, sift-mcp), a web-based review
dashboard, structured case management, sandbox enforcement, and HMAC-signed
approvals.

To upgrade, run `setup-sift.sh` from your existing sift-mcp clone. The
installer reuses the existing venv and databases. Lite case data (markdown
files) does not auto-migrate to full case data (structured JSON) — start
fresh or transfer findings manually.

## Evidence Handling

Never place original evidence on any AIIR system. Only use working copies for which verified originals or backups exist. AIIR workstations process evidence through AI-connected tools, and any data loaded into these systems may be transmitted to the configured AI provider. Treat all AIIR systems as analysis environments, not evidence storage.

Evidence integrity is verified by SHA-256 hashes recorded at registration. Examiners can optionally lock evidence to read-only via `aiir evidence lock`. Proper evidence integrity depends on verified hashes, write blockers, and chain-of-custody procedures that exist outside this platform.

Case directories can reside on external or removable media. ext4 is preferred for full permission support. NTFS and exFAT are acceptable but file permission controls (read-only protection) will be silently ineffective. FAT32 is discouraged due to the 4 GB file size limit.

## Responsible Use and Legal

While steps have been taken to enforce human-in-the-loop controls, it is ultimately the responsibility of each examiner to ensure that their findings are accurate and complete. The AI, like a hex editor, is a tool to be used by properly trained incident response professionals. Users are responsible for ensuring their use complies with applicable laws, regulations, and organizational policies. Use only on systems and data you are authorized to analyze.

This software is provided "as is" without warranty of any kind. See [LICENSE](LICENSE) for full terms.

MITRE ATT&CK is a registered trademark of The MITRE Corporation. SIFT Workstation is a product of the SANS Institute.

## Acknowledgments

Architecture and direction by Steve Anson. Implementation by Claude Code (Anthropic).

## Clear Disclosure

I do DFIR. I am not a developer. This project would not exist without Claude Code handling the implementation. While an immense amount of effort has gone into design, testing, and review, I fully acknowledge that I may have been working hard and not smart in places. My intent is to jumpstart discussion around ways this technology can be leveraged for efficiency in incident response while ensuring that the ultimate responsibility for accuracy remains with the human examiner.

## License

MIT License - see [LICENSE](LICENSE)
