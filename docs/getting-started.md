# Getting Started

## Prerequisites

- SIFT Workstation (Ubuntu-based). WSL2 on Windows is also supported.
- Python 3.10+
- sudo access (required for the ledger and signing-key folders under `/var/lib/vhir/`)
- A **locally installed** MCP-compatible LLM client that supports Streamable HTTP transport with Bearer token authentication (Claude Code, Codex, self-hosted LibreChat, etc.). The client must run on your machine or local network — cloud-hosted LLM services (claude.ai, etc.) cannot reach internal gateway addresses. OAuth is not supported.

## Installation

### SIFT Workstation (All Components)

The quickstart installs all MCP servers, the gateway, and the vhir CLI:

```bash
curl -fsSL https://raw.githubusercontent.com/AppliedIR/sift-mcp/main/quickstart.sh -o /tmp/vhir-quickstart.sh && bash /tmp/vhir-quickstart.sh
```

This runs `setup-sift.sh` in quick mode — MCP servers, gateway, vhir CLI, and client config in one step.

### Step by Step

```bash
git clone https://github.com/AppliedIR/sift-mcp.git && cd sift-mcp
./setup-sift.sh
```

The installer prompts for:

- **Installation tier**: Quick (core only), Recommended (core + RAG + triage), or Custom
- **Examiner identity**: Your name slug (e.g., `alice`)
- **Client type**: Claude Code, Codex, LibreChat, or Other
- **Remote access**: Whether to enable TLS and bearer token auth

### Windows Forensic Workstation (Optional)

If you have a Windows forensic VM for Zimmerman tools and Hayabusa:

```powershell
git clone https://github.com/AppliedIR/wintools-mcp.git
cd wintools-mcp
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\setup-windows.ps1
```

`Set-ExecutionPolicy -Scope Process` allows scripts for this PowerShell window only. Windows 10/11 refuses to run them by default.

The Windows installer generates a bearer token. Copy it to your SIFT gateway configuration or LLM client setup.

## First Case

### 1. Initialize a Case

```bash
vhir case init
```

This prompts for case name, case ID (with auto-generated default), cases directory, and description. Or provide a name directly: `vhir case init "Suspicious Activity Investigation"`. Either way, a case directory is created under `~/cases/` with a unique ID and activated for the session.

### 2. Connect Your LLM Client

If you ran `vhir setup client` during installation, your LLM client is already configured.

**Claude Code:** Launch from the case directory so forensic controls and the sandbox apply:

```bash
cd ~/cases/INC-2026-0225
claude
```

**Codex**: `cd ~/cases/<case-name> && codex -p valhuntir`.

**Other MCP clients** (LibreChat, or any MCP client without a shell): Just start your client — it connects to the gateway at `http://127.0.0.1:4508/mcp` and the active case is resolved automatically from `~/.vhir/active_case`.

### 3. Give It the Host List, Then Ingest

Every ingest waits until you confirm the hosts its evidence names. Before the first ingest, open the Examiner Portal's Hosts tab (`vhir portal`) and upload a list of the machines in scope: one name per line with an optional FQDN, or a CSV or TSV export with a header row. Or give the LLM any inventory to prepare as a draft there. Hosts on the list confirm as the evidence arrives. For any other host, a waiting ingest shows in the Hosts tab: Confirm the proposed machine, or choose Start now to let the run write with its hosts as proposed.

### 4. Start Investigating

Ask your LLM client to analyze evidence:

```text
"Parse the Amcache hive at /cases/evidence/Amcache.hve"
"What tools should I use to investigate lateral movement?"
"Run hayabusa against the evtx logs and show critical alerts"
```

The LLM executes forensic tools via MCP and presents evidence as it finds it. Guide each phase — tell the LLM what to examine, review findings at each stage, and direct next steps. The human acts as the investigation manager. Too much LLM autonomy leads to cascading errors and wasted tokens. The LLM should check in at every major decision point.

### 5. Review and Approve

Findings made by the LLM are staged as DRAFT. Open the Examiner Portal to review:

```bash
vhir portal
```

The portal provides an 8-tab browser UI for reviewing findings, timeline events, evidence, IOCs, and more. Approve, reject, and commit decisions directly in the browser.

Or use the CLI:

```bash
vhir review --findings            # View findings
vhir approve                      # Interactive review
vhir approve F-alice-001 F-alice-002  # Approve specific findings
```

### 6. Generate a Report

```bash
vhir report --full --save report.json
```

Or ask the LLM to generate a report using report-mcp:

```text
"Generate an executive summary report for this case"
```

## Key Concepts

### Examiner Identity

Every action is attributed to an examiner. Set your identity:

```bash
vhir config --examiner alice
```

Resolution order: `--examiner` flag > `VHIR_EXAMINER` env var > `~/.vhir/config.yaml` > OS username.

### Case Directory

Each case has a flat directory with all data files:

```text
cases/INC-2026-0225/
├── CASE.yaml              # Case metadata
├── findings.json          # Investigation findings
├── timeline.json          # Incident timeline
├── todos.json             # Investigation TODOs
├── evidence.json          # Evidence registry
├── evidence/              # Evidence files (lock with vhir evidence lock)
├── extractions/           # Tool output and extracted artifacts
├── reports/               # Generated reports
├── approvals.jsonl        # Approval audit trail
└── audit/                 # Per-backend tool execution logs
```

### Human-in-the-Loop

The AI cannot approve its own work. All findings and timeline events stage as DRAFT. Only a human examiner can move them to APPROVED or REJECTED. The Examiner Portal is the preferred review interface — approve and reject in the browser, then sign the decisions with your passphrase (the browser signs; the passphrase never leaves it). The vhir CLI (`vhir approve`) provides the same capability from the terminal. There is no MCP tool for approval.

### Evidence IDs

Every tool execution generates a unique evidence ID: `{backend}-{examiner}-{YYYYMMDD}-{NNN}`. These IDs link findings to the specific tool executions that produced them.

### Provenance Tiers

Findings are classified by where the audit trail recorded their tool executions:

| Tier | Source | Meaning |
|------|--------|---------|
| MCP | MCP audit log | Evidence from an MCP tool (system-witnessed) |
| HOOK | Claude Code hook log | Evidence from Bash with hook capture (framework-witnessed) |
| SHELL | `supporting_commands` parameter | Evidence from direct shell (self-reported) |
| NONE | No audit record | No evidence trail — finding is rejected |
