# Getting Started

## Prerequisites

- SIFT Workstation (Ubuntu-based) or any Ubuntu 22.04+ system
- Python 3.10+
- sudo access (required for HMAC verification ledger at `/var/lib/vhir/verification/`)
- An LLM client with MCP support (Claude Code, Claude Desktop, LibreChat, etc.)

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
- **Client type**: Claude Code, Claude Desktop, LibreChat, or Other
- **Remote access**: Whether to enable TLS and bearer token auth

### Windows Forensic Workstation (Optional)

If you have a Windows forensic VM for Zimmerman tools and Hayabusa:

```powershell
git clone https://github.com/AppliedIR/wintools-mcp.git
cd wintools-mcp
.\scripts\setup-windows.ps1
```

The Windows installer generates a bearer token. Copy it to your SIFT gateway configuration or LLM client setup.

## First Case

### 1. Initialize a Case

```bash
vhir case init "Suspicious Activity Investigation"
```

This creates a case directory under `~/.vhir/cases/` with a unique case ID (e.g., `INC-2026-0225`) and activates it.

### 2. Connect Your LLM Client

If you ran `vhir setup client` during installation, your LLM client is already configured. Start your client — it will connect to the gateway at `http://127.0.0.1:4508/mcp`.

### 3. Start Investigating

Ask your LLM client to analyze evidence:

```text
"Parse the Amcache hive at /cases/evidence/Amcache.hve"
"What tools should I use to investigate lateral movement?"
"Run hayabusa against the evtx logs and show critical alerts"
```

The LLM will use MCP tools to execute forensic tools, record findings, and build a timeline.

### 4. Review and Approve

Findings stage as DRAFT. Open the Examiner Portal to review:

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

### 5. Generate a Report

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
├── evidence/              # Evidence files (read-only after registration)
├── extractions/           # Tool output and extracted artifacts
├── reports/               # Generated reports
├── approvals.jsonl        # Approval audit trail
└── audit/                 # Per-backend tool execution logs
```

### Human-in-the-Loop

The AI cannot approve its own work. All findings and timeline events stage as DRAFT. Only the vhir CLI (which requires a human at a terminal) can move them to APPROVED or REJECTED. This is enforced structurally — there is no MCP tool for approval.

### Evidence IDs

Every tool execution generates a unique evidence ID: `{backend}-{examiner}-{YYYYMMDD}-{NNN}`. These IDs link findings to the specific tool executions that produced them.

### Provenance Tiers

Findings are classified by how their evidence was gathered:

| Tier | Source | Meaning |
|------|--------|---------|
| MCP | MCP audit log | Evidence from an MCP tool (system-witnessed) |
| HOOK | Claude Code hook log | Evidence from Bash with hook capture (framework-witnessed) |
| SHELL | `supporting_commands` parameter | Evidence from direct shell (self-reported) |
| NONE | No audit record | No evidence trail — finding is rejected |
