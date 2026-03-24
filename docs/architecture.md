# Architecture

## System Overview

ValiHuntIR uses MCP (Model Context Protocol) to connect LLM clients to forensic tools. The architecture separates concerns into three layers:

1. **Gateway layer** — HTTP entry point, authentication, request routing
2. **MCP backends** — Specialized servers for different forensic functions
3. **Tool layer** — Actual forensic tool execution (subprocess-based)

```text
LLM Client
    │
    │  MCP Streamable HTTP (POST /mcp, SSE responses)
    │
    ▼
sift-gateway :4508                     wintools-mcp :4624
    │                                      │
    │  stdio (subprocess)                  │  subprocess.run(shell=False)
    │                                      │
    ▼                                      ▼
forensic-mcp                          Windows forensic tools
case-mcp                              (Zimmerman, Hayabusa)
report-mcp
sift-mcp ──► SIFT forensic tools
forensic-rag-mcp
windows-triage-mcp
opencti-mcp
case-dashboard ──► Examiner Portal
```

## Invariants

These are structural facts. If any other document contradicts these, the invariant is correct.

1. **All client-to-server connections use MCP Streamable HTTP.** No client connects via stdio. Stdio is internal only (gateway to backend MCPs).
2. **The gateway runs on the SIFT workstation.** It is not optional — even solo analysts use it (on localhost).
3. **wintools-mcp runs on a Windows machine.** It is independent of the gateway. The gateway does not manage or proxy wintools-mcp.
4. **Clients connect to two endpoints at most:** the gateway (SIFT tools) and wintools-mcp (Windows tools).
5. **The case directory is local per examiner.** Multi-examiner collaboration uses export/merge, not shared filesystem.
6. **Human approval is structural.** The AI cannot approve its own work. Only the vhir CLI can move findings to APPROVED.
7. **AGENTS.md is the source of truth for forensic rules.** Per-client config files (CLAUDE.md) are copies, not sources.
8. **forensic-knowledge is a shared data package.** It has no runtime state.

## Component Details

### sift-gateway

The gateway aggregates all SIFT-local MCPs behind one HTTP endpoint. It starts each backend as a stdio subprocess and exposes their tools via:

- `/mcp` — Aggregate endpoint (all tools from all backends)
- `/mcp/{backend-name}` — Per-backend endpoints
- `/api/v1/tools` — REST tool listing

The gateway uses the low-level MCP `Server` class (not FastMCP) because tools are discovered dynamically from backends at runtime. Authentication uses ASGI-level wrappers to avoid buffering SSE streams.

Available per-backend endpoints:

```text
http://localhost:4508/mcp/forensic-mcp
http://localhost:4508/mcp/case-mcp
http://localhost:4508/mcp/report-mcp
http://localhost:4508/mcp/sift-mcp
http://localhost:4508/mcp/forensic-rag-mcp
http://localhost:4508/mcp/windows-triage-mcp
http://localhost:4508/mcp/opencti-mcp
```

### forensic-mcp

The investigation state machine. Manages findings, timeline events, evidence listing, TODOs, and discipline methodology. 12 tools + 14 resources in default mode, or 26 tools in tools mode (discipline data as tools for clients without resource support).

### case-mcp

Case lifecycle management. Init, activate, close, migrate, list, status. Evidence registration and verification. Export/import for multi-examiner collaboration. Audit summary. Action and reasoning logging. Portal access. 15 tools with SAFE/CONFIRM safety tiers.

### report-mcp

Report generation with 6 data-driven profiles. Aggregates approved findings, IOCs, and MITRE mappings. Integrates with Zeltser IR Writing MCP for report templates. 6 tools.

### sift-mcp

Forensic tool execution on Linux/SIFT. Denylist-protected (blocks destructive system commands). Catalog-enriched responses for known tools, basic envelopes for uncataloged tools. 6 tools, 65+ catalog entries.

### wintools-mcp

Forensic tool execution on Windows. Catalog-gated (only cataloged tools can run). Denylist blocks dangerous binaries (cmd, powershell, wscript, etc.). Argument sanitization blocks shell metacharacters, response-file syntax (`@filename`), and output redirect flags. 7 tools, 22 catalog entries.

### forensic-rag-mcp

Semantic search across 23K+ forensic knowledge records from Sigma rules, MITRE ATT&CK, Atomic Red Team, Splunk Security, KAPE, Velociraptor, LOLBAS, GTFOBins. 3 tools.

### windows-triage-mcp

Offline Windows baseline validation. Checks files, processes, services, scheduled tasks, registry, DLLs, and named pipes against known-good databases. 13 tools.

### case-dashboard

The Examiner Portal. Web-based finding review interface served by the gateway at `/portal/`. Provides inline editing of findings (confidence, justification, observation, interpretation, MITRE IDs, IOCs), evidence artifact display, and an integrity section showing verification status, provenance, and content hashes. Edits are saved to `pending-reviews.json` and applied via `vhir approve --review`.

### opencti-mcp

Read-only threat intelligence from OpenCTI. IOC lookup, threat actor search, malware search, MITRE technique search. 10 tools.

## Deployment Topologies

### Solo Analyst

One SIFT workstation. The LLM client, vhir CLI, gateway, and all MCPs run on the same machine.

```text
┌─────────────────────── SIFT Workstation ───────────────────────┐
│                                                                │
│  LLM Client ──streamable-http──► sift-gateway :4508            │
│                                      │                         │
│                                    stdio                       │
│                                      │                         │
│                                  SIFT MCPs                     │
│                                      │                         │
│  vhir CLI ──filesystem──► Case Directory ◄── forensic-mcp      │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### SIFT + Windows

SIFT workstation plus a Windows forensic VM. The LLM client makes two separate HTTP connections.

```text
┌─────────────────────── SIFT Workstation ───────────────────────┐
│                                                                │
│  LLM Client ──streamable-http──► sift-gateway :4508 ──► MCPs  │
│                                                                │
│  vhir CLI ──filesystem──► Case Directory                       │
│                                                                │
└────────────────────────────────────────────────────────────────┘

┌───────────── Windows Forensic Workstation ─────────────────────┐
│                                                                │
│  wintools-mcp :4624                                            │
│       │                                                        │
│       └──SMB──► Case Directory (on SIFT)                       │
│                                                                │
└────────────────────────────────────────────────────────────────┘

LLM Client ──streamable-http──► wintools-mcp :4624
```

### Remote Client

The LLM client runs on a separate machine (e.g., analyst laptop). Requires TLS and bearer token auth. The examiner uses SSH to the SIFT workstation for CLI operations.

Install with `--remote` to enable TLS:

```bash
./setup-sift.sh --remote
```

### Multi-Examiner

Each examiner runs their own full stack on their own SIFT workstation. Collaboration is merge-based using JSON export/import.

```text
┌─ Examiner 1 — SIFT Workstation ─┐
│ LLM Client + vhir CLI            │
│ sift-gateway :4508 ──► MCPs      │
│ Case Directory (local)            │
└───────────────────────────────────┘
        │
        │  export / merge (JSON files)
        │
┌─ Examiner 2 — SIFT Workstation ─┐
│ LLM Client + vhir CLI            │
│ sift-gateway :4508 ──► MCPs      │
│ Case Directory (local)            │
└───────────────────────────────────┘
```

Finding and timeline IDs include the examiner name (e.g., `F-alice-001`, `T-bob-003`) for global uniqueness.

## Case Directory Structure

Flat layout. All data files at case root.

```text
cases/INC-2026-0225/
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
├── pending-reviews.json         # Portal edits awaiting approval
└── audit/
    ├── forensic-mcp.jsonl
    ├── sift-mcp.jsonl
    ├── claude-code.jsonl       # PostToolUse hook captures (Claude Code only)
    └── ...
```

## Response Envelope

Every forensic tool response is wrapped in a structured envelope with forensic-knowledge enrichment:

```json
{
  "success": true,
  "tool": "run_command",
  "data": {"output": {"rows": ["..."], "total_rows": 42}},
  "data_provenance": "tool_output_may_contain_untrusted_evidence",
  "audit_id": "sift-alice-20260225-001",
  "examiner": "alice",
  "caveats": ["Amcache entries indicate file presence, not execution"],
  "advisories": ["Cross-reference with Prefetch for execution confirmation"],
  "corroboration": {
    "for_execution": ["Prefetch", "UserAssist"],
    "for_timeline": ["$MFT timestamps", "USN Journal"]
  },
  "discipline_reminder": "Evidence is sovereign -- if results conflict with your hypothesis, revise the hypothesis, never reinterpret evidence to fit"
}
```

| Field | Source | Description |
|-------|--------|-------------|
| `audit_id` | Audit system | Unique ID for referencing in findings |
| `caveats` | forensic-knowledge | Artifact-specific limitations |
| `advisories` | forensic-knowledge | What the artifact does NOT prove |
| `corroboration` | forensic-knowledge | Suggested cross-reference artifacts and tools |
| `field_notes` | forensic-knowledge | Timestamp field meanings |
| `discipline_reminder` | Built-in | Rotating forensic methodology reminder (14 total) |

## Repos

| Repo | Purpose |
|------|---------|
| [sift-mcp](https://github.com/AppliedIR/sift-mcp) | SIFT monorepo: 11 packages, installer, platform docs |
| [wintools-mcp](https://github.com/AppliedIR/wintools-mcp) | Windows tool execution MCP + installer |
| [ValiHuntIR](https://github.com/AppliedIR/valihuntir) | CLI + architecture reference |

Public repos under the AppliedIR GitHub org.
