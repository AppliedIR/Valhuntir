# Valhuntir Platform Documentation

Valhuntir is a forensic investigation platform that connects LLM clients to forensic tools through MCP (Model Context Protocol) servers. It enforces human-in-the-loop controls, maintains chain-of-custody audit trails, and enriches tool output with forensic knowledge.

## What Valhuntir Does

- Provides MCP tools across the SIFT backends, with more when opensearch-mcp or wintools-mcp is added (the [MCP reference](mcp-reference.md) lists them per backend)
- Executes forensic tools (Zimmerman suite, Volatility, Sleuth Kit, Hayabusa, and more) through MCP servers
- Indexes evidence into OpenSearch for structured querying across millions of records (optional)
- Records findings, timeline events, and investigation reasoning with full audit trails
- Enforces human approval for all findings before they enter reports
- Enriches tool output with artifact caveats, corroboration suggestions, and discipline reminders from forensic-knowledge
- Generates IR reports using data-driven profiles with Zeltser IR Writing guidance

## Components

| Component | Purpose |
|-----------|---------|
| **sift-gateway** | HTTP gateway aggregating all SIFT-local MCPs behind one endpoint |
| **forensic-mcp** | Findings, timeline, evidence, TODOs, discipline (core tools plus discipline entries) |
| **case-mcp** | Case lifecycle, evidence management, export/import, backup, audit |
| **report-mcp** | Report generation with 6 profile types |
| **sift-mcp** | Linux forensic tool execution with FK enrichment |
| **forensic-rag-mcp** | Semantic search across 22K+ forensic knowledge records |
| **windows-triage-mcp** | Offline Windows baseline validation |
| **threatintel-mcp** | Read-only threat intelligence: each configured platform's records (OpenCTI, MISP), no verdict |
| **opensearch-mcp** | Evidence indexing, structured querying, enrichment (separate repo) |
| **wintools-mcp** | Windows forensic tool execution (separate repo) |
| **remnux-mcp** | Automated malware analysis on REMnux VM (optional, user-provided) |
| **vhir CLI** | Human-only case management, approval, reporting, evidence handling |
| **forensic-knowledge** | Shared YAML data package for tool guidance and artifact knowledge |

## Quick Start

```bash
# One-command install (SIFT workstation)
curl -fsSL https://raw.githubusercontent.com/AppliedIR/sift-mcp/main/quickstart.sh -o /tmp/vhir-quickstart.sh && bash /tmp/vhir-quickstart.sh
```

Or step by step:

```bash
git clone https://github.com/AppliedIR/sift-mcp.git && cd sift-mcp
./setup-sift.sh
```

## Documentation Guide

- [Getting Started](getting-started.md) — Installation, first case walkthrough, key concepts
- [User Guide](user-guide.md) — Investigation workflow, findings, timeline, reporting
- [Architecture](architecture.md) — System design, deployment topologies, protocol stack
- [CLI Reference](cli-reference.md) — All vhir CLI commands with options and examples
- [MCP Reference](mcp-reference.md) — Tools by backend with parameters and response formats
- [Deployment Guide](deployment.md) — Installation options, remote access, multi-examiner setup
- [Security Model](security.md) — Execution security, evidence handling, responsible use
