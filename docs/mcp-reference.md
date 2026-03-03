# MCP Reference

71 MCP tools across 8 backends. Seven backends run as stdio subprocesses of the sift-gateway. wintools-mcp runs independently on a Windows machine. The case-dashboard is a web UI served by the gateway (not an MCP backend).

## forensic-mcp (12 core tools + 14 discipline resources)

The investigation state machine. Manages findings, timeline, evidence listing, TODOs, and forensic discipline methodology.

### Core Tools

| Tool | Description |
|------|-------------|
| `record_finding` | Record a substantive finding with evidence references and provenance |
| `record_timeline_event` | Record a key event in the incident timeline |
| `get_findings` | Retrieve findings with optional status/examiner filters |
| `get_timeline` | Retrieve timeline events with optional filters (status, source, date range, event type) |
| `get_actions` | Retrieve recent investigative actions from the audit trail |
| `get_case_status` | Show active case summary (read-only) |
| `list_cases` | List available cases (read-only) |
| `list_evidence` | List registered evidence files |
| `add_todo` | Create an investigation TODO item |
| `list_todos` | List TODO items |
| `update_todo` | Update a TODO (note, assignee, priority) |
| `complete_todo` | Mark a TODO as completed |

### Discipline Tools (optional, when `reference_mode="tools"`)

These are available as MCP resources by default. Clients without resource support can use tools mode instead.

| Tool | Description |
|------|-------------|
| `get_investigation_framework` | Full methodology framework |
| `get_rules` | Investigation discipline rules |
| `get_checkpoint_requirements` | Checkpoint requirements for an action type |
| `validate_finding` | Validate finding against evidence standards |
| `get_evidence_standards` | Evidence quality standards |
| `get_confidence_definitions` | Confidence level definitions |
| `get_anti_patterns` | Investigation anti-patterns to avoid |
| `get_evidence_template` | Template for evidence presentation |
| `get_tool_guidance` | Tool-specific usage guidance from forensic-knowledge |
| `get_false_positive_context` | False positive context for a tool/finding type |
| `get_corroboration_suggestions` | Suggested corroboration artifacts |
| `list_playbooks` | List available investigation playbooks |
| `get_playbook` | Get a specific playbook |
| `get_collection_checklist` | Artifact collection checklist |

### MCP Resources (default mode)

| URI | Description |
|-----|-------------|
| `forensic-mcp://investigation-framework` | Full methodology framework |
| `forensic-mcp://rules` | Investigation rules |
| `forensic-mcp://checkpoint/{action_type}` | Checkpoint requirements |
| `forensic-mcp://validation-schema` | Finding validation schema |
| `forensic-mcp://evidence-standards` | Evidence quality standards |
| `forensic-mcp://confidence-definitions` | Confidence levels |
| `forensic-mcp://anti-patterns` | Anti-patterns |
| `forensic-mcp://evidence-template` | Evidence template |
| `forensic-mcp://tool-guidance/{tool_name}` | Tool guidance |
| `forensic-mcp://false-positive-context/{tool_name}/{finding_type}` | False positive context |
| `forensic-mcp://corroboration/{finding_type}` | Corroboration suggestions |
| `forensic-mcp://playbooks` | Playbook list |
| `forensic-mcp://playbook/{name}` | Specific playbook |
| `forensic-mcp://collection-checklist/{artifact_type}` | Collection checklist |

## case-mcp (14 tools)

Case lifecycle management, evidence operations, export/import, and audit.

| Tool | Safety | Description |
|------|--------|-------------|
| `case_init` | CONFIRM | Initialize a new case |
| `case_activate` | CONFIRM | Activate a case for the session |
| `case_list` | SAFE | List available cases |
| `case_status` | SAFE | Show active case details |
| `evidence_register` | CONFIRM | Register an evidence file (hash + read-only) |
| `evidence_list` | SAFE | List registered evidence |
| `evidence_verify` | SAFE | Re-hash and verify evidence integrity |
| `export_bundle` | SAFE | Export findings/timeline as JSON |
| `import_bundle` | CONFIRM | Import findings/timeline from JSON |
| `audit_summary` | SAFE | Audit trail summary (counts per MCP/tool) |
| `record_action` | AUTO | Record an investigative action |
| `log_reasoning` | AUTO | Log analytical reasoning (audit only, no approval needed) |
| `log_external_action` | AUTO | Log a non-MCP tool execution |
| `open_case_dashboard` | SAFE | Open the web-based case dashboard |

**Safety tiers:**
- **SAFE**: Read-only, no side effects
- **CONFIRM**: Modifies state, tool description advises confirmation
- **AUTO**: Logging tools, always permitted

## report-mcp (6 tools)

Report generation with data-driven profiles and Zeltser IR Writing integration.

| Tool | Description |
|------|-------------|
| `generate_report` | Generate report data for a profile (full, executive, timeline, ioc, findings, status) |
| `set_case_metadata` | Set incident metadata in CASE.yaml (type, severity, dates, scope, team) |
| `get_case_metadata` | Retrieve case metadata |
| `list_profiles` | List available report profile types |
| `save_report` | Save rendered report to case reports/ directory |
| `list_reports` | List saved reports |

### Report Profiles

| Profile | Purpose |
|---------|---------|
| `full` | Comprehensive IR report with all approved data |
| `executive` | Management briefing (1-2 pages, non-technical) |
| `timeline` | Chronological event narrative |
| `ioc` | Structured IOC export with MITRE mapping |
| `findings` | Detailed approved findings |
| `status` | Quick status for standups |

## sift-mcp (6 tools)

Forensic tool execution on Linux/SIFT. A small denylist blocks destructive system commands. Cataloged tools get enriched responses; uncataloged tools get basic envelopes.

| Tool | Description |
|------|-------------|
| `run_command` | Execute any forensic tool (denylist-protected) |
| `list_available_tools` | List cataloged tools with installation status |
| `list_missing_tools` | List tools not installed, with install guidance |
| `get_tool_help` | Usage info, flags, caveats, and FK knowledge for a tool |
| `check_tools` | Check which tools are installed and available |
| `suggest_tools` | Given an artifact type, suggest relevant tools |

### Tool Catalog

| File | Tools |
|------|-------|
| `zimmerman.yaml` | AmcacheParser, PECmd, AppCompatCacheParser, RECmd, MFTECmd, EvtxECmd, JLECmd, LECmd, SBECmd, RBCmd, SrumECmd, SQLECmd, bstrings |
| `volatility.yaml` | vol3 |
| `timeline.yaml` | hayabusa, log2timeline, mactime, psort |
| `sleuthkit.yaml` | fls, icat, mmls, blkls |
| `malware.yaml` | yara, strings, ssdeep, binwalk |
| `analysis.yaml` | grep, awk, sed, cut, sort, uniq, wc, head, tail, tr, diff, jq, zcat, zgrep, tar, unzip, file, stat, find, ls, md5sum, sha1sum, sha256sum, xxd, hexdump, readelf, objdump |
| `network.yaml` | tshark, zeek |
| `file_analysis.yaml` | bulk_extractor |
| `misc.yaml` | exiftool, regripper, hashdeep, 7z, dc3dd, ewfacquire, ewfmount, vshadowinfo, vshadowmount |

### Execution Pipeline

```text
MCP tool call → Denylist Check → subprocess.run(shell=False) → Parse Output → Catalog? → FK Enrichment → Response Envelope → Audit Entry
```

## forensic-rag-mcp (3 tools)

Semantic search across 23K+ forensic knowledge records.

| Tool | Description |
|------|-------------|
| `search_knowledge` | Semantic search with filters (source, technique, platform) |
| `list_knowledge_sources` | List available knowledge sources |
| `get_knowledge_stats` | Index statistics (document count, sources) |

Sources: Sigma rules, MITRE ATT&CK, Atomic Red Team, Splunk Security, KAPE, Velociraptor, LOLBAS, GTFOBins.

## windows-triage-mcp (13 tools)

Offline Windows baseline validation. Checks artifacts against known-good databases.

| Tool | Description |
|------|-------------|
| `check_file` | Check a file path against Windows baseline |
| `check_process_tree` | Validate a process tree |
| `check_service` | Check a service against baseline |
| `check_scheduled_task` | Check a scheduled task |
| `check_autorun` | Check an autorun entry |
| `check_registry` | Check a registry key/value |
| `check_hash` | Check a file hash (includes LOLDriver detection) |
| `analyze_filename` | Analyze a filename for suspicious patterns |
| `check_lolbin` | Check if a binary is a known LOLBin |
| `check_hijackable_dll` | Check if a DLL is hijackable |
| `check_pipe` | Check a named pipe against baseline |
| `get_db_stats` | Database statistics |
| `get_health` | Health check |

UNKNOWN results are neutral — most third-party software will not be in the baseline databases.

## opencti-mcp (10 tools)

Read-only threat intelligence from OpenCTI.

| Tool | Description |
|------|-------------|
| `get_health` | OpenCTI health check |
| `search_threat_intel` | Cross-entity search |
| `search_entity` | Type-specific search (threat_actor, malware, campaign, etc.) |
| `lookup_ioc` | Look up an IOC |
| `lookup_hash` | Look up a file hash |
| `search_attack_pattern` | Search MITRE ATT&CK patterns |
| `get_recent_indicators` | Get recent indicators |
| `get_entity` | Get entity details by ID |
| `get_relationships` | Get entity relationships |
| `search_reports` | Search threat reports |

## wintools-mcp (7 tools, separate deployment)

Forensic tool execution on Windows. Catalog-gated — only tools defined in YAML catalog files can execute.

| Tool | Description |
|------|-------------|
| `run_command` | Execute a cataloged forensic tool |
| `scan_tools` | Scan for all cataloged tools, report availability |
| `list_available_tools` | List cataloged tools with installation status |
| `list_missing_tools` | List tools not installed, with install guidance |
| `check_tools` | Check specific tools by name |
| `get_tool_help` | Tool-specific help, flags, caveats |
| `suggest_tools` | Suggest tools for an artifact type |

### Tool Catalog (22 entries)

| File | Tools |
|------|-------|
| `zimmerman.yaml` | AmcacheParser, AppCompatCacheParser, EvtxECmd, JLECmd, LECmd, MFTECmd, PECmd, RBCmd, RECmd, SBECmd, SQLECmd, SrumECmd, WxTCmd, bstrings |
| `timeline.yaml` | Hayabusa, mactime |
| `sysinternals.yaml` | autorunsc, sigcheck |
| `memory.yaml` | winpmem, dumpit, moneta, hollows_hunter |

### Security Model

```text
Tool call → Hardcoded Denylist (20+ binaries) → YAML Catalog Allowlist → Argument Sanitization → subprocess.run(shell=False)
```

Denylist blocks: cmd, powershell, pwsh, wscript, cscript, mshta, rundll32, regsvr32, certutil, bitsadmin, msiexec, bash, wsl, sh, msbuild, installutil, regasm, regsvcs, cmstp, control.

Argument sanitization blocks: shell metacharacters (`;`, `&&`, `||`, `` ` ``, `$(`, `${`), response-file syntax (`@filename`), dangerous flags (`-e`, `--exec`, etc.), and output redirect flags (`-o`, `--output`, `/out`, `--csv`, `--json`).
