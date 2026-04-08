# MCP Reference

100 MCP tools across 9 backends. Eight backends run on the SIFT workstation (7 as stdio subprocesses of sift-gateway, plus opensearch-mcp optionally). wintools-mcp runs independently on a Windows machine. The Examiner Portal (case-dashboard package) is a web UI served by the gateway — not an MCP backend.

Without optional backends: 73 tools / 7 backends. With opensearch-mcp: 90 / 8. With wintools-mcp: 100 / 9.

## forensic-mcp (23 tools)

The investigation state machine. Manages findings, timeline events, evidence listing, TODOs, and forensic discipline methodology. Provides 9 core tools plus 14 discipline entries. The discipline entries are exposed as MCP resources by default; when `reference_mode="tools"` is set, they become tools instead (for clients without resource support). Either way, the server provides 23 callable endpoints.

### Core Tools (9)

| Tool | Parameters | Description | When the LLM uses it |
|------|-----------|-------------|---------------------|
| `record_finding` | `finding` (dict), `artifacts` (list), `supporting_commands` (list), `analyst_override` | Stage a finding as DRAFT with evidence provenance | After analyzing evidence and getting examiner approval — records the substantive finding |
| `record_timeline_event` | `event` (dict), `analyst_override` | Stage a timeline event as DRAFT | When a timestamp is significant to the incident narrative |
| `get_findings` | `status`, `limit` (20), `offset` | Retrieve findings, optionally filtered | To review what's been recorded, check for duplicates |
| `get_timeline` | `status`, `limit`, `offset`, `start_date`, `end_date`, `event_type`, `source`, `examiner` | Retrieve timeline events with filters | To review the incident timeline, check chronology |
| `get_actions` | `limit` (50) | Return recent actions from the audit trail | To review what tools have been run |
| `add_todo` | `description`, `assignee`, `priority` ("medium"), `related_findings`, `analyst_override` | Create an investigation TODO | When follow-up analysis is needed |
| `list_todos` | `status` ("open"), `assignee` | List TODO items | To check what's outstanding |
| `update_todo` | `todo_id`, `status`, `note`, `assignee`, `priority`, `analyst_override` | Update a TODO | To add notes, reassign, or change status |
| `complete_todo` | `todo_id`, `analyst_override` | Mark a TODO as completed | When follow-up is done |

### Discipline Tools (14)

Available as MCP resources by default. Exposed as tools when `reference_mode="tools"`.

| Tool / Resource | Parameters | Description | When the LLM uses it |
|----------------|-----------|-------------|---------------------|
| `get_investigation_framework` | — | Full methodology: principles, HITL checkpoints, workflow, golden rules | At investigation start to load forensic methodology |
| `get_rules` | — | All forensic discipline rules as structured data | When needing to verify correct procedure |
| `get_checkpoint_requirements` | `action_type` | What's required before a specific action (attribution, root cause, exclusion) | Before making significant conclusions |
| `validate_finding` | `finding_json` (dict) | Check finding against format and methodology standards | Before recording a finding — pre-validation |
| `get_evidence_standards` | — | Evidence classification levels (CONFIRMED, INDICATED, INFERRED, UNKNOWN, CONTRADICTED) | When assessing evidence quality |
| `get_confidence_definitions` | — | Confidence levels (HIGH/MEDIUM/LOW/SPECULATIVE) with criteria | When setting finding confidence |
| `get_anti_patterns` | — | Common forensic mistakes to avoid | To self-check analysis approach |
| `get_evidence_template` | — | Required evidence presentation format | When formatting evidence for the examiner |
| `get_tool_guidance` | `tool_name` | How to interpret results from a specific forensic tool | After running a tool — to interpret output correctly |
| `get_false_positive_context` | `tool_name`, `finding_type` | Common false positives for a tool/finding combination | When evaluating whether a detection is genuine |
| `get_corroboration_suggestions` | `finding_type` | Cross-reference suggestions based on finding type | When deciding what to examine next |
| `list_playbooks` | — | Available investigation playbooks | At investigation start — to select a procedure |
| `get_playbook` | `name` | Step-by-step procedure for a specific investigation type | When following a structured investigation workflow |
| `get_collection_checklist` | `artifact_type` | Evidence collection checklist per artifact type | When collecting evidence for a specific artifact |

### MCP Resources (default mode)

| URI | Corresponds to |
|-----|---------------|
| `forensic-mcp://investigation-framework` | `get_investigation_framework` |
| `forensic-mcp://rules` | `get_rules` |
| `forensic-mcp://checkpoint/{action_type}` | `get_checkpoint_requirements` |
| `forensic-mcp://validation-schema` | `validate_finding` |
| `forensic-mcp://evidence-standards` | `get_evidence_standards` |
| `forensic-mcp://confidence-definitions` | `get_confidence_definitions` |
| `forensic-mcp://anti-patterns` | `get_anti_patterns` |
| `forensic-mcp://evidence-template` | `get_evidence_template` |
| `forensic-mcp://tool-guidance/{tool_name}` | `get_tool_guidance` |
| `forensic-mcp://false-positive-context/{tool_name}/{finding_type}` | `get_false_positive_context` |
| `forensic-mcp://corroboration/{finding_type}` | `get_corroboration_suggestions` |
| `forensic-mcp://playbooks` | `list_playbooks` |
| `forensic-mcp://playbook/{name}` | `get_playbook` |
| `forensic-mcp://collection-checklist/{artifact_type}` | `get_collection_checklist` |

### How forensic-mcp Guides the LLM

When `record_finding()` is called, the server validates the finding against methodology standards and returns actionable feedback — checking for missing fields, insufficient evidence, and common anti-patterns. This is not a system prompt instruction; it's structural enforcement at the tool level.

The `validate_finding()` tool allows the LLM to pre-check a finding before committing it. The server returns a structured assessment with specific issues to address.

Discipline resources provide on-demand access to forensic methodology. The LLM can query checkpoint requirements before making significant conclusions, check evidence standards when assessing confidence, and retrieve corroboration suggestions when planning the next analysis step.

## case-mcp (15 tools)

Case lifecycle management, evidence operations, export/import, backup, and audit logging.

| Tool | Safety | Parameters | Description | When the LLM uses it |
|------|--------|-----------|-------------|---------------------|
| `case_init` | CONFIRM | `name`, `description`, `case_id`, `share_wintools`, `cases_dir` | Initialize a new case | At investigation start |
| `case_activate` | CONFIRM | `case_id`, `cases_dir` | Switch active case pointer | When switching between cases |
| `case_list` | SAFE | — | List all cases with status | To see available cases |
| `case_status` | SAFE | `case_id` | Detailed case status with finding counts, platform capabilities | To check investigation progress |
| `evidence_register` | CONFIRM | `path`, `description` | Register evidence file with SHA-256 hash | After receiving evidence files |
| `evidence_list` | SAFE | — | List registered evidence files | To see what evidence is available |
| `evidence_verify` | SAFE | — | Re-hash and verify evidence integrity | To confirm evidence hasn't been modified |
| `export_bundle` | SAFE | `since` | Export findings/timeline as JSON bundle | For multi-examiner collaboration |
| `import_bundle` | CONFIRM | `bundle_path` | Import findings/timeline from JSON | To merge another examiner's work |
| `audit_summary` | SAFE | — | Audit trail statistics per backend and tool | To review investigation activity |
| `record_action` | AUTO | `description`, `tool`, `command`, `analyst_override` | Record an investigative action | To log significant actions |
| `log_reasoning` | AUTO | `text`, `analyst_override` | Record analytical reasoning to audit trail | At decision points — choosing direction, forming hypotheses |
| `log_external_action` | AUTO | `command`, `output_summary`, `purpose`, `analyst_override` | Record non-MCP tool execution | After running Bash commands outside MCP |
| `backup_case` | CONFIRM | `destination`, `purpose` | Back up case data files with SHA-256 manifest | At investigation checkpoints |
| `open_case_dashboard` | SAFE | — | Open the Examiner Portal in the browser | When the examiner wants to review in the browser |

**Safety tiers:**
- **SAFE**: Read-only, no side effects
- **CONFIRM**: Modifies state, tool description advises the LLM to confirm with the examiner
- **AUTO**: Logging tools, always permitted

### How case-mcp Guides the LLM

`case_status()` returns platform capabilities — which optional backends are available (opensearch-mcp, wintools-mcp, remnux-mcp, OpenCTI) — so the LLM knows what tools it can use. It also returns investigation guidance based on the current case state. This dynamic context replaces static instructions that may become stale during a session.

## report-mcp (6 tools)

Report generation with data-driven profiles and Zeltser IR Writing integration. Only APPROVED findings appear in reports.

| Tool | Parameters | Description | When the LLM uses it |
|------|-----------|-------------|---------------------|
| `generate_report` | `profile` ("full"), `case_id` | Generate report data for a profile | When the examiner asks for a report |
| `set_case_metadata` | `field`, `value` | Set metadata in CASE.yaml (incident_type, severity, dates, scope, team) | To populate report headers |
| `get_case_metadata` | `field` | Retrieve case metadata | To check what metadata is set |
| `list_profiles` | — | List available report profiles with descriptions | To show the examiner what report types are available |
| `save_report` | `filename`, `content`, `profile` | Save rendered report to case reports/ directory | After the LLM has rendered the report narrative |
| `list_reports` | — | List saved reports | To check what reports already exist |

### Report Profiles

| Profile | Purpose | Content |
|---------|---------|---------|
| `full` | Comprehensive IR report | All approved findings, timeline, IOCs, MITRE mappings, Zeltser guidance |
| `executive` | Management briefing | 1-2 pages, non-technical summary |
| `timeline` | Chronological narrative | Events in order with context |
| `ioc` | IOC export | Structured indicators with MITRE mapping |
| `findings` | Finding details | All approved findings with evidence |
| `status` | Quick status | Counts and progress for standups |

### How report-mcp Works

`generate_report()` collects approved findings, timeline events, and IOCs, performs MITRE ATT&CK mapping, aggregates IOCs, runs report reconciliation against the HMAC verification ledger (detecting any post-approval tampering), and returns structured JSON with Zeltser IR Writing guidance. The LLM uses this data and the Zeltser guidance to render narrative sections, then saves the result with `save_report()`.

## sift-mcp (5 tools)

Forensic tool execution on Linux/SIFT. A denylist blocks destructive system commands (mkfs, shutdown, kill, nc/ncat). All other binaries can execute. Tools in the forensic catalog get enriched responses; uncataloged tools get basic envelopes.

| Tool | Parameters | Description | When the LLM uses it |
|------|-----------|-------------|---------------------|
| `run_command` | `command` (list), `purpose`, `timeout`, `save_output`, `input_files`, `preview_lines`, `skip_enrichment` | Execute any forensic tool | Core tool — every forensic analysis action on SIFT |
| `list_available_tools` | `category` | List cataloged tools with availability status | To discover what tools are installed |
| `get_tool_help` | `tool_name` | Usage info, flags, caveats, FK knowledge | Before running an unfamiliar tool |
| `check_tools` | `tool_names` (list) | Check tool installation status | To verify tools are available before a workflow |
| `suggest_tools` | `artifact_type`, `question` | Suggest relevant tools with corroboration guidance | When deciding how to analyze a specific artifact type |

### Tool Catalog (59 FK entries)

The forensic-knowledge package provides YAML definitions for 59 tools across 17 categories. When sift-mcp executes a cataloged tool, the response is enriched with:

| Field | Description |
|-------|-------------|
| `caveats` | Tool-specific limitations (e.g., "Amcache entries indicate file presence, not execution") |
| `advisories` | What the artifact does NOT prove, common misinterpretations |
| `corroboration` | Suggested cross-reference artifacts and tools grouped by purpose |
| `field_meanings` | What timestamp and data fields actually represent |
| `discipline_reminder` | Rotating forensic methodology reminder (from a pool of 15+) |

Uncataloged tools execute normally with basic response envelopes (audit_id, data_provenance marker, discipline reminder).

### Enrichment Delivery

Accuracy content (caveats, field_meanings) is always delivered — these prevent misinterpretation. Discovery content (advisories, corroboration, cross-MCP suggestions) decays after the first 3 calls per tool and re-appears every 10th call. This keeps early interactions informative without repeating the same suggestions across a 100-call session.

### Tool Catalog Categories

| Category | Tools |
|----------|-------|
| zimmerman | AmcacheParser, PECmd, AppCompatCacheParser, RECmd, MFTECmd, EvtxECmd, JLECmd, LECmd, SBECmd, RBCmd, SrumECmd, SQLECmd, bstrings |
| volatility | vol3 |
| timeline | hayabusa, log2timeline, mactime, psort |
| sleuthkit | fls, icat, mmls, blkls |
| malware | yara, strings, ssdeep, binwalk, capa, densityscout, moneta, hollows_hunter, sigcheck, maldump, 1768_cobalt |
| network | tshark, zeek |
| file_analysis | bulk_extractor |
| registry | regripper |
| memory | winpmem, vol3 |
| imaging | dc3dd, ewfacquire, ewfmount |
| hashing | hashdeep, ssdeep |
| persistence | autorunsc |
| carving | foremost, scalpel |
| triage | densityscout |
| browser | hindsight |
| logs | logparser |
| mcp | check_file, check_process_tree, search_threat_intel, search (FK entries for MCP tools) |

### Execution Security

- `subprocess.run(shell=False)` — no shell, no arbitrary command chains
- Argument sanitization — shell metacharacters blocked
- Path validation — `/proc`, `/sys`, `/dev` blocked for input
- `rm` protection — case directories protected from deletion
- Flag restrictions — `find` blocks `-exec`/`-delete`, `sed` blocks `-i`, `tar` blocks extraction/creation, `awk` blocks `system()`/pipes
- Output truncation — large output capped; use `save_output=True` for large results

## forensic-rag-mcp (3 tools)

Semantic search across 22,000+ forensic knowledge records from 23 authoritative sources.

| Tool | Parameters | Description | When the LLM uses it |
|------|-----------|-------------|---------------------|
| `search_knowledge` | `query`, `top_k` (5), `source`, `source_ids` (list), `technique`, `platform` | Semantic search with filters | To ground analysis in authoritative references |
| `list_knowledge_sources` | — | List available knowledge sources | To discover what sources can be filtered on |
| `get_knowledge_stats` | — | Index statistics (document count, sources, model) | To verify the index is loaded and healthy |

### Knowledge Sources (23)

| Source ID | Records | Description |
|-----------|---------|-------------|
| `sigma` | ~4,000+ | SigmaHQ Detection Rules |
| `mitre_attack` | ~1,200+ | MITRE ATT&CK Enterprise Techniques |
| `atomic` | ~1,500+ | Atomic Red Team Tests |
| `elastic` | ~1,000+ | Elastic Detection Rules |
| `splunk_security` | ~2,000+ | Splunk Security Content |
| `lolbas` | ~200+ | LOLBAS Living Off The Land Binaries |
| `gtfobins` | ~300+ | GTFOBins Unix Binaries |
| `loldrivers` | ~500+ | LOLDrivers Vulnerable Drivers |
| `hijacklibs` | ~400+ | HijackLibs DLL Hijacking |
| `kape` | ~800+ | KAPE Targets & Modules |
| `velociraptor` | ~300+ | Velociraptor Artifact Exchange |
| `forensic_artifacts` | ~200+ | ForensicArtifacts Definitions |
| `mitre_car` | ~100+ | MITRE Cyber Analytics Repository |
| `mitre_d3fend` | ~200+ | MITRE D3FEND Defensive Techniques |
| `mitre_atlas` | ~100+ | MITRE ATLAS AI/ML Attacks |
| `mitre_engage` | ~50+ | MITRE Engage Adversary Engagement |
| `capec` | ~500+ | MITRE CAPEC Attack Patterns |
| `mbc` | ~300+ | MITRE MBC Malware Behavior Catalog |
| `cisa_kev` | ~1,000+ | CISA Known Exploited Vulnerabilities |
| `stratus_red_team` | ~50+ | Stratus Red Team Cloud Attacks |
| `chainsaw` | ~50+ | Chainsaw Detection Rules |
| `hayabusa` | ~100+ | Hayabusa Built-in Rules |
| `forensic_clarifications` | ~50+ | Authoritative Forensic Clarifications |

### Score Interpretation

| Score | Quality | Action |
|-------|---------|--------|
| 0.85+ | Excellent | High confidence, cite directly |
| 0.75-0.84 | Good | Relevant, include in analysis |
| 0.65-0.74 | Fair | May be tangential, use judgment |
| < 0.65 | Weak | Likely not relevant |

Combined boost from source matching and technique matching is capped at 120% of the raw semantic score to prevent over-ranking marginal matches.

## windows-triage-mcp (13 tools)

Offline Windows baseline validation. Checks artifacts against 2.6 million known-good records from multiple Windows versions. No network calls required.

| Tool | Parameters | Description | When the LLM uses it |
|------|-----------|-------------|---------------------|
| `check_file` | `path`, `hash`, `os_version` | Check file path against Windows baseline | When encountering an unknown file in system directories |
| `check_process_tree` | `process_name`, `parent_name`, `path`, `user` | Validate parent-child process relationship | When analyzing process creation events |
| `check_service` | `service_name`, `binary_path`, `os_version` (req) | Check a Windows service | When investigating service-based persistence |
| `check_scheduled_task` | `task_path`, `os_version` (req) | Check a scheduled task | When investigating task scheduler persistence |
| `check_autorun` | `key_path`, `value_name`, `os_version` (req) | Check a registry autorun entry | When investigating registry persistence |
| `check_registry` | `key_path`, `value_name`, `hive`, `os_version` | Check a registry key/value against full baseline | For general registry investigation (requires 12GB database) |
| `check_hash` | `hash` | Check hash against LOLDrivers vulnerable driver database | When a suspicious driver hash is found |
| `analyze_filename` | `filename` | Analyze for deception: Unicode homoglyphs, typosquatting, double extensions | When a filename looks suspicious |
| `check_lolbin` | `filename` | Check if binary is a known LOLBin | When a legitimate tool is used in suspicious context |
| `check_hijackable_dll` | `dll_name` | Check if DLL is vulnerable to search-order hijacking | When a DLL is found in an unexpected location |
| `check_pipe` | `pipe_name` | Check named pipe against baseline and C2 patterns | When named pipes are observed (Cobalt Strike, Metasploit) |
| `get_db_stats` | — | Database statistics: record counts, OS versions, last update | To verify database coverage before checks |
| `get_health` | — | Server health: uptime, connectivity, cache hit rates | To diagnose issues |

### Verdict Interpretation

| Verdict | Meaning | Action |
|---------|---------|--------|
| EXPECTED | In Windows baseline | Likely legitimate — check execution context |
| EXPECTED_LOLBIN | Baseline match + LOLBin capability | Legitimate binary, but check if being abused |
| SUSPICIOUS | Anomaly detected | Investigate further — wrong path, Unicode deception, known C2, vulnerable driver |
| UNKNOWN | Not in database | **Neutral** — most third-party software returns this. Not an indicator. |

### Important Notes

- `os_version` is REQUIRED for service, scheduled task, and autorun checks — these artifacts vary significantly between Windows versions.
- `check_hash` checks against LOLDrivers only. For broader threat intel (malware hashes, IOCs), use `opencti-mcp lookup_ioc`.
- `check_registry` requires the full registry baseline database (~12GB). `check_autorun` is faster for persistence checks.
- UNKNOWN is the most common result. It means "not in the baseline database" — not "suspicious."

## opencti-mcp (8 tools)

Read-only threat intelligence from a configured OpenCTI instance.

| Tool | Parameters | Description | When the LLM uses it |
|------|-----------|-------------|---------------------|
| `get_health` | — | OpenCTI connectivity check | Before investigation, to verify intel source |
| `search_threat_intel` | `query`, `limit` (5), `offset`, `labels`, `confidence_min`, `created_after`, `created_before` | Broad cross-entity search (up to 20 results per type) | For initial IOC/threat actor research |
| `search_entity` | `type`, `query`, `limit` (10), `offset`, `labels`, `confidence_min`, `created_after`, `created_before` | Type-specific search (up to 50 results) | For focused queries on a single entity type |
| `lookup_ioc` | `ioc` | Full context for an IOC (IP, hash, domain, URL) with related entities | When a specific IOC needs to be contextualized |
| `get_recent_indicators` | `days` (7), `limit` (20) | Recently added IOCs | For situational awareness |
| `get_entity` | `entity_id` | Full entity details by UUID | To get complete context after finding an entity via search |
| `get_relationships` | `entity_id`, `direction`, `relationship_types`, `limit` (50) | Entity relationships (uses, indicates, targets) | To map threat actor toolkits, malware capabilities |
| `search_reports` | `query`, `limit` (10), `offset`, `labels`, `confidence_min`, `created_after`, `created_before` | Search threat reports | For analytical narrative that individual IOCs lack |

### Entity Types for search_entity

`threat_actor`, `malware`, `attack_pattern`, `vulnerability`, `campaign`, `tool`, `infrastructure`, `incident`, `observable`, `sighting`, `organization`, `sector`, `location`, `course_of_action`, `grouping`, `note`

### Confidence Interpretation

| Confidence | Meaning |
|------------|---------|
| 80-100 | High confidence, verified intel |
| 50-79 | Medium confidence, corroborate with other sources |
| < 50 | Low confidence, note uncertainty |

## opensearch-mcp (17 tools)

Evidence indexing, structured querying, and programmatic enrichment. Connects to a local or remote OpenSearch instance. Optional but recommended for investigations at scale.

### Query Tools (8)

| Tool | Parameters | Description | When the LLM uses it |
|------|-----------|-------------|---------------------|
| `idx_search` | `query`, `index`, `case_id`, `limit` (50), `offset`, `sort` ("@timestamp:desc"), `time_from`, `time_to`, `compact` (true) | Full-text + structured query (OpenSearch query_string) | Core search tool — every evidence query |
| `idx_count` | `query` ("*"), `index`, `case_id` | Fast document count with filters | To assess scale before querying |
| `idx_aggregate` | `field`, `query` ("*"), `index`, `case_id`, `limit` (50) | Group-by analysis (top N values) | For pattern analysis: top processes, IP distribution |
| `idx_timeline` | `query` ("*"), `index`, `case_id`, `interval` ("1h"), `time_field` ("@timestamp"), `time_from`, `time_to` | Date histogram for temporal analysis | To visualize activity over time |
| `idx_field_values` | `field`, `query` ("*"), `index`, `case_id`, `limit` (50) | Enumerate unique values in a field | To understand data distribution |
| `idx_get_event` | `event_id`, `index` | Retrieve single document by _id | To get full document details (uncompacted) |
| `idx_status` | — | Index inventory: names, doc counts, sizes | To see what's indexed |
| `idx_case_summary` | `case_id`, `include_fields` (false) | Complete case overview: hosts, artifacts, fields, enrichment status, time ranges | First call in any indexed investigation |

### Ingest Tools (6)

| Tool | Parameters | Description | When the LLM uses it |
|------|-----------|-------------|---------------------|
| `idx_ingest` | `path`, `hostname`, `include`, `exclude`, `source_timezone`, `all_logs`, `reduced_ids`, `full`, `dry_run` (true), `vss`, `password`, `no_hayabusa` | Full triage ingest (auto-discovers artifact types). Case ID from active case. | For KAPE/triage output, mounted images, containers |
| `idx_ingest_memory` | `path`, `hostname`, `tier` (1), `plugins`, `dry_run` (true) | Volatility 3 memory analysis and ingest | For memory dumps |
| `idx_ingest_json` | `path`, `hostname`, `index_suffix`, `time_field`, `dry_run` (true) | Generic JSON/JSONL ingest | For Suricata, tshark, Velociraptor output |
| `idx_ingest_delimited` | `path`, `hostname`, `index_suffix`, `time_field`, `delimiter`, `recursive`, `dry_run` (true) | Generic CSV/TSV/Zeek/bodyfile ingest | For delimited formats, supertimelines |
| `idx_ingest_accesslog` | `path`, `hostname`, `index_suffix` ("accesslog"), `dry_run` (true) | Apache/Nginx access log ingest | For web server logs |
| `idx_ingest_status` | `case_id` | Monitor running ingest operations | To check ingest progress |

### Enrichment Tools (2)

| Tool | Parameters | Description | When the LLM uses it |
|------|-----------|-------------|---------------------|
| `idx_enrich_triage` | `case_id` | Baseline enrichment via windows-triage-mcp | After ingest — stamps EXPECTED/SUSPICIOUS verdicts |
| `idx_enrich_intel` | `case_id`, `dry_run` (true), `force` | Threat intel enrichment via OpenCTI | After ingest — stamps MALICIOUS/CLEAN verdicts |

### Detection Tool (1)

| Tool | Parameters | Description | When the LLM uses it |
|------|-----------|-------------|---------------------|
| `idx_list_detections` | `severity`, `detector_type`, `limit` (50), `offset` | List Hayabusa/Sigma detection alerts | To review automated detections |

### Index Naming Convention

All indices follow: `case-{case_id}-{artifact_type}-{hostname}`

Examples:
- `case-incident-001-evtx-server01`
- `case-incident-001-shimcache-dc01`
- `case-incident-001-zeek-conn-fw01`
- `case-incident-001-vol-pslist-dc01`
- `case-incident-001-hayabusa-server01`

Wildcard queries across a case: `index="case-incident-001-*"`

### How opensearch-mcp Guides the LLM

`idx_case_summary()` returns investigation hints listing the top artifact types by document count and suggesting which tools to query next. On the first call, full hints are provided; subsequent calls provide a one-line pointer.

`idx_search()` adds a shimcache/amcache reminder when querying indices that contain Shimcache or Amcache data. This contextual reminder (decaying after the first 2 calls) reinforces that these artifacts prove presence, not execution — a common forensic misinterpretation.

After ingest, `idx_ingest()` returns `next_steps` suggesting enrichment and query tools with specific artifact types to check.

## wintools-mcp (10 tools, separate deployment)

Forensic tool execution on Windows. Catalog-gated — only tools defined in YAML catalog files can execute. Runs independently on a Windows workstation, exposing a Streamable HTTP endpoint on port 4624. The gateway can proxy requests to wintools-mcp, or LLM clients can connect directly.

### Discovery Tools (6)

| Tool | Parameters | Description | When the LLM uses it |
|------|-----------|-------------|---------------------|
| `scan_tools` | — | Scan for all cataloged tools, report availability | First use — discover what's installed |
| `list_windows_tools` | `category` | List tools with installation status, filterable by category | To see available tools in a category |
| `list_missing_windows_tools` | — | List tools not installed, with install guidance | To identify gaps in tool coverage |
| `check_windows_tools` | `tool_names` (list) | Check specific tools by name | To verify tools before a workflow |
| `get_windows_tool_help` | `tool_name` | Tool-specific help, flags, caveats | Before running an unfamiliar tool |
| `suggest_windows_tools` | `artifact_type`, `question` | Suggest tools for an artifact type | When deciding how to analyze a Windows artifact |

### Evidence Access (1)

| Tool | Parameters | Description | When the LLM uses it |
|------|-----------|-------------|---------------------|
| `get_share_info` | — | Get SMB share paths (share_root, case_dir, evidence_dir, extractions_dir) | To understand where evidence files are on the Windows side |

### KAPE Discovery (1)

| Tool | Parameters | Description | When the LLM uses it |
|------|-----------|-------------|---------------------|
| `list_kape_targets` | `list_type` ("targets" or "modules") | List KAPE targets/modules in structured categories | When planning evidence parsing with KAPE |

### Batch Execution (1)

| Tool | Parameters | Description | When the LLM uses it |
|------|-----------|-------------|---------------------|
| `batch_scan` | `tool`, `directory`, `filter_pattern`, `max_files` (500), `timeout` (3600) | Run a tool against files in a directory with safety bounds | For directory-level scanning (sigcheck, densityscout, capa) |

### Generic Execution (1)

| Tool | Parameters | Description | When the LLM uses it |
|------|-----------|-------------|---------------------|
| `run_windows_command` | `command` (list), `purpose`, `timeout`, `save_output`, `input_files` | Execute a cataloged forensic tool | Core tool — every Windows forensic analysis action |

### Tool Catalog (31 entries)

| File | Count | Tools |
|------|-------|-------|
| `zimmerman.yaml` | 14 | AmcacheParser, AppCompatCacheParser, EvtxECmd, JLECmd, LECmd, MFTECmd, PECmd, RBCmd, RECmd, SBECmd, SQLECmd, SrumECmd, WxTCmd, bstrings |
| `sysinternals.yaml` | 5 | autorunsc, sigcheck, strings, handle, procdump |
| `memory.yaml` | 4 | winpmem, dumpit, moneta, hollows_hunter |
| `timeline.yaml` | 3 | Hayabusa, chainsaw, mactime |
| `analysis.yaml` | 3 | capa, yara, densityscout |
| `collection.yaml` | 1 | KAPE |
| `scripts.yaml` | 1 | Get-InjectedThreadEx |

### Security Model

```
Tool call → Hardcoded Denylist (20+ binaries) → YAML Catalog Allowlist → Argument Sanitization → subprocess.run(shell=False)
```

**Denylist** (unconditionally blocked): cmd, powershell, pwsh, wscript, cscript, mshta, rundll32, regsvr32, certutil, bitsadmin, msiexec, bash, wsl, sh, msbuild, installutil, regasm, regsvcs, cmstp, control (including .exe variants).

**Argument sanitization** blocks: shell metacharacters (`;`, `&&`, `||`, `` ` ``), response-file syntax (`@filename`), dangerous flags (`-e`, `--exec`, `-enc`), output redirect flags.

## Response Envelope

Every forensic tool response (from sift-mcp and wintools-mcp) is wrapped in a structured envelope:

```json
{
  "success": true,
  "tool": "run_command",
  "data": {"output": {"rows": ["..."], "total_rows": 42}},
  "data_provenance": "tool_output_may_contain_untrusted_evidence",
  "audit_id": "sift-steve-20260220-001",
  "examiner": "steve",
  "caveats": ["Amcache entries indicate file presence, not execution"],
  "advisories": ["Cross-reference with Prefetch for execution confirmation"],
  "corroboration": {
    "for_execution": ["Prefetch", "UserAssist"],
    "for_timeline": ["$MFT timestamps", "USN Journal"]
  },
  "field_meanings": {"KeyLastWriteTimestamp": "Last time the registry key was modified"},
  "discipline_reminder": "Evidence is sovereign -- if results conflict with your hypothesis, revise the hypothesis"
}
```

| Field | Source | Description |
|-------|--------|-------------|
| `audit_id` | Audit system | Unique ID for referencing in findings (`{backend}-{examiner}-YYYYMMDD-NNN`) |
| `data_provenance` | Built-in | Marks tool output as potentially containing untrusted evidence (adversarial content defense) |
| `caveats` | forensic-knowledge | Artifact-specific limitations and interpretation warnings |
| `advisories` | forensic-knowledge | What the artifact does NOT prove, common misinterpretations |
| `corroboration` | forensic-knowledge | Suggested cross-reference artifacts and tools grouped by purpose |
| `field_meanings` | forensic-knowledge | Timestamp field meanings and interpretation guidance |
| `discipline_reminder` | Built-in | Rotating forensic methodology reminder |
