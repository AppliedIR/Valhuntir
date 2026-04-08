# User Guide

Valhuntir turns a single analyst into the manager of an agentic AI incident response team. This guide covers the full investigation workflow — from case creation through evidence analysis to final reporting.

> **Important Note** — While extensively tested, this is a new platform.
> ALWAYS verify results and guide the investigative process. If you just
> tell Valhuntir to "Find Evil" it will more than likely hallucinate
> rather than provide meaningful results. The AI can accelerate, but the
> human must guide it and review all decisions.

## Investigation Workflow

The recommended workflow uses OpenSearch for evidence indexing. Without OpenSearch, the same tools are available through direct file-based analysis — OpenSearch adds scale and structured querying, not capability.

```
1. Create a case             → case_init() or vhir case init
2. Register evidence         → evidence_register() or vhir evidence register
3. Ingest and index          → idx_ingest() to parse evidence into OpenSearch
4. Scope the investigation   → idx_case_summary() for hosts, artifacts, time ranges
5. Check for detections      → idx_list_detections() for Hayabusa/Sigma alerts
6. Enrich programmatically   → idx_enrich_triage() + idx_enrich_intel()
7. Search and analyze        → idx_search(), idx_aggregate(), idx_timeline()
8. Deep analysis             → run_command() with SIFT tools, run_windows_command()
9. Cross-reference           → search_knowledge(), check_file(), lookup_ioc()
10. Record findings          → record_finding() with evidence artifacts
11. Human review             → Examiner Portal or vhir approve
12. Generate report          → generate_report() with Zeltser guidance
```

Without OpenSearch, steps 3-7 are replaced by direct tool execution (`run_command`) and manual analysis. Steps 8-12 are identical either way.

## Case Management

### Creating a Case

From the CLI:

```bash
vhir case init "Suspicious Activity Investigation"
vhir case init "Ransomware Response" --description "Finance server, Feb 2026"
```

Or via the LLM (through case-mcp):

```
"Create a new case for the phishing investigation"
→ case_init(name="Phishing Investigation")
```

Both paths create a case directory under `~/.vhir/cases/` with a unique ID (e.g., `INC-2026-0225`) and activate it for the session.

### Managing Multiple Cases

```bash
vhir case list                    # List all cases with status
vhir case activate INC-2026-0225  # Switch active case
vhir case status                  # Current case details
vhir case close INC-2026-0225 --summary "Investigation complete"
vhir case reopen INC-2026-0225    # Reopen if needed
```

The LLM can also list and activate cases through `case_list()` and `case_activate()`.

### Case Directory Structure

Each case uses a flat directory layout with structured JSON files:

```
cases/INC-2026-0225/
├── CASE.yaml                    # Case metadata (name, status, examiner)
├── evidence/                    # Original evidence (lock with vhir evidence lock)
├── extractions/                 # Extracted artifacts and tool output
├── reports/                     # Generated reports
├── findings.json                # F-alice-001, F-alice-002, ...
├── timeline.json                # T-alice-001, ...
├── todos.json                   # TODO-alice-001, ...
├── iocs.json                    # IOC-alice-001, ... (auto-extracted from findings)
├── evidence.json                # Evidence registry with SHA-256 hashes
├── actions.jsonl                # Investigative actions (append-only)
├── evidence_access.jsonl        # Chain-of-custody log
├── approvals.jsonl              # Approval audit trail
├── pending-reviews.json         # Portal edits awaiting commit
└── audit/
    ├── forensic-mcp.jsonl       # Per-backend MCP audit logs
    ├── sift-mcp.jsonl
    ├── case-mcp.jsonl
    ├── claude-code.jsonl        # PostToolUse hook (Claude Code only)
    └── ...
```

### Evidence Registration

Register evidence files to establish chain of custody:

```bash
vhir evidence register /path/to/disk.E01 --description "Workstation image"
vhir evidence register /path/to/memory.raw --description "Memory dump from DC01"
```

Or via MCP: `evidence_register(path="/path/to/disk.E01", description="Workstation image")`

Registration computes a SHA-256 hash and records it in `evidence.json`. Verify integrity at any time:

```bash
vhir evidence verify              # Re-hash all registered evidence
vhir evidence lock                # Set evidence directory to read-only
vhir evidence unlock              # Restore write access for re-extraction
```

### Case Backup

Back up case data (metadata, findings, timeline, audit trails) for archival or disaster recovery:

```bash
vhir backup /path/to/destination                     # Case data only (interactive)
vhir backup /path/to/destination --all               # Include evidence + extractions
vhir backup --verify /path/to/backup/INC-2026-0225/  # Verify backup integrity
```

The LLM can also create case-data-only backups at investigation checkpoints via `backup_case()`.

## Evidence Indexing with OpenSearch

When opensearch-mcp is installed, evidence is parsed programmatically and indexed into OpenSearch, giving the LLM 17 purpose-built query tools instead of consuming billions of tokens reading raw artifacts.

### Ingesting Evidence

Full triage package (auto-discovers hosts and artifact types):

```bash
opensearch-ingest scan /path/to/kape/output --hostname SERVER01 --case incident-001
```

Memory image:

```bash
opensearch-ingest memory /path/to/memory.raw --hostname DC01 --case incident-001
```

Generic formats:

```bash
opensearch-ingest json /path/to/suricata/eve.json --hostname FW01 --case incident-001
opensearch-ingest delimited /path/to/zeek/logs/ --hostname SENSOR01 --case incident-001
opensearch-ingest accesslog /path/to/apache/access.log --hostname WEB01 --case incident-001
```

Or via MCP:

```
idx_ingest(case_dir="/path/to/evidence", hostname="SERVER01")
idx_ingest_memory(memory_path="/path/to/memory.raw", hostname="DC01")
idx_ingest_json(path="/path/to/eve.json", hostname="FW01")
idx_ingest_delimited(path="/path/to/zeek/", hostname="SENSOR01")
idx_ingest_accesslog(path="/path/to/access.log", hostname="WEB01")
```

### 15 Parsers

15 parser modules handle the forensic evidence spectrum. The table below groups related parsers — W3C covers IIS, HTTPERR, and Windows Firewall as separate parse paths; Prefetch and SRUM each have their own module.

| Parser | Artifacts | Source |
|--------|-----------|--------|
| evtx | Windows Event Logs | pyevtx-rs (ECS-normalized) |
| EZ Tools (10) | Shimcache, Amcache, MFT, USN, Registry, Shellbags, Jumplists, LNK, Recyclebin, Timeline | Eric Zimmerman tools via wintools-mcp |
| Volatility 3 | Memory forensics (26 plugins, 3 tiers) | vol3 subprocess |
| JSON/JSONL | Suricata EVE, tshark, Velociraptor, any JSON | Auto-detect format |
| Delimited | CSV, TSV, Zeek TSV, bodyfile, L2T supertimelines | Auto-detect delimiter |
| Access logs | Apache/Nginx combined/common format | Regex parser |
| W3C | IIS, HTTPERR, Windows Firewall | W3C Extended Log Format |
| Defender | Windows Defender MPLog | Pattern extraction |
| Tasks | Windows Scheduled Tasks XML | defusedxml |
| WER | Windows Error Reporting | Crash report parser |
| SSH | OpenSSH auth logs | Regex with timezone handling |
| Transcripts | PowerShell transcripts | Header + command extraction |
| Prefetch/SRUM | Execution + network usage | Plaso or wintools |

Every parser produces deterministic content-based document IDs (re-ingest = zero duplicates), full provenance (`host.name`, `vhir.source_file`, `vhir.ingest_audit_id`, `vhir.parse_method`, `pipeline_version`), and proper `@timestamp` with timezone handling.

### Hayabusa Auto-Detection

After EVTX ingest, opensearch-mcp checks if Hayabusa is installed and automatically runs it against the event logs. Hayabusa applies 3,700+ Sigma-based detection rules and indexes the alerts into `case-*-hayabusa-*` indices. Query alerts with:

```
idx_list_detections(case_id="incident-001")
idx_search(query="level:critical OR level:high", index="case-incident-001-hayabusa-*")
```

### Querying Indexed Evidence

Start with a case overview, then query:

```
# Understand what's available
idx_case_summary(case_id="incident-001")
# Returns: hosts, artifact types, doc counts, fields per type, enrichment status

# Full-text + structured queries
idx_search(query="event.code:4688 AND process.parent.name:cmd.exe",
           index="case-incident-001-evtx-*")

# Aggregations
idx_aggregate(field="process.name", query="triage.verdict:SUSPICIOUS")

# Temporal analysis
idx_timeline(query="threat_intel.verdict:MALICIOUS", interval="1h")

# Unique values
idx_field_values(field="source.ip", index="case-incident-001-evtx-*")

# Document counts
idx_count(query="event.code:4624", index="case-incident-001-evtx-*")

# Single document lookup
idx_get_event(doc_id="...", index="case-incident-001-evtx-server01")
```

All indices follow the naming convention: `case-{case_id}-{artifact_type}-{hostname}`. Wildcard queries across a case: `index="case-incident-001-*"`.

### Programmatic Enrichment

Two post-ingest enrichment pipelines add context without consuming LLM tokens:

**Triage baseline** (`idx_enrich_triage`): Checks indexed filenames and services against the Windows baseline database (via windows-triage-mcp). Stamps documents with `triage.verdict` (EXPECTED, SUSPICIOUS, UNKNOWN, EXPECTED_LOLBIN). Includes 14 registry persistence detection rules (IFEO, Winlogon, LSA, Print Monitors, etc.) that run as direct OpenSearch queries.

**Threat intelligence** (`idx_enrich_intel`): Extracts unique external IPs, hashes, and domains from indexed data, looks them up in OpenCTI, and stamps matching documents with `threat_intel.verdict` and confidence. 200 unique IOCs checked in ~10 seconds vs. 100K inline lookups that would take 83 minutes.

Both enrichments are programmatic — zero LLM tokens consumed. After enrichment, query for results:

```
idx_search(query="triage.verdict:SUSPICIOUS")
idx_search(query="threat_intel.verdict:MALICIOUS")
idx_aggregate(field="triage.verdict", query="*")
```

### Monitoring Ingest Operations

```
idx_ingest_status(case_id="incident-001")
idx_status()   # Index inventory: names, doc counts, sizes
```

## Deep Analysis with Forensic Tools

### SIFT Tools (via sift-mcp)

sift-mcp provides `run_command()` for executing any forensic tool installed on the SIFT workstation. A denylist blocks destructive binaries (mkfs, shutdown, kill, nc/ncat). All other tools can execute. Cataloged tools get enriched responses with forensic-knowledge data (caveats, corroboration suggestions, field meanings); uncataloged tools get basic response envelopes.

Examples of what you can ask the LLM:

```
"Parse the Amcache hive at /cases/evidence/Amcache.hve"
"Run Prefetch analysis on all .pf files in /cases/evidence/prefetch/"
"What tools should I use to investigate lateral movement artifacts?"
"Analyze this memory dump with Volatility — list processes and network connections"
"Run hayabusa against the evtx logs and show critical/high alerts"
"Extract the $MFT and build a filesystem timeline"
```

### Windows Tools (via wintools-mcp)

wintools-mcp runs on a separate Windows workstation and provides catalog-gated tool execution. Only tools defined in YAML catalog files can run. 31 cataloged tools across 7 categories: Zimmerman suite (14), Sysinternals (5), memory analysis (4), timeline (3), malware analysis (3), collection (1), and scripts (1).

Additional capabilities:
- `batch_scan` — run a tool against all files in a directory with safety bounds
- `list_kape_targets` — list KAPE targets/modules for evidence parsing
- `get_share_info` — get SMB share paths for evidence access

### Tool Discovery

Both sift-mcp and wintools-mcp provide tools to discover what's available:

```
# What forensic tools are installed?
list_available_tools()              # sift-mcp
list_windows_tools()                # wintools-mcp

# What should I use for this artifact type?
suggest_tools(artifact_type="lateral_movement")
suggest_windows_tools(artifact_type="registry")

# How do I use this specific tool?
get_tool_help(tool_name="AmcacheParser")
get_windows_tool_help(tool_name="hayabusa")
```

## Cross-Reference and Validation

### Forensic Knowledge RAG (forensic-rag-mcp)

Semantic search across 22,000+ records from 23 authoritative sources:

| Source | Description |
|--------|-------------|
| `sigma` | SigmaHQ Detection Rules |
| `atomic` | Atomic Red Team Tests |
| `mitre_attack` | MITRE ATT&CK Framework |
| `mitre_car` | MITRE Cyber Analytics Repository |
| `mitre_d3fend` | MITRE D3FEND Defensive Techniques |
| `mitre_atlas` | MITRE ATLAS AI/ML Attack Framework |
| `mitre_engage` | MITRE Engage Adversary Engagement |
| `capec` | MITRE CAPEC Attack Patterns |
| `mbc` | MITRE MBC Malware Behavior Catalog |
| `cisa_kev` | CISA Known Exploited Vulnerabilities |
| `elastic` | Elastic Detection Rules |
| `splunk_security` | Splunk Security Content |
| `lolbas` | LOLBAS Project |
| `gtfobins` | GTFOBins |
| `loldrivers` | LOLDrivers Vulnerable Driver Database |
| `hijacklibs` | HijackLibs DLL Hijacking Database |
| `forensic_artifacts` | ForensicArtifacts Definitions |
| `kape` | KAPE Targets & Modules |
| `velociraptor` | Velociraptor Artifact Exchange |
| `stratus_red_team` | Stratus Red Team Cloud Attacks |
| `chainsaw` | Chainsaw Detection Rules (EVTX + MFT) |
| `hayabusa` | Hayabusa Built-in Detection Rules |
| `forensic_clarifications` | Authoritative Forensic Artifact Clarifications |

Query with optional filters:

```
search_knowledge(query="credential dumping detection",
                 source_ids=["sigma", "mitre_attack"])
search_knowledge(query="lateral movement", platform="windows")
search_knowledge(query="T1003.001")  # MITRE technique ID
list_knowledge_sources()              # See all available sources
```

Relevance scores: 0.85+ excellent, 0.75-0.84 good, 0.65-0.74 fair, <0.65 likely not relevant.

### Windows Baseline Validation (windows-triage-mcp)

Offline validation against 2.6 million known Windows file and process baseline records. No network calls required.

```
check_file(path="C:\\Windows\\System32\\svchost.exe")
check_process_tree(process_name="svchost.exe", parent_name="services.exe")
check_service(service_name="BITS", os_version="W11_22H2")
check_scheduled_task(task_path="\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
                     os_version="W10_21H2")
check_lolbin(filename="certutil.exe")
check_hash(hash="d41d8cd98f00b204e9800998ecf8427e")
check_hijackable_dll(dll_name="version.dll")
check_pipe(pipe_name="\\MSSE-1234-server")
analyze_filename(filename="scvhost.exe")
```

Verdicts:
- **EXPECTED** — in the Windows baseline
- **EXPECTED_LOLBIN** — baseline match with LOLBin capability (legitimate but abusable)
- **SUSPICIOUS** — anomaly detected (wrong path, Unicode homoglyphs, known C2 pipe, vulnerable driver)
- **UNKNOWN** — not in the database (neutral, not an indicator — most third-party software returns this)

### Threat Intelligence (opencti-mcp)

Live threat intelligence from your configured OpenCTI instance. Read-only queries:

```
lookup_ioc(ioc="203.0.113.1")                    # IP, hash, domain, or URL
search_threat_intel(query="APT29")                 # Broad cross-entity search
search_entity(type="malware", query="Cobalt Strike")  # Type-specific search
get_recent_indicators(days=7)                      # Recent IOCs
get_relationships(entity_id="...")                 # Who uses it, what it targets
search_reports(query="APT29 campaign")             # Threat reports
```

### Malware Analysis (remnux-mcp)

When connected to a REMnux VM, escalate suspicious files for automated analysis:

```
upload_from_host(file_path="/path/to/suspect.exe")
analyze_file(file_path="samples/suspect.exe", depth="standard")
extract_iocs(file_path="samples/suspect.exe")
```

Depth tiers: `quick` (initial triage), `standard` (default), `deep` (known-malicious or evasive).

## Recording Findings

Findings are the core output of an investigation. Each finding represents something significant enough to appear in the final IR report.

### What Qualifies as a Finding

- A suspicious artifact, anomaly, or IOC with supporting evidence
- A benign exclusion (ruling something out, with evidence why)
- A causal link between events
- A significant evidence gap that affects conclusions

Routine tool output is NOT a finding. "Ran AmcacheParser, got 42 entries" goes in the audit trail. "AmcacheParser shows Mimikatz installation at 14:32 UTC, no corresponding Prefetch entry" is a finding.

### How Findings Are Created

The intended flow:

1. LLM analyzes tool output
2. LLM presents evidence to the examiner with the actual log entry/record (not a summary)
3. Examiner gives conversational approval
4. LLM calls `record_finding()` with evidence artifacts and provenance

### Finding Fields

| Field | Required | Description |
|-------|----------|-------------|
| `title` | Yes | Brief summary of the finding |
| `observation` | Yes | What was seen (factual — the evidence itself) |
| `interpretation` | Yes | What it might mean (analytical) |
| `confidence` | Yes | HIGH, MEDIUM, LOW, or SPECULATIVE |
| `confidence_justification` | Yes | Why this confidence level |
| `type` | Yes | finding, conclusion, attribution, or exclusion |
| `audit_ids` | Yes | References to MCP tool execution evidence IDs |
| `event_timestamp` | Recommended | When the incident event occurred (ISO 8601, from the evidence) |
| `host` | Recommended | Which system is affected |
| `affected_account` | Recommended | Which user/service account |
| `mitre_ids` | Optional | MITRE ATT&CK technique IDs |
| `iocs` | Optional | Indicators of compromise |
| `tags` | Optional | Searchable labels |
| `artifacts` | Recommended | Evidence artifacts (see below) |
| `supporting_commands` | Optional | Shell commands used (for SHELL provenance tier) |

### Evidence Artifacts

Every finding should include artifacts showing the actual evidence:

```json
{
  "artifacts": [
    {
      "source": "/cases/evidence/Security.evtx",
      "extraction": "EvtxECmd -f Security.evtx --csv /tmp/out",
      "content": "2026-01-24 15:00:41,4688,SERVER01\\admin,cmd.exe,...",
      "content_type": "csv_row",
      "audit_id": "sift-steve-20260124-042"
    }
  ]
}
```

Each artifact must include an `audit_id` from the MCP tool response that produced the data. Artifacts without `audit_id` are rejected.

### Provenance Enforcement

Every finding must be traceable to evidence:

| Tier | Source | Trust Level |
|------|--------|-------------|
| **MCP** | MCP audit log | System-witnessed (highest) |
| **HOOK** | Claude Code hook log | Framework-witnessed |
| **SHELL** | `supporting_commands` parameter | Self-reported |
| **NONE** | No audit record | **Rejected** by hard gate |

Findings with NONE provenance and no supporting commands are automatically rejected by `record_finding()`.

### IOC Auto-Extraction

When findings include IOCs (IPs, hashes, domains, URLs), they are automatically extracted to `iocs.json` with category and status tracking. IOC approval cascades from the parent finding — when all source findings reach the same status, the IOC follows.

## Timeline

Timeline events represent key moments in the incident narrative — timestamps that would appear in a timeline report. Not every timestamp in the evidence is a timeline event; MFT entries showing normal system activity are data, while the timestamp when a malicious process first executed is a timeline event.

### Recording Timeline Events

```
record_timeline_event(event={
    "timestamp": "2026-01-24T15:00:41Z",
    "description": "cmd.exe spawned from Excel.exe on SERVER01",
    "source": "Security.evtx Event ID 4688",
    "event_type": "execution",
    "artifact_ref": "evtx:Security:4688:12345",
    "related_findings": ["F-steve-001"]
})
```

Event types: `process`, `network`, `file`, `registry`, `auth`, `persistence`, `lateral`, `execution`, `other`.

### Filtering Timeline

```bash
vhir review --timeline                           # All timeline events
vhir review --timeline --status APPROVED          # Approved only
vhir review --timeline --type lateral             # By event type
vhir review --timeline --start 2026-01-20T00:00 --end 2026-01-22T23:59
```

Via MCP: `get_timeline(status="APPROVED", event_type="lateral", start_date="2026-01-20")`

## Review and Approval

All findings and timeline events stage as DRAFT. Only a human examiner can approve or reject them — the AI cannot bypass the approval mechanism.

### Examiner Portal

The Examiner Portal is the primary review interface. Open it:

```bash
vhir portal
```

The portal has 8 tabs:

| Tab | Purpose |
|-----|---------|
| **Overview** | Investigation progress, getting started guide |
| **Findings** | Core review workflow with provenance chain display |
| **Timeline** | Chronological events with color-coded ruler |
| **Hosts** | Systems involved (aggregated from findings) |
| **Accounts** | User/service accounts (aggregated from findings) |
| **Evidence** | Registered files with SHA-256 integrity verification |
| **IOCs** | Indicators extracted from findings with category/status filters |
| **TODOs** | Outstanding investigation tasks |

Examiners can edit finding fields inline (confidence, justification, observation, interpretation, MITRE IDs, IOCs, tags), approve or reject items, and commit decisions — all in the browser.

Keyboard shortcuts: `1`-`8` switch tabs, `j`/`k` navigate items, `a` approve, `r` reject, `e` edit, `Shift+C` commit.

The Commit button (`Shift+C`) uses challenge-response authentication: the browser derives a PBKDF2 key from the examiner's password and proves knowledge via HMAC — the password never leaves the browser.

### CLI Approval

```bash
vhir approve                                    # Interactive review
vhir approve F-steve-001 F-steve-002            # Approve specific findings
vhir approve F-steve-003 --note "Confirmed"     # With examiner note
vhir approve F-steve-004 --edit                 # Edit in $EDITOR first
vhir approve --findings-only                    # Review only findings
vhir approve --timeline-only                    # Review only timeline
vhir approve --review                           # Apply pending portal edits
```

### Rejecting Findings

```bash
vhir reject F-steve-004 --reason "Insufficient evidence, timestamp inconsistency"
```

### Reviewing Case Status

```bash
vhir review                              # Case summary
vhir review --findings                   # Findings table
vhir review --findings --detail          # Full finding details
vhir review --findings --status DRAFT    # Filter by status
vhir review --timeline                   # Timeline events
vhir review --todos --open               # Open TODOs
vhir review --evidence                   # Evidence integrity
vhir review --iocs                       # IOCs from findings
vhir review --audit                      # Audit trail
```

### Integrity Verification

```bash
vhir review --verify                # Full verification (all examiners)
vhir review --verify --mine         # Current examiner only
```

This performs three levels of verification:
- **Content hash check**: SHA-256 hashes in `findings.json` vs. `approvals.jsonl`
- **Ledger reconciliation**: Cross-checks approved items against the HMAC verification ledger
- **HMAC verification**: Recomputes HMAC-SHA256 signatures using the examiner's password

## Report Generation

Reports are generated through report-mcp (via the LLM) or the vhir CLI. Only APPROVED findings appear in reports.

### Report Profiles

| Profile | Purpose |
|---------|---------|
| `full` | Comprehensive IR report with all approved data |
| `executive` | Management briefing (1-2 pages, non-technical) |
| `timeline` | Chronological event narrative |
| `ioc` | Structured IOC export with MITRE mapping |
| `findings` | Detailed approved findings |
| `status` | Quick status for standups |

### Via LLM

Ask the LLM:

```
"Generate a full incident response report"
"Create an executive summary for management"
"Generate an IOC report with MITRE mappings"
```

The LLM calls `generate_report()` which returns structured case data, IOC aggregation, MITRE ATT&CK mapping, and Zeltser IR Writing guidance. The LLM then renders narrative sections following Zeltser's IR templates and the guidance from the [Zeltser IR Writing MCP](https://website-mcp.zeltser.com/mcp).

### Via CLI

```bash
vhir report --full --save full-report.json
vhir report --executive-summary
vhir report --ioc
vhir report --status-brief
vhir report --timeline --from 2026-01-20 --to 2026-01-22
vhir report --findings F-steve-001,F-steve-002
```

### Setting Case Metadata

Report metadata is stored in CASE.yaml and appears in generated reports:

```
set_case_metadata(field="incident_type", value="ransomware")
set_case_metadata(field="severity", value="critical")
set_case_metadata(field="scope", value="Finance department, 30 hosts")
```

## Investigation TODOs

Track what still needs to be done:

```bash
vhir todo add "Analyze USB device history" --priority high --finding F-steve-002
vhir todo add "Cross-reference DNS logs" --assignee bob
vhir review --todos --open
vhir todo complete TODO-steve-001
```

The LLM can also manage TODOs through forensic-mcp's `add_todo()`, `list_todos()`, `update_todo()`, and `complete_todo()` tools.

## Collaboration (Multi-Examiner)

Each examiner works on their own SIFT workstation with a local case directory. Collaboration uses export/merge:

### Export

```bash
vhir export --file findings-alice.json
vhir export --file recent-alice.json --since 2026-01-24T00:00
```

### Merge

```bash
vhir merge --file findings-bob.json
```

Merge uses last-write-wins by `modified_at` timestamp. APPROVED findings are protected from overwrite. IDs include the examiner name (e.g., `F-alice-001`, `F-bob-003`) so they never collide across examiners.

## Audit Trail

Every MCP tool call is logged to a per-backend JSONL file in the case `audit/` directory with a unique evidence ID (`{backend}-{examiner}-{YYYYMMDD}-{NNN}`).

```bash
vhir audit log                       # Recent audit entries
vhir audit log --mcp forensic-mcp    # Filter by backend
vhir audit log --tool run_command    # Filter by tool
vhir audit summary                   # Counts per MCP and tool
```

When Claude Code is the LLM client, a PostToolUse hook additionally captures every Bash command to `audit/claude-code.jsonl`.

The LLM can also write to the audit trail:
- `log_reasoning()` — record analytical decisions at decision points (no approval needed)
- `log_external_action()` — record non-MCP tool execution
- `record_action()` — record investigative actions
