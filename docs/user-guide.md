# User Guide

## Investigation Workflow

A typical investigation follows this flow:

1. **Initialize** — Create a case, register evidence
2. **Analyze** — Execute forensic tools, examine artifacts
3. **Record** — Capture findings and timeline events as they emerge
4. **Review** — Human examiner reviews DRAFT findings
5. **Approve** — Move findings to APPROVED or REJECTED
6. **Report** — Generate case reports from approved data

## Case Management

### Creating a Case

```bash
aiir case init "Ransomware Investigation - ACME Corp"
```

The case is automatically activated. To see your active case:

```bash
aiir case status
```

### Managing Multiple Cases

```bash
aiir case list                    # List all cases
aiir case activate INC-2026-0225  # Switch active case
aiir case close INC-2026-0225 --summary "Investigation complete"
aiir case reopen INC-2026-0225    # Reopen if needed
```

### Evidence Registration

Register evidence files to create an integrity baseline:

```bash
aiir evidence register /path/to/disk.E01 --description "Workstation forensic image"
aiir evidence list                # Show registered evidence
aiir evidence verify              # Re-hash and check for modifications
```

Registered files are set to read-only (chmod 444) as a defense-in-depth measure.

## Recording Findings

Findings are the core output of an investigation. Each finding represents something that would appear in the final IR report:

- A suspicious artifact or IOC with supporting evidence
- A benign exclusion (ruling something out, with evidence)
- A causal link between events
- A significant evidence gap

### How Findings Are Created

The LLM records findings through forensic-mcp's `record_finding()` tool. The intended flow:

1. LLM analyzes tool output
2. LLM presents evidence to the examiner
3. Examiner gives conversational approval
4. LLM calls `record_finding()` with evidence details

### Finding Fields

| Field | Description |
|-------|-------------|
| `title` | Short description of the finding |
| `description` | Detailed explanation with evidence |
| `confidence` | HIGH, MEDIUM, LOW, or SPECULATIVE |
| `confidence_justification` | Reasoning for the confidence level |
| `mitre_ids` | MITRE ATT&CK technique IDs |
| `iocs` | Indicators of compromise |
| `evidence_ids` | References to tool execution evidence IDs |
| `artifacts` | Evidence artifacts — source file, extraction command, raw content, content type, purpose |
| `supporting_commands` | Shell commands used (for SHELL provenance) — command, output excerpt, purpose |

### Provenance Enforcement

Every finding must be traceable to evidence. Findings are classified by provenance tier:

- **MCP**: Evidence gathered through MCP tools (highest trust)
- **HOOK**: Evidence gathered via Bash with Claude Code hook capture
- **SHELL**: Evidence from direct shell commands (self-reported via `supporting_commands`)
- **NONE**: No evidence trail — **finding is rejected**

Findings with NONE provenance and no supporting commands are automatically rejected by a hard gate in `record_finding()`.

## Timeline

Timeline events represent key moments in the incident narrative — timestamps that would appear in a timeline report.

### Recording Timeline Events

The LLM records events through `record_timeline_event()` with:

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 timestamp of the event |
| `description` | What happened |
| `source` | Where the timestamp came from (e.g., "Prefetch", "Security.evtx") |
| `event_type` | Classification: process, network, file, registry, auth, persistence, lateral, execution |
| `artifact_ref` | Unique artifact reference for deduplication |
| `related_findings` | Finding IDs this event supports |

### Filtering Timeline

```bash
aiir review --timeline                           # All timeline events
aiir review --timeline --status APPROVED          # Approved only
aiir review --timeline --type lateral             # Lateral movement events
aiir review --timeline --start 2026-02-20T00:00   # Date range
```

## Review and Approval

### Reviewing Case Status

```bash
aiir review                    # Case summary
aiir review --findings         # Findings table
aiir review --findings --detail # Full finding details
aiir review --timeline         # Timeline events
aiir review --todos            # TODO items
aiir review --audit            # Audit trail
aiir review --evidence         # Evidence integrity
aiir review --iocs             # IOCs from findings
```

### Integrity Verification

```bash
aiir review --verify                # Full verification (all examiners, prompts for each password)
aiir review --verify --mine         # HMAC verification for current examiner only
```

This performs three levels of verification:
- **Content hash check**: Compares SHA-256 hashes in `findings.json` against `approvals.jsonl`
- **Ledger reconciliation**: Cross-checks approved items against the HMAC verification ledger (no password needed)
- **HMAC verification**: Recomputes HMAC-SHA256 signatures using the examiner's password to confirm cryptographic integrity. Prompts for each examiner's password separately. Use `--mine` to check only your own entries.

### Approving Findings

Interactive mode (reviews each DRAFT finding):

```bash
aiir approve
```

Approve specific findings:

```bash
aiir approve F-alice-001 F-alice-002 --note "Confirmed with disk forensics"
```

Approve with interpretation override:

```bash
aiir approve F-alice-003 --interpretation "Confirmed malicious based on YARA match"
```

### Rejecting Findings

```bash
aiir reject F-alice-004 --reason "Insufficient evidence, timestamp inconsistency"
```

### Dashboard Review

The case dashboard is the primary review interface. Open it with:

```bash
aiir dashboard
```

The dashboard displays all findings and timeline events with inline editing for:

- **Confidence** — select HIGH / MEDIUM / LOW / SPECULATIVE
- **Justification** — explain the confidence level
- **Observation** — what was observed
- **Interpretation** — what it means
- **MITRE IDs** — ATT&CK technique references
- **IOCs** — indicators of compromise

Findings that include `artifacts` (source files, extraction commands, raw content) display them in the Evidence section. Findings without artifacts fall back to showing `supporting_commands`.

Review, approve, reject, and commit findings directly in the browser using the Commit button (Shift+C). The dashboard uses challenge-response authentication — the password never leaves the browser. Both the dashboard and the CLI produce identical HMAC-signed approval records.

Alternatively, edits can be applied from the CLI:

```bash
aiir approve --review
```

This applies pending edits saved in `pending-reviews.json`, recomputes content hashes, and updates HMAC signatures.

## Report Generation

Reports are generated through report-mcp (via the LLM) or the aiir CLI.

### Report Profiles

| Profile | Purpose |
|---------|---------|
| `full` | Comprehensive IR report with all approved data |
| `executive` | Management briefing (1-2 pages, non-technical) |
| `timeline` | Chronological event narrative |
| `ioc` | Structured IOC export with MITRE mapping |
| `findings` | Detailed approved findings |
| `status` | Quick status for standups |

### Via LLM (report-mcp)

Ask the LLM:
```text
"Generate a full incident response report"
"Create an executive summary for management"
"Generate an IOC report with MITRE mappings"
```

The LLM calls `generate_report()` which returns structured case data and Zeltser IR Writing guidance. The LLM then renders narrative sections following the guidance.

### Via CLI

```bash
aiir report --full --save full-report.json
aiir report --executive-summary
aiir report --ioc
aiir report --status-brief
aiir report --timeline --from 2026-02-20 --to 2026-02-22
```

## Investigation TODOs

Track what still needs to be done:

```bash
aiir todo add "Analyze USB device history" --priority high --finding F-alice-002
aiir todo add "Cross-reference with DNS logs" --assignee bob
aiir review --todos --open      # Show open TODOs
aiir todo complete TODO-alice-001
```

The LLM can also manage TODOs through forensic-mcp's `add_todo()`, `list_todos()`, `update_todo()`, and `complete_todo()` tools.

## Collaboration (Multi-Examiner)

Each examiner works on their own SIFT workstation with a local case directory. Collaboration uses export/merge:

### Export

```bash
aiir export --file findings-alice.json
aiir export --file recent-alice.json --since 2026-02-24T00:00
```

### Merge

```bash
aiir merge --file findings-bob.json
```

Merge uses last-write-wins by `modified_at` timestamp. APPROVED findings are protected from overwrite. IDs include the examiner name (e.g., `F-alice-001`, `F-bob-003`) so they never collide.

## Audit Trail

Every tool execution is logged:

```bash
aiir audit log                       # Recent audit entries
aiir audit log --mcp forensic-mcp    # Filter by backend
aiir audit log --tool run_command    # Filter by tool
aiir audit summary                   # Counts per MCP and tool
```

Audit files are append-only JSONL in the case `audit/` directory. Each backend writes its own file. When Claude Code is the client, a PostToolUse hook additionally captures every Bash command to `audit/claude-code.jsonl`.
