# CLI Reference

The `aiir` CLI handles all human-only operations: case management, approval, reporting, evidence handling, and configuration. It is not callable by the AI.

## Global Options

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--case PATH` | Override active case directory (most commands) |

## Case Management

### `aiir case init`

Initialize a new case.

```bash
aiir case init "Ransomware Investigation"
aiir case init "Phishing Campaign" --description "CEO spearphish, Feb 2026"
```

| Argument/Option | Description |
|-----------------|-------------|
| `name` | Case name (required) |
| `--description` | Case description |

### `aiir case activate`

Set the active case for the session.

```bash
aiir case activate INC-2026-0225
```

### `aiir case list`

List all available cases.

```bash
aiir case list
```

### `aiir case status`

Show active case summary.

```bash
aiir case status
```

### `aiir case close`

Close a case.

```bash
aiir case close INC-2026-0225 --summary "Investigation complete, all findings approved"
```

### `aiir case reopen`

Reopen a closed case.

```bash
aiir case reopen INC-2026-0225
```

### `aiir case migrate`

Migrate a case from the legacy `examiners/` directory structure to the current flat layout.

```bash
aiir case migrate --examiner alice
aiir case migrate --import-all    # Merge all examiners' data
```

## Dashboard

### `aiir dashboard`

Open the case review dashboard in the default browser.

```bash
aiir dashboard
```

The dashboard is the primary review interface — examiners can review, edit, approve, reject, and commit findings entirely in the browser. Use the Commit button (Shift+C) to apply decisions with challenge-response authentication. Alternatively, `aiir approve --review` applies pending edits from the CLI.

## Review

### `aiir review`

Display case information, findings, timeline, evidence, and audit logs.

```bash
aiir review                              # Case summary
aiir review --findings                   # Findings table
aiir review --findings --detail          # Full finding details
aiir review --findings --status DRAFT    # Filter by status
aiir review --timeline                   # Timeline events
aiir review --timeline --type lateral    # Filter by event type
aiir review --timeline --start 2026-02-20T00:00 --end 2026-02-22T23:59
aiir review --todos                      # All TODOs
aiir review --todos --open               # Open TODOs only
aiir review --audit                      # Audit trail
aiir review --evidence                   # Evidence integrity
aiir review --iocs                       # IOCs from findings
aiir review --verify                     # Cross-check findings vs approvals + HMAC verification
aiir review --verify --mine              # HMAC verification for current examiner only
```

| Option | Description |
|--------|-------------|
| `--findings` | Show findings summary table |
| `--detail` | Show full detail (with --findings or --timeline) |
| `--timeline` | Show timeline events |
| `--todos` | Show TODO items |
| `--open` | Show only open TODOs (with --todos) |
| `--audit` | Show audit log |
| `--evidence` | Show evidence integrity |
| `--iocs` | Extract IOCs from findings grouped by status |
| `--verify` | Cross-check findings against approval records and HMAC verification ledger |
| `--mine` | Filter HMAC verification to current examiner only (with --verify) |
| `--status` | Filter by status: DRAFT, APPROVED, REJECTED |
| `--start` | Start date filter (ISO format) |
| `--end` | End date filter (ISO format) |
| `--type` | Filter by event type (with --timeline) |
| `--limit N` | Limit entries shown (default: 50) |

## Approval

### `aiir approve`

Approve staged findings and/or timeline events. Requires password confirmation.

```bash
aiir approve                                    # Interactive review
aiir approve F-alice-001 F-alice-002            # Approve specific findings
aiir approve F-alice-003 --note "Confirmed"     # With examiner note
aiir approve F-alice-004 --edit                 # Edit in $EDITOR first
aiir approve --findings-only                    # Review only findings
aiir approve --timeline-only                    # Review only timeline
aiir approve --by bob                           # Review items by examiner
aiir approve --review                           # Apply pending dashboard edits
```

| Option | Description |
|--------|-------------|
| `ids` | Finding/event IDs to approve (omit for interactive) |
| `--note` | Add examiner note |
| `--edit` | Open in $EDITOR before approving |
| `--interpretation` | Override interpretation field |
| `--by` | Filter items by creator examiner |
| `--findings-only` | Review only findings |
| `--timeline-only` | Review only timeline events |
| `--review` | Apply pending dashboard edits from `pending-reviews.json`, recompute hashes and HMAC signatures |

### `aiir reject`

Reject staged findings or timeline events.

```bash
aiir reject F-alice-004 --reason "Insufficient evidence"
aiir reject T-alice-007 --reason "Timestamp unreliable"
```

| Option | Description |
|--------|-------------|
| `ids` | Finding/event IDs to reject (required) |
| `--reason` | Reason for rejection |

## Evidence

### `aiir evidence register`

Register an evidence file (computes and records SHA-256 hash).

```bash
aiir evidence register /path/to/disk.E01 --description "Workstation image"
```

### `aiir evidence list`

List registered evidence files with hashes.

```bash
aiir evidence list
```

### `aiir evidence verify`

Re-hash registered evidence files and report any modifications.

```bash
aiir evidence verify
```

### `aiir evidence log`

Show evidence access log.

```bash
aiir evidence log
aiir evidence log --path disk.E01    # Filter by path substring
```

### `aiir evidence lock` / `aiir evidence unlock`

Set evidence directory to read-only (bind mount) or restore write access.

```bash
aiir evidence lock
aiir evidence unlock
```

Legacy aliases: `aiir lock-evidence`, `aiir unlock-evidence`, `aiir register-evidence`.

## Reporting

### `aiir report`

Generate case reports from approved data.

```bash
aiir report --full --save full-report.json
aiir report --executive-summary
aiir report --timeline --from 2026-02-20 --to 2026-02-22
aiir report --ioc
aiir report --status-brief
aiir report --findings F-alice-001,F-alice-002
```

| Option | Description |
|--------|-------------|
| `--full` | Full case report (JSON) |
| `--executive-summary` | Executive summary |
| `--timeline` | Timeline report |
| `--ioc` | IOC report from approved findings |
| `--findings IDS` | Specific finding IDs (comma-separated) |
| `--status-brief` | Quick status counts |
| `--from` | Start date filter (ISO) |
| `--to` | End date filter (ISO) |
| `--save FILE` | Save output to file (relative paths use case_dir/reports/) |

## TODOs

### `aiir todo add`

Add a TODO item.

```bash
aiir todo add "Analyze USB device history" --priority high --finding F-alice-002
aiir todo add "Cross-reference DNS logs" --assignee bob
```

### `aiir todo complete`

Mark a TODO as completed.

```bash
aiir todo complete TODO-alice-001
```

### `aiir todo update`

Update a TODO.

```bash
aiir todo update TODO-alice-001 --note "Partial analysis done, needs USB timeline"
aiir todo update TODO-alice-001 --priority high
aiir todo update TODO-alice-001 --assignee carol
```

## Audit

### `aiir audit log`

Show audit trail entries.

```bash
aiir audit log
aiir audit log --limit 20
aiir audit log --mcp forensic-mcp
aiir audit log --tool run_command
```

### `aiir audit summary`

Show audit summary with counts per MCP and tool.

```bash
aiir audit summary
```

## Collaboration

### `aiir export`

Export findings and timeline as JSON for sharing.

```bash
aiir export --file findings-alice.json
aiir export --file recent.json --since 2026-02-24T00:00
```

### `aiir merge`

Merge incoming JSON into local findings and timeline.

```bash
aiir merge --file findings-bob.json
```

## Execution

### `aiir exec`

Execute a forensic command with audit trail logging. Requires TTY confirmation.

```bash
aiir exec --purpose "Extract prefetch files" -- cp -r /mnt/evidence/prefetch/ extractions/
```

## Setup

### `aiir setup`

Routes to setup subcommands. Run `aiir setup client` to configure your LLM client.

### `aiir setup client`

Configure LLM client for AIIR endpoints.

```bash
aiir setup client                                    # Interactive wizard
aiir setup client --client=claude-code -y            # Solo, Claude Code
aiir setup client --sift=http://10.0.0.5:4508 --windows=10.0.0.10:4624
aiir setup client --remote --token=aiir_gw_...       # Remote with auth
```

| Option | Description |
|--------|-------------|
| `--client` | Target client: claude-code, claude-desktop, librechat, other |
| `--sift` | SIFT gateway URL |
| `--windows` | Windows wintools-mcp endpoint |
| `--remnux` | REMnux endpoint |
| `--examiner` | Examiner identity |
| `--no-mslearn` | Exclude Microsoft Learn MCP |
| `-y` / `--yes` | Accept defaults |
| `--remote` | Remote setup (gateway on another host) |
| `--token` | Bearer token for gateway auth |

### `aiir setup test`

Test connectivity to all detected MCP servers.

```bash
aiir setup test
```

### `aiir setup join-code`

Generate a join code for remote machines.

```bash
aiir setup join-code --expires 2
```

## Service Management

### `aiir service status`

Show status of all backend services.

```bash
aiir service status
```

### `aiir service start` / `stop` / `restart`

Manage backend services through the gateway API.

```bash
aiir service start forensic-mcp
aiir service stop opencti-mcp
aiir service restart                   # All backends
```

## Configuration

### `aiir config`

Manage AIIR settings.

```bash
aiir config --show                     # Show current config
aiir config --examiner alice           # Set examiner identity
aiir config --setup-password           # Set approval password (min 8 chars)
aiir config --reset-password           # Reset password (requires current)
```

## Join (Remote Setup)

### `aiir join`

Join a SIFT gateway from a remote machine using a join code.

```bash
aiir join --sift 10.0.0.5 --code ABC123
aiir join --sift 10.0.0.5:4508 --code ABC123 --ca-cert ca-cert.pem
```
