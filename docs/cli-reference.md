# CLI Reference

The `vhir` CLI handles all human-only operations: case management, approval, reporting, evidence handling, and configuration. It is not callable by the AI.

## Global Options

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--case PATH` | Override active case directory (most commands) |

## Case Management

### `vhir case init`

Initialize a new case. Run with no arguments for interactive mode.

```bash
vhir case init                                           # Interactive — prompts for name, ID, directory
vhir case init "Ransomware Investigation"                # Create with auto-generated ID
vhir case init "Investigation" --case-id INC-2026-001    # Create with custom case ID
vhir case init "Phishing Campaign" --description "CEO spearphish, Feb 2026"
```

| Argument/Option | Description |
|-----------------|-------------|
| `name` | Case name (optional — interactive prompts if omitted on TTY) |
| `--case-id` | Override auto-generated case ID |
| `--description` | Case description |

### `vhir case activate`

Set the active case for the session.

```bash
vhir case activate INC-2026-0225
```

### `vhir case list`

List all available cases.

```bash
vhir case list
```

### `vhir case status`

Show active case summary.

```bash
vhir case status
```

### `vhir case close`

Close a case.

```bash
vhir case close INC-2026-0225 --summary "Investigation complete, all findings approved"
```

### `vhir case reopen`

Reopen a closed case.

```bash
vhir case reopen INC-2026-0225
```

### `vhir case migrate`

Migrate a case from the legacy `examiners/` directory structure to the current flat layout.

```bash
vhir case migrate --examiner alice
vhir case migrate --import-all    # Merge all examiners' data
```

## Examiner Portal

### `vhir portal`

Open the Examiner Portal in the default browser.

```bash
vhir portal
```

The portal is the primary review interface — examiners can review, edit, approve, reject, and commit findings entirely in the browser. Use the Commit button (Shift+C) to apply decisions with challenge-response authentication. Alternatively, `vhir approve --review` applies pending edits from the CLI.

## Review

### `vhir review`

Display case information, findings, timeline, evidence, and audit logs.

```bash
vhir review                              # Case summary
vhir review --findings                   # Findings table
vhir review --findings --detail          # Full finding details
vhir review --findings --status DRAFT    # Filter by status
vhir review --timeline                   # Timeline events
vhir review --timeline --type lateral    # Filter by event type
vhir review --timeline --start 2026-02-20T00:00 --end 2026-02-22T23:59
vhir review --todos                      # All TODOs
vhir review --todos --open               # Open TODOs only
vhir review --audit                      # Audit trail
vhir review --evidence                   # Evidence integrity
vhir review --iocs                       # IOCs from findings
vhir review --verify                     # Cross-check findings vs approvals + HMAC verification
vhir review --verify --mine              # HMAC verification for current examiner only
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

### `vhir approve`

Approve staged findings and/or timeline events. Requires password confirmation.

```bash
vhir approve                                    # Interactive review
vhir approve F-alice-001 F-alice-002            # Approve specific findings
vhir approve F-alice-003 --note "Confirmed"     # With examiner note
vhir approve F-alice-004 --edit                 # Edit in $EDITOR first
vhir approve --findings-only                    # Review only findings
vhir approve --timeline-only                    # Review only timeline
vhir approve --by bob                           # Review items by examiner
vhir approve --review                           # Apply pending portal edits
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
| `--review` | Apply pending portal edits from `pending-reviews.json`, recompute hashes and HMAC signatures |

### `vhir reject`

Reject staged findings or timeline events.

```bash
vhir reject F-alice-004 --reason "Insufficient evidence"
vhir reject T-alice-007 --reason "Timestamp unreliable"
```

| Option | Description |
|--------|-------------|
| `ids` | Finding/event IDs to reject (required) |
| `--reason` | Reason for rejection |

## Evidence

### `vhir evidence register`

Register an evidence file (computes and records SHA-256 hash).

```bash
vhir evidence register /path/to/disk.E01 --description "Workstation image"
```

### `vhir evidence list`

List registered evidence files with hashes.

```bash
vhir evidence list
```

### `vhir evidence verify`

Re-hash registered evidence files and report any modifications.

```bash
vhir evidence verify
```

### `vhir evidence log`

Show evidence access log.

```bash
vhir evidence log
vhir evidence log --path disk.E01    # Filter by path substring
```

### `vhir evidence lock` / `vhir evidence unlock`

Set evidence directory to read-only (bind mount) or restore write access.

```bash
vhir evidence lock
vhir evidence unlock
```

Legacy aliases: `vhir lock-evidence`, `vhir unlock-evidence`, `vhir register-evidence`.

## Reporting

### `vhir report`

Generate case reports from approved data.

```bash
vhir report --full --save full-report.json
vhir report --executive-summary
vhir report --timeline --from 2026-02-20 --to 2026-02-22
vhir report --ioc
vhir report --status-brief
vhir report --findings F-alice-001,F-alice-002
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

### `vhir todo add`

Add a TODO item.

```bash
vhir todo add "Analyze USB device history" --priority high --finding F-alice-002
vhir todo add "Cross-reference DNS logs" --assignee bob
```

### `vhir todo complete`

Mark a TODO as completed.

```bash
vhir todo complete TODO-alice-001
```

### `vhir todo update`

Update a TODO.

```bash
vhir todo update TODO-alice-001 --note "Partial analysis done, needs USB timeline"
vhir todo update TODO-alice-001 --priority high
vhir todo update TODO-alice-001 --assignee carol
```

## Audit

### `vhir audit log`

Show audit trail entries.

```bash
vhir audit log
vhir audit log --limit 20
vhir audit log --mcp forensic-mcp
vhir audit log --tool run_command
```

### `vhir audit summary`

Show audit summary with counts per MCP and tool.

```bash
vhir audit summary
```

## Collaboration

### `vhir export`

Export findings and timeline as JSON for sharing.

```bash
vhir export --file findings-alice.json
vhir export --file recent.json --since 2026-02-24T00:00
```

### `vhir merge`

Merge incoming JSON into local findings and timeline.

```bash
vhir merge --file findings-bob.json
```

## Backup

### `vhir backup`

Back up case data for archival, legal preservation, or disaster recovery.

```bash
vhir backup /path/to/destination                     # Case data only (interactive)
vhir backup /path/to/destination --include-evidence   # Include evidence files
vhir backup /path/to/destination --include-extractions # Include extractions
vhir backup /path/to/destination --all               # Everything
vhir backup --verify /path/to/backup/INC-2026-0225/  # Verify backup integrity
```

| Argument/Option | Description |
|-----------------|-------------|
| `destination` | Backup destination directory |
| `--include-evidence` | Include evidence files |
| `--include-extractions` | Include extraction files |
| `--all` | Include evidence + extractions |
| `--verify BACKUP_PATH` | Verify an existing backup's integrity |

Creates a timestamped directory with all case metadata, findings, timeline, audit trails, and a `backup-manifest.json` with SHA-256 hashes. The `--verify` option re-hashes every file and reports mismatches or missing files.

## Execution

### `vhir exec`

Execute a forensic command with audit trail logging. Requires TTY confirmation.

```bash
vhir exec --purpose "Extract prefetch files" -- cp -r /mnt/evidence/prefetch/ extractions/
```

## Setup

### `vhir setup`

Routes to setup subcommands. Run `vhir setup client` to configure your LLM client.

### `vhir setup client`

Configure LLM client for Valhuntir endpoints.

```bash
vhir setup client                                    # Interactive wizard
vhir setup client --client=claude-code -y            # Solo, Claude Code
vhir setup client --sift=http://10.0.0.5:4508 --windows=10.0.0.10:4624
vhir setup client --remote --token=vhir_gw_...       # Remote with auth
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

### `vhir setup test`

Test connectivity to all detected MCP servers.

```bash
vhir setup test
```

### `vhir setup join-code`

Generate a join code for remote machines.

```bash
vhir setup join-code --expires 2
```

## Service Management

### `vhir service status`

Show status of all backend services.

```bash
vhir service status
```

### `vhir service start` / `stop` / `restart`

Manage backend services through the gateway API.

```bash
vhir service start forensic-mcp
vhir service stop opencti-mcp
vhir service restart                   # All backends
```

## Configuration

### `vhir config`

Manage Valhuntir settings.

```bash
vhir config --show                     # Show current config
vhir config --examiner alice           # Set examiner identity
vhir config --setup-password           # Set approval password (min 8 chars)
vhir config --reset-password           # Reset password (requires current)
```

## Join (Remote Setup)

### `vhir join`

Join a SIFT gateway from a remote machine using a join code.

```bash
vhir join --sift 10.0.0.5 --code ABC123
vhir join --sift 10.0.0.5:4508 --code ABC123 --ca-cert ca-cert.pem
```
