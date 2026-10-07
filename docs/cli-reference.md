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
vhir review --findings --verify          # Verify every signed decision (no passphrase)
vhir review --findings --verify --expect-key alice=SHA256:… --expect-head 41:…   # Anchored
vhir review --findings --verify --mine   # Show only your items
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
| `--verify` | Verify every signed decision against the case (with `--findings`). No passphrase or terminal needed. Exit 0: every approved item verifies (or was approved under 0.6), with no failure; 2: a failure; 5: a usage error. Prints every signing key with its full fingerprint and each chain's head, and "anchored" or "Not anchored" |
| `--expect-key` | `NAME=SHA256:<fingerprint>[:FROM-TO]`: a fingerprint you kept off this machine (repeatable) |
| `--expect-head` | `[CHAIN@]SEQ:HASH`: a head you kept off this machine (repeatable) |
| `--ledger` | Verify against this chain copy instead of the box's ledger and the case's copies (repeatable) |
| `--mine` | With `--verify`, show only your items (the exit code still covers the case) |
| `--status` | Filter by status: DRAFT, APPROVED, REJECTED |
| `--start` | Start date filter (ISO format) |
| `--end` | End date filter (ISO format) |
| `--type` | Filter by event type (with --timeline) |
| `--limit N` | Limit entries shown (default: 50) |

## Approval

### `vhir approve`

Approve staged findings and/or timeline events. Every item, and each item decided with it ("cascade from F-…"), is shown first; then your passphrase signs exactly those decisions. A 0.6 password is upgraded to a signing key at the first signed decision.

```bash
vhir approve                                    # Interactive review
vhir approve F-alice-001 F-alice-002            # Approve specific findings
vhir approve F-alice-003 --note "Confirmed"     # With examiner note
vhir approve F-alice-004 --edit                 # Edit in $EDITOR first
vhir approve --findings-only                    # Review only findings
vhir approve --timeline-only                    # Review only timeline
vhir approve --by bob                           # Review items by examiner
vhir approve --review                           # Sign reviews staged in the portal
vhir approve --reattest F-alice-005             # Sign a fresh approval of an item approved under 0.6
vhir approve F-alice-006 --show-signed          # Also print the full signed view
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
| `--review` | Sign the reviews staged in the Examiner Portal (`pending-reviews.json`). Your own entries are selected; another examiner's are shown and included only if you say so |
| `--reattest` | Sign a fresh approval of APPROVED items with no signed line (approved under 0.6), dated now; the original record is unchanged |
| `--show-signed` | Also print each item's full signed view |

### `vhir reject`

Reject findings or timeline events (an APPROVED one too). A rejection is signed like an approval.

```bash
vhir reject F-alice-004 --reason "Insufficient evidence"
vhir reject T-alice-007 --reason "Timestamp unreliable"
```

| Option | Description |
|--------|-------------|
| `ids` | Finding/event IDs to reject (required) |
| `--reason` | Reason for rejection |
| `--review` | Walk through DRAFT items interactively |

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

Exits 0 only when every registered file verifies: 2 when any file was modified, 1 when any is missing or can't be read.

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
vhir backup /path/to/destination --include-opensearch # Include OpenSearch indices
vhir backup /path/to/destination --all               # Everything (evidence + extractions + OpenSearch)
vhir backup --verify /path/to/backup/INC-2026-0225/  # Verify backup integrity
```

| Argument/Option | Description |
|-----------------|-------------|
| `destination` | Backup destination directory |
| `--include-evidence` | Include evidence files |
| `--include-extractions` | Include extraction files |
| `--include-opensearch` | Include OpenSearch index snapshot (local Docker only) |
| `--all` | Include evidence + extractions + OpenSearch (if available) |
| `--verify BACKUP_PATH` | Verify an existing backup's integrity |

Creates a timestamped directory with all case metadata, findings, timeline, audit trails, and a `backup-manifest.json` with SHA-256 hashes. The case's copies of its signed history (`ledger/`: its chains, its 0.6 records and the public signing keys) are written first and carried; no passphrase verifier or signing-key file is. The printout lists every signing key with its full fingerprint and each chain's head. The `--verify` option re-hashes every file and reports mismatches or missing files.

### `vhir restore`

Restore a case from a backup directory, into a folder you confirm.

```bash
vhir restore /path/to/backup/INC-2026-0411-2026-04-13   # Full restore
vhir restore /path/to/backup/... --skip-opensearch       # Skip OpenSearch index restore
vhir restore /path/to/backup/... --skip-ledger           # Skip restoring the 0.6 approval records
vhir restore /path/to/backup/... --target /cases/INC-1   # Restore here, without asking
```

| Argument/Option | Description |
|-----------------|-------------|
| `backup_path` | Path to backup directory (contains backup-manifest.json) |
| `--skip-opensearch` | Skip OpenSearch index restore |
| `--skip-ledger` | Skip restoring the case's 0.6 approval records to this box |
| `--target DIR` | Restore into `DIR` instead of being asked. Required without a terminal |

Restore asks `Restore case <id> to [<folder it was backed up from>]:`; Enter accepts that folder, or type another path. Without a terminal (scripts, agents), `--target` is required and restore refuses without it. If the folder holds an interrupted restore (`.restore-in-progress`), restore names it and asks before removing it, defaulting to no; without a terminal it refuses, and you remove the folder yourself. An existing folder without that marker is never overwritten. If the folder can't be created (permission denied), prints exact `mkdir`/`chown` commands to fix it. Never auto-activates the case — prints activation instructions after restore. No credential is restored: each signing key the case's chains hold that this box doesn't is added as a retired public key ("KEY ADDED"), so the case verifies here; a chain of another case is refused. Examiners enrol on this box with `vhir config --setup-password`.

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
vhir setup join-code --name lab2   # A code that joins as lab2 only, ending lab2's earlier gateway tokens
```

A code bound with `--name` lets a LAN examiner re-join under their own name; their passphrase, signing key and ledger lines are unchanged. It can't take the box owner's own name.

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
vhir service stop threatintel-mcp
vhir service restart                   # All backends
```

## Configuration

### `vhir config`

Manage Valhuntir settings.

```bash
vhir config --show                     # Show current config
vhir config --examiner alice           # Set examiner identity
vhir config --setup-password           # Passphrase and signing key (at least 8 characters; 15+ recommended)
vhir config --reset-password           # Change the passphrase (same key, requires the current one)
vhir config --forgot-password          # New key under a new passphrase; the old key is kept as retired
vhir config --upgrade-key              # Signing key for a 0.6 password (prints the fingerprint if you have one)
```

## Join (Remote Setup)

### `vhir join`

Join a SIFT gateway from a remote machine using a join code.

```bash
vhir join --sift 10.0.0.5 --code ABC123
vhir join --sift 10.0.0.5:4508 --code ABC123 --ca-cert ca-cert.pem
vhir join --sift 10.0.0.5 --code ABC123 --name lab2   # Join under a chosen examiner name
```

The gateway names the joining examiner after this machine's host name (lower case, the part before the first dot, at most 20 characters), or `--name`. A name another token or an enrolled examiner already holds is refused. The join prints the name it got and the command to enrol it for approvals, which the person named runs once at the SIFT terminal:

```bash
vhir enrol --name lab2              # Passphrase and signing key for lab2 (at least 8 characters; 15+ recommended)
vhir enrol --name lab2 --reset      # Change lab2's passphrase
vhir enrol --name lab2 --forgot     # New key for lab2; the old one is kept as retired
vhir enrol --name lab2 --upgrade    # Signing key for lab2's 0.6 password
```
