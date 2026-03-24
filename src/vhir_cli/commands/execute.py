"""Execute forensic commands with case context and audit trail.

Writes to cli-exec.jsonl using the canonical audit schema with
source="cli_exec" and audit IDs (cliexec-{examiner}-{YYYYMMDD}-{NNN}).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from vhir_cli.approval_auth import require_tty_confirmation
from vhir_cli.case_io import get_case_dir

_MCP_NAME = "cli-exec"
_EVIDENCE_PREFIX = "cliexec"


def cmd_exec(args, identity: dict) -> None:
    """Execute a forensic command with audit logging."""
    case_dir = get_case_dir(getattr(args, "case", None))

    if not args.cmd:
        print(
            'No command provided. Usage: vhir exec --purpose "reason" -- <command> [args...]',
            file=sys.stderr,
        )
        sys.exit(1)

    # Strip leading '--' if present
    cmd_parts = args.cmd
    if cmd_parts and cmd_parts[0] == "--":
        cmd_parts = cmd_parts[1:]

    if not cmd_parts:
        print("No command specified after '--'.", file=sys.stderr)
        sys.exit(1)

    command_str = " ".join(cmd_parts)
    purpose = args.purpose
    examiner = identity.get("examiner", identity.get("analyst", ""))

    # Confirm execution via /dev/tty (blocks AI-via-Bash from piping "y")
    print(f"Case: {case_dir.name}")
    print(f"Purpose: {purpose}")
    print(f"Command: {command_str}")
    if not require_tty_confirmation("Execute? [y/N]: "):
        print("Cancelled.")
        return

    # Pre-allocate evidence ID
    audit_id = _next_audit_id(case_dir, examiner)

    # Execute
    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd_parts,
            shell=False,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(case_dir),
        )
        exit_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except subprocess.TimeoutExpired:
        exit_code = -1
        stdout = ""
        stderr = "Command timed out (300s)"
    except OSError as e:
        exit_code = -1
        stdout = ""
        stderr = f"Failed to execute command: {e}"
        if e.errno == 2:
            stderr = f"Command not found: {cmd_parts[0]}"
    elapsed_ms = (time.monotonic() - start) * 1000

    # Display output
    if stdout:
        print(f"\n--- stdout ---\n{stdout[:10000]}")
    if stderr:
        print(f"\n--- stderr ---\n{stderr[:5000]}", file=sys.stderr)
    print(f"\nExit code: {exit_code}")

    # Write audit entry
    _log_exec(
        case_dir,
        command_str,
        purpose,
        exit_code,
        stdout,
        stderr,
        examiner,
        audit_id,
        elapsed_ms,
    )
    print(f"Audit ID: {audit_id}")


def _next_audit_id(case_dir: Path, examiner: str) -> str:
    """Generate next audit ID: cliexec-{examiner}-{date}-{seq}."""
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    audit_dir = case_dir / "audit"
    log_file = audit_dir / f"{_MCP_NAME}.jsonl"
    max_seq = 0
    if log_file.exists():
        pattern = f"{_EVIDENCE_PREFIX}-{examiner}-{today}-"
        try:
            with open(log_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        eid = entry.get("audit_id", "")
                        if eid.startswith(pattern):
                            try:
                                seq = int(eid[len(pattern) :])
                                max_seq = max(max_seq, seq)
                            except ValueError:
                                pass
                    except json.JSONDecodeError:
                        continue
        except OSError as e:
            import logging

            logging.debug("Could not read audit log for sequence: %s", e)
    return f"{_EVIDENCE_PREFIX}-{examiner}-{today}-{max_seq + 1:03d}"


def _log_exec(
    case_dir: Path,
    command: str,
    purpose: str,
    exit_code: int,
    stdout: str,
    stderr: str,
    examiner: str,
    audit_id: str,
    elapsed_ms: float,
) -> None:
    """Write execution record to audit trail using canonical schema."""
    audit_dir = case_dir / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    log_file = audit_dir / f"{_MCP_NAME}.jsonl"

    # Summarize output for audit (not full stdout/stderr)
    stdout_summary = f"{len(stdout.splitlines())} lines"
    if exit_code != 0 and stderr:
        stdout_summary += f"; stderr: {stderr[:200]}"

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "mcp": _MCP_NAME,
        "tool": "exec",
        "audit_id": audit_id,
        "examiner": examiner,
        "case_id": os.environ.get("VHIR_ACTIVE_CASE", ""),
        "source": "cli_exec",
        "params": {"command": command, "purpose": purpose},
        "result_summary": {"exit_code": exit_code, "output": stdout_summary},
        "elapsed_ms": round(elapsed_ms, 1),
    }
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        print(f"WARNING: Failed to write exec audit log: {log_file}", file=sys.stderr)
