"""Execute forensic commands with case context and audit trail.

Writes to cli-exec.jsonl using the canonical audit schema with
source="cli_exec" and audit IDs (cliexec-{examiner}-{YYYYMMDD}-{NNN}).
"""

from __future__ import annotations

import errno
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from vhir_cli.approval_auth import require_tty_confirmation
from vhir_cli.case_io import (
    CaseFileNotRegular,
    CaseFileTooLarge,
    get_case_dir,
    kept,
    open_regular,
)
from vhir_cli.display import one_line

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

    # Nothing runs unless its audit entry can be written: the log is read as a
    # regular file only (a device or FIFO is refused unread) and opened now;
    # the entry goes through this handle
    log_file = case_dir / "audit" / f"{_MCP_NAME}.jsonl"
    try:
        if log_file.parent.is_symlink():  # the folder too: never another case's trail
            raise OSError(errno.ELOOP, "a symbolic link")
        log_file.parent.mkdir(parents=True, exist_ok=True)
        audit_id = _next_audit_id(case_dir, examiner)
        # never through a link: the entry stays in the case
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
        fd = os.open(log_file, flags, 0o644)
        audit_fh = os.fdopen(fd, "ab", buffering=0)
        if os.fstat(fd).st_nlink != 1:
            audit_fh.close()
            raise OSError(errno.EMLINK, "another name links to it")
    except OSError as e:
        print(f"Not run: vhir exec can't write this command's audit entry ({_why(log_file, e)}). "
              f"{_advice(e)}", file=sys.stderr)  # fmt: skip
        sys.exit(1)

    # Execute. Once it has started, the command is audited whatever happens:
    # output that isn't UTF-8 is kept as \x escapes, not raised on.
    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd_parts,
            shell=False,
            capture_output=True,
            text=True,
            errors="backslashreplace",
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
    except BaseException as e:  # interrupted or failed while it ran: run() killed it
        how = "interrupted" if isinstance(e, KeyboardInterrupt) else "failed"
        failed = _log_exec(audit_fh, command_str, purpose, -1, "", f"{how} ({type(e).__name__})",
                           examiner, audit_id, (time.monotonic() - start) * 1000)  # fmt: skip
        if failed:
            print(_ran_unaudited(log_file, failed), file=sys.stderr)
        raise
    elapsed_ms = (time.monotonic() - start) * 1000

    # Write audit entry, before showing the output: printing it can fail
    failed = _log_exec(
        audit_fh,
        command_str,
        purpose,
        exit_code,
        stdout,
        stderr,
        examiner,
        audit_id,
        elapsed_ms,
    )

    # Display output. A reader that stopped early (| head) never hides a
    # failed write: the warning is on stderr
    try:
        if stdout:
            print(f"\n--- stdout ---\n{stdout[:10000]}")
        if stderr:
            print(f"\n--- stderr ---\n{stderr[:5000]}", file=sys.stderr)
        print(f"\nExit code: {exit_code}")
        sys.stdout.flush()  # here, not at exit, so a closed pipe is seen now
    except BrokenPipeError:
        if not failed:
            raise
        # nothing more can reach the closed pipe, at exit either
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    if failed:  # last, and never an audit id that names no entry
        print(_ran_unaudited(log_file, failed), file=sys.stderr)
        sys.exit(1)
    print(f"Audit ID: {audit_id}")


_WRITABLE = (
    "Check that the case's disk has free space and that its audit/ folder and "
    "log are writable, then run it again."
)
_LOG_SHAPES = (
    "not a regular file",
    "a folder",
    "a symbolic link",
    "another name links to it",
)


def _advice(e: OSError) -> str:
    """For a log too large, or one that isn't the case's own regular file: it
    was left as it is (an audit log is evidence); for anything else (a
    permission, a full disk), check the folder."""
    why = e.why if isinstance(e, CaseFileNotRegular) else (
        "a symbolic link" if e.errno == errno.ELOOP else
        "another name links to it" if e.errno == errno.EMLINK else "")  # fmt: skip
    if isinstance(e, CaseFileTooLarge) or why in _LOG_SHAPES:
        return kept(why)
    return _WRITABLE


def _why(log_file: Path, e: OSError) -> str:
    why = (e.why if isinstance(e, (CaseFileNotRegular, CaseFileTooLarge)) else
           "a symbolic link" if e.errno == errno.ELOOP else e.strerror)  # fmt: skip
    return one_line(f"{log_file}: {why or type(e).__name__}")


def _ran_unaudited(log_file: Path, e: OSError) -> str:
    return (f"WARNING: the command ran, but its audit entry couldn't be written "
            f"({_why(log_file, e)}), so it is not in the case's audit trail.")  # fmt: skip


def _next_audit_id(case_dir: Path, examiner: str) -> str:
    """Generate next audit ID: cliexec-{examiner}-{date}-{seq}."""
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    audit_dir = case_dir / "audit"
    log_file = audit_dir / f"{_MCP_NAME}.jsonl"
    max_seq = 0
    if log_file.exists():
        pattern = f"{_EVIDENCE_PREFIX}-{examiner}-{today}-"
        # a regular file only, line by line with each line capped; any read
        # error refuses the run
        with open_regular(log_file) as f:
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
    return f"{_EVIDENCE_PREFIX}-{examiner}-{today}-{max_seq + 1:03d}"


def _log_exec(
    audit_fh,
    command: str,
    purpose: str,
    exit_code: int,
    stdout: str,
    stderr: str,
    examiner: str,
    audit_id: str,
    elapsed_ms: float,
) -> OSError | None:
    """Write execution record to audit trail using canonical schema, through
    the log opened before the run, and close it. Returns the error when the
    entry couldn't be written in full."""
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
    data, size = (json.dumps(entry, default=str) + "\n").encode("utf-8"), None
    with audit_fh:
        try:
            size = os.fstat(audit_fh.fileno()).st_size
            done = 0
            # a short write is a failure unless the rest follows
            while done < len(data):
                n = audit_fh.write(data[done:])
                if not n:
                    raise OSError(errno.EIO, "short write")
                done += n
            os.fsync(audit_fh.fileno())
        except OSError as e:
            # never leave a partial line for the next entry to glue onto
            if size is not None:
                os.ftruncate(audit_fh.fileno(), size)
            return e
    return None
