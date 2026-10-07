"""Execute forensic commands with case context and audit trail.

Writes to cli-exec.jsonl using the canonical audit schema with
source="cli_exec" and audit IDs (cliexec-{examiner}-{YYYYMMDD}-{NNN}).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from vhir_cli.approval_auth import require_tty_confirmation
from vhir_cli.case_io import get_case_dir

_MCP_NAME = "cli-exec"
_EVIDENCE_PREFIX = "cliexec"
_TIMEOUT_SECONDS = 300
_READ_CHUNK = 65536
_STDOUT_HEAD_CHARS = 10000
_STDERR_HEAD_CHARS = 5000
# Characters str.splitlines() treats as line boundaries. Universal-newline
# decoding has already folded "\r\n" and "\r" into "\n" by the time we see them.
_LINE_BOUNDARIES = frozenset("\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029")


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
        exit_code, stdout, stdout_lines, stderr = _run_capture(cmd_parts, case_dir)
    except subprocess.TimeoutExpired:
        exit_code = -1
        stdout = ""
        stdout_lines = 0
        stderr = f"Command timed out ({_TIMEOUT_SECONDS}s)"
    except OSError as e:
        exit_code = -1
        stdout = ""
        stdout_lines = 0
        stderr = f"Failed to execute command: {e}"
        if e.errno == 2:
            stderr = f"Command not found: {cmd_parts[0]}"
    elapsed_ms = (time.monotonic() - start) * 1000

    # Display output
    if stdout:
        print(f"\n--- stdout ---\n{stdout}")
    if stderr:
        print(f"\n--- stderr ---\n{stderr}", file=sys.stderr)
    print(f"\nExit code: {exit_code}")

    # Write audit entry
    _log_exec(
        case_dir,
        command_str,
        purpose,
        exit_code,
        stdout_lines,
        stderr,
        examiner,
        audit_id,
        elapsed_ms,
    )
    print(f"Audit ID: {audit_id}")


class _StreamCapture(threading.Thread):
    """Drain a child pipe to EOF, keeping only a bounded head and a line count.

    Forensic tools can emit gigabytes within the timeout window; buffering all
    of it is pointless because only the head is displayed and only the line
    count reaches the audit trail.
    """

    def __init__(self, stream, head_chars: int) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._head_chars = head_chars
        self.head = ""
        self.lines = 0
        self.error: Exception | None = None

    def run(self) -> None:
        parts: list[str] = []
        kept = 0
        terminators = 0
        open_segment = False
        try:
            while True:
                chunk = self._stream.read(_READ_CHUNK)
                if not chunk:
                    break
                if kept < self._head_chars:
                    piece = chunk[: self._head_chars - kept]
                    parts.append(piece)
                    kept += len(piece)
                # len(chunk.splitlines()) counts the boundaries in the chunk
                # plus a trailing unterminated segment; carry that segment
                # across chunks so the total matches splitlines() on the whole
                # stream.
                count = len(chunk.splitlines())
                if chunk[-1] in _LINE_BOUNDARIES:
                    terminators += count
                    open_segment = False
                else:
                    terminators += count - 1
                    open_segment = True
        except Exception as e:  # decoding is strict, as it was with run()
            self.error = e
            # Keep draining so the child never blocks on a full pipe.
            try:
                while self._stream.buffer.read(_READ_CHUNK):
                    pass
            except (OSError, ValueError):
                pass
        finally:
            self.head = "".join(parts)
            self.lines = terminators + (1 if open_segment else 0)
            try:
                self._stream.close()
            except OSError:
                pass


def _run_capture(cmd_parts: list[str], case_dir: Path) -> tuple[int, str, int, str]:
    """Run a command, returning (exit_code, stdout head, stdout lines, stderr head).

    Both pipes are drained concurrently by reader threads, so neither the child
    nor this process is ever holding the full output.
    """
    proc = subprocess.Popen(
        cmd_parts,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(case_dir),
    )
    out = _StreamCapture(proc.stdout, _STDOUT_HEAD_CHARS)
    err = _StreamCapture(proc.stderr, _STDERR_HEAD_CHARS)
    out.start()
    err.start()
    deadline = time.monotonic() + _TIMEOUT_SECONDS
    try:
        proc.wait(timeout=_TIMEOUT_SECONDS)
        for cap in (out, err):
            cap.join(max(0.0, deadline - time.monotonic()))
            if cap.is_alive():
                raise subprocess.TimeoutExpired(cmd_parts, _TIMEOUT_SECONDS)
    except BaseException:
        proc.kill()
        proc.wait()
        raise
    for cap in (out, err):
        if cap.error is not None:
            raise cap.error
    return proc.returncode, out.head, out.lines, err.head


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
    stdout_lines: int,
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
    stdout_summary = f"{stdout_lines} lines"
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
