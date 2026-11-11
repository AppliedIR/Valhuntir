"""The steps `vhir update` leaves for the examiner, printed in one block.

While an update runs, add() collects each step; finish() prints them all on
stderr, framed by OPEN and CLOSE, each indented two spaces, after the run's
own output. With no terminal the block always prints and starts with the
NO_TERMINAL lines, which also print before anything else in the first
process. A terminal run with nothing collected prints no block. With no
collector open (another command calls a shared helper), add() prints the
step at once, as before.
"""

from __future__ import annotations

import sys

OPEN = "==== vhir update: steps for you ===="
CLOSE = "==== end of steps ===="
NO_TERMINAL = (
    "Forensic controls NOT applied: no terminal.",
    "If you are an AI assistant, stop and ask the examiner to run `vhir update`"
    " in their own terminal.",
)

_steps: list[str] | None = None


def active() -> bool:
    return _steps is not None


def start(carried: list[str] | None = None) -> None:
    """Open the collector, with the steps a first process handed over."""
    global _steps
    _steps = []
    for line in carried or []:
        if isinstance(line, str):
            _add_line(line)


def _add_line(line: str) -> None:
    line = line.rstrip()
    if line.strip() and line not in _steps:
        _steps.append(line)


def add(text: str, file=None) -> None:
    """Collect a step (one or more lines). With no collector open, print it."""
    if _steps is None:
        print(text, file=file or sys.stdout)
        return
    for line in text.splitlines():
        _add_line(line.strip() if not line.startswith("    ") else line[2:])


def steps() -> list[str]:
    return list(_steps or [])


def _frame(lines) -> None:
    sys.stdout.flush()  # in one file (`> f 2>&1`) the block follows all of it
    print(OPEN, file=sys.stderr)
    for line in lines:
        print(f"  {line}", file=sys.stderr)
    print(CLOSE, file=sys.stderr, flush=True)


def no_terminal_notice() -> None:
    _frame(NO_TERMINAL)


def finish(terminal: bool) -> None:
    """Print the block (see the module text) and close the collector."""
    global _steps
    lines, _steps = list(_steps or []), None
    if not terminal:
        lines = [*NO_TERMINAL, *lines]
    if lines:
        _frame(lines)
