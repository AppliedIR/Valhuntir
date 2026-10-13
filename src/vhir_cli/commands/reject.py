"""Reject findings, timeline events and IOCs: a mode of the approve paths.

Every rejection is a signed decision, made through the same order as an
approval: the items (and the cascades they bring) are shown first, and the
password comes last. `vhir reject` accepts DRAFT and APPROVED findings and
timeline events, and IOCs; `--review` walks the DRAFT items with
reject / skip / quit.
"""

from __future__ import annotations

import sys
from pathlib import Path

from vhir_cli.case_io import get_case_dir, refuse_without_terminal
from vhir_cli.commands.approve import (
    _REJECT_CHOICES,
    _approve_specific,
    _interactive_review,
)


def cmd_reject(args, identity: dict) -> None:
    """Reject specific findings/timeline events/IOCs, or review DRAFT items."""
    case_dir = get_case_dir(getattr(args, "case", None))
    refuse_without_terminal(case_dir, identity["examiner"], "reject", args.ids)
    config_path = Path.home() / ".vhir" / "config.yaml"
    show_signed = getattr(args, "show_signed", False)

    review = getattr(args, "review", False)
    if review and args.ids:
        print("Error: --review cannot be used with specific IDs.", file=sys.stderr)
        sys.exit(1)
    if review:
        _interactive_review(
            case_dir,
            identity,
            config_path,
            choices=_REJECT_CHOICES,
            show_signed=show_signed,
        )
        return
    if not args.ids:
        print(
            "Error: provide IDs to reject, or use --review for interactive mode.",
            file=sys.stderr,
        )
        sys.exit(1)
    _approve_specific(
        case_dir,
        args.ids,
        identity,
        config_path,
        decision="reject",
        reason=getattr(args, "reason", "") or "",
        show_signed=show_signed,
    )
