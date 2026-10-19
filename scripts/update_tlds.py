#!/usr/bin/env python3
"""Refresh the vendored IANA TLD snapshot.

    python scripts/update_tlds.py          # update in place
    python scripts/update_tlds.py --check  # exit 1 if a newer version exists

Fetches https://data.iana.org/TLD/tlds-alpha-by-domain.txt, the authoritative
list of top-level domains in the DNS root. The list is vendored rather than
fetched at runtime so that IOC extraction works offline and, more importantly,
so that re-running a report on the same case produces the same IOC list.

Uses only the standard library so it can run in CI without installing anything.
"""

from __future__ import annotations

import argparse
import sys
import urllib.request
from pathlib import Path

IANA_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
TARGET = (
    Path(__file__).resolve().parent.parent / "src" / "vhir_cli" / "data" / "tlds.txt"
)
TIMEOUT = 60


def fetch() -> str:
    req = urllib.request.Request(
        IANA_URL, headers={"User-Agent": "vhir-cli-tld-update"}
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310
        return resp.read().decode("utf-8")


def version_of(text: str) -> str:
    first = text.splitlines()[0] if text else ""
    return first.strip() if first.startswith("#") else "(unknown)"


def sanity_check(text: str) -> None:
    """Refuse to write a truncated or malformed list."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    entries = [ln for ln in lines if not ln.startswith("#")]
    if len(entries) < 1000:
        sys.exit(
            f"Refusing to write: only {len(entries)} entries, list looks truncated."
        )
    for required in ("COM", "NET", "ORG", "UK", "DE"):
        if required not in entries:
            sys.exit(f"Refusing to write: {required} missing, list looks malformed.")
    if not all(e.replace("-", "").isalnum() for e in entries):
        sys.exit("Refusing to write: non-alphanumeric entry found.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if the upstream list differs from the vendored one",
    )
    args = ap.parse_args()

    remote = fetch()
    sanity_check(remote)
    local = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""

    if remote == local:
        print(f"Up to date: {version_of(local)}")
        return 0

    if args.check:
        print(
            f"Outdated.\n  vendored: {version_of(local)}\n  upstream: {version_of(remote)}"
        )
        return 1

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(remote, encoding="utf-8")
    print(f"Updated {TARGET.relative_to(Path.cwd())}\n  to: {version_of(remote)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
