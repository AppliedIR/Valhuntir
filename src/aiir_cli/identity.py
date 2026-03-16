"""Examiner identity resolution.

Always captures os_user. Explicit examiner identity resolved by priority:
1. --examiner flag (highest)
2. AIIR_EXAMINER env var
3. AIIR_ANALYST env var (deprecated alias)
4. .aiir/config.yaml examiner or analyst field
5. Falls back to OS username
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import yaml

_EXAMINER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")


def _sanitize_slug(raw: str) -> str:
    """Sanitize a raw string into a valid examiner slug.

    Lowercases, replaces invalid characters with hyphens, strips leading/trailing
    hyphens, and truncates to 20 characters.
    """
    slug = re.sub(r"[^a-z0-9-]", "-", raw.lower()).strip("-")[:20]
    if not slug:
        return "unknown"
    slug = slug.lstrip("-")
    return slug if slug else "unknown"


def get_examiner_identity(flag_override: str | None = None) -> dict:
    """Resolve examiner identity from all sources.

    Returns:
        {
            "os_user": "sansforensics",
            "examiner": "jane-doe",
            "examiner_source": "config" | "flag" | "env" | "os_user",
            # Backward-compatible aliases
            "analyst": "jane-doe",
            "analyst_source": "config" | "flag" | "env" | "os_user",
        }
    """
    os_user = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))

    def _result(examiner: str, source: str) -> dict:
        examiner = _sanitize_slug(examiner)
        if not examiner:
            # Safeguard: if the resolved value is empty, fall back to os_user
            print(
                f"Warning: empty examiner identity from source '{source}'. "
                f"Falling back to OS user '{os_user}'.",
                file=sys.stderr,
            )
            examiner = os_user
            source = "os_user"
        return {
            "os_user": os_user,
            "examiner": examiner,
            "examiner_source": source,
            # Backward-compatible aliases
            "analyst": examiner,
            "analyst_source": source,
        }

    # Priority 1: --examiner flag
    if flag_override:
        return _result(flag_override, "flag")

    # Priority 2: AIIR_EXAMINER env var
    env_examiner = os.environ.get("AIIR_EXAMINER")
    if env_examiner:
        return _result(env_examiner, "env")

    # Priority 3: AIIR_ANALYST env var (deprecated alias)
    env_analyst = os.environ.get("AIIR_ANALYST")
    if env_analyst:
        return _result(env_analyst, "env")

    # Priority 4: .aiir/config.yaml
    config_path = Path.home() / ".aiir" / "config.yaml"
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
            examiner = config.get("examiner") or config.get("analyst")
            if examiner:
                return _result(examiner, "config")
        except (OSError, yaml.YAMLError) as e:
            print(
                f"Warning: could not read identity config {config_path}: {e}",
                file=sys.stderr,
            )

    # Priority 5: OS username
    return _result(os_user, "os_user")


# Backward-compatible alias
get_analyst_identity = get_examiner_identity


def warn_if_unconfigured(identity: dict) -> None:
    """Warn if using OS username fallback."""
    if identity["examiner_source"] == "os_user":
        print(
            f"No examiner identity configured. Using OS user '{identity['os_user']}'.\n"
            f"Run 'aiir config --examiner <name>' to set your identity.\n"
            f"Tip: For audit accountability, use individual OS accounts rather than shared ones.\n",
            file=sys.stderr,
        )
