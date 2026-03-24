"""Configuration file utilities."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path


def _write_600(path: Path, content: str) -> None:
    """Write file with 0o600 permissions from creation — no world-readable window."""
    try:
        fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    except OSError as e:
        raise OSError(f"Failed to create temp file in {path.parent}: {e}") from e
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(path))
    except OSError as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise OSError(f"Failed to write config file {path}: {e}") from e
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
