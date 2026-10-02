"""Tests never touch /var/lib/vhir, which holds the real verification
ledgers and approval passwords.

Every module-level path into it points at a temporary directory for each
test, and the two that are built inside functions are skipped. A guard
records any access under /var/lib/vhir anyway: it refuses the access and
fails the test, even where the code under test swallows the OSError.
"""

from __future__ import annotations

import os
import sys

import pytest

_ROOT = "/var/lib/vhir"
_EVENTS = {
    "open",
    "os.listdir",
    "os.scandir",
    "os.mkdir",
    "os.rename",
    "os.replace",
    "os.remove",
    "os.rmdir",
    "os.chmod",
    "shutil.copyfile",
    "shutil.rmtree",
}
_HITS: list[str] = []


def _audit(event, args):
    if event not in _EVENTS:
        return
    for a in args:
        if isinstance(a, (str, bytes, os.PathLike)):
            p = os.path.abspath(os.fsdecode(a))
            if p == _ROOT or p.startswith(_ROOT + "/"):
                _HITS.append(f"{event} {p}")
                raise PermissionError(f"test touched {p}")


sys.addaudithook(_audit)


@pytest.fixture(autouse=True)
def _forbid_var_lib_vhir():
    n = len(_HITS)
    yield
    assert _HITS[n:] == [], f"test touched {_ROOT}: {_HITS[n:]}"


@pytest.fixture(autouse=True)
def _isolate_var_lib_vhir(tmp_path_factory, monkeypatch):
    from vhir_cli import approval_auth, verification
    from vhir_cli.commands import backup, update

    root = tmp_path_factory.mktemp("var_lib_vhir")
    for mod, name, sub in (
        (verification, "VERIFICATION_DIR", "verification"),
        (approval_auth, "_PASSWORDS_DIR", "passwords"),
        (backup, "VERIFICATION_DIR", "verification"),  # imported by name
        (backup, "_PASSWORDS_DIR", "passwords"),
        (backup, "_SNAPSHOTS_DIR", "snapshots"),
    ):
        monkeypatch.setattr(mod, name, root / sub)
    # Built inside functions: the legacy pins/ migration and update's check.
    monkeypatch.setattr(approval_auth, "_maybe_migrate_pin_dir", lambda: None)
    monkeypatch.setattr(update, "_ensure_password_dir", lambda: None)
