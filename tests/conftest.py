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
# Operations on a path, and the argument positions that hold paths.
_EVENTS = {
    "open": (0,),
    "os.listdir": (0,),
    "os.scandir": (0,),
    "os.mkdir": (0,),
    "os.rename": (0, 1),
    "os.replace": (0, 1),
    "os.remove": (0,),
    "os.rmdir": (0,),
    "os.chmod": (0,),
    "os.chown": (0,),
    "os.utime": (0,),
    "os.truncate": (0,),
    "os.link": (0, 1),
    "os.symlink": (0, 1),
    "shutil.copyfile": (0, 1),
    "shutil.rmtree": (0,),
}
_HITS: list[str] = []


def _under_root(value) -> str | None:
    if isinstance(value, (str, bytes, os.PathLike)):
        p = os.path.abspath(os.fsdecode(value))
        if p == _ROOT or p.startswith(_ROOT + "/"):
            return p
    return None


def _audit(event, args):
    hit = None
    if event in _EVENTS:
        hit = next(
            filter(
                None, (_under_root(args[i]) for i in _EVENTS[event] if i < len(args))
            ),
            None,
        )
    elif event == "subprocess.Popen":
        # The installer and backup reach it through cp and chown.
        argv = args[1]
        argv = (
            [argv] if isinstance(argv, (str, bytes, os.PathLike)) else list(argv or ())
        )
        hit = next((os.fsdecode(a) for a in argv if _ROOT in os.fsdecode(a)), None)
    if hit:
        _HITS.append(f"{event} {hit}")
        raise PermissionError(f"test touched {hit}")


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
