"""A case's identity (`case_uuid` in CASE.yaml), and one folder per identity.

The identity is minted in one place, sift-common's `ensure_case_uuid`, which
also creates the case's host logs. vhir calls it when sift-common is
installed (on a SIFT workstation); without it, nothing is minted here and the
minter runs at the case's first activation or ingest on a SIFT box.

`~/.vhir/case-paths.json` maps each identity to the folder that holds it.
A second folder with the same identity (a copy made with `cp -r`) is
refused at activation: both would write into the same indices. The copy
gets its own identity with `vhir case new-identity`.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import uuid
from pathlib import Path

import yaml

from vhir_cli.case_io import _atomic_write


def host_identity():
    """sift-common's host_identity module, or None without the sift stack (or
    with a sift-common from before case identities)."""
    if importlib.util.find_spec("sift_common") is None:
        return None
    try:
        from sift_common import host_identity as module
    except ImportError:
        return None
    if not hasattr(module, "update_case_meta"):
        return None
    return module


def case_uuid(case_dir: Path) -> str:
    """The case's UUID from CASE.yaml, or "" when it has none."""
    try:
        meta = yaml.safe_load((Path(case_dir) / "CASE.yaml").read_text()) or {}
    except (OSError, yaml.YAMLError):
        return ""
    raw = (
        str(meta.get("case_uuid") or "").strip().lower()
        if isinstance(meta, dict)
        else ""
    )
    return raw if len(raw.replace("-", "")) == 32 else ""


def ensure_identity(case_dir: Path, naming_version: int = 1) -> None:
    """Mint the case's identity if it has none (sift-common only).

    A case whose CASE.yaml has lost its UUID while its host logs record one
    is refused, with the UUID to restore (ValueError).
    """
    module = host_identity()
    if module is None:
        return
    try:
        module.ensure_case_uuid(case_dir, naming_version=naming_version)
    except module.HostLogError as e:
        raise ValueError(str(e)) from None


def _paths_file() -> Path:
    return Path.home() / ".vhir" / "case-paths.json"


@contextlib.contextmanager
def _paths_lock():
    import fcntl

    lock = _paths_file().with_name("case-paths.lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _read_paths() -> dict:
    """The recorded folders; refused, never read as empty, when the file
    can't be read: overwriting it would drop every record and the copy check."""
    path = _paths_file()
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        raise ValueError(
            f"{path} can't be read ({e}). It records which folder holds each "
            "case; fix or move it aside, then try again."
        ) from None
    if not isinstance(data, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in data.items()
    ):
        raise ValueError(
            f"{path} isn't a map of case identities to folders; fix or move it "
            "aside, then try again."
        )
    return data


def _holds(folder: str, identity: str) -> bool:
    """True when `folder` is a case whose CASE.yaml has `identity`."""
    return Path(folder).is_dir() and case_uuid(Path(folder)) == identity


def copy_of(case_dir: Path) -> str:
    """Why this folder can't sign as the case: another recorded folder still
    holds its identity (a copy made with `cp -r`), or "". `record_case_path`'s
    check, read-only (no record is written); an unreadable record is left to
    activation to report."""
    identity = case_uuid(case_dir)
    if not identity:
        return ""
    try:
        recorded = _read_paths().get(identity)
    except ValueError as e:  # never fail open: which folder is the original is unknown
        return str(e)
    here = str(Path(case_dir).resolve())
    if recorded and recorded != here and _holds(recorded, identity):
        return copy_text(here, recorded, identity)
    return ""


def copy_text(here: str, recorded: str, identity: str) -> str:
    """The refusal for a folder whose identity another folder holds on this
    box, and the way back when this folder is in fact the original (a copy
    signed or was activated first)."""
    return (
        f"{here} is a copy of the case in {recorded}: both have case identity "
        f"{identity}. Sign in {recorded}. If {here} is the original (the copy "
        f"signed or was activated first): move {recorded} aside, sign in or "
        f"activate {here}, then move the copy back and run `vhir case "
        "new-identity` on the copy, never on the original. Decisions the copy "
        "signed show as UNSIGNED_STATUS in the original; approve those ids again "
        "in the original."
    )


def record_case_path(case_dir: Path) -> None:
    """Record the case's folder for its identity, refusing a second folder.

    The folder recorded before stays the identity's while it still holds it;
    a renamed or removed original gives way to this folder.
    """
    identity = case_uuid(case_dir)
    if not identity:
        return
    here = str(Path(case_dir).resolve())
    with _paths_lock():
        paths = _read_paths()
        recorded = paths.get(identity)
        if recorded and recorded != here and _holds(recorded, identity):
            raise ValueError(
                f"{here} is a copy of the case in {recorded}: both have case "
                f"identity {identity}, so both would write into the same indices. "
                f"Activate {recorded}, or give the copy its own identity with "
                f"`vhir case new-identity {Path(here).name}`."
            )
        if recorded != here:
            paths[identity] = here
            _atomic_write(_paths_file(), json.dumps(paths, indent=2, sort_keys=True))


def new_identity(case_dir: Path) -> str:
    """Give a copied case its own identity; returns the new UUID.

    Only a copy can take one: another folder must hold, and be recorded for,
    the same identity. The original keeps its identity, since its stored
    records are named after it. The copy carries no legacy alias.
    """
    module = host_identity()
    if module is None:
        raise ValueError(
            "vhir case new-identity needs the SIFT workstation's sift-common "
            "package (the case's host logs record its identity)."
        )
    case_dir = Path(case_dir)
    old = case_uuid(case_dir)
    if not old:
        raise ValueError(f"{case_dir} has no case_uuid to replace.")
    here = str(case_dir.resolve())
    recorded = _read_paths().get(old)
    if not recorded or recorded == here or not _holds(recorded, old):
        raise ValueError(
            f"{here} holds case identity {old} and no other folder does, so it "
            "isn't a copy. A new identity would leave its stored records "
            "under the old one."
        )
    new = str(uuid.uuid4())
    c12 = new.replace("-", "")[:12]
    try:
        with module.case_lock(case_dir, shared=False):
            # One write of both keys, before the logs learn the new identity:
            # whatever happens after it, the copy no longer reads the
            # original's older indices.
            module.update_case_meta(
                case_dir, {"case_uuid": new, "legacy_alias": "none"}
            )
            module.write_case_header(
                case_dir, c12, f"new identity for a copy of {old}", case_uuid=new
            )
    except module.CaseLockBusy as e:
        raise ValueError(
            f"{case_dir} is in use ({e}); try again when it's idle."
        ) from None
    record_case_path(case_dir)
    return new
