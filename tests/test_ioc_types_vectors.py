"""ioc_types against the vectors file, which sift-mcp holds too, byte for byte:
the module hashes to the file's SHA-256 and gives every case's output, each
written into the file as a literal value."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from vhir_cli import ioc_types

VECTORS = json.loads(Path(__file__).with_name("ioc_types_vectors.json").read_text())


def test_the_module_hashes_to_the_vectors_file():
    module = Path(ioc_types.__file__).read_bytes()
    assert hashlib.sha256(module).hexdigest() == VECTORS["module_sha256"]


@pytest.mark.parametrize(("given", "want"), VECTORS["canonical"])
def test_canonical(given, want):
    assert ioc_types.canonical(given) == want


@pytest.mark.parametrize(("given", "want"), VECTORS["label"])
def test_label(given, want):
    assert ioc_types.label(given) == want


@pytest.mark.parametrize(("value", "given", "want"), VECTORS["ck"])
def test_ck(value, given, want):
    assert ioc_types.ck(value, given) == want


@pytest.mark.parametrize(("value", "want"), VECTORS["vk"])
def test_vk(value, want):
    assert ioc_types.vk(value) == want


@pytest.mark.parametrize(("value", "want"), VECTORS["rk"])
def test_rk(value, want):
    assert ioc_types.rk(value) == want


@pytest.mark.parametrize(("a", "b", "want"), VECTORS["same"])
def test_same(a, b, want):
    assert ioc_types.same(tuple(a), tuple(b)) is want
    assert ioc_types.same(tuple(b), tuple(a)) is want
