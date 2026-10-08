"""One examiner-name rule, and how a joining machine's host name becomes one."""

from __future__ import annotations

import pytest

from vhir_cli.identity import join_name, valid_name


@pytest.mark.parametrize("name", ["steve", "lab-laptop", "a", "x" * 20, "w2"])
def test_valid_names(name):
    assert valid_name(name)


@pytest.mark.parametrize("name", ["", "Bad_Name", "-x", "x" * 21, "Steve", "a.b"])
def test_invalid_names(name):
    assert not valid_name(name)


@pytest.mark.parametrize(
    "raw, name",
    [
        ("Lab-Laptop.local", "lab-laptop"),
        ("Steve.local", "steve"),
        ("WKS_01", "wks-01"),
        ("--edge", "edge"),
        ("a" * 30, "a" * 20),
    ],
)
def test_a_host_name_becomes_an_examiner_name(raw, name):
    assert join_name(raw) == name and valid_name(name)
