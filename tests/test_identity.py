"""Tests for examiner identity resolution."""

import os
from unittest.mock import patch

import pytest
import yaml

from vhir_cli.identity import (
    _sanitize_slug,
    get_analyst_identity,
    get_examiner_identity,
)


def test_flag_override_takes_priority():
    identity = get_examiner_identity(flag_override="analyst1")
    assert identity["examiner"] == "analyst1"
    assert identity["examiner_source"] == "flag"
    assert "os_user" in identity
    # Backward compatibility
    assert identity["analyst"] == "analyst1"
    assert identity["analyst_source"] == "flag"


def test_env_var_second_priority():
    with patch.dict(os.environ, {"VHIR_EXAMINER": "env_examiner"}):
        identity = get_examiner_identity()
        # _sanitize_slug replaces underscores with hyphens
        assert identity["examiner"] == "env-examiner"
        assert identity["examiner_source"] == "env"


def test_deprecated_env_var():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("VHIR_EXAMINER", None)
        os.environ["VHIR_ANALYST"] = "env_analyst"
        try:
            identity = get_examiner_identity()
            # _sanitize_slug replaces underscores with hyphens
            assert identity["examiner"] == "env-analyst"
            assert identity["examiner_source"] == "env"
        finally:
            os.environ.pop("VHIR_ANALYST", None)


def test_os_user_fallback():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("VHIR_EXAMINER", None)
        os.environ.pop("VHIR_ANALYST", None)
        identity = get_examiner_identity()
        assert (
            identity["examiner_source"] == "os_user"
            or identity["examiner_source"] == "config"
        )
        assert identity["os_user"] == os.environ.get(
            "USER", os.environ.get("USERNAME", "unknown")
        )


def test_backward_compatible_alias():
    """get_analyst_identity is an alias for get_examiner_identity."""
    identity = get_analyst_identity(flag_override="test")
    assert identity["examiner"] == "test"
    assert identity["analyst"] == "test"


@pytest.fixture
def clean(tmp_path, monkeypatch):
    """No examiner from the environment or a config; the OS user is alice."""
    for key in ("VHIR_EXAMINER", "VHIR_ANALYST", "USERNAME"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("USER", "alice")
    monkeypatch.setattr("vhir_cli.identity.Path.home", lambda: tmp_path)
    return tmp_path


def _config(home, examiner):
    (home / ".vhir").mkdir()
    (home / ".vhir" / "config.yaml").write_text(yaml.dump({"examiner": examiner}))


@pytest.mark.parametrize("raw", ["!!!", "---", "_", " ", "@@ ##", "\u00e9\u00e9"])
@pytest.mark.parametrize("source", ["flag", "env", "config"])
def test_a_name_with_nothing_usable_warns_and_falls_back_to_the_os_user(
    clean, capsys, raw, source
):
    if source == "env":
        os.environ["VHIR_EXAMINER"] = raw
    if source == "config":
        _config(clean, raw)
    identity = get_examiner_identity(raw if source == "flag" else None)
    assert identity["examiner"] == identity["analyst"] == "alice"
    assert identity["examiner_source"] == identity["analyst_source"] == "os_user"
    assert capsys.readouterr().err == (
        f"Warning: empty examiner identity from source '{source}'. "
        "Falling back to OS user 'alice'.\n"
    )


@pytest.mark.parametrize(
    "raw, want",
    [
        ("jane-doe", "jane-doe"),
        ("Jane_Doe", "jane-doe"),
        ("-x-", "x"),
        ("a" * 25, "a" * 20),
    ],
)
def test_a_usable_name_is_kept_without_a_warning(clean, capsys, raw, want):
    identity = get_examiner_identity(raw)
    assert (identity["examiner"], identity["examiner_source"]) == (want, "flag")
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("raw", ["", "!", "---", "_-_", "\u00e9"])
def test_the_slug_of_nothing_usable_is_empty(raw):
    assert _sanitize_slug(raw) == ""


def test_the_fallback_os_user_is_made_a_name_too(clean, monkeypatch, capsys):
    monkeypatch.setenv("USER", "Bob.Smith")
    identity = get_examiner_identity("!!!")
    assert (identity["examiner"], identity["os_user"]) == ("bob-smith", "Bob.Smith")
    assert "Falling back to OS user 'Bob.Smith'." in capsys.readouterr().err


def test_an_os_user_with_nothing_usable_is_the_last_unknown(clean, monkeypatch, capsys):
    # Only when the OS user's own name has no letter or digit left
    monkeypatch.setenv("USER", "___")
    identity = get_examiner_identity("!!!")
    assert (identity["examiner"], identity["examiner_source"]) == ("unknown", "os_user")
    err = capsys.readouterr().err
    assert "from source 'flag'" in err and "OS user '___'" in err


def test_with_no_name_anywhere_the_os_user_is_used_without_the_warning(clean, capsys):
    identity = get_examiner_identity()
    assert (identity["examiner"], identity["examiner_source"]) == ("alice", "os_user")
    assert capsys.readouterr().err == ""


def test_an_os_user_with_nothing_usable_and_no_name_says_so(clean, monkeypatch, capsys):
    monkeypatch.setenv("USER", "___")
    identity = get_examiner_identity()
    assert (identity["examiner"], identity["examiner_source"]) == ("unknown", "os_user")
    assert capsys.readouterr().err == (
        "Warning: empty examiner identity from source 'os_user'. "
        "Falling back to OS user '___'.\n"
    )
