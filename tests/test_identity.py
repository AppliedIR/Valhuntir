"""Tests for examiner identity resolution."""

import os
from unittest.mock import patch

from vhir_cli.identity import get_analyst_identity, get_examiner_identity


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
