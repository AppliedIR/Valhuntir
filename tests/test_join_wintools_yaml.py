"""`vhir join --wintools` needs a usable ~/.vhir/wintools.yaml.

Without one the join used to go ahead as an examiner join and print
"Joined as ...". Now it stops before any network call or config write.
"""

from __future__ import annotations

import os
import sys
from argparse import Namespace
from unittest.mock import MagicMock, patch

import pytest
import yaml

import vhir_cli.commands.join as J

OK = {"gateway_url": "https://10.0.0.5:4508", "backends": ["wintools-mcp"],
      "gateway_token": "vhir_gw_new", "examiner": "lab-wt", "bound": False,
      "wintools_registered": True}  # fmt: skip


def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    vhir = tmp_path / ".vhir"
    vhir.mkdir()
    (vhir / "config.yaml").write_text(
        "gateway_url: https://old:4508\ngateway_token: old\n"
    )
    (vhir / "gateway.yaml").write_text(
        "api_keys:\n  vhir_gw_local: {examiner: steve}\n"
    )
    return vhir


def _snapshot(vhir):
    return {n: (vhir / n).read_bytes() for n in ("config.yaml", "gateway.yaml")}


def _requests():
    """A gateway that accepts the join, so a join that goes ahead succeeds."""
    mod = MagicMock()
    resp = MagicMock(status_code=200)
    resp.json.return_value = OK
    mod.post.return_value = resp
    mod.exceptions.ConnectionError = ConnectionError
    mod.exceptions.SSLError = type("SSLError", (Exception,), {})
    return mod


def _join(monkeypatch, mod):
    monkeypatch.setattr(J, "_find_ca_cert", lambda: None)
    with patch.dict(sys.modules, {"requests": mod}):
        J.cmd_join(Namespace(sift="10.0.0.5", code="ABCD-EFGH", wintools=True,
                             ca_cert=None, skip_setup=True), {})  # fmt: skip


def _missing(vhir):
    pass


def _mode_000(vhir):
    p = vhir / "wintools.yaml"
    p.write_text("url: http://10.0.0.20:4624/mcp\ntoken: vhir_wt_x\n")
    p.chmod(0)


def _not_yaml(vhir):
    (vhir / "wintools.yaml").write_text("url: [unclosed\n")


@pytest.mark.parametrize("make", [_missing, _mode_000, _not_yaml],
                         ids=["missing", "mode-000", "invalid-yaml"])  # fmt: skip
def test_wintools_join_without_a_usable_file_is_refused(
    tmp_path, monkeypatch, capsys, make
):
    if make is _mode_000 and os.geteuid() == 0:
        pytest.skip("root reads a mode 000 file")
    vhir = _home(tmp_path, monkeypatch)
    make(vhir)
    before = _snapshot(vhir)
    mod = _requests()
    with pytest.raises(SystemExit) as e:
        _join(monkeypatch, mod)
    assert e.value.code == 1
    got = capsys.readouterr()
    assert (
        "Cannot join as wintools: ~/.vhir/wintools.yaml is missing or unreadable."
        in got.err
    )
    assert "Joined" not in got.out
    mod.post.assert_not_called()
    assert _snapshot(vhir) == before


def test_wintools_join_with_a_valid_file_goes_ahead(tmp_path, monkeypatch, capsys):
    vhir = _home(tmp_path, monkeypatch)
    (vhir / "wintools.yaml").write_text(
        yaml.dump({"url": "http://10.0.0.20:4624/mcp", "token": "vhir_wt_x"})
    )
    mod = _requests()
    _join(monkeypatch, mod)
    body = mod.post.call_args.kwargs["json"]
    assert body["machine_type"] == "wintools"
    assert (body["wintools_url"], body["wintools_token"]) == (
        "http://10.0.0.20:4624/mcp",
        "vhir_wt_x",
    )
    assert (
        yaml.safe_load((vhir / "config.yaml").read_text())["gateway_token"]
        == "vhir_gw_new"
    )
    assert "Windows wintools-mcp registered with gateway" in capsys.readouterr().out
