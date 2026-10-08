"""`vhir join --name` and `vhir setup join-code --name`.

A join is named after the machine's host name, normalised by the gateway;
`--name` chooses another. The join prints the name it got and the exact
`vhir enrol --name` line that enrols it for approvals. A code the box owner
binds to a name joins as that name only, and the gateway ends that name's
earlier tokens; both commands say so.
"""

from __future__ import annotations

import sys
from argparse import Namespace
from unittest.mock import MagicMock, patch

import pytest

import vhir_cli.commands.join as J


def _requests(status=200, data=None):
    mod = MagicMock()
    resp = MagicMock(status_code=status)
    resp.json.return_value = data or {}
    mod.post.return_value = resp
    mod.exceptions.ConnectionError = ConnectionError
    mod.exceptions.SSLError = type("SSLError", (Exception,), {})
    return mod


def _join(monkeypatch, data, **args):
    mod = _requests(200, data)
    monkeypatch.setattr(J, "_find_ca_cert", lambda: None)
    monkeypatch.setattr(J, "_write_config", lambda *a, **k: None)
    with patch.dict(sys.modules, {"requests": mod}):
        J.cmd_join(Namespace(sift="10.0.0.5", code="ABCD-EFGH", wintools=False,
                             ca_cert=None, skip_setup=True, **args), {})  # fmt: skip
    return mod.post.call_args.kwargs["json"]


OK = {"gateway_url": "https://10.0.0.5:4508", "backends": [], "gateway_token": "t",
      "examiner": "lab2", "bound": False, "enrol_command": "vhir enrol --name lab2"}  # fmt: skip


def test_join_sends_the_chosen_name(monkeypatch, capsys):
    body = _join(monkeypatch, OK, name="lab2")
    assert body["name"] == "lab2"
    out = capsys.readouterr().out
    assert "Joined as lab2." in out and "  vhir enrol --name lab2" in out


def test_without_name_the_gateway_names_it(monkeypatch, capsys):
    body = _join(monkeypatch, OK)
    assert "name" not in body and body["hostname"]


def test_a_bound_join_says_the_earlier_token_is_gone(monkeypatch, capsys):
    _join(monkeypatch, {**OK, "bound": True})
    assert "Joined as lab2; your earlier token for lab2 no longer works." in (
        capsys.readouterr().out
    )


def test_a_refused_name_prints_the_gateway_s_reason(monkeypatch, capsys):
    mod = _requests(409, {"code": "NAME_IN_USE", "error": "steve is already in use. …"})
    monkeypatch.setattr(J, "_find_ca_cert", lambda: None)
    with patch.dict(sys.modules, {"requests": mod}), pytest.raises(SystemExit):
        J.cmd_join(Namespace(sift="10.0.0.5", code="C", wintools=False, ca_cert=None,
                             skip_setup=True, name=None), {})  # fmt: skip
    assert "Join failed: steve is already in use." in capsys.readouterr().err


def _mint(monkeypatch, data, **args):
    mod = _requests(200, data)
    for name, value in (("_ensure_static_ip", lambda: "10.0.0.5"),
                        ("_ensure_remote_binding", lambda: None),
                        ("_get_local_gateway_url", lambda: "http://127.0.0.1:4508"),
                        ("_get_local_gateway_token", lambda: "vhir_gw_test"),
                        ("_setup_samba_share", lambda code: None)):  # fmt: skip
        monkeypatch.setattr(J, name, value)
    with patch.dict(sys.modules, {"requests": mod}):
        J.cmd_setup_join_code(Namespace(expires=2, **args), {})
    return mod.post.call_args.kwargs["json"]


def test_a_join_code_can_be_bound_to_a_name(monkeypatch, capsys):
    body = _mint(monkeypatch, {"code": "ABCD-EFGH", "expires_hours": 2, "name": "lab2"},
                 name="lab2")  # fmt: skip
    assert body == {"expires_hours": 2, "name": "lab2"}
    assert "This code joins as lab2 only, and ends lab2's earlier gateway tokens" in (
        capsys.readouterr().out
    )


def test_an_unbound_code_sends_no_name(monkeypatch, capsys):
    assert _mint(monkeypatch, {"code": "X", "expires_hours": 2}, name=None) == {
        "expires_hours": 2
    }


def test_the_parser_takes_name_on_both():
    from vhir_cli.main import build_parser

    p = build_parser()
    assert (
        p.parse_args(["join", "--sift", "x", "--code", "c", "--name", "lab2"]).name
        == "lab2"
    )
    assert p.parse_args(["setup", "join-code", "--name", "lab2"]).name == "lab2"
