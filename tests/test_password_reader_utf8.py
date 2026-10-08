"""The password reader decodes UTF-8: a non-ASCII character is one character.

It decoded each byte on its own, so "é" became two U+FFFD and Backspace
removed half of it. It now decodes as UTF-8 incrementally; Backspace removes
one code point. Driven through a real pseudo-terminal.
"""

from __future__ import annotations

import os
import pty
import signal

from vhir_cli import approval_auth


def _read(monkeypatch, typed: bytes) -> str:
    """Type `typed` once the prompt has put the terminal in raw mode (which
    discards anything typed before it), with an alarm in case it never ends."""
    master, slave = pty.openpty()
    monkeypatch.setattr(
        approval_auth, "open", lambda *a, **k: os.fdopen(slave, "r"), raising=False
    )
    real_setraw = approval_auth.tty.setraw

    def setraw(fd, *a, **k):
        real_setraw(fd, *a, **k)
        os.write(master, typed)

    monkeypatch.setattr(approval_auth.tty, "setraw", setraw)
    signal.signal(
        signal.SIGALRM, lambda *a: (_ for _ in ()).throw(TimeoutError("no Enter"))
    )
    signal.alarm(10)
    try:
        return approval_auth.getpass_prompt("Password: ")
    finally:
        signal.alarm(0)
        os.close(master)


def test_a_non_ascii_character_is_one_character(monkeypatch):
    assert _read(monkeypatch, "café\r".encode()) == "café"


def test_backspace_removes_one_code_point(monkeypatch):
    assert _read(monkeypatch, "café".encode() + b"\x7f" + "é!\r".encode()) == "café!"


def test_the_0_6_reading_is_reproduced_for_the_upgrade_only():
    assert approval_auth.legacy_decoded("café") == "caf��"
    assert approval_auth.legacy_decoded("plain") == "plain"
