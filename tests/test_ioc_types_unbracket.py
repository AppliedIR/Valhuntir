"""unbracket and refang against the simple loop unbracket replaces, kept here as
the oracle: one layer of brackets off every bracketed mark a pass, until a pass
changes nothing. The corpus is seeded, so it is the same every run: every
bracket form at depths 0 to 8, closed and not, alone and inside an address, and
random strings of brackets, marks and name characters. A deep value takes
linear time."""

from __future__ import annotations

import random
import re
import time

import pytest

from vhir_cli import ioc_types


def oracle(value: str) -> str:
    """One layer of brackets off every bracketed mark a pass. A pass that
    changes the value shortens it, so the loop ends."""
    while len(n := re.sub(r"\[(\W)\]", r"\1", value)) < len(value):
        value = n
    return value


# marks unbracket takes out (\W) and forms it leaves (a name character, a word,
# the three-character scheme separator, nothing)
MARKS = [".", "@", ":", "/", "-", " ", "[", "]", "(", ")", "\u3002",
         "x", "_", "7", "dot", "://", ""]  # fmt: skip


FORMS = [
    v for mark in MARKS for opened in range(9) for closed in range(9)
    for form in ["[" * opened + mark + "]" * closed]
    for v in (form, f"user{form}evil.example.com", f"evil{form}example{form}com")
]  # fmt: skip


def _random(seed: int, count: int) -> list[str]:
    rng = random.Random(seed)
    sizes = [rng.randrange(40) for _ in range(count)]
    return ["".join(rng.choice("[].@:/(){}ax_ ") for _ in range(n)) for n in sizes]


CORPUS = FORMS + _random(20261104, 20000)


def test_unbracket_gives_what_the_loop_gives_on_every_value_of_the_corpus():
    assert [v for v in CORPUS if ioc_types.unbracket(v) != oracle(v)] == []


def test_refang_is_hxxp_made_http_then_the_loop():
    values = [*CORPUS, *(f"hxxp{v}//evil.example.com" for v in FORMS)]
    wrong = [
        v for v in values if ioc_types.refang(v) != oracle(v.replace("hxxp", "http"))
    ]
    assert wrong == []


@pytest.mark.parametrize("depth", range(9))
@pytest.mark.parametrize("mark", [".", "@", ":"])
def test_a_mark_closed_at_any_depth_comes_out_alone(mark, depth):
    assert ioc_types.unbracket(f"a{'[' * depth}{mark}{']' * depth}b") == f"a{mark}b"


def test_a_mark_64k_brackets_deep_refangs_within_a_second():
    deep = "user" + "[" * 65536 + "@" + "]" * 65536 + "evil.example.com"
    start = time.perf_counter()
    got = ioc_types.refang(deep)
    took = time.perf_counter() - start
    assert got == "user@evil.example.com"
    assert took < 1.0, f"refang took {took:.2f} s"
