"""structured_iocs keeps its 3-tuple shape, (value, network, own type), and
is built on walk_iocs's walk: the values and their order are walk_iocs's, a
value is network exactly when the walk's verdict is True (False and None,
no type speaking for it, are not), and the own type is a {"value", "type"}
dict's own type, else None."""

import pytest

from vhir_cli.defang import structured_iocs, walk_iocs

FIELDS = {
    "a {value, type} list": [
        {"value": "evil.example", "type": "domain-name"},
        {"value": "10.1.2.3", "type": "ipv4-addr"},
        {"value": "d41d8cd98f00b204e9800998ecf8427e", "type": "md5"},
    ],
    "a {type: values} dict": {"domain": ["a.example", "b.example"], "md5": "x" * 32},
    "plain strings": ["c.example", "10.9.9.9"],
    "mixed": ["d.example", {"value": "e.example", "type": "url"}, {"ip": ["10.0.0.1"]}],
    "a list-valued record": [{"value": ["f.example", "g.example"], "type": "domain"}],
    "nested lists": [[["h.example"]]],
    "case of the keys": [{"Value": "i.example", "TYPE": "domain-name"}],
}


@pytest.mark.parametrize("name", FIELDS)
def test_the_content_follows_the_walk(name):
    field = FIELDS[name]
    got = structured_iocs([{"iocs": field}])
    assert all(isinstance(t, tuple) and len(t) == 3 for t in got), got
    walked = walk_iocs(field)
    assert [(v, n) for v, n, _ in got] == [
        (v, verdict is True) for v, verdict, _ in walked
    ], (
        got,
        walked,
    )


def test_the_own_type_is_the_records_own():
    got = structured_iocs(
        [
            {
                "iocs": [
                    {"value": "evil.example", "type": "domain-name"},
                    "plain.example",
                    {"domain": ["keyed.example"]},
                ]
            }
        ]
    )
    assert got == [
        ("evil.example", True, "domain-name"),
        ("plain.example", False, None),
        ("keyed.example", True, None),
    ], got


def test_a_type_that_says_not_network_and_no_type_are_both_not_network():
    got = structured_iocs(
        [{"iocs": [{"value": "x" * 32, "type": "md5"}, {"value": "j.example"}]}]
    )
    walked = walk_iocs([{"value": "x" * 32, "type": "md5"}, {"value": "j.example"}])
    assert [verdict for _, verdict, _ in walked] == [False, None], walked
    assert got == [("x" * 32, False, "md5"), ("j.example", False, None)], got


def test_findings_with_no_iocs_field_hold_none():
    assert structured_iocs([{"id": "F-x"}, "not a record", {"iocs": None}]) == []


def test_a_value_past_the_display_depth_is_not_walked():
    deep = "k.example"
    for _ in range(9):
        deep = [deep]
    shallow = "k.example"
    for _ in range(7):
        shallow = [shallow]
    assert walk_iocs(deep) == [] and structured_iocs([{"iocs": deep}]) == []
    assert [v for v, _, _ in structured_iocs([{"iocs": shallow}])] == ["k.example"]
