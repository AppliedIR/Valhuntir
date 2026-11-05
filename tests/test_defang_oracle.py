"""defang_iocs writes what the function it replaced wrote, byte for byte, with
less work: a regex is compiled and run only for an IOC whose fold occurs in
the text's fold, and only where it occurs. The replaced function is frozen
below twice, as vhir-cli and as report-mcp each held it, and both run beside
it on traps, an adversarial report and generated texts. The fold that picks
where to look is checked against every pair of characters re.I treats as
equal on the running interpreter, so it never misses an occurrence. The same
file is in vhir-cli's tests and in sift-mcp's."""

from __future__ import annotations

import _sre
import random
import re

import pytest

# isort: split
from vhir_cli.defang import _folded, defang_iocs

# The two copies as they were before report-mcp called vhir-cli's: same
# regexes, same functions. Each runs in its own namespace, never the live one.
FROZEN_VHIR = r"""
import re

_IPV4 = re.compile(
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
)
_URL = re.compile(r"(?i)(https?)://([^/\s:?#]+)(\S*)")


def _defanged(text: str) -> str:
    m = _URL.fullmatch(text)
    if m:
        scheme = m.group(1)
        scheme = scheme[0] + ("XX" if scheme[1:3].isupper() else "xx") + scheme[3:]
        return f"{scheme}://{m.group(2).replace('.', '[.]')}{m.group(3)}"
    return text.replace(".", "[.]")


def defang_iocs(text: str, iocs: list[str]) -> str:
    def one(m: re.Match, name: bool) -> str:
        s, i = m.string, m.start()
        if name and i and s[i - 1] in "/\\" and (i < 2 or s[i - 2] not in "/\\:"):
            return m.group(0)  # a path component, not a host
        return _defanged(m.group(0))

    for v in iocs:
        name = not (_URL.fullmatch(v) or _IPV4.fullmatch(v))
        whole = re.compile(r"(?<![\w.-])" + re.escape(v) + r"(?![\w-]|\.[\w-])", re.I)
        text = whole.sub(lambda m, name=name: one(m, name), text)
    return text
"""
FROZEN_REPORT = r"""
import re

_IPV4 = re.compile(
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
)
_URL = re.compile(r"(?i)(https?)://([^/\s:?#]+)(\S*)")


def _defanged(text: str) -> str:
    m = _URL.fullmatch(text)
    if m:
        scheme = m.group(1)
        scheme = scheme[0] + ("XX" if scheme[1:3].isupper() else "xx") + scheme[3:]
        return f"{scheme}://{m.group(2).replace('.', '[.]')}{m.group(3)}"
    return text.replace(".", "[.]")


def _defang_iocs(text: str, iocs: list[str]) -> str:
    def one(m: re.Match, name: bool) -> str:
        s, i = m.string, m.start()
        if name and i and s[i - 1] in "/\\" and (i < 2 or s[i - 2] not in "/\\:"):
            return m.group(0)  # a path component, not a host
        return _defanged(m.group(0))

    for v in iocs:
        name = not (_URL.fullmatch(v) or _IPV4.fullmatch(v))
        whole = re.compile(r"(?<![\w.-])" + re.escape(v) + r"(?![\w-]|\.[\w-])", re.I)
        text = whole.sub(lambda m, name=name: one(m, name), text)
    return text
"""


def _load(src, name):
    ns: dict = {}
    exec(compile(src, f"<frozen {name}>", "exec"), ns)
    return ns[name]


frozen_vhir = _load(FROZEN_VHIR, "defang_iocs")
frozen_report = _load(FROZEN_REPORT, "_defang_iocs")


def _same(text, iocs):
    want = frozen_vhir(text, iocs)
    assert frozen_report(text, iocs) == want
    return defang_iocs(text, iocs) == want


DOTTED_I, DOTLESS_I, LONG_S, KELVIN = "\u0130", "\u0131", "\u017f", "\u212a"

TRAPS = [
    # each IOC runs on what the ones before it left: a URL holding other IOCs
    ("GET http://1.2.3.4/a?ip=5.6.7.8 then 1.2.3.4 and 5.6.7.8",
     ["http://1.2.3.4/a?ip=5.6.7.8", "1.2.3.4", "5.6.7.8"]),
    ("see http://a.com/r?u=http://b.com/x now",
     ["http://a.com/r?u=http://b.com/x", "http://b.com/x", "b.com", "a.com"]),
    # a defang that makes a later match: a URL right before a dot of a longer
    # domain, a host ending in .http before ://, a URL holding hxxp
    ("http://x/?a=evil.verylongdomain.com", ["evil.verylongdomain.com", "http://x/?a=evil"]),
    ("http://x/?a=evil.verylongdomain.com", ["http://x/?a=evil", "evil.verylongdomain.com"]),
    ("http://a.http://x.y/", ["http://a.http://x.y/", "http://x.y/"]),
    ("http://x.com/?a=http://evil.com/aaaaaaaaaaa",
     ["http://evil.com/aaaaaaaaaaa", "http://x.com/?a=hxxp"]),
    ("http://a/http://a/http://a", ["http://a/http://a"]),
    # a match inside a token
    ("1.2.3.4..abc 1.2.3.4.abc 1.2.3.4. 1.2.3.4", ["1.2.3.4"]),
    # case: U+0130 lowers to two characters; the dotless i, long s, Kelvin sign
    (f"EV{DOTTED_I}L.COM ev{DOTTED_I}l.com x{DOTTED_I} evil.com", ["evil.com", "evi\u0307l.com"]),
    (f"{DOTTED_I * 3} evil.com {DOTTED_I}evil.com", ["evil.com"]),
    (f"ev{DOTLESS_I}l.com evil{LONG_S}ite.com {KELVIN}ali.org EV{DOTTED_I}L.COM",
     ["evil.com", "evilsite.com", "kali.org"]),
    ("\u03a3\u0391\u03a3.com \u03c3\u03b1\u03c2.com \u03c3\u03b1\u03c3.com", ["\u03c3\u03b1\u03c3.com"]),
    ("HTTP://EVIL.COM/X and Http://evil.com/x", ["http://evil.com/x"]),
    ("Evil.com evil.com EVIL.COM", ["Evil.com", "evil.com"]),
    # path components and hosts
    ("/evil.com \\evil.com //evil.com \\/evil.com :/evil.com x/evil.com http://evil.com",
     ["evil.com"]),
    ("evil.com. and evil.com.. and https://evil.com./x and evil.com.x",
     ["evil.com", "https://evil.com./x"]),
    ("Beacon to evil.com, EVIL.COM, notevil.com, sub.evil.com, evil.com.au, evil[.]com; "
     "185.220.101.45 and 185.220.101.450; http://bad.example.com/x.php",
     ["http://bad.example.com/x.php", "185.220.101.45", "evil.com"]),
    # one occurrence right where the one before it ends
    (" ?a.b??a.b? and ?a.b?", ["?a.b?"]),
    ("x", [""]),
    ("", ["a.com"]),
]  # fmt: skip

META = r"https://sub.example-evil.com/p?q=1+2*(x)[y]$&z=a.b|c^d{2}\e"
META2 = r"http://meta.example.com/a.b*c+d?e=(f)|g[h]{i}^$\\"
ADVERSARIAL_IOCS = sorted(
    {"example-evil.com", "sub.example-evil.com", "a.sub.example-evil.com", "10.1.2.3",
     "10.1.2.30", "10.1.2.0", "http://10.1.2.3:8080/x", META, META2,
     "HTTP://Sub.Example-Evil.COM/Case", "Example-Evil.com", "multi.example.org",
     "192.168.7.7", "http://refanged.example.net/a", "trailing.example.com",
     "only-record.example.com", "x.example.com", "172.16.0.9"},
    key=lambda v: (-len(v), v),
)  # fmt: skip
ADVERSARIAL = "\n".join([
    "# Adversarial defang set", "",
    "example-evil.com", "sub.example-evil.com", "a.sub.example-evil.com",
    "notsub.example-evil.com and example-evil.com.au and sub.example-evil.community and my-example-evil.com",
    "EXAMPLE-EVIL.COM, Example-Evil.com; Sub.Example-Evil.COM.",
    "At line end: example-evil.com",
    "At line end with a dot: sub.example-evil.com.",
    r"Paths: /example-evil.com and C:\example-evil.com and //example-evil.com and \\example-evil.com\share and "
    "http://example-evil.com/ and /\\example-evil.com",
    "IPs: 10.1.2.3 10.1.2.30 110.1.2.3 10.1.2.3.4 10.1.2.3/24 10.1.2.0/24 10.1.2.0 10a1b2c3 10.1.2.300",
    "URLs: http://10.1.2.3:8080/x http://10.1.2.3:8080/xy " + META,
    "Case URL: HTTP://Sub.Example-Evil.COM/Case and http://sub.example-evil.com/case",
    "Metachar URL: " + META2 + " end",
    "Regex-dot decoys: subXexample-evil.com multi-example.org multiXexample.org 192x168x7x7",
    "Multi-type: multi.example.org 192.168.7.7 172.16.0.9 plain.example.net",
    "Refanged: http://refanged.example.net/a hxxp://refanged[.]example[.]net/a refanged.example.net",
    "Trailing dot: trailing.example.com. trailing.example.com",
    "Only in records: only-record.example.com 10.9.9.9 x.example.com file.exe",
    "Markdown: [link](https://sub.example-evil.com/p) `10.1.2.3` **example-evil.com**",
    "CRLF line: sub.example-evil.com\r",
    "Tab\tsub.example-evil.com\t10.1.2.3",
    "Already defanged: sub[.]example-evil[.]com hxxp://10[.]1[.]2[.]3:8080/x",
    "Last: 10.1.2.3",
])  # fmt: skip


@pytest.mark.parametrize("text,iocs", TRAPS)
def test_each_trap_is_written_as_the_frozen_function_wrote_it(text, iocs):
    assert _same(text, iocs)


def test_the_adversarial_report_is_written_as_the_frozen_function_wrote_it():
    assert _same(ADVERSARIAL, ADVERSARIAL_IOCS)
    # and line by line, as the block's lines were
    for line in ADVERSARIAL.split("\n"):
        assert _same(line, ADVERSARIAL_IOCS)


CASE_FORMS = {"i": "iI" + DOTTED_I + DOTLESS_I, "s": "sS" + LONG_S, "k": "kK" + KELVIN}
NOISE = list("abceikst.-/\\:?=&#_ []()*+$^|{}\t") + [
    "\n",
    "\r\n",
    "\u00e9",
    "\u03a3",
    "\u03c2",
]


def _label(rng):
    return "".join(rng.choice("abceikstx") for _ in range(rng.randint(1, 4)))


def _ioc(rng):
    k = rng.random()
    domain = ".".join(_label(rng) for _ in range(rng.randint(2, 3)))
    if k < 0.35:
        return domain
    if k < 0.6:
        return ".".join(str(rng.randint(0, 255)) for _ in range(4))
    host = domain if k < 0.8 else ".".join(str(rng.randint(0, 255)) for _ in range(4))
    path = "".join(
        rng.choice("abc/?=.:-\\*+()[]$|^{}") for _ in range(rng.randint(0, 8))
    )
    return rng.choice(["http", "https", "HTTP", "hxxp"]) + "://" + host + path


def _variant(rng, v):
    return "".join(
        rng.choice(CASE_FORMS.get(c, c + c.upper())) if rng.random() < 0.3 else c
        for c in v
    )


def _text(rng, pool):
    out = []
    for _ in range(rng.randint(5, 30)):
        if rng.random() < 0.5:
            v, r = rng.choice(pool), rng.random()
            if r < 0.3:
                v = _variant(rng, v)
            elif r < 0.4:
                v = v.replace(".", "[.]").replace("http", "hxxp")
            elif r < 0.5:
                v = rng.choice(["/", "\\", "//", "\\\\", ":/", "x"]) + v
            out.append(v)
        else:
            out.append("".join(rng.choice(NOISE) for _ in range(rng.randint(0, 5))))
    return "".join(out)


def test_generated_texts_are_written_as_the_frozen_function_wrote_them():
    rng = random.Random(20261105)
    differ = []
    for n in range(10_000):
        pool = [_ioc(rng) for _ in range(rng.randint(1, 6))]
        pool += [p[2:] for p in pool if "." in p[2:] and rng.random() < 0.4]
        pool += [p.split("://")[1].split("/")[0] for p in pool if "://" in p]
        pool += [
            p.split(".", 1)[1] for p in pool if p.count(".") > 1 and rng.random() < 0.3
        ]
        iocs = sorted(set(pool), key=lambda v: (-len(v), v))
        text = _text(rng, pool)
        if not _same(text, iocs):
            differ.append((n, text, iocs))
    assert differ == []


def _code_points():
    return [chr(n) for n in range(0x110000) if not 0xD800 <= n <= 0xDFFF]


def test_the_fold_is_as_long_as_the_text_and_folds_each_character_alone():
    chars = _code_points()
    folded = _folded("".join(chars))
    assert len(folded) == len(chars)
    assert all(f == _folded(c) for f, c in zip(folded, chars, strict=True))
    # capital sigma is folded alone too, never as a final sigma
    assert _folded("\u0391\u03a3 \u03a3") == "".join(
        map(_folded, "\u0391\u03a3 \u03a3")
    )


def test_every_pair_re_i_treats_as_equal_has_one_fold():
    """sre compiles a pattern character it doesn't count as cased to an exact
    literal, so only cased characters match another. A text character matches
    a cased one only if sre lowers it to that one's lowering or to one of its
    extra cases, all cased themselves, so every such text character is cased
    by some str case method or is what one of those methods gives a cased
    character. The pairs are taken from re itself over those characters."""
    chars = _code_points()
    methods = (str.lower, str.upper, str.casefold, str.title)
    cased = [c for c in chars if any(f(c) != c for f in methods)]
    assert {c for c in chars if _sre.unicode_iscased(ord(c))} <= set(cased)
    partners = set(cased)
    for c in cased:
        partners.update(r for f in methods[:3] if len(r := f(c)) == 1)
        partners.add(chr(_sre.unicode_tolower(ord(c))))
    partners = "".join(sorted(partners))
    pairs, missed = 0, []
    for c in cased:
        for m in re.compile(re.escape(c), re.I).finditer(partners):
            if m.group(0) != c:
                pairs += 1
                if _folded(m.group(0)) != _folded(c):
                    missed.append((hex(ord(c)), hex(ord(m.group(0)))))
    assert pairs > 1000 and missed == []
    # every match of a sample over all of Unicode is one of those partners
    sample = cased[::97] + list(
        "iIsSkK" + DOTTED_I + DOTLESS_I + LONG_S + KELVIN + "\u03a3\u00b5"
    )
    everything = "".join(chars)
    for c in sample:
        for m in re.compile(re.escape(c), re.I).finditer(everything):
            assert m.group(0) in partners or m.group(0) == c


@pytest.fixture
def compiles(monkeypatch):
    """How many patterns sre compiles, re's cache emptied first."""
    compiler = getattr(re, "_compiler", None) or re.sre_compile
    count, real = [0], compiler.compile

    def counted(*args, **kwargs):
        count[0] += 1
        return real(*args, **kwargs)

    re.purge()
    monkeypatch.setattr(compiler, "compile", counted)
    return count


def test_an_ioc_absent_from_the_text_is_not_compiled_or_run(compiles):
    text = "Beacon to evil.com from 10.1.2.3; notbad.example.org stays"
    absent = [f"host{n}.example.net" for n in range(200)] + [
        "10.9.9.9",
        "http://x.org/a",
    ]
    assert defang_iocs(text, absent) == text
    assert compiles[0] == 0


def test_a_save_compiles_at_most_one_pattern_per_ioc_it_finds(compiles):
    iocs = [f"host{n}.example.net" for n in range(600)]
    iocs += ["evil.com", "10.1.2.3", "bad.example.org"]  # the last only inside a name
    text = "\n".join(["Beacon to EVIL.com from 10.1.2.3; notbad.example.org"] * 2000)
    want = frozen_vhir(text, iocs)
    re.purge()
    compiles[0] = 0
    assert defang_iocs(text, iocs) == want
    assert compiles[0] == 3
