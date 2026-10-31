"""The IOC types a record can hold: one entry per id, with its category, its
label and the other spellings that mean it. A spelling folds (trimmed, lower
case, without spaces, "_" and "-") to one id, or to none. Stdlib only."""

from __future__ import annotations

import re

# id: (category, label, the other spellings that mean it, space-separated)
IDS = {
    "url": ("network", "URL", ""),
    "url:path": ("network", "URL path", "url_path uri-path uri-stem cs-uri-stem"),
    "email-addr": (
        "network",
        "Email",
        "email email-src email-dst target-email email-address email-reply-to",
    ),
    "email-message:subject": ("network", "Email subject", "email-subject"),
    "email-message:message-id": (
        "network",
        "Message ID",
        "email-message-id message-id",
    ),
    "ipv4-addr": (
        "network",
        "IPv4",
        "ipv4 ip ip-src ip-dst ip-address ipv4-address src-ip dst-ip source-ip destination-ip dest-ip ip4",
    ),
    "ipv6-addr": ("network", "IPv6", "ipv6 ipv6-address ip6"),
    "domain-name": ("network", "Domain", "domain fqdn"),
    "hostname": (
        "network",
        "Hostname",
        "target-machine computer-name computer machine-name netbios-name workstation",
    ),
    "user-agent": ("network", "User agent", "http-user-agent"),
    "mac-addr": ("network", "MAC address", "mac mac-address"),
    "ja3": ("network", "JA3", "ja3-fingerprint ja3-fingerprint-md5"),
    "ja3s": ("network", "JA3S", "ja3s-fingerprint ja3s-fingerprint-md5"),
    "ja4": ("network", "JA4", "ja4-fingerprint"),
    "jarm": ("network", "JARM", "jarm-fingerprint"),
    "hassh": ("network", "HASSH", "hassh-md5"),
    "hassh-server": ("network", "HASSH server", "hasshserver-md5"),
    "x509-certificate:hash": (
        "network",
        "Certificate fingerprint",
        "x509-fingerprint x509-fingerprint-sha1 x509-fingerprint-sha256 x509-fingerprint-md5 certificate-fingerprint cert-thumbprint thumbprint",
    ),
    "cryptocurrency-wallet": (
        "network",
        "Crypto wallet",
        "bitcoin-address btc xmr crypto-wallet wallet",
    ),
    "file:hash:sha256": ("host", "SHA256", "sha256"),
    "file:hash:sha1": ("host", "SHA1", "sha1"),
    "file:hash:md5": ("host", "MD5", "md5"),
    "file:hash:sha512": ("host", "SHA512", "sha512"),
    "file:hash:imphash": ("host", "Imphash", "imphash import-hash"),
    "file:hash:ssdeep": ("host", "SSDEEP", "ssdeep"),
    "file:hash:tlsh": ("host", "TLSH", "tlsh"),
    "file:name": ("host", "File name", "filename process-name"),
    "file:path": ("host", "File", "file-path file unc-path directory full-path folder"),
    "registry-key": (
        "system",
        "Registry key",
        "windows-registry-key regkey registry registry-path",
    ),
    "scheduled-task": (
        "system",
        "Scheduled task",
        "windows-scheduled-task task schtask",
    ),
    "process:command-line": ("system", "Command line", "command-line cmdline command"),
    "service-name": (
        "system",
        "Service name",
        "windows-service-name svc windows-service",
    ),
    "mutex": ("system", "Mutex", "mutant mutex-name"),
    "named-pipe": ("system", "Named pipe", "pipe pipe-name"),
    "windows-sid": ("identity", "Windows SID", "security-identifier"),
    "user-account": (
        "identity",
        "Account",
        "account target-user user username logon-name",
    ),
    "unknown": ("unknown", "Unknown", "other"),
}


def _fold(t: str) -> str:
    return re.sub(r"[\s_-]", "", t.strip().lower())


CATEGORY = {i: c for i, (c, _, _) in IDS.items()}
_BY_FOLD = {_fold(s): i for i, (_, _, more) in IDS.items() for s in [i, *more.split()]}


def canonical(t) -> str | None:
    """The id a type means; None for a spelling the table doesn't hold or a
    type that is not text."""
    return _BY_FOLD.get(_fold(t)) if isinstance(t, str) else None


def label(t) -> str:
    """The label of the id a type means; otherwise the type as text."""
    i = canonical(t)
    return IDS[i][1] if i else str(t)


def untyped(t) -> bool:
    """A type read as left out: empty, false or only whitespace."""
    return not t or (isinstance(t, str) and not t.strip())


def listing() -> str:
    """The ids by category, each with what it holds."""
    groups: dict[str, list[str]] = {}
    for i, (c, lb, _) in IDS.items():
        groups.setdefault(c, []).append(f"{i} ({lb})")
    return "; ".join(f"{c}: {', '.join(ids)}" for c, ids in groups.items())


def refang(value: str) -> str:
    """Refang a defanged value as record_finding does before storing it."""
    v = value.replace("[.]", ".").replace("hxxp", "http")
    return re.sub(r"\[(\W)\]", r"\1", v)


def is_ipv4(value: str) -> bool:
    """One IPv4 address, with at most one trailing port or prefix."""
    stripped = re.sub(r"[:/]\d{1,5}$", "", value.strip())
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", stripped):
        return False
    return all(0 <= int(o) <= 255 for o in stripped.split("."))


def normalize(value: str) -> str:
    """An IOC value as record_finding compares two of them."""
    v = value.strip()
    if re.match(r"^[a-fA-F0-9]{32,64}$", v):
        return v.lower()
    if "." in v and not v.replace(".", "").isdigit():
        return v.lower().rstrip(".")
    if "\\" in v:
        return v.lower()
    return v


_QUAD = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def ck(value, t=None) -> str:
    """The key of a value under its type: refanged, and an IPv4 address
    without its :port when it is typed ipv4-addr exactly or not typed, or when
    a dotted quad remains."""
    x = refang(str(value).strip())
    i = "ipv4-addr" if untyped(t) and is_ipv4(x) else canonical(t)
    bare = re.sub(r":\d{1,5}$", "", x)
    if i == "ipv4-addr" and (untyped(t) or t == "ipv4-addr" or _QUAD.match(bare)):
        x = bare
    return normalize(x)


def vk(value) -> str:
    """The key of a value refanged."""
    return normalize(refang(str(value).strip()))


def rk(value) -> str:
    """The key of a value as written."""
    return normalize(str(value).strip())


def keys(value, t=None) -> set[str]:
    """The keys a value and its type are matched on."""
    return {ck(value, t), vk(value), rk(value)}


def same(a, b) -> bool:
    """Whether two (value, type) pairs are one IOC: they share a key."""
    return bool(keys(*a) & keys(*b))


def components(pairs: list) -> list[list]:
    """The (value, type) pairs grouped by same(), directly or through other
    pairs; each group in the order given."""
    up = list(range(len(pairs)))

    def top(n: int) -> int:
        while up[n] != n:
            up[n] = n = up[up[n]]
        return n

    first: dict[str, int] = {}
    for n, p in enumerate(pairs):
        for k in keys(*p):
            up[top(first.setdefault(k, n))] = top(n)
    groups: dict[int, list] = {}
    for n, p in enumerate(pairs):
        groups.setdefault(top(n), []).append(p)
    return list(groups.values())
