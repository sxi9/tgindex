"""Entity extraction with validation.

Writing the regexes is a day's work; killing the false positives is the rest
of the week. Every type that *can* be checksum-validated is.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from .crypto_validate import b58check, bech32_valid, eip55_ok, iban_ok, luhn_ok

DATA = Path(__file__).parent / "data"


@lru_cache(maxsize=1)
def tlds() -> frozenset[str]:
    try:
        return frozenset(
            line.strip().lower()
            for line in (DATA / "tlds.txt").read_text().splitlines()
            if line.strip() and not line.startswith("#")
        )
    except OSError:
        return frozenset(
            "com org net io ru de uk fr cn jp br in ir info biz co me tv cc xyz "
            "online site top app dev gov edu mil int pro club shop live vip".split()
        )


@dataclass(frozen=True)
class Entity:
    type: str
    value: str       # as it appeared
    norm: str        # canonical form used for pivots and watchlist matching

    def __hash__(self):
        return hash((self.type, self.norm))


RX = {
    "url":     re.compile(r"\bhttps?://[^\s<>\"'\]\[)]{4,2000}", re.I),
    "onion":   re.compile(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b", re.I),
    "email":   re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@([A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})+)\b"),
    "domain":  re.compile(r"\b((?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})\b"),
    "ipv4":    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "ipv6":    re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"),
    "btc":     re.compile(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,87})\b"),
    "eth":     re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "trx":     re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b"),
    "xmr":     re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    "cve":     re.compile(r"\bCVE[-‐‑]\d{4}[-‐‑]\d{4,7}\b", re.I),
    "md5":     re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1":    re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256":  re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "handle":  re.compile(r"(?<![\w/])@([A-Za-z][A-Za-z0-9_]{4,31})\b"),
    "hashtag": re.compile(r"(?<![\w&])#([A-Za-zЀ-ӿ؀-ۿ][\wЀ-ӿ؀-ۿ]{1,48})\b"),
    "card":    re.compile(r"(?<![\d.\-])(?:\d[ \-]?){12,18}\d(?![\d.\-])"),
    "iban":    re.compile(r"\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b"),
    "phone":   re.compile(r"(?<![\w.])\+\d{1,3}[\s().\-]?\d{2,4}(?:[\s().\-]?\d{2,4}){1,4}(?![\w.])"),
    "btc_tx":  re.compile(r"\b(?:tx|txid|hash)[:= ]+([a-fA-F0-9]{64})\b", re.I),
}

_TME_HOSTS = {"t.me", "telegram.me", "telegram.dog", "telesco.pe"}
_TME_RESERVED = {
    "s", "c", "joinchat", "addstickers", "share", "proxy", "socks", "iv",
    "setlanguage", "addtheme", "login", "bg", "invoice", "addemoji", "boost", "nft",
}
TME_RX = re.compile(r"(?:https?://)?(?:t\.me|telegram\.me|telegram\.dog)/(?:s/)?([A-Za-z0-9_]{4,32})\b", re.I)


# Real TLDs that are overwhelmingly filenames in the wild. Only trusted
# when seen as a URL host, never from bare text.
AMBIGUOUS_TLDS = {"zip", "mov"}


def _is_domain(host: str) -> bool:
    host = host.rstrip(".").lower()
    if len(host) > 253 or "." not in host:
        return False
    tld = host.rsplit(".", 1)[-1]
    if tld not in tlds():
        return False
    return all(0 < len(lbl) <= 63 and not lbl.startswith("-") and not lbl.endswith("-")
               for lbl in host.split("."))


def _public_ip(raw: str) -> bool:
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_reserved
                or ip.is_link_local or ip.is_multicast or ip.is_unspecified)


def _plausible_card(digits: str) -> bool:
    if not (13 <= len(digits) <= 19) or len(set(digits)) <= 1:
        return False
    if digits[0] not in "3456":          # Amex/Visa/MC/Discover IINs
        return False
    return luhn_ok(digits)


def extract(text: str, *, extra_urls: Iterable[str] = ()) -> set[Entity]:
    """Return validated entities. Unvalidatable types are dropped, not guessed."""
    if not text and not extra_urls:
        return set()
    text = text or ""
    found: set[Entity] = set()
    add = lambda t, v, n: found.add(Entity(t, v, n))

    urls = [m.group(0).rstrip(".,;:!?)»”") for m in RX["url"].finditer(text)]
    urls += [u for u in extra_urls if u]
    hosts: set[str] = set()
    for u in urls:
        add("url", u, u.lower())
        try:
            host = (urlparse(u).hostname or "").lower()
        except ValueError:
            continue
        if host:
            hosts.add(host)

    for m in RX["onion"].finditer(text):
        add("onion", m.group(0), m.group(0).lower())

    email_domains = set()
    for m in RX["email"].finditer(text):
        if _is_domain(m.group(1)):
            add("email", m.group(0), m.group(0).lower())
            email_domains.add(m.group(1).lower())

    tme_users = set()
    for m in TME_RX.finditer(text):
        name = m.group(1).lower()
        if name not in _TME_RESERVED:
            tme_users.add(name)
    for u in urls:
        for m in TME_RX.finditer(u):
            name = m.group(1).lower()
            if name not in _TME_RESERVED:
                tme_users.add(name)
    for name in tme_users:
        add("tme_channel", name, name)

    for host in hosts | email_domains:
        if host.endswith(".onion"):
            continue
        if _is_domain(host) and host not in _TME_HOSTS:
            add("domain", host, host)
    for m in RX["domain"].finditer(text):
        host = m.group(1).lower().rstrip(".")
        if host.endswith(".onion") or host in _TME_HOSTS:
            continue
        if host.rsplit(".", 1)[-1] in AMBIGUOUS_TLDS and host not in hosts:
            continue
        if _is_domain(host):
            add("domain", m.group(1), host)

    for key in ("ipv4", "ipv6"):
        for m in RX[key].finditer(text):
            if _public_ip(m.group(0)):
                add("ip", m.group(0), m.group(0).lower())

    for m in RX["btc"].finditer(text):
        v = m.group(1)
        if v.lower().startswith("bc1"):
            if bech32_valid(v):
                add("btc", v, v.lower())
        elif b58check(v):
            add("btc", v, v)

    for m in RX["eth"].finditer(text):
        if eip55_ok(m.group(0)):
            add("eth", m.group(0), m.group(0).lower())

    for m in RX["trx"].finditer(text):
        if b58check(m.group(0)):
            add("trx", m.group(0), m.group(0))

    for m in RX["xmr"].finditer(text):
        add("xmr", m.group(0), m.group(0))

    for m in RX["cve"].finditer(text):
        norm = re.sub(r"[‐‑]", "-", m.group(0)).upper()
        add("cve", m.group(0), norm)

    eth_bodies = {m.group(0)[2:].lower() for m in RX["eth"].finditer(text)}
    for key, length in (("md5", 32), ("sha1", 40), ("sha256", 64)):
        for m in RX[key].finditer(text):
            v = m.group(0).lower()
            if len(v) != length or v in eth_bodies or v.isdigit():
                continue
            add("filehash", m.group(0), v)

    for m in RX["handle"].finditer(text):
        add("handle", m.group(0), m.group(1).lower())

    for m in RX["hashtag"].finditer(text):
        add("hashtag", m.group(0), m.group(1).lower())

    for m in RX["card"].finditer(text):
        digits = re.sub(r"[ \-]", "", m.group(0))
        if _plausible_card(digits):
            add("card", m.group(0).strip(), digits)
            add("card_bin", digits[:6], digits[:6])

    for m in RX["iban"].finditer(text):
        if iban_ok(m.group(0)):
            add("iban", m.group(0), m.group(0).replace(" ", "").upper())

    for m in RX["phone"].finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 8 <= len(digits) <= 15:
            add("phone", m.group(0).strip(), "+" + digits)

    return found


def discover_channels(text: str, *, outlinks: Iterable[str] = ()) -> set[str]:
    """Snowball fuel: new channel usernames mentioned anywhere in a message."""
    out: set[str] = set()
    for blob in [text or ""] + [u for u in outlinks if u]:
        for m in TME_RX.finditer(blob):
            name = m.group(1).lower()
            if name not in _TME_RESERVED:
                out.add(name)
    for m in RX["handle"].finditer(text or ""):
        out.add(m.group(1).lower())
    return out
