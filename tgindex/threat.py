"""Threat-intelligence layer: ransomware, leaks, access brokering.

Defensive monitoring. Everything here classifies and structures content that
is already publicly posted, so a defender can find mentions of their own
estate - victim disclosures, leaked credentials, access listings, CVE chatter.

Gazetteers hold names that are published constantly by CISA, Europol and every
IR vendor; none of it is sensitive on its own.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

# ---------------------------------------------------------------- gazetteers

RANSOM_FAMILIES = {
    "lockbit", "alphv", "blackcat", "clop", "cl0p", "akira", "play ransomware",
    "black basta", "blackbasta", "ransomhub", "qilin", "medusa", "inc ransom",
    "8base", "hunters international", "bianlian", "rhysida", "cactus",
    "noescape", "royal ransomware", "conti", "revil", "sodinokibi", "hive",
    "vice society", "snatch", "mallox", "trigona", "stormous", "everest",
    "dragonforce", "lynx", "safepay", "interlock", "killsec", "fog ransomware",
    "brain cipher", "space bears", "termite", "helldown", "sarcoma", "babuk",
    "darkside", "blackbyte", "nokoyawa", "monti", "daixin", "karakurt",
    "losttrust", "meow ransomware", "ragnar locker", "ragnarlocker", "avaddon",
    "egregor", "maze ransomware", "netwalker", "ryuk", "doppelpaymer",
    "zeppelin", "blacksuit", "embargo", "apos", "cicada3301", "funksec",
    "nitrogen ransomware", "arcus media", "handala", "abyss", "ciphbit",
    "madliberator", "underground team", "kairos", "chort", "weyhro",
}

INFOSTEALERS = {
    "redline", "raccoon stealer", "vidar", "lumma", "lummac2", "stealc",
    "rhadamanthys", "azorult", "atomic stealer", "amos stealer", "erbium",
    "aurora stealer", "phemedrone", "meduza stealer", "risepro", "mystic stealer",
    "titan stealer", "bandit stealer", "nexus stealer", "kematian", "acr stealer",
    "formbook", "agent tesla", "snake keylogger", "metastealer",
}

LOADERS_BOTNETS = {
    "emotet", "qakbot", "qbot", "icedid", "bumblebee", "pikabot", "darkgate",
    "socgholish", "gootloader", "latrodectus", "smokeloader", "amadey",
    "cobalt strike", "brute ratel", "sliver c2", "havoc c2",
}

# File hosts that routinely carry dumps and leak archives.
LEAK_HOSTS = {
    "mega.nz", "mega.io", "gofile.io", "anonfiles.com", "file.io",
    "dropmefiles.com", "temp.sh", "catbox.moe", "pixeldrain.com", "send.cm",
    "krakenfiles.com", "1fichier.com", "uploadrar.com", "dosya.co",
    "transfer.sh", "filetransfer.io", "wetransfer.com", "bayfiles.com",
    "anonymfile.com", "qu.ax", "buzzheavier.com", "filebin.net",
}

# Term -> tag. Matched as whole phrases, case-insensitive.
TERMS: dict[str, tuple[str, ...]] = {
    "data_leak": (
        "data breach", "data leak", "leaked database", "database leak", "db leak",
        "full dump", "sql dump", "leaked data", "breached", "exfiltrated",
        "data dump", "leak of", "we leaked", "publishing data", "stolen data",
    ),
    "credentials": (
        "combolist", "combo list", "combolists", "stealer logs",
        "stealer log", "ulp", "url:login:pass", "cookies dump", "fullz",
        "credential dump", "cracked accounts", "login:pass", "email:pass",
        "mail:pass", "mailpass", "user:pass", "cpanel access", "smtp access",
        "brute logs", "session cookies", "private logs", "cloud of logs",
        "fresh logs", "valid hits", "checked accounts", "antipublic",
        "openbullet", "silverbullet",
        "hq combo", "autofill", "credit cards from logs",
        "passwords dump", "russianmarket", "2easy", "genesis market", "logs shop",
    ),
    "initial_access": (
        "rdp access", "vpn access", "citrix access", "initial access",
        "domain admin", "shell access", "webshell access", "access for sale",
        "selling access", "corporate access", "network access", "vpn creds",
        "esxi access", "fortinet access", "sonicwall access",
    ),
    "ransomware": (
        "ransom note", "leak site", "victim blog", "double extortion",
        "encrypted your", "decryptor", "we have downloaded", "deadline to pay",
        "publish all data", "onion blog", "negotiation chat",
    ),
    "exploit": (
        "0day", "zero-day", "zero day", "poc exploit",
        "rce exploit", "exploit for sale", "weaponized",
    ),
    "carding": (
        "cc dump", "card dump", "cvv", "bin list", "carding", "track1", "track2",
        "non vbv", "fresh cc",
    ),
}

# Vocabulary that appears constantly in legitimate security reporting.
# These only apply a tag when a structural signal corroborates them, so a
# vendor blog post about ransomware is not filed as a ransomware actor post.
WEAK_TERMS: dict[str, tuple[str, ...]] = {
    "credentials": (
        "credential stuffing", "account takeover", "cracking", "checker",
        "bruteforce", "dehashed", "breachforums", "leakbase", "leaked passwords",
        "combo", "config for",
    ),
    "ransomware": (
        "ransomware", "ransom demand", "encrypted files", "extortion",
    ),
    "data_leak": ("breach", "leak", "dump", "database"),
    "exploit": (
        "proof of concept", "privilege escalation", "actively exploited",
        "in the wild exploitation", "vulnerability",
    ),
    "initial_access": ("broker", "access broker"),
}

# Structural evidence that something is an actual actor/market post rather
# than commentary about one.
STRUCTURAL = {"leak_host", "cred_lines", "tox_id", "session_id",
              "record_count", "leak_file", "ransom_family", "stealer"}

BENIGN_DOMAINS = {
    "t.me", "telegram.org", "telegram.me", "x.com", "twitter.com", "youtube.com",
    "www.youtube.com", "github.com", "linkedin.com", "www.linkedin.com",
    "medium.com", "reddit.com", "facebook.com", "instagram.com", "google.com",
    # security press
    "bleepingcomputer.com", "thehackernews.com", "securityaffairs.com",
    "krebsonsecurity.com", "therecord.media", "darkreading.com",
    "infosecurity-magazine.com", "helpnetsecurity.com", "hackread.com",
    "cyberscoop.com", "scworld.com", "theregister.com", "zdnet.com",
    "arstechnica.com", "wired.com", "techcrunch.com", "securityweek.com",
    # vendor research
    "talosintelligence.com", "abuse.ch", "malwarebytes.com", "sophos.com",
    "crowdstrike.com", "mandiant.com", "paloaltonetworks.com", "trendmicro.com",
    "kaspersky.com", "securelist.com", "eset.com", "welivesecurity.com",
    "checkpoint.com", "sentinelone.com", "proofpoint.com", "recordedfuture.com",
    "intel471.com", "flashpoint.io", "group-ib.com", "rapid7.com",
    "tenable.com", "qualys.com", "fortinet.com", "cisco.com", "microsoft.com",
    "redcanary.com", "huntress.com", "esentire.com", "varonis.com",
    # government / standards
    "cisa.gov", "nvd.nist.gov", "nist.gov", "us-cert.gov", "ic3.gov",
    "fbi.gov", "europol.europa.eu", "ncsc.gov.uk", "mitre.org", "cve.org",
    "first.org", "enisa.europa.eu",
    # analysis and infrastructure tooling
    "virustotal.com", "any.run", "hybrid-analysis.com", "joesandbox.com",
    "tria.ge", "urlscan.io", "shodan.io", "censys.io", "alienvault.com",
    "exploit-db.com", "packetstormsecurity.com", "archive.org",
    "github.io", "gitlab.com", "stackoverflow.com", "npmjs.com", "pypi.org",
    "amazonaws.com", "cloudflare.com", "akamai.com", "googleapis.com",
    "bit.ly", "t.co", "tinyurl.com", "ipwhois.app", "ipinfo.io",
}

# ---------------------------------------------------------------- regexes

RX = {
    # TOX IDs are the standard contact channel on ransomware leak sites.
    "tox": re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{76}(?![A-Fa-f0-9])"),
    # Session messenger IDs start 05 and are 66 hex total.
    "session": re.compile(r"(?<![A-Fa-f0-9])05[A-Fa-f0-9]{64}(?![A-Fa-f0-9])"),
    "records": re.compile(
        r"(\d[\d.,]*)\s*([kmb]|thousand|million|billion)?\s*"
        r"(records?|rows?|lines?|users?|accounts?|customers?|entries|clients?|patients?)\b",
        re.I),
    "size": re.compile(r"(\d[\d.,]*)\s*(gb|tb|mb)\b", re.I),
    "victim_rev": re.compile(r"revenue[:\s]*\$?\s*([\d.,]+)\s*([mb]|million|billion)?", re.I),
    # A dump is usually shipped as a named archive; the filename is a pivot.
    "leak_file": re.compile(
        r"\b([\w.\-]{3,64}\.(?:txt|csv|sql|zip|rar|7z|tar\.gz|json|xlsx))\b", re.I),
    # Presence of credential-pair FORMAT, as a classification signal only.
    # The matched text is never captured, stored or emitted - see count_cred_lines.
    "cred_format": re.compile(
        r"(?m)^\s*(?:https?://)?[\w.\-]+(?:\.[a-z]{2,24})?[:|]"
        r"[^\s:|]{3,64}[:|][^\s:|]{3,64}\s*$"),
}

_MULT = {"": 1, "k": 1_000, "thousand": 1_000, "m": 1_000_000,
         "million": 1_000_000, "b": 1_000_000_000, "billion": 1_000_000_000}

_GAZ = [
    ("ransom_family", RANSOM_FAMILIES, "ransomware"),
    ("stealer", INFOSTEALERS, "malware"),
    ("malware_tool", LOADERS_BOTNETS, "malware"),
]

# Pre-compile whole-phrase matchers once.
def _phrase_rx(terms: Iterable[str]) -> re.Pattern:
    parts = sorted((re.escape(t) for t in terms), key=len, reverse=True)
    return re.compile(r"(?<![\w])(" + "|".join(parts) + r")(?![\w])", re.I)

_GAZ_RX = {name: _phrase_rx(vals) for name, vals, _ in _GAZ}
_TERM_RX = {tag: _phrase_rx(vals) for tag, vals in TERMS.items()}
_WEAK_RX = {tag: _phrase_rx(vals) for tag, vals in WEAK_TERMS.items()}


@dataclass(frozen=True)
class ThreatEntity:
    type: str
    value: str
    norm: str


def parse_magnitude(num: str, unit: str | None) -> int | None:
    try:
        base = float(num.replace(",", ""))
    except ValueError:
        return None
    return int(base * _MULT.get((unit or "").lower(), 1))


def count_cred_lines(text: str) -> int:
    """How many lines look like credential pairs.

    Returns a COUNT only. The tool deliberately never captures, stores or
    surfaces the credential values themselves - the defensive question is
    "are my users in this dump", answered by the affected domains, not by
    harvesting the secrets.
    """
    if not text:
        return 0
    return sum(1 for _ in RX["cred_format"].finditer(text))


def extract(text: str, *, domains: Iterable[str] = ()) -> set[ThreatEntity]:
    """Threat-specific entities layered on top of the generic extractor."""
    if not text:
        return set()
    out: set[ThreatEntity] = set()
    add = lambda t, v, n: out.add(ThreatEntity(t, v, n))

    for etype, rx in _GAZ_RX.items():
        for m in rx.finditer(text):
            add(etype, m.group(1), m.group(1).lower())

    for m in RX["tox"].finditer(text):
        add("tox_id", m.group(0), m.group(0).upper())
    for m in RX["session"].finditer(text):
        add("session_id", m.group(0), m.group(0).lower())

    for d in domains:
        d = d.lower()
        if d in LEAK_HOSTS:
            add("leak_host", d, d)

    # Largest claimed record count in the message - the headline number.
    best = 0
    for m in RX["records"].finditer(text):
        n = parse_magnitude(m.group(1), m.group(2))
        if n and n > best and n >= 1000:
            best = n
    if best:
        add("record_count", str(best), str(best))

    for m in RX["size"].finditer(text):
        add("data_size", m.group(0), m.group(0).lower().replace(" ", ""))

    for m in RX["leak_file"].finditer(text):
        fn = m.group(1).lower()
        if not fn.endswith((".png", ".jpg", ".jpeg", ".gif", ".mp4")):
            add("leak_file", m.group(1), fn)

    n = count_cred_lines(text)
    if n >= 2:
        # Count only. Values are never recorded.
        add("cred_lines", str(n), str(n))

    return out


def classify(text: str, *, threat_entities: Iterable[ThreatEntity] = (),
             onion: bool = False) -> set[str]:
    """Rule-based tags. Deliberately conservative - a tag should mean something."""
    if not text:
        return set()
    tags: set[str] = set()
    tents = list(threat_entities)

    for tag, rx in _TERM_RX.items():
        if rx.search(text):
            tags.add(tag)

    structural = {e.type for e in tents} & STRUCTURAL
    if structural or onion:
        # Only now do topical words count.
        for tag, rx in _WEAK_RX.items():
            if rx.search(text):
                tags.add(tag)

    for ent in tents:
        if ent.type == "ransom_family":
            tags.add("ransomware")
        elif ent.type in ("stealer", "malware_tool"):
            tags.add("malware")
        elif ent.type == "leak_host":
            tags.add("data_leak")
        elif ent.type in ("tox_id", "session_id"):
            tags.add("operator_contact")
        elif ent.type == "record_count":
            tags.add("data_leak")
        elif ent.type == "cred_lines":
            tags.add("credentials")
        elif ent.type == "leak_file":
            tags.add("data_leak")

    if onion and tags & {"ransomware", "data_leak", "initial_access"}:
        tags.add("darkweb")
    # Two independent structural signals: treat as a first-party actor or
    # market post, not reporting about one.
    if len(structural) >= 2:
        tags.add("actor_post")
    if tags:
        tags.add("threat")
    return tags


def _is_infrastructure(host: str) -> bool:
    """Benign, research, or leak-hosting infrastructure - never a victim.

    Matched on the registrable suffix so subdomains (www.bleepingcomputer.com,
    blog.talosintelligence.com, bazaar.abuse.ch) are caught too.
    """
    host = host.lower().rstrip(".")
    if host.endswith(".onion"):
        return True
    for known in BENIGN_DOMAINS | LEAK_HOSTS:
        if host == known or host.endswith("." + known):
            return True
    return False


def victim_candidates(domains: Iterable[str], tags: Iterable[str], *,
                      structural: Iterable[str] = ()) -> list[str]:
    """In an actual leak or extortion post, a non-infrastructure domain is
    usually the victim. Surfaced as a candidate, never as a conclusion.

    Requires structural evidence: on a news article about a breach, the
    domains present are the reporter's sources, not victims. Gating on
    structure is what keeps this column meaningful.
    """
    tags, structural = set(tags), set(structural)
    if not tags & {"ransomware", "data_leak", "credentials"}:
        return []
    if not structural:
        return []
    out = []
    for d in domains:
        d = d.lower().rstrip(".")
        if _is_infrastructure(d):
            continue
        if d.startswith("www."):
            d = d[4:]
            if _is_infrastructure(d):
                continue
        out.append(d)
    return sorted(set(out))


def structural_signals(threat_entities: Iterable[ThreatEntity]) -> set[str]:
    return {e.type for e in threat_entities} & STRUCTURAL


TAGS = sorted(set(TERMS) | {"malware", "operator_contact", "darkweb",
                           "actor_post", "threat"})
