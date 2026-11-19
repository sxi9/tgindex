"""Regression tests. Run: python3 tests.py"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from tgindex.crypto_validate import (b58check, bech32_valid, eip55_ok, iban_ok,
                                     keccak256, luhn_ok)
from tgindex.entities import extract
from tgindex.parse import parse_count, parse_page
from tgindex.query import fts_query, pivot, search, spread
from tgindex.store import Store

PASS = FAIL = 0


def ok(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL  {label}\n        got={got!r} want={want!r}")


def group(name):
    print(f"\n{name}")


# ---------------- checksums ----------------
group("checksum validators")
ok("keccak256 empty", keccak256(b"").hex(),
   "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
ok("keccak256 abc", keccak256(b"abc").hex(),
   "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
ok("btc genesis", b58check("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
ok("btc tampered", b58check("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"), False)
ok("btc p2sh", b58check("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"))
ok("bech32 v0", bech32_valid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))
ok("bech32m v1", bech32_valid("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"))
ok("bech32 bad", bech32_valid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"), False)
ok("eip55 valid", eip55_ok("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"))
ok("eip55 invalid", eip55_ok("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1Beaed"), False)
ok("eip55 lowercase", eip55_ok("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"))
ok("luhn good", luhn_ok("4111111111111111"))
ok("luhn bad", luhn_ok("4111111111111112"), False)
ok("iban good", iban_ok("GB82 WEST 1234 5698 7654 32"))
ok("iban bad", iban_ok("GB82 WEST 1234 5698 7654 33"), False)

# ---------------- extraction ----------------
group("entity extraction")
text = ("pay bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 or 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa "
        "bad=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb "
        "eth 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed bad 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1Beaed "
        "http://expyuzz4wqqyqhjn.onion/ https://downloads.zip/p attach file.zip "
        "card 4111 1111 1111 1111 nope 4111111111111112 "
        "CVE-2024-3400 44d88612fea8a8f36de82e1278abb02f t.me/somechan @vendor1 "
        "admin@mail.example.org nothing.notarealtld 10.0.0.1")
by: dict[str, list[str]] = {}
for e in extract(text):
    by.setdefault(e.type, []).append(e.norm)

ok("btc both forms", sorted(by.get("btc", [])) ==
   sorted(["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]))
ok("bad btc dropped", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb" not in by.get("btc", []))
ok("one eth only", by.get("eth") == ["0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"])
ok("onion found", "expyuzz4wqqyqhjn.onion" in by.get("onion", []))
ok("valid card", "4111111111111111" in by.get("card", []))
ok("card bin", "411111" in by.get("card_bin", []))
ok("bad card dropped", "4111111111111112" not in by.get("card", []))
ok("file.zip not domain", "file.zip" not in by.get("domain", []))
ok("downloads.zip is domain", "downloads.zip" in by.get("domain", []))
ok("fake tld dropped", "nothing.notarealtld" not in by.get("domain", []))
ok("private ip dropped", "10.0.0.1" not in by.get("ip", []))
ok("cve", "CVE-2024-3400" in by.get("cve", []))
ok("filehash", "44d88612fea8a8f36de82e1278abb02f" in by.get("filehash", []))
ok("tme channel", "somechan" in by.get("tme_channel", []))
ok("email", "admin@mail.example.org" in by.get("email", []))

# ---------------- parsing ----------------
group("parsing")
ok("count M", parse_count("4.45M"), 4450000)
ok("count K", parse_count("12.9K"), 12900)
ok("count plain", parse_count("842"), 842)
ok("count junk", parse_count("n/a"), None)
ok("fts quoting", fts_query('what\'s up'), '"what\'s" "up"')
ok("fts keyword kept", fts_query("alpha OR beta"), '"alpha" OR "beta"')
ok("fts prefix kept", fts_query("tele*"), '"tele"*')

# ---------------- store round trip ----------------
group("store, dedup, alerting")
from tgindex.parse import Message

db = tempfile.mktemp(suffix=".db")
st = Store(db)
st.watch("1a1zp1ep5qgefi2dmptftl5slmv7divfna", label="lowercased by analyst")
st.watch("EVIL.example.com", type="domain", label="uppercased by analyst")
st.watch("toncoin", type="keyword", label="keyword watch")

body = ("send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa then https://evil.example.com "
        "about toncoin")
orig = Message(channel="alpha", msg_id=1, uid="alpha/1",
               date="2026-01-01T00:00:00+00:00", text=body, views=100)
fwd = Message(channel="beta", msg_id=7, uid="beta/7",
              date="2026-01-01T00:05:00+00:00", text=body, views=9000,
              fwd_channel="alpha", fwd_msg_id=1, fwd_name="Alpha")
r1 = st.ingest([orig])
r2 = st.ingest([fwd])

ok("orig inserted", r1["new"], 1)
ok("fwd inserted", r2["new"], 1)
ok("btc alert despite case", st.db.execute(
    "SELECT COUNT(*) c FROM alerts WHERE entity_type='btc'").fetchone()["c"], 2)
ok("domain alert despite case", st.db.execute(
    "SELECT COUNT(*) c FROM alerts WHERE entity_type='domain'").fetchone()["c"], 2)
ok("keyword alert fired", st.db.execute(
    "SELECT COUNT(*) c FROM alerts WHERE entity_type='keyword'").fetchone()["c"], 2)

hits = search(st, "toncoin", dedup=True)
ok("dedup collapses forward", len(hits), 1)
ok("spread counted", hits[0].copies, 2)
ok("reach summed", hits[0].reach, 9100)
ok("original preferred over forward", hits[0].channel, "alpha")

nodedup = search(st, "toncoin", dedup=False)
ok("no-dedup returns both", len(nodedup), 2)

p = pivot(st, "evil.example.com", type="domain")
ok("pivot channel count", p["total_channels"], 2)
ok("pivot message count", p["total_messages"], 2)

sp = spread(st, "alpha/1")
ok("spread copies", sp["copies"], 2)
ok("spread lag", sp["timeline"][1]["lag_minutes"], 5.0)

# watchlist added after the fact must backfill
st.watch("alpha", type="tme_channel", label="late addition")
before = st.db.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
st.backfill_alerts()
ok("backfill is idempotent", st.db.execute(
    "SELECT COUNT(*) c FROM alerts").fetchone()["c"] >= before)

st.close()
Path(db).unlink(missing_ok=True)
for suffix in ("-wal", "-shm"):
    Path(db + suffix).unlink(missing_ok=True)

# ---------------- threat layer ----------------
group("threat classification")
from tgindex import threat as TH
from tgindex.entities import extract as gen

def tagcheck(txt, onion=False):
    g = gen(txt)
    doms = [e.norm for e in g if e.type == "domain"]
    ents = TH.extract(txt, domains=doms)
    tags = TH.classify(txt, threat_entities=ents, onion=onion)
    vics = TH.victim_candidates(doms, tags, structural=TH.structural_signals(ents))
    return tags, {e.type for e in ents}, vics

benign = "Our SOC blocked a credential stuffing attempt. Details on bleepingcomputer.com"
tags, _, vics = tagcheck(benign)
ok("benign SOC post untagged", tags, set())
ok("benign yields no victims", vics, [])

news = "Breach exposed 20 million records. Report at www.bleepingcomputer.com"
tags, _, vics = tagcheck(news)
ok("news is tagged topically", "data_leak" in tags)
ok("news is NOT an actor post", "actor_post" not in tags)
ok("news source is not a victim", vics, [])

leak = ("LockBit published all data from acme-industries.com. 480 GB, 2.4 million "
        "records. TOX: " + "A1B2C3D4E5F6" * 6 + "A1B2")
tags, types, vics = tagcheck(leak)
ok("leak post is actor_post", "actor_post" in tags)
ok("ransomware tagged", "ransomware" in tags)
ok("family extracted", "ransom_family" in types)
ok("tox id extracted", "tox_id" in types)
ok("record count extracted", "record_count" in types)
ok("victim found", "acme-industries.com" in vics)

combo = ("""HQ COMBO 2.4M lines antipublic checked URL:LOGIN:PASS
vpn.northwind-logistics.com:admin:Passw0rd123
mail.contoso-group.co.uk:kpatel:Summer2025
combo_2025.txt via https://gofile.io/d/xyz""")
tags, types, vics = tagcheck(combo)
ok("combolist tagged credentials", "credentials" in tags)
ok("combolist is actor_post", "actor_post" in tags)
ok("leak host extracted", "leak_host" in types)
ok("leak file extracted", "leak_file" in types)
ok("cred lines counted", "cred_lines" in types)
ok("affected domains found", len(vics) >= 2)
ok("leak host not a victim", "gofile.io" not in vics)

# the tool counts credential lines but must never store their values
ents = TH.extract(combo, domains=[])
cred = [e for e in ents if e.type == "cred_lines"]
ok("cred_lines stores a count only", cred[0].norm.isdigit() if cred else False)
ok("no password text in any entity",
   not any("Passw0rd123" in e.value or "Passw0rd123" in e.norm for e in ents))

ok("infra filter catches subdomains", TH._is_infrastructure("blog.talosintelligence.com"))
ok("infra filter catches www", TH._is_infrastructure("www.bleepingcomputer.com"))
ok("real victim is not infra", TH._is_infrastructure("acme-industries.com"), False)

print(f"\n{'='*46}\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
