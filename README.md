# tgindex

[![tests](https://github.com/sxi9/tgindex/actions/workflows/tests.yml/badge.svg)](https://github.com/sxi9/tgindex/actions/workflows/tests.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![dependencies](https://img.shields.io/badge/dependencies-2-lightgrey)](requirements.txt)

Telegram public-channel search and monitoring. Own crawl, structured index,
validated entity extraction, forward dedup, watchlist alerting, and a threat
layer for leaks, ransomware and credential dumps.

Built as an evaluation prototype: run it against your own channel list and judge
result quality before committing to the production build.

![tgindex search](docs/screenshot-search.png)

Search blends BM25 with recency and reach, collapses forwards to the origin post
(reporting spread separately), and attaches every extracted entity as a chip you
can pivot on.

## Why this exists

Sites like `telegramsearchengine.com` are not search engines. That one is a
Google Programmable Search Engine (`cx=3efd7fa5ca51ba289`) in a styled wrapper —
you inherit Google's coverage, Google's refresh rate, and no structure at all.

This crawls `t.me/s/` directly, so it has its own coverage and freshness, and it
stores typed documents rather than text blobs. That makes queries possible that a
site-restricted web search structurally cannot express:

| | Google CSE wrapper | tgindex |
|---|---|---|
| Coverage | whatever Google crawled | whatever you crawl |
| Freshness | days to weeks | minutes |
| Filter by date / views / media | no | yes |
| "every channel that posted this wallet" | no | yes (`pivot`) |
| Forward dedup and spread | no | yes (`spread`) |
| Real-time watchlist alerts | no | yes (`watch`) |

### Pivot

![tgindex pivot](docs/screenshot-pivot.png)

Every channel that ever carried a value, when each first posted it, and a ranked
list of what else travels alongside it — each row itself a further pivot.

## Quickstart

```bash
python3 -m tgindex seed seeds.txt
```

```bash
python3 -m tgindex crawl --channels 55 --pages 2 --depth 1 --workers 5 --rps 3
```

```bash
python3 -m tgindex search "wallet security" --entities
```

```bash
python3 -m tgindex serve --port 8000
```

Only dependencies are `requests` and `lxml`. Index is a single SQLite file.

## Threat intelligence layer

Built for the leaks / ransomware / credential-dump vertical. On ingest every
message is classified and threat-specific entities are extracted alongside the
generic ones.

![tgindex threats](docs/screenshot-threats.png)

**Tags** — `ransomware` `data_leak` `credentials` `initial_access` `malware`
`exploit` `carding` `operator_contact` `darkweb` `actor_post`

```bash
python3 -m tgindex search --tag credentials --entities
python3 -m tgindex threats
```

**Threat entities** (all pivotable like any other):

| type | what |
|---|---|
| `ransom_family` | ~70 published ransomware family names |
| `stealer` / `malware_tool` | infostealers, loaders, C2 frameworks |
| `leak_host` | mega.nz, gofile.io, anonfiles and friends |
| `leak_file` | dump filenames (`combo_2025.txt`, `logs_batch_44.zip`) |
| `tox_id` / `session_id` | operator contact IDs from leak-site posts |
| `record_count` | largest claimed record/line count in the post |
| `data_size` | claimed archive size |
| `cred_lines` | **count** of credential-format lines (see below) |
| `victim_domain` | affected-org candidates |

**Mention vs actor post.** Security vocabulary is everywhere in legitimate
reporting, so terms are split into strong and weak. Weak topical words
(`ransomware`, `breach`, `credential stuffing`) only apply a tag when a
*structural* signal corroborates them — a leak host, a record count, an
operator contact ID, a family name, credential-format lines. Two independent
structural signals mark the message `actor_post`. A vendor blog about LockBit
is tagged `ransomware`; a LockBit leak post is tagged `actor_post`.

`victim_domain` is likewise gated on structure: on a news article the domains
present are the reporter's sources, not victims. ~100 press, vendor,
government and tooling domains are filtered as infrastructure, matched on
registrable suffix so subdomains are caught too.

### Credential dumps: counts, never values

For combolists, stealer logs and `.txt` dumps the tool records **how many
lines look like credential pairs** and **which domains are affected**. It never
captures, stores or displays the credential values themselves.

That is deliberate. The defensive question is "are my users in this dump",
which the affected-domain list answers. Harvesting the secrets answers a
different question, and this tool does not do it. Two regression tests assert
it: `cred_lines` holds only a digit string, and no password text reaches any
stored entity.

### Watchlist presets

```bash
python3 -m tgindex watch preset ransomware
```

`ransomware` (~70 families), `stealers`, `malware`, `leak-hosts`,
`operator-contact`. Each backfills over everything already indexed.

## Finding seed channels

Discovery amplifies whatever neighbourhood you seed into, so sourcing the first
list is the hard part — and it is domain work, not engineering.

```bash
python3 -m tgindex verify candidates.txt --seed
python3 -m tgindex leads
```

`verify` probes handles and reports whether each is a **crawlable public
channel**, before you spend crawl budget. `leads` ranks the un-crawled queue by
how threat-relevant the content that referenced each candidate was, so you crawl
the promising ones first instead of draining the queue alphabetically.

### What this method can and cannot reach

`t.me/s/` serves only channels that are public *and* have web preview enabled.
Private, invite-only, preview-disabled channels and user accounts return a bare
contact page — they exist, but this collector cannot see them.

That is not a minor caveat for the threat vertical. Measured against
[ransomware.live](https://ransomware.live) (424 tracked groups), only 4 publish
a Telegram handle at all — ransomware is Tor-first — and **0 of those 4 are
crawlable**. The actor core runs invite-only precisely to avoid this kind of
collection.

So the reachable surface is:

| tier | reachable via `t.me/s/` |
|---|---|
| Actor / market channels (invite-only) | no — needs MTProto with an account |
| Aggregator and monitoring channels that republish actor content | yes |
| Research, CERT and press channels | yes |

Aggregators are the useful seed for this collector: they are public because they
want an audience, and they carry actor content plus links into the ecosystem.
Reaching the actor tier itself is the Tier-2 MTProto build.

## Theming

The UI is skinned from `tgindex/theme.py` — themes are data, so swapping one
token dict re-skins every page. Three ship:

| theme | look |
|---|---|
| `ink` (default) | neutral charcoal, warm amber accent, Space Grotesk / Inter / JetBrains Mono |
| `slate` | cool blue-grey, cyan accent |
| `terminal` | phosphor green on near-black, monospace throughout |

```bash
python3 -m tgindex serve --theme terminal
```

`web.py` emits structure and never names a colour, so adding a theme is copying
a `Theme(...)` block, changing the tokens, and registering it in `THEMES`.

Assets in `tgindex/assets.py`: the mark is an original glyph drawn from
primitives, and icons are [Lucide](https://lucide.dev) (ISC licence), vendored
as an inline sprite so the UI has no CDN or runtime dependency. Icons are
referenced by semantic key (`theme.icon("alerts")`), so a theme can swap icon
sets without touching `web.py`.

## Commands

| command | what it does |
|---|---|
| `seed <file\|names>` | add channels to the crawl queue |
| `crawl` | drain the queue, snowballing outward to `--depth` |
| `poll` | re-fetch page 1 of active channels (the real-time loop) |
| `search <q>` | BM25 + recency + reach, forward-deduped |
| `pivot <value>` | every channel that posted an entity, plus co-occurrence |
| `spread <uid>` | propagation timeline for a canonical message |
| `watch add/list/rm` | manage the watchlist; adding backfills over the index |
| `alerts` | the alert feed |
| `entities` | top extracted entities by channel spread |
| `facets` | counts by channel, media, entity type |
| `coord` | channel pairs posting identical content in a short window |
| `stats` | index health |
| `serve` | web UI on :8000 |

## How it works

```
seeds ──> crawl t.me/s/<ch>?before=<id> ──> parse ──> ingest ──> index
            ^                                           │
            └──── discovery: forwards, t.me links, @ ────┘
```

Public channels render their whole history as server-side HTML at
`t.me/s/<username>` — no auth, no API key. `?before=<msg_id>` pages backwards.
Everything here is built on that.

**Modules**

- `fetch.py` — token-bucket rate limiter, retry with backoff, `Retry-After` handling
- `parse.py` — HTML to typed records; `<br>`-aware text extraction, forward origin, reply, media, link preview
- `entities.py` — extraction with validation
- `crypto_validate.py` — Keccak-256 (pure Python), base58check, bech32/bech32m, Luhn, IBAN mod-97
- `store.py` — schema, FTS5, dedup, watchlist matching
- `crawl.py` — thread-pool fetch, single-threaded ingest
- `query.py` — search, pivot, spread, facets, coordination
- `web.py` — stdlib UI, no framework

**Entity types.** Validation is the point; unvalidatable candidates are dropped,
not guessed.

`btc` (base58check + bech32/bech32m) · `eth` (EIP-55) · `trx` · `xmr` ·
`domain` (IANA TLD list) · `url` · `ip` (public only) · `email` · `phone` ·
`card` + `card_bin` (Luhn + IIN) · `iban` (mod-97) · `onion` (v2/v3) · `cve` ·
`filehash` · `handle` · `hashtag` · `tme_channel`

**Dedup.** Every message carries `canonical_uid` — the forward origin if known,
else itself. Search collapses on it and reports `copies` and `reach`, so one
viral post is a single result, not 400. The origin is preferred over any forward
even when a forward has far more views: provenance beats reach.

**Alerting.** Two paths, because they are different problems:

- *Entity watches* — O(1) dict lookup against extracted values on ingest. Case
  variants are indexed both ways, so a base58 address typed in the wrong case
  still matches.
- *Keyword watches* (`--type keyword`) — FTS percolation over each ingest batch.
  This is what you want for brand and term monitoring.

Adding a watch backfills over everything already indexed.

## Deliberately not here

- **OCR / ASR.** Cut on cost. The pipeline stores media type and `content_hash`,
  and enrichment is a separate pass, so it can be backfilled later by replaying
  the archive — *provided you keep the media*. See "If you add OCR later".
- **MTProto collection.** Needs an account pool and ongoing ops. Add it per
  channel where you need deletions, media bytes, or membership signals.
- **Vector / hybrid retrieval.** BM25 only for now.

## Production port

SQLite FTS5 stands in for OpenSearch. The document shape is already the target
mapping, so the port is mechanical:

| prototype | production |
|---|---|
| SQLite `messages` + FTS5 | OpenSearch index, same fields |
| `unicode61` tokenizer | per-language analyzers (ICU) — **do this first** |
| `entities` table | nested field + separate pivot index |
| in-process dict watchlist | Redis set lookup |
| keyword watches via FTS | OpenSearch `percolate` |
| in-process crawl loop | fetch workers → Kafka → ingest consumers |
| `requests` + thread pool | same, across an egress IP pool |

The single most important change is the tokenizer. `unicode61` is adequate for
Latin and passable for Cyrillic; it will quietly destroy recall on Arabic,
Persian, and CJK. Fix that before worrying about scale.

### If you add OCR later

Keep media references (file id, `content_hash`, mime type) and ideally the bytes
in S3 from day one. OCR is a worker reading off the same bus, so a stored archive
can be replayed. If media is discarded, that content is gone permanently —
`t.me/s/` only serves what still exists.

## Known limits

- **Public channels only.** No groups, no private/invite-only channels, no
  channels with previews disabled.
- **No deletion tracking.** A scraped index serves content the author removed.
  Retaining deleted messages is a deliberate choice with legal consequences —
  decide it explicitly.
- **Views are approximate.** Telegram serves `4.45M`, so precision is lost above 1K.
- **`1.2.3.4` parses as an IP.** Version strings and IPs are genuinely ambiguous
  in text; this one is left in on purpose rather than guessed away.
- **Username aliases.** A renamed channel serves its old username too. The parser
  resolves to the canonical name from the page header, so aliases merge correctly —
  this is why a crawl of an alias can report `0 new`.
- **Discovery is the real moat.** Your index is only as good as your channel list.
  Curating it is domain work, not engineering work, and it is routinely
  underestimated.

## Legal

Scraping `t.me/s/` reads public HTML, but the corpus contains personal data.
Retention policy, GDPR posture (Art. 14 is a real question for a scraped corpus),
and abuse-material hashing all need deciding before this runs at scale — not
after.

## Tests

```bash
python3 tests.py
```

75 assertions: Keccak-256 and base58check/bech32/EIP-55/Luhn/IBAN against known
vectors, false-positive rejection, dedup and spread, case-insensitive watchlist
matching, threat classification (mention vs actor post), and an assertion that
no credential value reaches any stored entity.
