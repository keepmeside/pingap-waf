# JA4 support, and the `bot` plugin

## What ships

| Fingerprint | Status | Why |
| --- | --- | --- |
| **JA4H** (HTTP request) | **Ships now** | Computed from the request head. No TLS access needed, so it works on plain HTTP |
| JA4 (TLS ClientHello) | Deferred | Reachability confirmed by a spike; three gate items still open. See [spikes/ja4-finding.md](./spikes/ja4-finding.md) |
| JA4S (server response) | Deferred | Depends on the same TLS work as JA4 |
| JA4T / JA4TCP | **Permanent non-goal** | Requires raw TCP SYN options. Pingora does not surface them, and nothing short of patching it would change that |

JA4H is not a lesser version of JA4 — it fingerprints a different layer. It is also the
layer that carries the value: every blocking entry in the reference product's shipped
library is a JA4H, so an HTTP-only fingerprint already covers the clients operators
actually want to stop.

**JA4H is weaker than JA4 and must not be presented as it.** It reflects how an HTTP
client is written — method, version, which headers it sends and in what order — all of
which a determined attacker can imitate far more easily than a TLS stack. It is a
client-behaviour signal, not an identity, and nothing security-critical should rest on it
alone.

## HTTP/2 requests get no fingerprint

Deliberate, and the most important thing on this page.

JA4H's second component hashes header names **in the order the client sent them**. Pingora
preserves that order only for HTTP/1.x, where h1 parsing builds a parallel case map
reachable through `case_header_iter()` and gated on `has_case()`. For HTTP/2 the map is
`None`, and the only iteration left is `http::HeaderMap`'s — whose own documentation states
the order "is arbitrary" and that callers "must not rely on any incidental order".

Computing a fingerprint from that would be worse than computing none. The value would be
*stable within a build*, so it would pass every obvious test — identical across repeated
requests, different for different clients — while matching no published JA4H for any
client. Every library entry would miss, an automation client over h2 would go unblocked,
and a legitimate client whose arbitrary order happened to collide with a deny entry would
be refused. Nothing would error.

So on HTTP/2 the fingerprint is **not emitted**, the request is counted as a miss, and it
is allowed through. Misses are broken out **by protocol version**, because an all-h2 miss
population is expected and has to stay distinguishable from an attacker forcing misses.

If h2 coverage is needed later it requires an explicitly h2-flavoured fingerprint type that
is never compared against HTTP/1.x entries. `to_h1_raw()` and
`pseudo_raw_h1_request_header()` do **not** solve it — they serialise from the same
unordered map.

## Fail-open

A request with no computable fingerprint is **allowed**. A fingerprint rule cannot match a
fingerprint that does not exist, so policy is skipped rather than guessed.

That is a real gap: an attacker who can force a miss bypasses bot policy. It is the right
default anyway — failing closed would refuse every HTTP/2 request on a domain with a bot
profile — but it is only defensible because it is *measurable*. The miss rate and its
per-protocol breakdown are queryable, so an operator can see whether their policy covers
their traffic instead of assuming it. An operator who needs deny-on-miss can pair it with
a monitored rollout.

## Verifying the fingerprint

Canonicalisation is pinned to FoxIO's reference implementation and checked against ten
request/fingerprint pairs from FoxIO's own committed pcap fixtures
(`crates/pingap-bot/tests/ja4h.rs`). All ten reproduce byte-for-byte, including a pair that
differs only in header order and a pair that differs only in method.

**A fingerprint value with no originating request validates nothing.** The reference
product commits values like `ge11nn030000_b51846f30ce9`, and those are log-parser samples:
they show the format and say nothing about whether a given canonicalisation is right. The
same limitation was recorded for the JA4 spike's own output. Ground truth here means a
request *and* its fingerprint, together.

Format: `{a}_{b}_{c}_{d}`

| Part | Content |
| --- | --- |
| `a` | method (2) + version (2) + cookie flag + referer flag + header count (2) + language (4) |
| `b` | SHA-256, first 12 hex characters, of the header names comma-joined in the order sent |
| `c` | the same, of the cookie **names**, sorted |
| `d` | the same, of the cookie `name=value` pairs, sorted by name |

`Cookie` and `Referer` are excluded from the count and from `b` — they are already
represented by their flags and by `c`/`d`. Absent cookies give twelve zeros.

The fingerprint is published as a context variable, so an access-log format picks it up as
`{:ja4h}` with no change to `pingap-logger`. It is published on **every** request,
including allowed ones: that population is what an operator builds a deny list from.

## Configuration

```toml
[plugins."bot:edge"]
category = "bot"
profile = "edge"
mode = "detect"            # detect | block
allow_known_bots = true    # exempt search-engine crawlers
use_signatures = true      # the shipped self-declared-client signatures
rules = [
  { fingerprint_type = "ja4h", fingerprint = "ge11nn040000_5b1e8b5f4d2d", action = "deny" },
  { user_agent = "(?i)internal-scraper", action = "log" },
]

[locations.app]
plugins = ["bot:edge", "waf:strict"]
```

| Key | Default | Meaning |
| --- | --- | --- |
| `step` | `request` | Only `request` is accepted; a typo fails at config load |
| `profile` | `default` | Recorded on every verdict, so a block names the policy that caused it |
| `mode` | `detect` | `detect` records verdicts and refuses nothing |
| `allow_known_bots` | `false` | Exempt known-good crawlers before any rule runs |
| `use_signatures` | `false` | Prepend the shipped scanner/scraper/HTTP-library signatures |
| `rules` | none | Ordered; first terminal match decides |

**`detect` is the default.** Blocking on a client-behaviour signal costs a real user who
cannot reach the site, so a fingerprint deny list should be measured against real traffic
first. An entry with no rules, no signatures and `allow_known_bots = false` enforces
nothing and is refused at config load.

Rules take `fingerprint` (with `fingerprint_type`), `user_agent` (a regex), or both — both
means "this client, and only when it presents that UA", which targets one automation build
without catching the family. `action` is `allow`, `deny` or `log`; `log` is **not**
terminal, so adding one for visibility cannot silently disable the rules below it.

A configured fingerprint matches as a prefix on `_` boundaries, because published entries
carry only `a_b`: the cookie components identify a session rather than a client, so
comparing them for equality would make every library entry miss.

### Known-good crawlers

`allow_known_bots` exempts Googlebot, Bingbot, DuckDuckBot and Applebot **by User-Agent**,
before any rule runs. A User-Agent is a claim, not evidence — anyone can send `Googlebot` —
so this exists to stop a broad deny from costing an operator their search ranking, and for
nothing else. Confirm by reverse DNS if the decision matters; this crate does not implement
that.

### Where bot decisions live

One surface. The WAF used to match User-Agents too, and while both did, a scraper could be
refused by the WAF with an anomaly score attached — a score is a thing an injection payload
has and a scraper does not. Those patterns moved here (`use_signatures`), and a
test asserts no WAF category carries a client-fingerprint rule. The WAF still inspects the
`User-Agent` header for real payloads: a SQL injection carried there is still a WAF hit.

## Analytics

Counts per fingerprint, per verdict, per domain, plus the miss breakdown — aggregated in
Rust rather than SQL, because the control-plane store lacks the window functions a ranked top-N
would otherwise use.

**Aggregate only.** A fingerprint is a weak tracking identifier, so there is deliberately
no per-visitor history: observations carry no address and no timestamp. Counts answer the
operational question — what is hitting me, and is my rule working — without profiling
anyone.
