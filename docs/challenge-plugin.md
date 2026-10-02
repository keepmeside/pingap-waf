# Challenge Plugin

The challenge tier is off by default. Enable it only when the Location also lists a
`challenge` plugin after the `waf` or `acl` entry that writes the challenge marker.
Identity-bound state requires either `basic.trusted_proxies` or the explicit
`client_ip_from_peer = true` assertion on a directly exposed node.

The plugin supports a self-contained proof-of-work page and a silent JavaScript
fingerprint. The PoW page runs a JavaScript solver — the browser searches
`SHA-256(salt + nonce)` for `difficulty` leading zero bits and submits the result —
so a JavaScript-capable client passes with no interaction, while a client with no
script engine sees a `JavaScript is required` notice and cannot complete it. Tokens are single-use, expire, are bound to the domain and client identity,
and are held in a bounded process-global store. Pass cookies use `HttpOnly`, `Secure`,
`Path=/`, `SameSite=Lax`, and no `Domain` attribute.

The default configuration is intentionally conservative:

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | No challenge response is produced until enabled |
| `kind` | `pow` | Proof-of-work interstitial |
| `difficulty` | `4` | Leading SHA-256 zero bits, bounded to 1..10 |
| `token_ttl` | `5m` | Lifetime of an issued token |
| `pass_ttl` | `1h` | Lifetime of a solved pass cookie |
| `max_attempts` | `8` | Failed proof presentations before a token is dropped |
| `max_entries` | `4096` | Maximum outstanding token records |
| `max_domains` | `256` | Maximum active domain buckets before the policy fails toward its configured outcome |
| `loop_threshold` | `3` | Repeated unsolved challenges trigger the configured bypass direction |
| `ladder` | `[2, 4, 8]` | Consecutive-failure counts that raise the challenge tier |
| `decay` | `15m` | Idle time after which an accrued tier falls back toward the floor |
| `exempt` | `[]` | Addresses never challenged — the challenge tier's promise alone |
| `bypass_on_loop` | `refuse` | Past `loop_threshold`: `refuse` answers 403, `allow` keeps issuing |

When the entry cap is reached, the plugin answers with a stateless HMAC proof instead of
admitting the request: that cap is reachable by traffic, so the tier keeps verifying — the
fallback token carries the same binding and the same proof, solves through the same path,
and earns the same pass cookie, at the cost of the store an attacker spent. When the
domain cap is reached, it fails toward the configured policy with a 503: that cap is a
configuration fault rather than a traffic condition — unregistered hosts collapse into one
bucket, so a full domain set means the registered host set outgrew `max_domains` — and
there is no availability argument for issuing a challenge the store cannot hold. Both
paths are counted separately (`saturated_entries` beside `stateless_fallback`,
`saturated_domains`) so saturation cannot look like normal challenge traffic.

`difficulty`, `token_ttl`, `pass_ttl`, `max_attempts`, `loop_threshold` and the `ladder` are
inherited starting values, not figures measured against this product's traffic. The
`max_entries` and `max_domains` caps are chosen bounds that bound memory, not tuned limits.
Tune them per domain.

## Scope

Challenge state is keyed per domain, not per Location: the key is the
classified domain label plus the client identity — the same label the
behavioural tier and the WAF and ACL marker counts key on. Escalation and
token state are one store per domain and identity, shared by every entry
under the host: failures accrued under either of two Locations raise the
tier both read, and the pass cookie is host-scoped and identity-bound, so
two entries under one host should share one secret — with different secrets
each entry refuses the other's cookie and the client solves in a loop.
Per-entry settings — kind, difficulty, ladder, decay — still apply per
Location, and the store caps come from the first-constructed entry. An
operator wanting independently escalating challenge state per path needs a
separate hostname; wanting `/admin` challenged harder than `/` is two
entries with different difficulty under the one host.

## Escalation

Consecutive failures raise a client's challenge tier, and a tier changes the page, never
the verdict: a marked request is answered with an interstitial at every tier, and the only
refusals the tier ever originates are the loop direction and the saturation policy above.
The `ladder` maps failure counts onto tiers — `[2, 4, 8]` means the fourth failure raises
the tier to 1, the eighth to 2 — and the tier decides the page: odd tiers serve the silent
fingerprint page, even tiers serve the proof-of-work page at `difficulty` plus the tier.
The marker's level is the maximum of what the originating policy, the behavioural snapshot
and the adaptive decision each contribute, and the ladder's escalation raises it further.
A solve lowers the tier, and an idle entry decays back toward the floor after `decay`, so
a client that stops and comes back later is not fighting its own past.

## Exemption

`exempt` is checked before any challenge state exists: a listed address is never issued a
challenge and never accrues escalation, and every hit is counted (`exempt_hit`) and logged
(`outcome="exempt"`), so a promise that silently stops matching is visible as the line's
absence. The promise is narrow on purpose — it binds the challenge tier alone. The WAF,
the ACL and every other tier still inspect, and still refuse, an address the challenge
exempts; an operator who wants an address past the gateway must say so to every tier that
enforces. An entry that is not an IP address or CIDR range refuses construction and names
the entry, because an exempt list that silently skips a bad entry is a promise that looks
made and was not.

## Access-log variables

The plugin publishes two access-log variables on every path it takes a decision on:
`challenge_status` (`issued`, `solved` or `exempt`) and `challenge_key_id`, this node's
pass-cookie key identifier — the first hex of the secret's SHA-256, the same value baked
into every pass cookie this node signs. The two travel together because the pair is what
a cross-node secret mismatch reads from: two nodes sharing traffic with two different
secrets produce the same client-visible solve loop, and the mismatch surfaces as two
different `challenge_key_id` values in the two nodes' logs rather than as an unexplained
solve rate. The identifier is derived from the secret, not the secret itself; no cookie
value and no token is ever placed in a log variable.

Every challenge decision — issued, solved, failed, exempt, bypassed, saturated — also
leaves a `debug` log line on target `challenge` naming the domain, the outcome and the
reason (the originating policy's reason on the issued path, which proof was satisfied on
the solved path, which check refused on the failed path), at the same level the ACL and
WAF record their own per-request decisions.

## Domain keys and published counters

Token records and counters are keyed by the **classified domain label**, never by the raw
`Host` header: a host registered on a Location keeps its canonical spelling, and every
unregistered host lands in one shared `<unregistered-host>` overflow bucket. No request can
mint a per-host label, so the key set is the registered host set plus one overflow entry.

Per-domain counters — `issued`, `solved`, `failed`, `expired` (per-domain attribution; the
per-domain rows sum to the total), `bypassed`, `saturated` with its `saturated_domains`,
`saturated_entries` and `stateless_fallback` variants, and `exempt_hit` — are published as
JSON on the admin API at `GET /api/metrics/detection` (capability `view_metrics`). Nothing
is keyed by client identity, and the route is admin-only: no counter is reachable from the
public data plane.

The same document publishes `challenge_markers`: the per-domain count of markers the
`waf`/`acl` entries wrote, counted at the write rather than the read. The read cannot
observe its own gap — a challenge entry that is mis-ordered or absent never sees the
marker — so the write is the side that moves: a `challenge_markers` row climbing while
the same label's `challenge.issued` stays at zero is a marker pipeline no challenge
entry is completing. The projection layer refuses that order when it generates the
plugin list; this counter is what makes the same gap visible in hand-written config,
which the projection never sees.

No admin UI exists for this fork-owned plugin; configure it in the policy TOML or through
the control-plane projection once that projection is enabled.
