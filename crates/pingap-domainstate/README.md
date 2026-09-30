# pingap-domainstate

Bounded, domain-keyed, expiring state for pingap.

One primitive, and deliberately nothing else: a container keyed by `(domain, client
identity)` whose every map has a bound, whose entries expire, and which knows nothing about
what it holds. Four subsystems share the bounding, eviction and expiry logic without sharing
a decision — the payload parameter is unconstrained and no policy vocabulary appears in the
API, so a `should_block`-shaped method showing up here is the signal to stop and move it to
the consumer.

`tests/purity.rs` asserts both halves of that, because the drift is gradual and always looks
reasonable at the diff that introduces it.

## Why it is not on a plugin instance

Plugin instances are rebuilt, not reused, whenever the config hash changes, and the control
plane applies a projected version on every intent edit — so instance-held state is destroyed
routinely, not exceptionally. What that costs: an issued-but-unverified token vanishes on each
apply, a client that spent CPU solving a proof-of-work posts back a nonce for a token that no
longer exists, is re-issued, and solves again. Escalation tiers reset, granting amnesty on
every apply.

One container per subsystem therefore, **process-global, instantiated once, held by nothing on
any plugin instance**. Not persisted across a process restart: a token on disk is a bearer
credential on disk, and a graceful restart re-challenging every client is the cheaper trade.

Global ownership and domain keying are orthogonal. The first gives durability across rebuilds,
the second gives isolation, and `tests/isolation.rs` asserts isolation against a
process-global store rather than a local one so the test proves the arrangement that ships.

## Client identity

`identity::ClientIdentity` resolves, once at construction, which address a request's state is
keyed on:

| Configuration | Identity | Why it is safe |
|---|---|---|
| `basic.trusted_proxies` set | the workspace's existing resolver | already spoof-resistant: a peer not on the list gets its own address back and its forwarded headers dropped |
| `client_ip_from_peer = true` | the TCP peer address | the node is directly exposed, so the peer *is* the client and cannot be forged by the party sending the request |
| neither | **construction refused** | the resolver would return `X-Forwarded-For` verbatim, so the client would pick its own key |

The middle branch is an explicit operator assertion for directly-exposed nodes — a small VPS
terminating its own TLS has no proxy list and needs none. A *false* assertion fails loudly:
every client collapses onto one address and every counter fires globally at once, which is why
`ScopedStore::total_entries` is published. "One identity for the whole site" should be a number
on a dashboard, not an incident to reconstruct.

Refusal is at construction rather than on the request path, so it is loud and pre-startup.

## Bounds

`Limits` has two, and both are required.

| Key | Default | On overflow |
|---|---|---|
| `max_domains` | 256 | `Full::Domains` — a configuration fault. Fail toward the configured policy |
| `max_entries_per_domain` | 5000 | `Full::Entries` — reachable by traffic. The caller decides |

The split matters because the two conditions have different causes. A domain key derives from a
client-supplied `Host` header, and a Location with no host restriction matches every value of
it, so a cap on distinct domains that an attacker can reach is worse than no cap: a flood of
generated hosts consumes it, after which every new client on every real domain is refused a
state entry. `HostPolicy` closes that by collapsing every unregistered host into **one** shared
bucket that never allocates a slot, which makes `Full::Domains` a fault in the operator's own
host list rather than something traffic can cause.

`Full::Entries` is returned rather than resolved by displacing a live entry. Displacement would
let an attacker flush honest clients' state on demand, and would hide saturation from a caller
that has a cheaper fallback — which is the only reason to report it at all.

A cap of zero disables state for that domain: every admission is refused, nothing grows.

## Expiry

Lazy, on access, with no eager sweep promised. A sweep needs a trigger and an owner, and the
only periodic mechanism in the tree holds one interval shared by every task. What is guaranteed
instead:

- an expired entry is unreachable through every accessor, including `remove`, which returns
  `None` rather than the value — reclaim must not double as a read path or a spent credential
  could be replayed;
- a domain reclaims its expired entries the next time it receives any request, so its cap cannot
  be held by stale entries;
- a domain whose entries have all expired gives its slot back, so a long tail of short-lived
  hosts cannot exhaust `max_domains` with empty buckets.

The honest residual: a domain that receives *no* traffic keeps its expired entries until its own
cap forces reclaim. That is bounded by the cap, which is what makes it survivable. If measurement
later shows it is not, a sweep becomes a real requirement with a named owner.

An entry is live while the clock is strictly before its deadline, so a refresh extends the TTL
from the refresh rather than from the original insert — a client that keeps arriving is not
dropped mid-session because of when it first did.

`ManualClock` is exported so expiry tests advance time by hand. Nothing here sleeps: a clock that
needed a background thread would not survive daemonisation, since pingora's `fork()` carries only
the calling thread.

## Synchronisation

A `Mutex`, not a lock-free map. The container is read *and* written per request under a key, and
the lock is what makes a take-once operation atomic: two concurrent presentations of the same
entry produce exactly one `Some` from `remove`. Sharding is a local change to one type if
measurement ever shows contention; `benches/store.rs` exists so that question is answered with a
number rather than an intuition.

A poisoned lock is recovered from rather than propagated. A panic in one worker would otherwise
make the container unusable for the life of the process, turning one bad request into an outage,
and the invariants here — a bound and a deadline — are re-checked on every access.

## Dependencies

`pingap-core` (the client-address resolver, the trusted-proxy accessor and the clock),
`pingora` (the session type) and `snafu`. No new crates.

Unlike its siblings this crate has no `plugin` feature: nothing depends on it yet, so a gated
module would be compiled by no `--features` combination CI passes and would rot unread. Every
consumer of it is itself a plugin, so the pingora dependency costs them nothing.
