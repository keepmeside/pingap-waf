# Behaviour Plugin

Behavioural detection is off by default — set `enabled = true` to turn it on. It keeps
bounded per-domain, per-client profiles and publishes a non-terminal score. A score can
influence the challenge level, but it cannot deny or originate a challenge by itself. A
weight of zero disables a signal; there are no separate per-signal enable flags.

Profiles are keyed by client identity, so enabling the detector carries the same
contract as the challenge tier: either `basic.trusted_proxies` or the explicit
`client_ip_from_peer = true` assertion on a directly exposed node, or the plugin
refuses to build naming both remedies. Adoption is judged against the config under
validation, not the one running — one apply that sets the key and enables the
detector together is accepted, and one that drops the key while the detector stays
enabled is refused. Hot reload keeps the running value, so on `--autoreload` and
etcd-watch nodes a first adoption commits but the plugin fails to construct at each
reload until the process restarts; a node whose running `basic.trusted_proxies` is
already set adopts the detector by reload alone.

The inherited default weights and thresholds are starting values, not measured guidance.
Tune them against the traffic of each domain.

Each signal contributes a humanness credit between 0 and 100, and the weighted average is
the score: timing credit is paid for *irregular* inter-request intervals — a metronomic
client is the machine-like shape — URL entropy and path diversity for varied URLs, speed
for slowness, error pattern for the absence of errors, and user-agent consistency for a
single agent.

| Key | Default |
| --- | --- |
| `enabled` | `false` |
| `window` | `5m` (300 s) |
| `max_clients` | `5000` |
| `max_url_keys` | `64` |
| `max_user_agents` | `8` |
| `max_interval_samples` | `32` |
| `min_samples` | `6` |
| `budget_ms` | `2` |
| signal weights | `25,20,20,15,10,10` (timing, entropy, diversity, speed, errors, UA) |

Profiles are bounded from insertion, and overflow is counted. A profile at every cap
measures ≈6.5 KB (counting-allocator measurement, `crates/pingap-behaviour/tests/footprint.rs`),
so a domain at the default `max_clients = 5000` holds ≈33 MB of profiles at the cap. The
interval-sample window and the URL aggregate rebuilt from it dominate that footprint, so
`max_interval_samples` and `max_url_keys` are the two levers. Per request, landing one
observation and scoring the full profile measure ≈4.9 µs at p50 and ≈5.1 µs at p99
(`cargo bench -p pingap-behaviour --bench scoring`), recorded separately from the detector
and container costs. Error observations can be
biased toward requests that reached the response hook; low observation counts therefore
produce no confident signal.

Profiles and counters are keyed by the **classified domain label**, never by the raw
`Host` header: a host registered on a Location keeps its canonical spelling, and every
unregistered host lands in one shared `<unregistered-host>` overflow bucket. No request
can mint a per-host label.

Per-domain classification counters — `human`, `suspicious`, `bot`, `ddos` and
`insufficient` (too few signals to classify), the same fixed name set the
`behaviour_profile` access-log variable writes — are published as JSON on the admin API
at `GET /api/metrics/detection` (capability `view_metrics`). Nothing is keyed by client
identity, and the route is admin-only: no counter is reachable from the public data plane.

Alongside the counters, `behaviour_tracked` publishes a per-domain gauge of distinct
identities currently holding a profile. The counters count events; the gauge counts
clients. A gauge pinned at 1 while the same label's request counters climb is the
detectable shape of a false `client_ip_from_peer` assertion — every request mapped onto
one identity, most often a proxy that was trusted without being one. The gauge is
aggregate and per-domain like every other published number; no identity itself is
published.

No admin UI exists for this plugin yet.
