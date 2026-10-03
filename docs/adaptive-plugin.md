# Adaptive Plugin

The adaptive learner is off by default and is a modulation layer over the configured
policy. Before calibration, after a restore, or after a stale baseline is discarded, the
configured static limits apply exactly. Learned output can tighten a limit and select a
stronger challenge for a request already marked for challenge; it cannot create a refusal
or a challenge on an otherwise allowed request.

| Key | Default |
| --- | --- |
| `enabled` | `false` |
| `max_samples_per_hour` | `240` |
| `min_days_to_calibrate` | `7` |
| `min_confidence` | `0.6` |
| ratio ladder | `2,3,5,10,20` |
| factor ladder | `0.9,0.75,0.5,0.25,0.1` |
| `min_factor` | `0.1` |
| `allow_loosening` | `false` |
| `modulate_rate_limit` | `true` |
| `persist` | `true` (hourly aggregate only, ~1.3 KB per domain) |
| `max_baseline_age_days` | `14` |
| `sample_window` | `1h` (3600 s) |
| `client_ip_from_peer` | `false` — assert the node is directly exposed when no trusted-proxy list is configured |

Samples are keyed by client identity, so enabling the learner carries the same
contract: either `basic.trusted_proxies` or the `client_ip_from_peer` assertion
above, or the plugin refuses to build naming both remedies. Adoption is judged
against the config under validation, not the one running — one apply that sets
the key and enables the learner together is accepted, and one that drops the key
while the learner stays enabled is refused. Hot reload keeps the running value,
so on `--autoreload` and etcd-watch nodes a first adoption commits but the
plugin fails to construct at each reload until the process restarts; a node
whose running `basic.trusted_proxies` is already set adopts the learner by
reload alone.

Denied, challenged, and bot-classified traffic is excluded from samples so known attacks
cannot train the baseline to tolerate them. Persistence stores derived hourly aggregates,
not client identities or raw requests.

The learned rate factor is a dial on the configured limiter, and the dial is explicit:
`modulate_rate_limit` decides whether the factor reaches a limiter at all. The factor
multiplies the ceiling of whatever `limit` plugin handles the request — the limiter keeps
its own keying (per-IP, header, cookie or query), so a per-domain multiplier over a per-IP
limiter is not a per-domain limiter, and the operator declares the first, never the second.
`false` leaves the configured ceiling exactly in force while learning, calibration and the
challenge-level dial continue.

The ratio and factor ladders, `min_confidence`, `min_days_to_calibrate`, `max_baseline_age_days`
and `min_factor` are inherited starting values, not figures measured against this product's
traffic. `max_samples_per_hour` is a chosen bound that caps per-request sampling cost, not a
tuned limit. Measured (`cargo bench -p pingap-adaptive --bench sampling`), the full
per-request learner sequence — rate observation, sample recording, the ratio decision and
the factor clamp — costs ≈1.2 µs at p50 and ≈1.5 µs at p99 with the hourly profile at its
sample cap, so recording stays on every request rather than being sampled down to every
Nth. Tune them per domain; a low-traffic domain may never calibrate, and the static
configured limits apply in that case.

## Domain keys

Learners are keyed by the **classified domain label**, never by the raw `Host` header: a
host registered on a Location keeps its canonical spelling, and every unregistered host
lands in one shared `<unregistered-host>` overflow bucket. No request can mint a per-host
label.

## Persistence across restarts

With `--admin` (the control-plane store), a background task restores every stored baseline
once at startup and then writes a domain's baseline back only when it changed, so an
idle-but-calibrated learner costs nothing per cycle. A restored learner resumes
**uncalibrated** and re-earns calibration from live samples rather than trusting the stored
aggregate. A stored row past `max_baseline_age_days` is discarded visibly — the discard is
counted on the learner and published, not silently dropped. A baseline keeps its own
learned time across restarts, so its age stays honest instead of refreshing on every
restart. With no adaptive plugin constructed in the deployment, the stored rows simply stay
put until one is.

## Published state

Per-domain state — `enabled`, `calibrated`, `samples`, `samples_required`, `confidence`,
`min_confidence`, `discarded_baselines` and `modulated` (counted per fixed decision reason,
only when a calibrated decision actually moved a dial) — is published as JSON on the admin API
at `GET /api/metrics/detection` (capability `view_metrics`). The calibration gate is published
with its reading: `samples` against `samples_required` and `confidence` against
`min_confidence`, so "not yet calibrated" reads as "8 of 168 samples" rather than a silent
false. A config apply that sets `enabled = false` does not erase what was learned — the row
survives and carries `enabled: false`, saying the feature is off instead of reading as a live
calibrated learner; with no adaptive plugin ever constructed there are no rows at all. Nothing
is keyed by client identity, and the route is admin-only: no metric is reachable from the
public data plane.

No admin UI exists for this plugin yet.
