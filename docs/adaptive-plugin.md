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
| `persist` | `true` (hourly aggregate only, ~1.3 KB per domain) |
| `max_baseline_age_days` | `14` |
| `sample_window` | `1h` (3600 s) |
| `client_ip_from_peer` | `false` — assert the node is directly exposed when no trusted-proxy list is configured |

Denied, challenged, and bot-classified traffic is excluded from samples so known attacks
cannot train the baseline to tolerate them. Persistence stores derived hourly aggregates,
not client identities or raw requests.

The ratio and factor ladders, `min_confidence`, `min_days_to_calibrate`, `max_baseline_age_days`
and `min_factor` are inherited starting values, not figures measured against this product's
traffic. `max_samples_per_hour` is a chosen bound that caps per-request sampling cost, not a
tuned limit. Tune them per domain; a low-traffic domain may never calibrate, and the static
configured limits apply in that case.

No admin UI exists for this plugin yet.
