# Behaviour Plugin

Behavioural detection is off by default — set `enabled = true` to turn it on. It keeps
bounded per-domain, per-client profiles and publishes a non-terminal score. A score can
influence the challenge level, but it cannot deny or originate a challenge by itself. A
weight of zero disables a signal; there are no separate per-signal enable flags.

The inherited default weights and thresholds are starting values, not measured guidance.
Tune them against the traffic of each domain.

| Key | Default |
| --- | --- |
| `enabled` | `false` |
| `window` | `5m` (300 s) |
| `max_clients` | `5000` |
| `max_url_keys` | `64` |
| `max_user_agents` | `8` |
| `min_samples` | `6` |
| `budget_ms` | `2` |
| signal weights | `25,20,20,15,10,10` (timing, entropy, diversity, speed, errors, UA) |

Profiles are bounded from insertion, and overflow is counted. Error observations can be
biased toward requests that reached the response hook; low observation counts therefore
produce no confident signal. No admin UI exists for this plugin yet.
