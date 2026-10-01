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
| `max_entries` | `4096` | Maximum outstanding token records |
| `max_domains` | `256` | Maximum active domain buckets before the policy fails toward its configured outcome |
| `loop_threshold` | `3` | Repeated unsolved challenges trigger the configured bypass direction |

When the entry cap is reached, the plugin uses a stateless HMAC proof instead of admitting
the request. When the domain cap is reached, it fails toward the configured policy. Both
paths are counted separately so saturation cannot look like normal challenge traffic.

`difficulty`, `token_ttl`, `pass_ttl`, `max_attempts`, `loop_threshold` and the `ladder` are
inherited starting values, not figures measured against this product's traffic. The
`max_entries` and `max_domains` caps are chosen bounds that bound memory, not tuned limits.
Tune them per domain.

No admin UI exists for this fork-owned plugin; configure it in the policy TOML or through
the control-plane projection once that projection is enabled.
