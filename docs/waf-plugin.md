# `waf` plugin

Native WAF rule matching, wired into pingap as a per-Location plugin. No
libmodsecurity, no SecLang, no C++ in the request path — which is what keeps the musl
static build working.

Attach it like any other plugin:

```toml
[plugins.waf]
category = "waf"
categories = { sql_injection = "detect", xss = "detect" }

[locations.app]
upstream = "app"
plugins = ["waf"]
```

A Location that does not list the plugin never receives an instance, so enabling the WAF
on one domain and not another is a matter of which Locations name it. Note that a plugin
name maps to **one process-global instance**: two Locations listing `waf` share its
configuration. Divergent policy means two named entries, not one name listed twice.

## Configuration

| Key | Default | Meaning |
| --- | --- | --- |
| `step` | `request` | Only `request` is accepted. A typo fails at config load rather than producing a WAF that silently never runs |
| `categories` | all `detect` | Per-category mode, keyed by the names in [waf-category-mapping.md](./waf-category-mapping.md) |
| `paranoia` | `1` | `1`–`4`. Rules above the level do not participate. Higher finds more and costs more |
| `anomaly_threshold` | `5` | Accumulated score at which a request in `block` mode is refused |
| `budget_ms` | `10` | Per-request evaluation budget |
| `on_budget_exhausted` | `allow` | `allow` or `block`, for an evaluation that could not finish |
| `body_inspect_limit` | `131072` | Request-body bytes to inspect. Capped independently of `client_max_body_size` so the two cannot silently disagree. `0` is refused — there is no "inspect nothing" setting |
| `over_cap` | `inspect_prefix` | `inspect_prefix` or `reject`, for a body past that limit |
| `response_prefix_limit` | `65536` | Response-body prefix to inspect. The response hook is synchronous, so a whole body is never buffered |
| `ip_list` | none | Addresses and CIDR ranges, matched before any pattern runs |
| `ip_list_mode` | `deny` | `deny` or `allow` |
| `custom_rules` | none | Operator-authored patterns; see below |

### Modes, and why response-side has fewer

| Mode | Request-side | Response-side |
| --- | --- | --- |
| `off` | ✓ | ✓ |
| `detect` | ✓ — record a hit, allow the request | ✓ |
| `block` | ✓ — refuse with 403 | **rejected at config load** |
| `redact` | rejected at config load | ✓ — mask the matched bytes in place |

`block` on a response-side category is not accepted, and not silently downgraded.
`ResponseBodyPluginResult` is `Unchanged | PartialReplaced | FullyReplaced` — there is
no variant that denies — and by the time a body hook runs the status and headers are
already downstream. A `block` that behaved as `redact` would tell an operator a leak is
prevented when it is only being rewritten on the way past.

**`detect` is the default and should stay the default until a category's false-positive
rate is known on *your* traffic.** The ported detectors measure 0 false positives over
the frozen 560-case benign corpus, but that corpus is a regression fence, not a sample
of production. See [spikes/detector-baseline.md](./spikes/detector-baseline.md).

### Custom rules

```toml
[plugins.waf.custom_rules.no-internal-paths]
category = "local_file_inclusion"
pattern = '(?i)/internal/(admin|debug)'
severity = "error"      # notice | warning | error | critical → score 2 | 3 | 4 | 5
paranoia = 1
action = "block"        # optional; overrides the category's mode for this rule alone
```

Patterns are rejected at config load if they cannot compile, if they exceed 2,000
characters, or if they carry an unbounded quantifier inside a lookaround. That last shape
is quadratic in input size and nothing at runtime can bound it — measured at 1 KB =
1.0 ms rising to 16 KB = 243.6 ms, extrapolating to ~15 s at the default
`body_inspect_limit`, with neither the backtrack limit nor `budget_ms` able to preempt a
rule already running.

`*`, `+` and `{n,}` all count as unbounded there, including inside a negated character
class — `(?=[^&]*etc)` is rejected for the same reason as `(?=.*etc)`. Use a bounded
repetition (`(?=.{0,64}etc)`) or, better, split the intent into separate rules whose
anomaly scores sum to the threshold.

## `ip_list` requires `basic.trusted_proxies`

Construction **fails**, naming the key, if `ip_list` is set while
`basic.trusted_proxies` is not:

```toml
[basic]
trusted_proxies = ["10.0.0.0/8"]   # your own proxies, not the world
```

With no trusted-proxy list, pingap honours `X-Forwarded-For` unconditionally — fine for
logging, and not a basis for an access decision, because the address is then one the
client chose. An `allow` list with no entries is refused for the same class of reason: it
would reject every request including the operator's own.

The client IP itself comes from pingap's own resolver, the same one the access log uses,
so a block can always be correlated with the traffic that caused it.

## Two response hooks, on purpose

Response-side detection is registered on both `handle_upstream_response_body` (before
cache admission) and `handle_response_body` (the serving path). Each alone leaves half
the behaviour missing: the first never fires on a cache hit, so a body admitted while a
category was `off` would be served unredacted for the rest of its TTL — with no hit and
no event, so the dashboard would show zero findings. The second does not change what is
stored in the cache.

The cost is a double scan on a cache miss, and it is measured rather than assumed.

## Before you enable body inspection

Inspection is not free, and the cost lands on the **allow** path — blocking is cheaper,
because evaluation stops at the threshold crossing. Measured p99 added latency: 815 µs
for headers and query only, 2.87 ms with a 1 KB body, and ~5.6 ms for a `POST` to a
cacheable Location on a cache miss. Full numbers, the structural cause, and the options
for reducing it are in [waf-benchmark.md](./waf-benchmark.md).

## Logging

Verdicts carry the rule ID, category, severity and anomaly score as structured data on
the request context — not a log line to be re-parsed. Raw bodies are never logged; a hit
records the rule and the matched field name.
