# Observability

What the gateway already instruments, what this fork adds, and what is still missing. Written
so the two are not confused: most of what an operator expects from "observability" was already
here before the WAF existed, and rebuilding it would produce two answers to the same question.

## Already provided, and unchanged

Nothing in this fork modifies these crates.

| Crate | What it gives you |
| --- | --- |
| [`pingap-logger`](../pingap-logger/README.md) | Access logs with a `{tag}` format language, file / syslog / stdout writers, rotation and compression. 27 tag categories including request and response headers, cookies, timing breakdowns, and `{:name}` for a `Ctx` variable |
| [`pingap-performance`](../pingap-performance/README.md) | Prometheus counters, gauges and histograms for traffic, latency, upstream behaviour and caching — `pingap_http_requests_total`, `pingap_http_response_time`, `pingap_http_responses_codes` and the rest — plus process introspection: memory, CPU count, threads, file descriptors, TCP connection counts |
| [`pingap-otel`](../pingap-otel/README.md) | A span per request, joined to any incoming trace context, exported over OTLP. Behind the `tracing` feature |
| `pingap-sentry` | Error reporting. Behind the `tracing` feature |
| `pingap-pyroscope` | Continuous CPU profiling. Behind the `pyro` feature |

Prometheus is pull by default and there is a push service for a short-lived process. The
`stats` plugin exposes the process metrics through the admin API.

If a question can be answered by a counter or a histogram, it is probably already answered
there, and the answer is better than anything this fork would add: those numbers are collected
on the request path by the proxy itself.

## What this fork adds

### Verdicts as structured data, not as text to re-parse

The reference product this fork replaces derives WAF verdicts and client fingerprints by
regex-parsing nginx access-log files, because it sits outside nginx. This gateway is inside the
proxy, so a verdict is structured data on the request context the moment it is decided:
`WafState` carries the profile, every hit with its rule ID, category, severity and score, the
total and enforcing scores, and three caveats — whether inspected bytes were truncated, whether
evaluation ran out of budget, whether a response was redacted. `BotState` carries the JA4H
fingerprint.

Nothing downstream re-parses a log line to recover any of it.

### The same verdict in the access log

Structured data on a context is not something an operator can grep. So the WAF also publishes
its verdict as access-log variables, reachable with `{:name}` tags:

```toml
[servers.https]
access_log = "{remote} {method} {path} {status} {:waf_action} {:waf_rules} {:waf_score}"
```

The full list, when each field is present, and why a clean request renders `pass` with empty
detail fields: [`docs/waf-plugin.md`](./waf-plugin.md#logging). The bot plugin's `{:ja4h}` uses
the same mechanism.

**Two defects had to be fixed before any of this rendered.** `{:name}` resolves through
`Ctx::append_log_value`, which did not read the variables map at all — that map fed
`location.rewrite` and nothing else — and separately the tag parser's character class excluded
digits, so `{:ja4h}` did not even parse and was emitted as literal text. `{:ja4h}` had been dead
since the JA4H support landed. Both are fixed, and the test asserts on rendered log bytes rather
than on the variables map, because an assertion against the map is exactly the one that passes
while every field renders empty.

### Findings that survive a burst

A finding is produced on the request path and written to the store by a batcher, and the two run
at very different speeds. Between them is a bounded queue whose policy is that **a finding which
stopped or altered a request is never discarded**:

- a `detect` is droppable, and is dropped when the queue is full;
- a `block` or `redact` displaces the oldest queued `detect` to get in;
- when the queue holds nothing droppable, the overflow is *counted* rather than stored —
  coarser than a row, but a number an operator can see move, where a discarded record is
  invisible by definition.

An undifferentiated drop-on-full queue fails in the exact conditions that make the record worth
keeping, because the queue fills during a volumetric attack, when findings spike. Nothing in the
queue blocks: a WAF that stalls traffic because its audit sink is slow is worse than one that
loses a sample.

Writes are batched into one transaction, which is load-bearing rather than an optimisation —
measured against this store, 330 rows/s inserted serially against 71,330 batched. A failed write
puts the batch back into the queue rather than losing it, and logs how many came back.

### Retention, and the two tables it does not touch

`waf_events` and `performance_metrics` are swept on a window: seven days of findings by default,
ninety days of rollups, because a rollup is the only record left once the findings it summarised
are gone.

`activity_log` and `alert_history` are **not** prunable and that is deliberate. They are
append-only: the store trait exposes no update and no delete for either, and a test asserts it by
reading the trait's own source. An audit trail that can be shortened through the same handle
that writes it is not an audit trail. The consequence is that they grow without bound, and the
reclaim path is `VACUUM INTO` at backup time rather than a sweep. Bounded growth is a real
requirement and the obvious way to meet it is a window on the audit trail; the test names
`prune_activity` and `prune_alert_history` so that doing it is a decision rather than a
convenience.

## What remains deliberately open

- **Nothing feeds the queue yet.** The WAF publishes access-log variables and the queue and writer
  exist and are tested, but no producer offers findings to the queue and no background task drives
  the writer. Sink ownership remains deliberately undecided: vendored `pingap-core`, linking
  `turso` into a plugin, or a third shared crate are materially different dependency boundaries.
- **No live rollup worker.** The pure Rust rollup and `performance_metrics` read/write paths exist,
  and `/api/performance` plus `/api/dashboard` expose stored rows. No runtime worker computes rows
  yet, so an empty series means no stored rollup, not zero traffic. Turso lacks the needed window
  functions, so rates, percentiles and deltas remain Rust-side.
- **No ACL verdict.** `decided_by: Option<usize>` is a rule-list position, not a stable identifier;
  it needs a stable rule ID before it can be logged.
- **Redaction is stored as not-blocked.** `waf_events` has one `blocked` column, so a migration is
  needed to distinguish redaction from detection in persisted rows.
- **No load test.** Queue overload is asserted by unit test; sustained WAF traffic and request-path
  latency attributable to event writing remain unmeasured.
- **Retention is implemented but not scheduled.** The tables have bounded sweep methods and
  defaults; runtime configuration and periodic scheduling remain open.

The query routes are read-only and do not fabricate request rate, latency, percentiles, upstream
health, bot analytics, or findings that have not reached the store. Those broad metrics remain
owned by existing Prometheus/performance instrumentation until live rollup inputs are designed.

## Query routes now available

- `GET /api/logs/waf-events` reads structured findings with domain, rule, category, verdict and
  time filters.
- `GET /api/performance` reads stored rollup rows oldest-first with bounded time, metric and limit
  filters.
- `GET /api/dashboard` returns the same rollup window plus storage-backed config drift. Drift is
  `unavailable` when no source is wired or it cannot be parsed; diagnostics and config contents
  are never returned.

All three are authenticated and read-only; the server-side route table, not UI visibility, is the
RBAC control.

## Security and data-shape gaps

`waf_events` still lacks matched-field excerpts, latency, and a distinct persisted redaction
verdict. These are schema decisions, not silently inferred values.

## Not built yet

- Live queue producer and background writer (sink ownership decision pending).
- Rollup worker inputs, retention scheduling, and overload latency measurement.
- ACL stable identifiers and the distinct redaction schema.
- Dashboard analytics beyond stored WAF rollup rows.

The queue's priority policy and its tests remain valid: enforced findings are protected from
queue eviction, while detect findings may be dropped under overload.

This page deliberately does not claim the Phase 11 success criteria that require those missing
runtime integrations.
