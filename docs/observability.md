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

## Not built yet

- **Nothing feeds the queue.** The WAF publishes access-log variables and the queue and writer
  exist and are tested, but no producer offers findings to the queue and no background task
  drives the writer. Wiring both needs a decision about where a process-global sink lives that a
  plugin crate can reach: `pingap-core` is vendored, `pingap-controlplane` would pull `turso`
  into a plugin, and a third small crate is the clean answer and a new workspace member.
- **No rollup worker.** `performance_metrics` has a table, an index and a prune method, and
  nothing computes a row. Rates, percentiles and deltas are to be computed in Rust, not SQL:
  the store's window functions have no `lag` or `lead` and no custom frames.
- **No query routes.** `read_waf_events` takes a time range; filtering by domain, rule, verdict
  and category is not built, and neither are the `logs`, `dashboard` or `performance` endpoints.
- **No ACL verdict.** The ACL plugin's state records `decided_by: Option<usize>` — a *position*
  in the rule list, not a stable identifier. Publishing a position under a name that reads like
  an ID would put a number in every log line that silently changes meaning the next time someone
  reorders a rule. It needs an identifier on the rule first.
- **Redaction is stored as not-blocked.** `waf_events` has one `blocked` column, so the queue
  protects a redaction like a block but the table cannot tell them apart. Widening the column is
  a migration.
- **No load test.** The queue's behaviour under deliberate overload is asserted by unit test;
  sustained traffic with the WAF enabled, confirming no request-path latency attributable to
  event writing, has not been measured.
