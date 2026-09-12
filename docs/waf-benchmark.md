# WAF latency

What the WAF adds to a request, measured after the detector port. Phase 04 owes an
absolute number here rather than a pass/fail, because nobody can predict this from
reading the code — and the number turned out to matter.

Reproduce both tables:

```bash
cargo bench -p pingap-waf --bench latency   # per-call p50/p99, table 1
cargo bench -p pingap-waf --bench bench     # criterion A/B, table 2
```

Hardware and build: `x86_64-unknown-linux-gnu`, release profile, 153 native request
rules and 40 response rules compiled from the ported detector set. Absolute values move
with the machine; the ratios in table 2 do not.

## 1. Per-call latency, detectors loaded

2000 timed calls each after a 200-call warmup, percentiles read off the sorted samples.
Not criterion means — a p99 computed from batch means is not a p99 of calls.

| Shape | p50 | p99 | max | budget cuts |
|---|---|---|---|---|
| request: headers + URI + query | 769 µs | **815 µs** | 1.28 ms | 0/2000 |
| request: same, plus a 1 KB body | 2.80 ms | **2.87 ms** | 3.20 ms | 0/2000 |
| response: 1 KB body, one hook | 1.34 ms | **1.39 ms** | 1.67 ms | 0/2000 |
| response: 1 KB body, both hooks (cache miss) | 2.69 ms | **2.74 ms** | 3.00 ms | 0/2000 |

The distributions are tight — p99 sits within 6% of p50 on every shape, and the maximum
within 20%. That is the useful part of the result: cost here is proportional to
rules × fields × bytes, not driven by a backtracking tail. Phase 03's `cost_check` gate
on lookaround shapes is what keeps it that way, and no inherited pattern needed
rewriting on cost grounds.

Zero budget cuts at the shipped 10 ms budget, so these are the rules' real cost rather
than the budget's ceiling.

### Worst realistic request

A `POST` with a 1 KB body to a cacheable Location, on a cache miss, pays both the
request-body scan and both response scans:

**2.87 ms + 2.74 ms ≈ 5.6 ms p99 added latency.**

## 2. Against the pre-detector floor

Phase 03 recorded the engine's cost with eight operator-authored patterns and no
detectors. Same criterion benchmarks, same fixtures, so the columns are comparable.

| Shape | 8 patterns (Phase 03) | Detectors loaded | Factor |
|---|---|---|---|
| request: headers only | 23.7 µs | 815 µs | 34× |
| request: 1 KB body | 28.5 µs | 3.05 ms | 107× |
| request: blocking | 64.7 µs | 1.11 ms | 17× |
| response: 1 KB prefix | 0.90 µs | 1.50 ms | 1675× |
| config load: validate + build | 2.49 ms | 71.0 ms | 28× |

Two of these deserve a note.

**Blocking is now cheaper than allowing** (1.11 ms against 3.05 ms). Evaluation stops
at the threshold crossing, so a malicious request exits early while a legitimate one
runs every rule. The allow path is the one to optimise; it is also the one every real
request takes.

**Config load costs 71 ms.** That is the reload path, not the request path — a config
change recompiles the ruleset once. Acceptable for a reload, and worth knowing before
someone builds a feature that rebuilds an engine per request.

## 3. Assessment

**This is above what a reverse proxy should add, and it is a per-request cost on the
allow path.** For a gateway whose own overhead is tens of microseconds, 815 µs on a
headers-only request and 5.6 ms on a `POST` to a cacheable Location is a large multiple
of the traffic it is protecting. Phase 04's risk register named this outcome in advance
("Latency is worse than expected… signal: step 12 shows p99 growth an operator would
reject") and its prescribed response is a **defaults change**: headers-only inspection
by default, body inspection opt-in per Location, and the cache-hit response
registration disablable per domain with the exposure documented.

That change is **not applied here.** Step 12 is defined as a measurement obligation, and
turning body inspection off by default trades a security default for latency — the kind
of trade this plan puts to an operator rather than deciding silently. Recording it is
the deliverable; choosing it is not.

The structural cause is worth stating because it bounds what tuning can achieve. Cost is
`rules × fields × bytes`: a headers-only request runs 153 patterns across roughly 15
fields, so ~2300 regex executions at ~330 ns each. Nothing prefilters. A literal
prescan (Aho-Corasick over each pattern's required substrings, skipping patterns that
cannot match) is the standard fix and typically removes most of that work, but it is an
engine change and outside this phase.

Options, cheapest first:

1. **Narrow the default field set.** Most patterns cannot match most fields. Cost falls
   proportionally, and nothing about the detection model changes.
2. **Literal prefilter in the engine.** The real fix. Bounded, testable against the
   frozen corpus, and it changes no rule semantics.
3. **Defaults change per the risk register.** Cheapest to ship, weakest posture — it
   buys latency by not inspecting bodies.

## 4. What these numbers exclude

The engine, not the plugin wrapper. Extracting header pairs from a pingora `Session` and
the `Bytes` copy the request-body buffer makes are not counted — both are borrows and
one memcpy against pattern matching over the same bytes, so they do not move these
figures, but they are not in them.

Detector accuracy over the frozen corpus is a separate measurement; see
[`spikes/detector-baseline.md`](./spikes/detector-baseline.md).
