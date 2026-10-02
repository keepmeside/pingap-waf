# WAF latency

What the WAF adds to a request, measured after the detector port and again after the
literal prefilter. The port owed an absolute number rather than a pass/fail, because
nobody can predict this from reading the code — and the number turned out to matter:
the first measurement is what prescribed the prefilter, and the second is what it
delivered.

Reproduce both tables:

```bash
cargo bench -p pingap-waf --bench latency   # per-call p50/p99, table 1
cargo bench -p pingap-waf --bench bench     # criterion, table 2
```

Hardware and build: `x86_64-unknown-linux-gnu`, release profile, 116 native request
rules and 40 response rules compiled from the ported detector set. The "before
prefilter" columns are a clean checkout of the pre-change tree (`2f7f349`), benched
interleaved with the current tree — before and after runs alternating in one session
on the same machine — because absolute percentiles move with ambient load; in that
session the p50s repeated within 1% across runs, and the ratios are the measurement.

## 1. Per-call latency, detectors loaded

2000 timed calls each after a 200-call warmup, percentiles read off the sorted samples.
Not criterion means — a p99 computed from batch means is not a p99 of calls.

| Shape | p50 | p99 | max | budget cuts | before prefilter (p50 → p99) |
|---|---|---|---|---|---|
| request: headers + URI + query | 124 µs | **137 µs** | 175 µs | 0/2000 | 700 µs → 727 µs |
| request: same, plus a 1 KB body | 524 µs | **581 µs** | 919 µs | 0/2000 | 2.73 ms → 2.78 ms |
| response: 1 KB body, one hook | 73 µs | **83 µs** | 157 µs | 0/2000 | 1.34 ms → 1.37 ms |
| response: 1 KB body, both hooks (cache miss) | 146 µs | **173 µs** | 247 µs | 0/2000 | 2.68 ms → 2.71 ms |

The distributions are tight — p99 sits within 20% of p50 on every shape, and every
maximum is sub-millisecond. Cost is proportional to rules × fields × bytes, not driven
by a backtracking tail; the rule engine's `cost_check` gate on lookaround shapes keeps
it that way. Zero budget cuts at the shipped 10 ms budget, so these are the rules'
real cost rather than the budget's ceiling.

### Worst realistic request

A `POST` with a 1 KB body to a cacheable Location, on a cache miss, pays both the
request-body scan and both response scans:

**581 µs + 173 µs ≈ 0.75 ms p99 added latency — down from ≈ 5.5 ms before the
prefilter, a 7.3× reduction with verdicts pinned identical (see §3).**

## 2. Against the pre-detector floor

The floor is the same engine with eight operator-authored patterns and no detectors,
measured in the pre-prefilter checkout (`2f7f349`) — as is the middle column, that
checkout's detector set. The right column is the same detector set with the
prefilter, from the current tree's run adjacent to it in the same session. Same
criterion benchmarks, same fixtures, so the columns are comparable.

| Shape | 8 patterns (floor) | Detectors, before prefilter | Detectors, with prefilter |
|---|---|---|---|
| request: headers only | 23.2 µs | 700 µs | **138 µs** |
| request: 1 KB body | 34.2 µs | 3.14 ms | **555 µs** |
| request: blocking | 62.4 µs | 1.01 ms | **316 µs** |
| response: 1 KB prefix | 0.88 µs | 1.47 ms | **79 µs** |
| config load: validate + build | 2.43 ms | 68.3 ms | **88.5 ms** |

Three of these deserve a note.

**Blocking improved 3.2× and is still cheaper than allowing with a body** (316 µs
against 555 µs). Evaluation stops at the threshold crossing, and the prefilter
shortens the road there: a matching payload opens its own gates, but the patterns
that cannot match it no longer run on the way to the crossing.

**Config load costs 88.5 ms, up from 68.3.** The build now also extracts every
pattern's literal set and constructs the automaton. That is the reload path, not the
request path — a config change recompiles the ruleset once — and worth knowing before
someone builds a feature that rebuilds an engine per request.

**The floor itself moved, in both directions.** Request-side, the eight-pattern floor
improved (23.2 → 20.6 µs headers, 34.2 → 24.1 µs body): even a small ruleset pays
for skipping its non-matching patterns. The response floor regressed 0.88 → 2.05 µs
— with two response patterns, the prescan costs more than the regexes it replaces.
Microsecond-scale and bounded by field size; on the detector set the same prescan is
an 18× win (1.47 ms → 79 µs).

## 3. The prefilter, applied

The pre-detector numbers above prescribed their own fix — cost was
`rules × fields × bytes`, every pattern over every field — and it is now applied:
the literal prefilter in the engine. No config knob, always on; the defaults
(`body_inspect_limit`, both response hooks) are unchanged, because the decision was
the prefilter, not the defaults change.

One Aho-Corasick automaton, built once per `RuleEngine::build` from the union of
every rule's required literals. One ASCII-case-insensitive pass over a superset of
the field texts any rule can inspect — every header value, the method, the URI,
query values and the clamped body, each in its raw, percent-decoded and
`+`-decoded form. A rule whose needles are all absent is skipped before its regex
runs, budget included: a skipped rule checks nothing, and `rules_checked` says so.

**Coverage is pinned, not assumed.** 154 of the 156 native patterns yield a literal
set. The two that do not are ungated by construction and always run:
`data_leakage` 65 — a literal key name followed by a 16-or-more-character secret
body; the body is the detection, and bounding it would only find secrets whose
characters were already known — and `web_shell` 61 — a passwd-shaped line whose head
and tail are unbounded classes; the shape between them is the detection. A test pins
this allowlist: a pattern that joins or leaves the ungated set fails CI rather than
silently always-running.

**Soundness is the threat model and it is test-pinned.** An unsound skip is silent
detection loss, so a skip is made only when provably no match: `regex-syntax`'s
literal extractor returns prefix and suffix sets whose members are contained in every
match of the pattern, an empty alternative voids the rule's gate, an unparsable
pattern gets no gate, and the automaton's case handling only over-approximates which
rules run. The frozen corpus — 726 cases, hash-pinned — runs every case in all three
input forms twice, once with the real gate and once with a forced-open gate, and
asserts identical verdicts, hits, enforcing scores, exhaustion and truncation. And
because an equivalence run over text that never fires cannot catch a scan line that
went missing, every carrier the prescan walks — method, URI, query, header, body,
response header, response body — is pinned by a probe that fires through that
carrier alone. That equivalence is why the latency win above can be trusted to
change no verdict.

**What the skip does to the budget.** The prescan runs off the budget clock — the
budget bounds rule evaluation, exactly as it did before the prefilter — and a rule
proven absent is a completed evaluation, not an unfinished one: it checks nothing,
so `rules_checked` reads lower and an evaluation finishes *more* often than an
unfiltered engine's. Exhaustion can only lift (`Some` → `None`), never newly
appear; with `on_budget_exhausted = block` that means a body whose absent rules
would have spent the budget is allowed as verified rather than blocked as
unfinished. That is the deliberate direction — a proven no-match is not an
unfinished check — and a test pins the mechanism through `rules_checked`.

**The defaults question this document used to leave open is closed by this
measurement.** The prescribed defaults change — headers-only inspection by default,
body inspection opt-in per Location — traded a security default for latency, and at
a 5.5 ms worst case that trade was worth putting to an operator. At ≈ 0.75 ms
worst-case p99 with body inspection unchanged, it no longer buys enough to be worth
its cost. The option stays recorded here for an operator whose traffic or hardware
moves these numbers back into that range.

## 4. What these numbers exclude

The engine, not the plugin wrapper. Extracting header pairs from a pingora `Session` and
the `Bytes` copy the request-body buffer makes are not counted — both are borrows and
one memcpy against pattern matching over the same bytes, so they do not move these
figures, but they are not in them.

Detector accuracy over the frozen corpus is a separate measurement; see
[`spikes/detector-baseline.md`](./spikes/detector-baseline.md).
