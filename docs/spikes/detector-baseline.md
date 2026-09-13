# Spike C — Detector false-positive baseline

**Baseline capture. Gates nothing, but produces the number the detector port must beat.**
The headline: **35.4% of benign traffic trips a detector**. Blocking mode on these
patterns as inherited would break roughly one request in three.

Run 2026-09-02. Harness `spikes/detector-baseline/`, corpus frozen at
`corpus/MANIFEST.sha256` (726 files).

## Corpus

Generated deterministically by `generate-corpus.py` — no randomness, no
timestamps. Regenerating produces byte-identical files, which is what makes the
freeze meaningful.

| Set | Cases | Minimum | |
|---|---|---|---|
| `malicious/sqli` | 52 | 50 | ok |
| `malicious/xss` | 50 | 50 | ok |
| `malicious/traversal` | 32 | 30 | ok |
| `malicious/cmdi` | 32 | 30 | ok |
| `benign` | 560 | 500 | ok |

**Frozen tree hash:** `ea65120d61d1b7b727944697c53df0ed9e6ae61975e8f3e6fc69d45fc88e1822`

The detector port must assert this hash before scoring. A corpus that can be edited to
pass is not a regression gate, and shrinking the benign set is the easiest way to
make an absolute false-positive count fall without improving anything.

## Baseline — rates, not counts

True positives, per category (a miss is a false negative):

| Category | TP | Total | TP rate |
|---|---|---|---|
| sqli | 47 | 52 | 0.9038 |
| xss | 47 | 50 | 0.9400 |
| traversal | 30 | 32 | 0.9375 |
| cmdi | 30 | 32 | 0.9375 |
| **all** | **154** | **166** | **0.9277** |

False positives on the benign set (a hit is a false positive):

| Detector | FP | Total | FP rate |
|---|---|---|---|
| sqli | 133 | 560 | **0.2375** |
| cmdi | 65 | 560 | **0.1161** |
| xss | 0 | 560 | 0.0000 |
| traversal | 0 | 560 | 0.0000 |
| **any detector** | **198** | **560** | **0.3536** |

The union is lower than the sum because some benign cases trip both sqli and cmdi.

**The detector port's target: `fp_rate < 0.3536` on this exact corpus, with the tree hash
asserted unchanged.** The TP rate of 0.9277 is the floor to hold while doing it —
a triage that improves precision by dropping recall is not an improvement.

## The three predicted defects, all confirmed

**1. `(?i)0x[0-9a-f]{2,}` — 30 benign cases, 5.4%.** Fires on every hex literal.
Design tokens, colour values, and any `0x`-prefixed identifier. It cannot
distinguish a SQL hex literal from a CSS value.

**2. `--[^\r\n]*$` — 65 benign cases, 11.6%.** The single largest FP source. Any
value ending in a double dash matches: em-dash prose (`"inconclusive -- see
appendix B"`), and every CLI-flag string (`npm run build -- --mode=production`,
`cargo test -- --nocapture`). There is no SQL context requirement at all.

**3. `SAFE_HEADERS` skips 11 headers, including `user-agent` and `content-type`.**
Demonstrated concretely by the runner:

```
payload "Mozilla/5.0 (X11) ' UNION SELECT password FROM users --"
  as a query value      -> hit=true
  as User-Agent header  -> hit=false   (user-agent is in SAFE_HEADERS)
```

Same bytes, opposite verdict, decided only by which field carried them. User-Agent
is a standard injection vector, so this is a bypass rather than a tuning choice.
All four detectors ship an identical private copy of the set
(`sql_injection.rs:36`, `xss_detector.rs:31`, `command_injection.rs:63`,
`path_traversal.rs:75`) — the port consolidates them, and fixing one copy would
leave three families blind.

## Two further FP sources not named in advance

Attributing the sqli and cmdi false positives to individual patterns turned up two
more that are as bad as the three predicted:

| Pattern | Benign FPs | Rate | Why |
|---|---|---|---|
| `;\s*\w` (cmdi) | 45 | 8.0% | matches every `Content-Type: text/html; charset=utf-8` |
| `\|\s*\w` (cmdi) | 20 | 3.6% | matches any pipe-delimited value |
| `(?i)\bselect\b.*\bfrom\b` | 8 | 1.4% | "Please select from the following options" |
| `(?i)\binsert\b.*\binto\b` | 8 | 1.4% | "Insert into the slot at the top" |
| `(?i)\bdelete\b.*\bfrom\b` | 8 | 1.4% | "Delete from your cart before checkout" |
| `(?i)\bdrop\b.*\b(table\|database)\b` | 7 | 1.2% | "Drop the table linens off" |
| `(?i)\bunion\b.*\bselect\b` | 7 | 1.2% | "The union representative and select committee" |

The keyword-pair patterns are individually small but collectively ~7%, and they
share one root cause: `.*` between two common English words, with no requirement
that either appear in a SQL-syntactic position. The `;\s*\w` case is worse — it
fires on a header value that appears in essentially every HTTP request that has a
body.

## Regex cost

No pathological backtracking found. Worst case 7.31 ms across the whole pattern
set against 64 KiB of adversarial input:

| Input | Time |
|---|---|
| `union` + 64 KiB (`.*` bait) | 7.31 ms |
| `0x` + 64 KiB hex | 7.03 ms |
| 64 KiB + trailing ` --` | 6.20 ms |
| backtick + 64 KiB | 6.30 ms |
| `<img ` + 20k `on` repeats | 4.81 ms |

Measured with Python's `re` as a proxy for cost *shape*, not absolute speed —
these patterns are all linear-time in this engine. The rule engine's time budget is still
required, because custom operator-authored patterns will not be, and `fancy-regex`
backtracks where `regex` does not. But no inherited pattern needs rewriting on
cost grounds.

## Consequences for the detector port

1. **`detect` is the mandatory default.** A 35.4% FP rate in blocking mode is not
   a tuning problem, it is an outage. This was already the position taken in advance; the
   number makes it non-negotiable.
2. **Blocking is opt-in per category, and only after that category's FP rate is
   acceptable.** On this baseline, xss and traversal are already at 0.0000 and
   could plausibly ship blocking first; sqli at 0.2375 and cmdi at 0.1161 cannot.
3. **Five patterns need narrowing or dropping, not three.** Add `;\s*\w` and
   `\|\s*\w` to the triage list — between them they account for 65 of the 198
   false positives.
4. The keyword-pair patterns need a SQL-context requirement (adjacent punctuation,
   a quote, or a statement boundary) rather than bare `.*` between English words.

## Post-port measurement

Same frozen corpus, same scoring, after the port and the five pattern fixes. The
corpus is hash-verified before it is scored (tree hash `ea65120d…`, 726 files in
`MANIFEST.sha256`), so a corpus quietly edited to make these numbers work would
fail the check rather than pass the gate. Reproduce with
`cargo test -p pingap-waf --test corpus -- --nocapture`.

| Paranoia | FP rate (560 benign) | TP rate (166 malicious) |
|---|---|---|
| **1 (default)** | **0.0000** (0/560) | **0.9940** (165/166) |
| 2 | 0.0107 | 0.9940 |
| 3 | 0.0643 | 1.0000 |
| 4 | 0.0643 | 1.0000 |

Against the baseline of `fp 0.3536` / `tp 0.9277`: false positives fall to zero at
the default paranoia level and recall *rises*. Per-detector true positives at
paranoia 1: cmdi 32/32, traversal 32/32, xss 50/50, sqli 51/52.

Two things this does **not** license.

Recall is not free at higher paranoia. Paranoia 3 buys the last malicious case
(166/166) for a 6.4% false-positive rate — a worse trade than it looks, because the
one case paranoia 1 misses is a single SQLi variant while 6.4% of benign traffic is
a real outage at any volume. The default stays at 1.

**A 0.0000 FP rate on this corpus is not a mandate to ship blocking on.** 560
benign cases are a regression fence, not a sample of anyone's production traffic,
and the corpus was assembled by the same project that wrote the patterns. `detect`
remains the default mode for every category, exactly as consequence 1 above
requires; what changed is that sqli and cmdi are no longer disqualified from *ever*
being promoted, not that any category is promoted now.
