# WAF category → CRS lineage

Native WAF categories are named after the [OWASP Core Rule Set][crs] groups they
descend from, so an operator who knows CRS recognises what a category covers.

**This is a lineage mapping, not a compatibility claim.** Pingap does not load
`.conf` rule files, does not implement SecLang, and does not embed
libmodsecurity. Nothing here promises that an arbitrary CRS rule file works. The
names exist so the UI, the logs, and the config keys are legible to someone whose
mental model came from ModSecurity.

The set of ten is not arbitrary: it is the set of CRS files the reference product
actually exposes to operators — eight request-side and two response-side.

## Categories

| Config key | CRS group | Upstream CRS file | Surface |
| --- | --- | --- | --- |
| `protocol_enforcement` | 920 | `REQUEST-920-PROTOCOL-ENFORCEMENT.conf` | request |
| `local_file_inclusion` | 930 | `REQUEST-930-APPLICATION-ATTACK-LFI.conf` | request |
| `remote_code_execution` | 932 | `REQUEST-932-APPLICATION-ATTACK-RCE.conf` | request |
| `php` | 933 | `REQUEST-933-APPLICATION-ATTACK-PHP.conf` | request |
| `generic` | 934 | `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf` | request |
| `xss` | 941 | `REQUEST-941-APPLICATION-ATTACK-XSS.conf` | request |
| `sql_injection` | 942 | `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` | request |
| `session_fixation` | 943 | `REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf` | request |
| `data_leakage` | 950 | `RESPONSE-950-DATA-LEAKAGES.conf` | response |
| `web_shell` | 955 | `RESPONSE-955-WEB-SHELLS.conf` | response |

### On `generic` (934)

Upstream CRS ships group 934 as `APPLICATION-ATTACK-GENERIC`. Some downstream
products label it `SSRF`. Pingap follows upstream, because an operator who reads
`ssrf` in a UI and then goes looking for CRS's SSRF rules will not find them —
the label would be a dead end rather than a shortcut.

## Modes differ by surface

Request-side categories take `off`, `detect`, or `block`.

Response-side categories take `off`, `detect`, or **`redact`** — never `block`.
This is a property of where the rules run, not a policy choice. A response-side
rule fires from the response-body hook, by which point the status line and
headers have already gone downstream; the hook's result type can replace body
bytes and nothing else. `redact` means the matched span is rewritten out of the
body. The response still completes with its original status.

Setting a response-side category to `block` is **rejected at config validation**
with the offending key named. It does not silently degrade to `redact` — an
operator who believes a leak is being blocked when it is only being rewritten has
been misled about their own security posture.

## Default mode

Every category defaults to `detect`. That is deliberate: the false-positive rate
measured against the inherited detector patterns during risk-reduction spikes was
**35.4%** (see `docs/spikes/detector-baseline.md`), so shipping `block` by default
would reject roughly one legitimate request in three. Tuning happens against real
traffic, per profile, with `detect` output as the evidence.

## Rule IDs

| Range | Owner |
| --- | --- |
| `1_000` – `999_999` | native rules, allocated per category |
| `1_000_000` and above | operator-authored custom rules |

A native rule's ID sits in `group × 1000 ..= group × 1000 + 999`, so the ID is
self-describing: `942_017` is visibly a SQL-injection rule. Because CRS group
numbers are distinct, the per-category ranges cannot overlap — asserted by test
rather than assumed.

The custom range is reserved so a future native category can never collide with a
rule someone has already deployed. A collision would silently change which rule a
historical log line refers to, which is the failure the whole scheme exists to
prevent.

A custom rule's ID is derived from its **name**, not its position in the config
file. Position-derived IDs shift when a rule is inserted above them; a name-derived
ID survives edits, reordering, and reloads. Two names that derive the same ID are
rejected at startup, naming both rules.

## Custom rule patterns are cost-checked

Patterns are [`fancy-regex`][fancy], which supports backreferences and lookaround
that the `regex` crate rejects outright. The price is backtracking, and one shape in
particular is rejected at config validation:

**A lookaround whose body contains an unbounded quantifier** — `(?=.*secret)`,
`(?!.+admin)`, `(?<=[a-z]{2,})` — is quadratic in the size of the text being
scanned. A lookaround cannot be delegated to the linear-time engine, so it is re-run
at every start position, and an unbounded body walks to the end of the input each
time. Measured on this engine, `(?=.*etc)(?=.*passwd)` takes 1.0 ms over 1 KB,
16.2 ms over 4 KB, and 243.6 ms over 16 KB — at the default 128 KiB
`body_inspect_limit` that extrapolates to roughly 15 seconds for one request, on a
worker shared by every domain in the process.

The per-request time budget does not save you here: it is checked *between* rules and
cannot interrupt one already running. Neither does a regex backtrack limit — the
delegated `.*` does not accumulate backtracks. Config load is the only place the
shape can be stopped, so that is where it is stopped.

Rewrite it as **separate rules whose scores sum**. Two rules matching `etc` and
`passwd`, each scoring 3 against a threshold of 5, fire together on the same request
and cost two linear scans instead of one quadratic one. This is what anomaly scoring
is for.

A **bounded** lookaround is fine and stays allowed: `(?=[/?&\s]|$)`, `(?=\d{3})`,
`(?![a-z])` each scan a fixed distance.

Also rejected: nested unbounded quantifiers (`(a+)+`), which are exponential rather
than merely quadratic, and patterns over 2 000 characters, which are almost always
generated rather than written.

## Severity and score

| Severity | Default score |
| --- | --- |
| `notice` | 2 |
| `warning` | 3 |
| `error` | 4 |
| `critical` | 5 |

Scores accumulate across matching rules; enforcement happens when the total from
categories in an enforcing mode reaches `anomaly_threshold` (default `5`). Hits
from categories in `detect` are recorded and reported but **cannot** contribute to
that total — otherwise turning a noisy category down to `detect` would still get
requests blocked because of it.

The shape of the severity ladder is inherited from CRS. The numbers are ours and
are config-overridable.

[crs]: https://owasp.org/www-project-modsecurity-core-rule-set/
[fancy]: https://docs.rs/fancy-regex/
