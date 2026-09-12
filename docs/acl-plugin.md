# `acl` plugin

One rule table per domain, evaluated top to bottom, plus an optional access list gating
the domain outright. Replaces reaching for four separate restriction plugins — and does
not reimplement their matching: IP/CIDR comes from `pingap-util`, referer host parsing
and the allow/deny semantics from `pingap-plugin`, GeoIP from the one embedded database
this process loads.

```toml
[plugins."acl:public"]
category = "acl"
default_action = "allow"
rules = [
  { field = "user_agent", operator = "regex", values = ["(?i)(nikto|sqlmap)"], action = "deny" },
  { field = "method",     operator = "in_list", values = ["TRACE", "TRACK"],   action = "deny" },
  { field = "ip",         operator = "in_cidr", values = ["10.0.0.0/8"],       action = "log" },
]

[locations.app]
upstream = "app"
plugins = ["acl:public"]
```

## Precedence

**The first matching rule with a terminal action decides.** Read the list top to bottom
and the outcome is whatever the first `allow` or `deny` that matches says. There is no
"most specific wins", no scoring, and no implicit reordering — overlapping allow/deny
rules are a classic source of accidental exposure, and every heuristic that tries to be
clever about them makes the list harder to reason about than the exposure was worth.

`log` is **not** terminal. It records the match and evaluation continues. If it stopped,
adding a `log` rule for visibility would silently disable every rule below it, turning an
observability change into a policy change.

When nothing terminal matches, `default_action` decides. It is `allow` by default so an
empty table is a no-op rather than an outage; set `deny` for "allow nothing unless
listed".

## Configuration

| Key | Default | Meaning |
| --- | --- | --- |
| `step` | `request` | Only `request` is accepted. A typo fails at config load rather than producing an access control that never runs |
| `default_action` | `allow` | `allow` or `deny`, applied when no rule reached a terminal action |
| `rules` | none | Array of rule tables, evaluated in written order |
| `access_list` | none | An inline gate; see below |
| `realm` | `Restricted` | Shown in the `WWW-Authenticate` challenge |

An entry with no `rules`, no `access_list` and `default_action = "allow"` enforces
nothing and is refused at config load — that is an entry somebody forgot to fill in, not
a policy. `default_action = "deny"` with no rules *is* a policy (refuse everything) and
is accepted.

### Rules

| Key | Default | Meaning |
| --- | --- | --- |
| `field` | required | `ip`, `geo_country`, `user_agent`, `referer`, `method`, `header` |
| `operator` | required | `equals`, `contains`, `regex`, `in_cidr`, `in_list` |
| `values` | required | Any one matching makes the rule match |
| `action` | required | `allow`, `deny`, `log` |
| `header` | — | Which header, and required when `field = "header"` |
| `order` | `0` | Sorting hint for stores that do not preserve insertion order |
| `enabled` | `true` | A disabled rule is skipped, not deleted |

Not every operator applies to every field, and a combination that cannot be evaluated is
refused by name rather than accepted as a rule that never fires:

| Field | Operators |
| --- | --- |
| `ip` | `in_cidr`, `equals`, `in_list` |
| `geo_country`, `method` | `equals`, `in_list` |
| `user_agent`, `referer`, `header` | `equals`, `contains`, `regex`, `in_list` |

`equals`, `contains` and `in_list` compare case-insensitively — HTTP methods and header
values are conventionally folded, and an operator writing `GET` should not get a different
answer than one writing `get`. `regex` is the escape hatch and is case-sensitive as
written; use `(?i)` when you do not want that.

`equals` takes exactly one value; use `in_list` for several. Two ways to express the same
thing would make the list less predictable, which is the property this plugin is built
around.

`order` exists for the admin UI and for the Phase 07 database, where row order is not a
promise. Sorting is **stable** and every rule defaults to `0`, so the default behaviour
is exactly written order, and setting `order` moves a rule between groups without
disturbing relative position inside one.

### GeoIP

`field = "geo_country"` needs the `geo` build feature. Without it the rule is **refused
at config load**, naming the field — better than a rule the operator believes is blocking
two countries. Build with `--features geo`; that also enables the `geo_restriction`
plugin, deliberately, so the two cannot disagree about whether GeoIP exists.

### Access lists

An access list is a **gate**, not a rule. It is evaluated before the rule table, and an
`allow` rule cannot let past an address the list refused — otherwise attaching an access
list would stop meaning anything as soon as any allow rule existed.

```toml
[plugins."acl:staging".access_list]
ip_allowlist = ["203.0.113.0/24"]
users = ["alice:f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7"]
satisfy = "any"
```

| Key | Default | Meaning |
| --- | --- | --- |
| `ip_allowlist` | empty | Addresses and CIDR ranges that satisfy the list without credentials |
| `users` | empty | `username:sha256hex` entries; the digest is of the password alone |
| `satisfy` | `any` | `any` — either half suffices. `all` — both must hold |

**An empty list admits nobody.** This is the one inherited convention the fork inverts:
the reference treated an empty list as "no restriction", so a half-written config served
unprotected traffic while looking configured. An empty half never satisfies either, so
`satisfy = "all"` with no `users` admits no one.

A list with users answers **401** with a challenge; an IP-only list answers **403**,
because challenging for a password that cannot exist invites a client to retry forever.

Generate a digest with `printf %s 'hunter2' | sha256sum`. Unsalted SHA-256 is a
deliberate, bounded choice: it keeps a recoverable password out of the config file and
costs about a microsecond so it can run per request. It is **not** a password KDF — an
attacker holding the file can brute-force a weak password offline. Slow-KDF-at-rest
belongs to the control-plane store, where a login happens once rather than per request.

## Ordering with other plugins

A Location's plugin list is evaluated in order and the first plugin to answer terminates
the request. Put the cheap gate first:

```toml
plugins = ["acl:public", "waf:strict"]
```

An `acl` entry refusing by IP costs far less than a WAF evaluation, and the WAF then never
runs for a request already refused. See [domain-model.md](./domain-model.md) for the whole
projection, including why isolation between domains comes from distinct named entries
rather than from listing one name twice.

## Logging

A denial records which rule decided, and an access-list refusal is recorded distinctly
from a rule denial — a dashboard that cannot tell a gated domain from a policy hit cannot
be acted on. Credentials are never logged.
