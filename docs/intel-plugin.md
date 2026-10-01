# Threat intelligence feeds

The WAF can add operator-selected IP and CIDR feeds to its static deny list. Feeds are
disabled unless a policy declares `intel.feed`; no URL is fetched by default. A feed is
fetched once per process, published by an atomic snapshot, and attributed in the WAF verdict
and access-log variables (`waf_intel_feed` and `waf_intel_category`).

```toml
[plugins.waf-strict]
category = "waf"
ip_list = ["203.0.113.0/24"]

[plugins.waf-strict.intel]
manual = ["198.51.100.10"]
max_body_bytes = 33554432
staleness = "24h"

[[plugins.waf-strict.intel.feed]]
name = "firehol-level1"
url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
category = "known-abuse"
enabled = true
```

The Tier-1 egress guard checks the initial URL, every redirect hop, and every DNS answer.
Loopback, private, link-local, unique-local and metadata ranges are refused by default. An
individual feed may set `allow_private_targets = true` for an internal mirror; each permitted
reserved-address decision is counted. Redirects are disabled by default (`redirect_hops = 0`)
and are bounded when explicitly enabled.

Responses are bounded by `max_body_bytes` and `max_entries`. Malformed lines are skipped and
counted. A failed refresh keeps the last good contribution for the configured staleness window;
after that it is removed and the stale-drop counter is distinct from the fetch-error counter.
An address removed from a later successful cycle is released immediately.

The parser accepts bare addresses, CIDR ranges, comment headers, CRLF, and the first column of
DShield-style tab-separated lines. DShield ranges are intentionally represented by their start
address only; use a CIDR feed when the complete range is required.

Feeds do not use client identity, so the WAF trusted-proxy construction gate is not needed for
this feature. The challenge, behavioural and adaptive controls have a separate identity contract.

## Defaults

| Key | Default | Meaning |
|---|---|---|
| `intel.manual` | `[]` | Addresses refused without a feed |
| `intel.feed` | `[]` | Feed URLs; none fetched unless declared |
| `intel.timeout` | `30s` | Per-fetch timeout |
| `intel.staleness` | `24h` | How long a failed refresh may keep serving the last good set |
| `intel.max_body_bytes` | `33554432` (32 MiB) | Cap on one feed response body |
| `intel.max_entries` | `250000` | Cap on accepted entries from one feed |
| `intel.redirect_hops` | `0` | Redirect budget; bounded to 10 when enabled |
| `feed.allow_private_targets` | `false` | Opt out of the reserved-address guard for an internal mirror |

The reserved-address classification — loopback, private, link-local, unique-local and the
link-local metadata address — is enforced at connection time and is not a configurable default.
`staleness`, `max_body_bytes` and `max_entries` are chosen limits, not figures measured against
production traffic; treat them as starting points to tune, not as validated values.

No admin UI exists for this fork-owned subsystem; configure it in the policy TOML or through the
control-plane projection as `waf:<profile>.intel`.
