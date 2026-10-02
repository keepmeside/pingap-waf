# Threat intelligence feeds

The WAF can add operator-selected IP and CIDR feeds to its static deny list. Feeds are
disabled unless a policy declares `intel.feed`; no URL is fetched by default. A feed is
fetched once per process, published by an atomic snapshot, and attributed in the WAF verdict
and access-log variables (`waf_intel_feed` and `waf_intel_category`).

```toml
[plugins.waf-strict]
category = "waf"

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

Feed and manual entries are matched against the same resolved client address
`ip_list` uses, and the construction gate covers `ip_list` alone, so a feed
config constructs without `basic.trusted_proxies` — though a feed-bearing entry
still needs one static deny source (`ip_list`, `intel.manual`, or a request
category with `mode = "block"`), or construction refuses it as selecting feeds
but denying nothing. What the gate leaves to the operator is the address's
trustworthiness: without `basic.trusted_proxies`, `X-Forwarded-For` is honoured
from any peer, so even a directly connected client that sends the header
chooses the address the match runs on — direct exposure is no remedy on this
path. Only the trusted-proxy list changes the resolution: a peer not on it has
its forwarded headers ignored and resolves to its own address. Set it to the
addresses of the proxies in front of the node — or, on a directly exposed
node, to any list that matches no real peer — when a feed's denial must
actually deny. The challenge, behavioural and adaptive controls have a
separate identity contract, where `client_ip_from_peer` asserts the peer
address directly.

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

## Published state

Per-feed statistics — generation, refresh outcome counts, and per configured feed its
category, accepted entry count and last successful fetch time — are published as JSON on the
admin API at `GET /api/metrics/detection` (capability `view_metrics`). The published
projection carries counts only: no feed rule, no address list, and no fetched content leaves
the process through it. The feed names in it are the configured, fixed enumeration — an
unconfigured name cannot appear.

No admin UI exists for this fork-owned subsystem; configure it in the policy TOML or through the
control-plane projection as `waf:<profile>.intel`.
