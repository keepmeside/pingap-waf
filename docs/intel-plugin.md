# Threat intelligence feeds

The WAF can add operator-selected IP and CIDR feeds to its static deny list. Feeds are
disabled unless a policy declares `intel.feed`; no URL is fetched by default. A feed is
fetched once per process, published by an atomic snapshot, and attributed in the WAF verdict
and access-log variables (`waf_intel_feed` and `waf_intel_category`).

```toml
[basic]
trusted_proxies = ["10.0.0.0/8"]   # your own proxies, not the world

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
`ip_list` uses, and construction refuses a policy that selects either without
`basic.trusted_proxies` — the same gate `ip_list` carries, for the same
reason. Without a trusted-proxy list, `X-Forwarded-For` is honoured from any
peer, so even a directly connected client that sends the header chooses the
address the match runs on — direct exposure is no remedy — and a feed's denial
would be enforced on an address the blocked party picked. Only the
trusted-proxy list changes the resolution: a peer not on it has its forwarded
headers ignored and resolves to its own address. Set it to the addresses of
the proxies in front of the node — or, on a directly exposed node, to any list
that matches no real peer.

A feed-bearing entry separately needs one static deny source (`ip_list`,
`intel.manual`, or a request category with `mode = "block"`), or construction
refuses it as selecting feeds but denying nothing. The challenge, behavioural
and adaptive controls have a separate identity contract, where
`client_ip_from_peer` asserts the peer address directly.

Adoption is judged against the config under validation, not the one running:
one apply that sets `basic.trusted_proxies` and selects intel together is
accepted, because the check constructs the candidate and the gate reads the
candidate's own list. Hot reload is the narrower path — `basic` is read at
process start and a reload keeps the running value — so on `--autoreload` and
etcd-watch nodes a first adoption commits but its WAF plugin fails to
construct at each reload until the process restarts (`--autorestart` or
manual); each reload logs `reload plugin fail` and raises a
`reload_config_fail` notification. A node whose
running `basic.trusted_proxies` is already set adopts intel by reload alone.

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
