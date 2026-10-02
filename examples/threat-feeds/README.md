# Threat feeds

A WAF policy with threat-intelligence feeds: a static `sql_injection` category,
one manual blocklist entry, and one declared feed that ships disabled because
its URL is a placeholder — set a real feed URL and `enabled = true` together. A
failed refresh keeps the last good set for the configured `staleness` window.

The WAF identity gate fires only when `ip_list` is set, so this config
validates without `basic.trusted_proxies` — but feed and manual entries are
matched against the same resolved client address `ip_list` uses, and without
a trust anchor that address is the client-chosen `X-Forwarded-For`. Set
`basic.trusted_proxies` (or run directly exposed) when the feed's denial must
actually deny.

Validate the configuration without starting the server:

```bash
pingap-waf -t -c=examples/threat-feeds/config.toml
```

Run it:

```bash
pingap-waf -c=examples/threat-feeds/config.toml --admin=127.0.0.1:3018
```

See `docs/intel-plugin.md` for the feed format, the egress guard and the
defaults.
