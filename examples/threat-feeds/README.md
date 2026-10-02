# Threat feeds

A WAF policy with threat-intelligence feeds: a static `sql_injection` category,
one manual blocklist entry, and one declared feed that ships disabled because
its URL is a placeholder — set a real feed URL and `enabled = true` together. A
failed refresh keeps the last good set for the configured `staleness` window.

The construction gate refuses a policy that selects intel entries without
`basic.trusted_proxies`, exactly as it refuses a bare `ip_list`: feed and
manual entries are matched against the same resolved client address, and
without a trust anchor that address is the client-chosen `X-Forwarded-For`,
honoured from any peer — direct exposure is no remedy. The `config.toml` in
this directory sets `10.0.0.0/8` as the shape; put your own proxies'
addresses there.

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
