# The domain model

A **domain** is the object operators think in: a hostname, where its traffic goes, and
what policy applies to it. Pingap has no such object, and this fork does not add one to
the data plane. A domain is a *projection* — a control-plane view that resolves entirely
onto config pingap already has.

This file is the contract for that projection. Phases 08, 09 and 10 all depend on it:
Phase 08 generates config from it, Phase 09 exposes it over the admin API, Phase 10
renders it. **Every domain field below names the config key it maps to. A field with no
mapping is rejected at design time**, because the alternative is Phase 08 silently
dropping it and an operator setting something that does nothing.

## Shape

```
Domain
  ├─ Server   ── listener, TLS, protocol toggles       → [servers.<name>]
  ├─ Location ── host/path match + plugin list         → [locations.<name>]
  │                                                        plugins = [
  │                                                          "waf:<profile>",
  │                                                          "acl:<profile>",
  │                                                          "bot:<profile>",
  │                                                        ]
  └─ Upstream ── backends, LB algorithm, health check  → [upstreams.<name>]
```

Policy is the Location's plugin list. That is the whole mechanism, and it is why two
hostnames on one listener can enforce completely different things without any change to
pingap's routing.

## Field mapping

Verified against `pingap-config/src/common.rs` and `pingap-proxy/src/server_conf.rs`.

### Routing and identity

| Domain field | Config key | Notes |
| --- | --- | --- |
| `hostname` | `locations.<n>.host` | Comma-separated list; one Location can serve several names |
| `path` | `locations.<n>.path` | Prefix, regex or exact, per pingap's own matching |
| `listener` | `servers.<n>.addr` | Comma-separated; the listener is shared across domains |
| `upstream` | `locations.<n>.upstream` | Names an `[upstreams.<name>]` entry |
| `priority` | `locations.<n>.weight` | Higher wins when two Locations both match |
| `notes` | `locations.<n>.remark` | Operator-facing only |

### Upstream and health

| Domain field | Config key |
| --- | --- |
| `backends` | `upstreams.<n>.addrs` |
| `lb_algorithm` | `upstreams.<n>.algo` |
| `health_check` | `upstreams.<n>.health_check` |
| `discovery` | `upstreams.<n>.discovery` (`static`, `dns`, `docker`, `transparent`) |
| `tls_sni` / `verify_cert` | `upstreams.<n>.sni` / `upstreams.<n>.verify_cert` |
| `circuit_breaker` | the four `upstreams.<n>.circuit_break_*` keys |

### Domain-level toggles

Each of these already exists in pingap. **None is reimplemented**; the control plane sets
the key and nothing more.

| Toggle | Config key | Level |
| --- | --- | --- |
| HTTP/2 | `servers.<n>.enabled_h2` | Server |
| gRPC-web | `locations.<n>.grpc_web` — plus `grpc-web` in `servers.<n>.modules` | both |
| Client max body size | `locations.<n>.client_max_body_size` | Location |
| Reverse-proxy headers | `locations.<n>.enable_reverse_proxy_headers` | Location |
| Real client IP | `basic.trusted_proxies` | **process-global** |
| TLS versions and ciphers | `servers.<n>.tls_min_version`, `tls_max_version`, `tls_cipher_list`, `tls_ciphersuites` | Server |
| Access log format | `servers.<n>.access_log` | Server |
| Server-Timing header | `servers.<n>.enable_server_timing` | Server |
| Concurrency cap | `locations.<n>.max_processing` | Location |
| Retries | `locations.<n>.max_retries`, `max_retry_window` | Location |

Two entries in that table are not what a UI would assume, and both must be surfaced
rather than smoothed over:

**Real client IP is process-global, not per-domain.** `basic.trusted_proxies` is one
list for the whole process (`pingap-core/src/http_header.rs` keeps it in a static). A
per-domain "real IP" control is therefore **not expressible** and the API must not offer
one. It also has a hard consequence for policy: with the list unset, forwarded headers
are trusted unconditionally, so a WAF `ip_list` or an ACL `ip` rule refuses to build at
all rather than enforce on an address the client chose.

**gRPC-web needs two keys at two levels.** The Location opts in and the Server must load
the module. Setting only one is a silent no-op.

### HSTS

**HSTS has no dedicated field in pingap, and this projection does not add one.** It maps
onto the existing `response_headers` plugin:

```toml
[plugins.hsts]
category = "response_headers"
set_headers = ["Strict-Transport-Security:max-age=31536000; includeSubDomains"]
```

…then `"hsts"` in the domain's plugin list. A dedicated `hsts: bool` was rejected
precisely because it has no config counterpart: it would have to grow its own header
writer beside a plugin that already does the job, and Phase 08 would then own two ways
to emit one header.

## Policy bindings

| Binding | Plugin category | Profile naming |
| --- | --- | --- |
| WAF ruleset | `waf` | `waf:strict`, `waf:audit-only` |
| ACL rule table | `acl` | `acl:<profile>` |
| Access list | `acl` (the `access_list` table inside a profile) | shared by attaching the same entry |
| Bot profile | `bot` | Phase 06 |

### The one thing that is not free

Binding is per-Location. **Instances are not.** A plugin lives in a process-global
registry keyed by its config-entry *name*, and every Location listing that name resolves
the same `Arc<dyn Plugin>` — `try_init_plugins` in `src/plugin/mod.rs` reuses an instance
whenever its `config_key()` matches, `get_context_plugins` in `pingap-proxy/src/server.rs`
looks plugins up by name, a Location holds only names, and every `Plugin` method takes
`&self`.

So any mutable state inside an instance is shared by every domain that binds it. A
counter or anomaly tally held there would be cross-domain: traffic against one tenant
would advance another's totals, and that tenant's clients would be refused because of
traffic they never sent. It would not show up in any single-domain test.

**The rule: isolation comes from distinct named entries, not from listing one name
twice.** Two domains needing independently-counted policy get `waf:tenant-a` and
`waf:tenant-b`, and the config-size cost is accepted.

Where one profile is legitimately shared, per-domain mutable state must be keyed by an
explicit identifier read from the request context — never by instance identity. As
shipped, `waf` and `acl` hold no per-request state at all: verdicts accumulate on `Ctx`,
which is per request by construction, and the only interior mutability is the `ArcSwap`
guarding the compiled ruleset — configuration, replaced on reload, never written by a
request. Asserted by `crates/pingap-waf/tests/domain_isolation.rs`, because the natural
way to add a counter later is to put it on the plugin.

## Order within a plugin list

The list is evaluated in order, and the first plugin to answer terminates the request
(`Server::handle_request_plugin`). Two consequences worth writing down:

- Put the cheapest gate first. An `acl` entry that refuses by IP costs far less than a
  WAF evaluation, and the WAF then never runs for a request already refused.
- Inside one `acl` entry, an access list gates *before* the rule table. An `allow` rule
  cannot let past an address the access list refused — otherwise attaching an access list
  would stop meaning anything as soon as any allow rule existed.

## Not expressible, and why

| Wanted | Why not |
| --- | --- |
| L4 / TCP / UDP load balancing | `pingora-core`'s `ServerAddress` is `Tcp` \| `Uds`. UDP cannot be listened on without patching Pingora |
| Per-domain real-IP configuration | `basic.trusted_proxies` is process-global |
| Response-side `block` | `ResponseBodyPluginResult` has no denying variant, and the status line is already sent. `redact` or `detect` only |
| Per-domain GeoIP database | one embedded database per process; `geo` is a build feature |

Anything else a domain object grows must arrive with a config key in the table above, or
it is not part of the model.
