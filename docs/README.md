# Documents

- [Docker deployment](./deployment.md), [security posture](./security-posture.md), and [upgrades](./upgrade.md)
- [acme chart](./acme_chart.md)
- [modules](./modules.md)
- **WAF** (this fork) — [plugin reference](./waf-plugin.md),
  [category → CRS lineage](./waf-category-mapping.md),
  [latency](./waf-benchmark.md), [spike findings](./spikes/)
- **ACL and domains** (this fork) — [plugin reference](./acl-plugin.md),
  [domain model](./domain-model.md)
- **Bot management** (this fork) — [JA4 support and the `bot` plugin](./ja4-support.md)
- **Detection and feeds** (this fork) — [threat-intelligence feeds](./intel-plugin.md),
  [challenge tier](./challenge-plugin.md), [behavioural scoring](./behaviour-plugin.md),
  [adaptive baseline](./adaptive-plugin.md)
- **Control plane** (this fork) — [store, per-user admin auth, driver constraints](./control-plane-store.md),
  [config projection and versioning](./config-projection.md),
  [admin API and its parity with the reference product](./api-parity.md),
  [observability: what pingap already instruments and what this adds](./observability.md)
- **Documentation site** (VitePress, English only) — assembled by
  [`scripts/build-website.sh`](../scripts/build-website.sh) and built under
  [`website/`](../website/). This fork does not vendor upstream's
  `.github/workflows/pages.yml` (see the root `NOTICE` for why), so the site is
  built by hand and nothing deploys automatically.

  | URL | Content |
  | --- | --- |
  | <https://pingap.io/> | **Upstream** pingap, built from upstream's crate / plugin READMEs. It carries none of the fork pages listed above |

  Local preview:

  ```bash
  ./scripts/build-website.sh
  cd website && npm install && npm run docs:dev
  ```

## Crate documentation

Each workspace crate has its own README describing what it owns, how it is
configured and where it sits in the dependency graph.

| Crate | What it does |
| --- | --- |
| [pingap-util](../pingap-util/README.md) | Crypto, IP rules, PEM/base64, path and formatting helpers |
| [pingap-core](../pingap-core/README.md) | `Ctx`, `HttpResponse`, the `Plugin` trait, background services, clock helpers |
| [pingap-config](../pingap-config/README.md) | Configuration model, storage backends, TOML/HCL/KDL |
| [pingap-discovery](../pingap-discovery/README.md) | Static / DNS / Docker / transparent backend discovery |
| [pingap-health](../pingap-health/README.md) | TCP, HTTP(S) and gRPC health checks |
| [pingap-upstream](../pingap-upstream/README.md) | Load balancing, circuit breaking, upstream connection options |
| [pingap-location](../pingap-location/README.md) | Host/path matching, rewriting, per-location limits |
| [pingap-certificate](../pingap-certificate/README.md) | SNI-based dynamic TLS certificate store |
| [pingap-acme](../pingap-acme/README.md) | Let's Encrypt HTTP-01 and DNS-01 automation |
| [pingap-cache](../pingap-cache/README.md) | Memory (TinyUFO) and file cache backends |
| [pingap-plugin](../pingap-plugin/README.md) | Built-in plugins — see the [plugin index](../pingap-plugin/README.md#plugin-index) |
| [pingap-imageoptim](../pingap-imageoptim/README.md) | PNG/JPEG → WebP/AVIF conversion |
| [pingap-logger](../pingap-logger/README.md) | Access logs, file/syslog writers, rotation and compression |
| [pingap-performance](../pingap-performance/README.md) | Prometheus metrics and process introspection |
| [pingap-otel](../pingap-otel/README.md) | OpenTelemetry distributed tracing |
| [pingap-sentry](../pingap-sentry/README.md) | Sentry error reporting |
| [pingap-pyroscope](../pingap-pyroscope/README.md) | Continuous CPU profiling |
| [pingap-webhook](../pingap-webhook/README.md) | Operational notifications to WeCom / DingTalk / HTTP |
| [pingap-proxy](../pingap-proxy/README.md) | The proxy engine: lifecycle, routing, server configuration |

The fork adds its own crates under `crates/`. Their READMEs are read on GitHub, **not
published to the documentation site** — `build-website.sh` only resolves `pingap-*`
crate READMEs at the repository root, and a `crates/`-prefixed README never reaches the
site (deliberate: publishing them would need a second resolver that no phase owns). The
user-facing documentation for each lives in the `docs/*-plugin.md` pages above.

| Crate | What it does |
| --- | --- |
| `crates/pingap-waf` | The native WAF rule engine and its plugin |
| `crates/pingap-acl` | Per-domain ACL rules and access lists, with the `challenge` marker |
| `crates/pingap-bot` | JA4H client fingerprinting and the `bot` plugin |
| `crates/pingap-controlplane` | Users, sessions, audit log, RBAC, config projection, the Turso store |
| `crates/pingap-admin-api` | The admin-API route table over the control plane |
| `crates/pingap-domainstate` | Bounded domain-keyed expiring state and the client-identity contract |
| `crates/pingap-events` | The shared WAF event queue every verdict offers to |
| `crates/pingap-intel` | Threat-feed fetch, the Tier-1 egress guard, the threat set |
| `crates/pingap-challenge` | Proof-of-work and silent-JS challenge tier, tokens, escalation |
| `crates/pingap-behaviour` | Per-client behavioural signals and scoring |
| `crates/pingap-adaptive` | Hourly baselines, calibration, the limit multiplier |

## Plugin documentation

Every plugin has a page covering its configuration keys, worked examples and the
caveats worth knowing before you deploy it:
[pingap-plugin/docs](../pingap-plugin/README.md#plugin-index).
