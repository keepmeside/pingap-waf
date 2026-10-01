# Spike — Can a connection-time egress guard be expressed on the pinned reqwest?

**Status: GO for a three-layer guard. NO-GO for a resolver-only guard — IP-literal targets never reach the resolver.**

Decision gate for threat-feed fetching. Run 2026-09-13 against `reqwest 0.13.4`,
the exact version in the workspace `Cargo.lock`.

Harness: `spikes/egress-guard/` — a raw-socket HTTP server on `127.0.0.1` that
answers one request per connection with a canned 200 or 302, plus a
`reqwest::dns::Resolve` implementation that records every name it is asked about
and refuses a configured range. The record is what makes the negative results
interpretable: without it, "the guard did not fire" and "the guard was never
consulted" look identical.

TLS is deliberately omitted. Every URL is `http://`, and whether a resolver is
consulted per redirect hop is TLS-independent. The production guard runs on the
workspace's real feature set.

## Results

| # | Case | Policy | Resolver | Outcome | Resolver consulted |
|---|---|---|---|---|---|
| A0 | 302 → `http://169.254.169.254/latest/meta-data/` | default | none | **200 OK from the metadata address** | n/a |
| B | 302 → `169.254.169.254` | `none()` | none | 302 returned, not followed | n/a |
| B | 302 → `127.0.0.1` | `none()` | none | 302 returned, not followed | n/a |
| C | direct `http://localhost:PORT/ok` | `limited(5)` | refuses `169.254/16` | 200 OK | **yes** — `localhost` |
| C | direct `http://blocked.test/latest/` | `limited(5)` | refuses the name | **ERROR** `dns error \| refused blocked.test: policy` | **yes** |
| C | 302 → `http://localhost:PORT/ok` | `limited(5)` | refuses `169.254/16` | 200 OK | **yes, on the hop** |
| C | 302 → `http://blocked.test/latest/` | `limited(5)` | refuses the name | **ERROR** `dns error \| refused blocked.test: policy` | **yes, on the hop** |
| C | 302 → `http://169.254.169.254/...` | `limited(5)` | refuses `169.254/16` | **200 OK — guard did not fire** | **no** |
| C | direct `http://169.254.169.254/` | `limited(5)` | refuses `169.254/16` | **200 OK — guard did not fire** | **no** |
| D | `http://feed.example/ok` with `resolve()` pinned to `127.0.0.1:PORT` | default | none | 200 OK | n/a — override path |

Names the resolver recorded across all of section C:

```
["localhost", "blocked.test", "localhost", "blocked.test"]
```

Four entries, from the four hostname cases. **Zero from the three IP-literal
cases**, two of which were explicitly in the refused range and returned 200.

## What this establishes

**The API exists at the pinned version.** `redirect::Policy::limited`
(`redirect.rs:51`), `::none` (`:58`) and `::custom` (`:102`);
`ClientBuilder::resolve` (`client.rs:2291`) and `resolve_to_addrs` (`:2299`);
`ClientBuilder::dns_resolver` (`:2310`); and `reqwest::dns::{Addrs, Name,
Resolve, Resolving}` publicly re-exported (`dns/mod.rs:3`, `lib.rs:378`).
`Resolving` is `Pin<Box<dyn Future<Output = Result<Addrs, BoxError>> + Send>>`
(`dns/resolve.rs:18`), so a resolver can both error and filter.

**A custom resolver is consulted on redirect hops, not only on the first
request.** Case C row 4 resolves `localhost` reached through a 302, and the
recorded list contains it a second time. This is the load-bearing result: without
it, a guard installed on the client would validate the configured URL and then
wave through whatever it redirected to.

**A refusal propagates to the caller as an error**, carrying the resolver's own
message: `client error (Connect) | dns error | refused blocked.test: policy`.

**Per-hop URL validation is expressible.** `Policy::custom` receives an `Attempt`
exposing `url()` (`redirect.rs:174`) and `previous()` (`:179`), and can return
`Action::stop()` (`:192`) or `Action::error()` (`:201`). So a policy can inspect
each hop's URL and refuse it — which matters, because of the next result.

**IP literals bypass the resolver entirely.** Both a direct request to
`http://169.254.169.254/` and a 302 into it returned 200 with the resolver never
invoked. Hyper has nothing to resolve when the host is already an address, so it
connects directly. **A guard implemented only as a `Resolve` impl has a hole
exactly where the metadata address lives**, which is the address the guard exists
to block.

**The unguarded baseline is live.** Case A0 — a plain `reqwest::Client::new()`
with the default redirect policy — followed a 302 into
`http://169.254.169.254/latest/meta-data/` and returned 200. This is not a
theoretical path on this host: `ip route get 169.254.169.254` reports
`via 10.0.1.1 dev eth0`, and `curl` receives 200 from it. The response body was
not read, since that path can return live credentials; only the status code was
needed to establish reachability.

**Pinning works.** `resolve("feed.example", 127.0.0.1:PORT)` made a request to
`http://feed.example/ok` reach the local server. Note the doc caveat at
`client.rs:2297-2298`: a port in the URL always overrides the pinned address's
port, so pinning controls the IP and not the port.

**A refused redirect hop reports the original URL, not the hop.** The error read
`error sending request for url (http://127.0.0.1:PORT/redirect-host-refused)`
with the resolver's message about `blocked.test` nested inside. An operator
reading only the outer message sees the feed they configured, not where it tried
to go. Feed-error reporting must surface the inner cause, or attribution is lost.

## Consequence for the guard design

Three layers, and the first one is not optional:

1. **Validate the URL host itself** — parse it; if it is an IP literal, check the
   range directly. Apply to the initial URL *and* to every hop, via
   `Policy::custom` + `Attempt::url()`. This is the only layer that catches an
   IP-literal target, and it is the layer a resolver-based design silently omits.
2. **A custom `Resolve`** for hostname targets, validating every address returned
   and erroring when none is allowed. Proven to fire on redirect hops.
3. **A redirect policy.** `Policy::none()` is the right default for a blocklist:
   a threat feed that redirects is suspicious by definition, and refusing to
   follow removes the hop-validation problem entirely. `Policy::custom` with a
   bounded hop count and per-hop validation is the opt-in for feeds that
   legitimately redirect.

Rebinding is closed by layers 1 and 2 together for hostnames: the resolver sees
the actual addresses and refuses before connecting. For IP literals there is no
resolution to rebind, so layer 1 is complete on its own.

## Not established

- **Whether `resolve()`/`dns_overrides` bypasses a custom `Resolve` for the same
  name.** Section D used a separate client with no resolver installed, so the
  interaction is untested. It matters if the design validates first and then pins:
  if the override short-circuits the resolver, pinning is the only enforcement for
  that name and layer 1 must have already run.
- **IPv6 refused ranges.** The spike's guard classified only IPv4 link-local. The
  production guard must cover `::1`, `fc00::/7`, `fe80::/10` and `::ffff:`-mapped
  IPv4 forms, none of which this run exercised.
- **TLS behaviour.** No TLS backend was built. SNI and certificate validation
  interact with pinning in ways this spike did not observe.

## Version notes

`reqwest = "0.13.4"` is a caret requirement and resolves to **0.13.5**. The first
build of this spike compiled 0.13.5, which is not the version the workspace pins;
it was rebuilt with `=0.13.4` before any result was recorded. Every figure above
is from 0.13.4.

Separately, the workspace `Cargo.lock` carries **two** reqwest versions —
`0.12.28` at line 6170 and `0.13.4` at line 6210. Whichever dependency pulls
0.12.28 was not identified here, but a second HTTP client version in the graph is
worth resolving before the feed work adds a third call site, and any egress guard
written for 0.13 will not cover a client built on 0.12.
