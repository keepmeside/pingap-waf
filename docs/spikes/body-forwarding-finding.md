# Spike E — Request body inspected, and still forwarded?

**Status: GO for the `request_body_filter` hook. NO-GO for both drain-in-request-filter variants.**

Decision gate for the detector port. Run 2026-09-02 against vendored `pingora 0.8.1`,
`pingora-core 0.8.1`, `pingora-proxy 0.8.1`.

Harness: `spikes/body-forwarding/` — a minimal `ProxyHttp` with three selectable
inspection strategies, plus `echo-upstream.py`, a raw-socket upstream that
reports the body byte count **it actually read** and a SHA-256 over those bytes.
The numbers below therefore come from the far side of the proxy. That matters:
in mode 1 the proxy's own log line says it read 4096 bytes, and the upstream
received 0.

## Results

| Mode | Body | Upstream `Content-Length` | Upstream bytes received | Verdict |
|---|---|---|---|---|
| `drain-request-filter` | 4 KiB | 4096 | **0** | body destroyed |
| `drain-with-buffering` | 4 KiB | 4096 | 4096 | works under the cap |
| `drain-with-buffering` | 1 MiB | 1048576 | **0** | body destroyed past the cap |
| `body-filter` | 4 KiB | 4096 | 4096 | byte-identical |
| `body-filter` | 1 MiB | 1048576 | 1048576 | byte-identical |

SHA-256 equality, proxied vs sent directly to the same upstream:

- 4 KiB: `a2e659dacb4691e8…` both paths — identical
- 1 MiB: `34bc6ad817807143…` both paths — identical

The empty-body SHA `e3b0c44298fc1c14…` in the two failing rows is the hash of
zero bytes, i.e. the upstream read nothing and timed out waiting for the
`Content-Length` the proxy had already promised it.

## Mode 1 — `PluginStep::Request` drain: confirmed broken

The red-team conclusion is confirmed empirically, and the mechanism is visible in
the spike's own log:

```
[spike] request_filter drained=4096 replay_buffer=0 truncated=false
{"content_length_header": 4096, "body_bytes_received": 0, "truncated": true}
```

The plugin read all 4096 bytes; the replay buffer held 0. `read_body_bytes`
mirrors into the retry buffer only under `if let Some(buffer) =
self.retry_buffer.as_mut()` (`pingora-core-0.8.1/src/protocols/http/v1/server.rs:426-436`),
and that buffer is still `None` (`:121`) because `enable_retry_buffering()` runs
at `pingora-proxy-0.8.1/src/proxy_h1.rs:103` — inside `proxy_to_upstream`
(`lib.rs:873`), strictly after `request_filter` returned (`lib.rs:782`).

**This is the failure that would have passed a test suite.** Blocking works
perfectly in this mode: the request terminates and never proxies, exactly like
pingap's admin plugin, which is why that plugin was a misleading precedent. Only
the *allow* path corrupts, and only an assertion made at the upstream can see it.

## Mode 2 — `enable_retry_buffering()` first: works to 64 KiB, then silently loses the body

Calling `enable_retry_buffering()` before draining does work — under the cap.
Past it the buffer sets `truncated`, `get_retry_buffer()` returns `None`
(`v1/server.rs:911-919`), and the mode-1 failure returns:

```
4 KiB:  drained=4096    replay_buffer=4096 truncated=false  -> upstream got 4096
1 MiB:  drained=1048576 replay_buffer=0    truncated=true   -> upstream got 0
```

`BODY_BUF_LIMIT = 1024 * 64` (`pingora-core-0.8.1/src/protocols/http/v1/common.rs:32`).

Rejected as a primary design. A WAF that forwards bodies correctly up to 64 KiB
and silently truncates above it is worse than one that refuses large bodies
outright, because the boundary is invisible to the operator and the failure
appears as an upstream timeout rather than an error.

## Mode 3 — `request_body_filter`: the answer

Inspecting per chunk in `request_body_filter` and leaving the buffer untouched
forwards every byte at both sizes. The detector port must dispatch its body hook from
here — pingap already implements this callback at
`pingap-proxy/src/server.rs:1233-1258`, where it accumulates
`ctx.state.payload_size` and 413s past `client_body_size_limit`.

## Unverified — carried to the detector port

**HTTP/2 downstream was not exercised.** The spike listener uses a bare
`add_tcp`, so h2c was never negotiated and `--http2-prior-knowledge` failed to
connect (`http_code=000`). This is a gap in the spike harness, not a result:
pingap enables h2 on its own listeners via `enable_h2()`, and
`request_body_filter` is dispatched from `proxy_h2.rs` as well as `proxy_h1.rs`,
so the mechanism is expected to hold. **The detector port must assert byte-identical body
delivery over HTTP/2 explicitly** rather than inheriting this spike's h1-only
evidence. Recorded as an open item rather than an assumed pass.

## Consequences for the detector port

- Body inspection lands in `handle_request_body`, dispatched from the existing
  `request_body_filter`. This is already the chosen design; the spike
  removes the last reason to reconsider.
- The success criterion "benign body arrives byte-identical, including above
  64 KiB" is the one that catches this defect class. Keep it, and keep the
  assertion at the upstream.
- Neither drain variant is a viable fallback. If the trait-hook route had failed,
  the fallback was a scope decision for the user, not an implementation choice.
