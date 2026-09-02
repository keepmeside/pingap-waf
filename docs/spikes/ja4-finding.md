# Spike A — JA4 ClientHello reachability

**Verdict: CONDITIONAL GO for Phase 16.** The mechanism is reachable and the
load-bearing unknown — extension order — is confirmed preserved. But three of the
plan's gate items are **not** satisfied by this spike, and Phase 16's gate requires
all of them. Phase 16 must not start until they are closed.

Run 2026-09-02. Harness `spikes/ja4-clienthello/`.

## Step 0 — the `ossl111` cfg gate: satisfied

```
ossl111 SATISFIED (version_number=0x30000020)
openssl_version  OpenSSL 3.0.2 15 Mar 2022
```

Resolved in `build.rs` from `DEP_OPENSSL_VERSION_NUMBER`, in seconds rather than
days, exactly as the plan asked. `set_client_hello_callback` is gated behind this
cfg and compiles.

## What the spike proves

| Question | Result |
|---|---|
| Client-hello callback fires | **yes** |
| Cipher list readable | **yes** — 31 ciphers |
| Legacy version readable | **yes** — `0x0303` |
| Extension list readable via `openssl-sys` FFI | **yes** — 12 extensions |
| **Extension order preserved** | **yes — see below** |
| ALPN callback coexists with client-hello callback | **yes** — `h2` negotiated on the same handshake that fired the callback |
| Borrow shapes reconcile | **yes** — compiles; `&mut SslRef` in the callback is what `SSL_client_hello_get1_extensions_present` needs |
| `unsafe` confinement | **1 block**, in `client_hello_extensions` only |

**Extension order is the finding that matters.** JA4 is order-sensitive, so a
set-but-unordered API would silently produce fingerprints that match no other
implementation. The returned list is:

```
0000 000b 000a 0023 0010 0016 0017 000d 002b 002d 0033 0015
```

That is **not ascending** — `0023` precedes `0010`, `000d` follows `0017` — so it
reflects wire order rather than a sorted set. Had it come back ascending the result
would have been ambiguous and the spike would have needed a second client to
distinguish the two cases; it did not.

Shaped fingerprint produced end to end: `t12d3112h2_e8f1e7e78f70_d46e53a606d8`.

## What the spike does NOT prove — Phase 16's gate is not met

Three gate items from `phase-16` remain open. Recording them plainly because a
"GO" that quietly omits them would be the failure mode this spike exists to
prevent.

**1. The computed value is not cross-checked against a reference implementation.**
`t12d3112h2_…` is *shape*-plausible and nothing more. The plan is explicit that
nginx-love's committed vectors are log-parser fixtures with no recorded
ClientHello, so they validate format only — and this spike did not run a FoxIO
reference implementation or a pcap with an independently known JA4. **Until that
cross-check happens, the value must be treated as unverified.** A plausible
fingerprint that matches nobody else's is worthless, and self-consistency is not
validation.

**2. Session resumption and HTTP/2 connection reuse are untested.** The spike
performs exactly one full handshake. Whether the callback fires on a resumed
session, or on a reused h2 connection, is unanswered — and it decides whether
Phase 16's fail-open default is a rare path or the common one.

**3. The musl static target was not exercised.** No musl target is installed on
this machine (`rustup target list --installed` shows none), so the plan's fourth
unknown is untouched. This is also where the spike's OpenSSL differs from
production in a way that matters:

| | OpenSSL |
|---|---|
| This spike (system, dynamic) | **3.0.2** |
| pingap's pinned `openssl-src` | **300.6.1+3.6.3** → OpenSSL **3.6.3** |

Both clear the 1.1.1 gate comfortably, so the cfg result carries over. But the
spike deliberately did not enable the `vendored` feature — forcing it would have
answered a different question than "does the cfg hold against what actually links".
Whether the whole chain works against vendored 3.6.3 **on musl** is precisely the
combination Phase 16 step 11 must verify, and a glibc-only outcome is a scope
decision for the user rather than something to absorb silently.

## Consequences

- **Phase 16 stays in the plan, conditionally.** The mechanism is real: callback
  fires, extensions are readable in wire order, ALPN coexists, one contained
  `unsafe`. Nothing found here cuts the phase.
- **Phase 16's gate is not satisfied and its own step 1 must re-confirm.** Its gate
  lists six items; this spike closes three (cfg, borrow shapes, extension order)
  and leaves three open (reference cross-check, resumption/h2, musl).
- **Phase 06 is unaffected.** JA4H needs no TLS access and remains the shipping
  fingerprint story regardless.
- The `unsafe` block written here is spike code. Phase 16 step 3 rewrites it with
  a captured-ClientHello fixture corpus rather than promoting this file.

## Note on the ALPN result

`alpn_coexists true` is worth one line of caution: the spike registers
`set_alpn_select_callback` on its own acceptor, whereas pingap registers it inside
`enable_h2()` on a `TlsSettings` built through the
`TlsSettings → SslAcceptorBuilder → SslContextBuilder` deref chain. The
coexistence result is strong evidence but not identical to pingap's construction
path, which Phase 16 step 5 exercises directly.
