//! An allowed request body reaches the upstream byte-identical.
//!
//! This file exists because of a design that was rejected, and it is the only reason
//! the rejection is enforced rather than remembered. Draining the body inside a
//! `PluginStep::Request` plugin looks like it works: Pingora mirrors request bytes into
//! a replayable buffer only when that buffer already exists at read time, and
//! `enable_retry_buffering()` runs inside `proxy_to_upstream`, strictly after
//! `request_filter` has returned. So bytes read from a request filter are handed over
//! and dropped, and the upstream receives the original `Content-Length` with no body.
//!
//! Blocking still works under that design — it terminates the request, so destroying
//! the body is harmless. **Every allowed request is silently corrupted.** A suite that
//! asserts "malicious POST returns 403" passes green throughout. So the assertions here
//! are on the bytes the proxy would forward, never on a status code.
#![cfg(feature = "plugin")]

use bytes::Bytes;
use pingap_config::PluginConf;
use pingap_core::{Ctx, Plugin};
use pingap_waf::plugin::{Waf, WafState};
use pingora::proxy::Session;
use tokio_test::io::Builder;

/// Blocking mode with a threshold of one, so a single hit is a refusal. The shipped
/// default is `detect`; enforcement is what this file is about.
const BLOCKING: &str = r#"
category = "waf"
anomaly_threshold = 1
categories = { sql_injection = "block", xss = "block" }
"#;

fn plugin(conf: &str) -> Waf {
    Waf::try_from(
        &toml::from_str::<PluginConf>(conf).expect("test config parses"),
    )
    .expect("test config builds")
}

/// Feed a whole body through the hook one chunk at a time and return what the upstream
/// would have received, in order.
///
/// Concatenating what the hook emits is the only honest way to check byte-identity:
/// a client status code cannot see a body that arrived empty.
fn forwarded(
    waf: &Waf,
    ctx: &mut Ctx,
    chunks: &[&[u8]],
) -> pingora::Result<Vec<u8>> {
    let mut session = Session::new_h1(Box::new(Builder::new().build()));
    let mut out = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        let last = i + 1 == chunks.len();
        let mut body = Some(Bytes::copy_from_slice(chunk));
        waf.handle_request_body(&mut session, ctx, &mut body, last)?;
        if let Some(emitted) = body {
            out.extend_from_slice(&emitted);
        }
    }
    Ok(out)
}

#[tokio::test]
async fn a_benign_body_reaches_the_upstream_byte_identical() {
    let waf = plugin(BLOCKING);
    let mut ctx = Ctx::default();
    // 4 KB across several chunks, so this covers reassembly rather than a
    // single-chunk special case.
    let body: Vec<u8> = (0..4096u32)
        .map(|i| b"abcdefghij"[(i % 10) as usize])
        .collect();
    let chunks: Vec<&[u8]> = body.chunks(700).collect();
    let out = forwarded(&waf, &mut ctx, &chunks).expect("allowed");
    assert_eq!(
        out.len(),
        body.len(),
        "a length change makes the request's Content-Length a lie"
    );
    assert_eq!(out, body, "the upstream must receive the original bytes");
}

#[tokio::test]
async fn a_body_above_the_retry_buffer_ceiling_still_arrives_intact() {
    // 96 KiB: past pingora's 64 KiB `BODY_BUF_LIMIT`, which is where the rejected
    // `enable_retry_buffering` fallback starts setting `truncated` and
    // `get_retry_buffer()` starts returning `None`. Nothing here depends on that
    // buffer, and this case is what says so.
    let waf = plugin(BLOCKING);
    let mut ctx = Ctx::default();
    let body: Vec<u8> = (0..98_304u32).map(|i| (i % 251) as u8).collect();
    let chunks: Vec<&[u8]> = body.chunks(8192).collect();
    let out = forwarded(&waf, &mut ctx, &chunks).expect("allowed");
    assert_eq!(out.len(), body.len());
    assert_eq!(out, body);
}

#[tokio::test]
async fn a_malicious_body_is_rejected_with_nothing_forwarded() {
    let waf = plugin(BLOCKING);
    let mut ctx = Ctx::default();
    let payload = b"comment=1'+OR+'1'='1'+--+&submit=1";
    let err = forwarded(&waf, &mut ctx, &[payload])
        .expect_err("a SQL injection in the body must be rejected");
    assert!(
        matches!(err.etype(), pingora::ErrorType::HTTPStatus(403)),
        "the rejection must render as a 403, not a 500: {err}"
    );
    let state = ctx.extensions.get::<WafState>().expect("state recorded");
    assert!(state.blocked);
    assert!(!state.hits.is_empty(), "a block must name its rules");
}

#[tokio::test]
async fn nothing_is_forwarded_until_the_body_has_been_judged() {
    // The property the withhold design exists for. A first chunk that reached the
    // upstream before the second was inspected would make the block meaningless for
    // any body larger than one chunk.
    let waf = plugin(BLOCKING);
    let mut ctx = Ctx::default();
    let mut session = Session::new_h1(Box::new(Builder::new().build()));
    let mut body = Some(Bytes::from_static(b"comment=harmless&more="));
    waf.handle_request_body(&mut session, &mut ctx, &mut body, false)
        .expect("first chunk is held");
    assert!(
        body.is_none(),
        "a non-final chunk must not be released to the upstream"
    );
}

#[tokio::test]
async fn an_over_cap_body_follows_its_configured_policy() {
    // `inspect_prefix`: inspect what fits, forward everything, record the shortfall. A
    // large upload is usually legitimate, and dropping it silently is worse than
    // inspecting less of it. What must never happen is a silent full bypass.
    let waf = plugin(
        "category = \"waf\"\nbody_inspect_limit = 32\nover_cap = \
         \"inspect_prefix\"\n",
    );
    let mut ctx = Ctx::default();
    let body = vec![b'z'; 200];
    let out = forwarded(&waf, &mut ctx, &[&body]).expect("forwarded");
    assert_eq!(out, body, "an under-inspected body is still not corrupted");
    let state = ctx.extensions.get::<WafState>().expect("state recorded");
    assert!(
        state.truncated,
        "an uninspected tail must be recorded, not silent"
    );

    // `reject`: refuse rather than accept something that could not be inspected. A 413,
    // not a 403 — the request was not denied by policy, it was too large to judge.
    let waf = plugin(
        "category = \"waf\"\nbody_inspect_limit = 32\nover_cap = \"reject\"\n",
    );
    let mut ctx = Ctx::default();
    let err = forwarded(&waf, &mut ctx, &[&body])
        .expect_err("the reject policy must refuse an oversized body");
    assert!(
        matches!(err.etype(), pingora::ErrorType::HTTPStatus(413)),
        "an over-cap rejection is a 413, not a policy denial: {err}"
    );
}

#[tokio::test]
async fn body_inspection_cannot_be_silently_switched_off() {
    // `body_inspect_limit = 0` would read as "inspect nothing", which is a full bypass
    // wearing the clothes of a limit. Validation refuses it, so the only way to reduce
    // body inspection is to name a real prefix and accept the recorded shortfall.
    let err = match Waf::try_from(
        &toml::from_str::<PluginConf>(
            "category = \"waf\"\nbody_inspect_limit = 0\n",
        )
        .expect("parses"),
    ) {
        Err(e) => e,
        Ok(_) => panic!("a zero body-inspection limit must be rejected"),
    };
    assert!(
        err.to_string().contains("body_inspect_limit"),
        "the error must name the key: {err}"
    );
}
