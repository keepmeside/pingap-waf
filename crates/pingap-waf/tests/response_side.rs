//! Response-side detection over both body hooks.
//!
//! Response-side is different in kind from request-side, not just in degree.
//! `ResponseBodyPluginResult` is `Unchanged | PartialReplaced | FullyReplaced` — there
//! is no `Respond` variant, and by the time a body hook runs the status and headers are
//! already downstream. So a finding here can only be **recorded** or **masked**, never
//! turned into a 403, and these tests assert that asymmetry rather than describing it.
//!
//! The two hooks sit on opposite sides of the cache and each alone leaves half the
//! behaviour missing. `handle_upstream_response_body` runs under `if !from_cache`,
//! before the cache write pingora comments as "cache the original response before any
//! downstream transformation" — so it sanitises what is admitted, and never fires on a
//! hit. `handle_response_body` runs on the serving path and covers hits, including
//! entries admitted before a rule existed. Both are registered; both are tested here.
#![cfg(feature = "plugin")]

use bytes::Bytes;
use pingap_config::PluginConf;
use pingap_core::{Ctx, Plugin, ResponseBodyPluginResult};
use pingap_waf::plugin::{Waf, WafState};
use pingora::proxy::Session;
use tokio_test::io::Builder;

/// Both response-side lineages in their only enforcing mode. `block` is not offered:
/// see `a_response_side_category_cannot_be_set_to_block`.
const REDACTING: &str = r#"
category = "waf"
anomaly_threshold = 1
categories = { data_leakage = "redact", web_shell = "redact" }
"#;

fn plugin(conf: &str) -> Waf {
    Waf::try_from(
        &toml::from_str::<PluginConf>(conf).expect("test config parses"),
    )
    .expect("test config builds")
}

/// Which of the two hooks to push a body through.
#[derive(Clone, Copy, PartialEq)]
enum Side {
    /// `handle_upstream_response_body` — what enters the cache.
    Upstream,
    /// `handle_response_body` — what leaves for the client, cache hits included.
    Downstream,
}

/// Push a response body through one hook and return what the client (or the cache
/// entry) would have received, plus the hook's own verdict.
fn served(
    waf: &Waf,
    ctx: &mut Ctx,
    chunk: &[u8],
    side: Side,
) -> (Vec<u8>, ResponseBodyPluginResult) {
    let mut session = Session::new_h1(Box::new(Builder::new().build()));
    let mut body = Some(Bytes::copy_from_slice(chunk));
    let result = match side {
        Side::Upstream => waf.handle_upstream_response_body(
            &mut session,
            ctx,
            &mut body,
            true,
        ),
        Side::Downstream => {
            waf.handle_response_body(&mut session, ctx, &mut body, true)
        },
    }
    .expect("response-side evaluation is total");
    (body.map(|b| b.to_vec()).unwrap_or_default(), result)
}

#[tokio::test]
async fn a_leaking_response_is_masked_in_place_at_the_same_length() {
    let waf = plugin(REDACTING);
    let leak = b"<p>Warning: mysql_connect(): Access denied</p>";
    for side in [Side::Upstream, Side::Downstream] {
        let mut ctx = Ctx::default();
        let (out, result) = served(&waf, &mut ctx, leak, side);
        assert_eq!(
            out.len(),
            leak.len(),
            "masking must preserve length or Content-Length starts lying"
        );
        assert_ne!(out, leak.to_vec(), "the leak was served unmodified");
        assert!(
            out.contains(&b'*'),
            "the matched span should be masked: {}",
            String::from_utf8_lossy(&out)
        );
        // The type has no way to deny, so a hit can only report a rewrite. This is
        // the assertion that documents why response-side cannot return 403.
        assert!(matches!(
            result,
            ResponseBodyPluginResult::PartialReplaced
                | ResponseBodyPluginResult::FullyReplaced
        ));
        let state = ctx.extensions.get::<WafState>().expect("state recorded");
        assert!(state.redacted);
        assert!(
            !state.blocked,
            "a response-side finding must never present as a denial"
        );
        assert!(!state.hits.is_empty(), "a redaction must name its rules");
    }
}

#[tokio::test]
async fn a_web_shell_signature_is_caught_on_the_way_out() {
    let waf = plugin(REDACTING);
    let mut ctx = Ctx::default();
    let (out, _) = served(
        &waf,
        &mut ctx,
        b"uid=0(root) gid=0(root) groups=0(root)",
        Side::Upstream,
    );
    assert!(
        out.contains(&b'*'),
        "a web-shell response was served intact"
    );
    let state = ctx.extensions.get::<WafState>().expect("state recorded");
    assert!(state.redacted);
}

#[tokio::test]
async fn a_response_cached_before_the_rule_existed_is_still_redacted() {
    // The cache-hit path runs `handle_response_body` and never the upstream hook. A
    // body admitted while the category was `off` would otherwise be served unredacted
    // for the rest of its TTL — with no hit and no event, so the operator's dashboard
    // shows zero response-side findings and they conclude the leak is fixed.
    let waf = plugin(REDACTING);
    let mut ctx = Ctx::default();
    let (out, _) = served(
        &waf,
        &mut ctx,
        b"uid=0(root) gid=0(root) groups=0(root)",
        Side::Downstream,
    );
    assert!(out.contains(&b'*'), "a cache hit was served unredacted");
}

#[tokio::test]
async fn an_unredacted_body_is_never_admitted_to_the_cache() {
    // The upstream hook runs before the cache write, so what it emits *is* the cache
    // entry. If it emitted the original bytes, every later hit would serve the leak.
    let waf = plugin(REDACTING);
    let leak = b"<p>Warning: mysql_connect(): Access denied</p>";
    let mut ctx = Ctx::default();
    let (admitted, _) = served(&waf, &mut ctx, leak, Side::Upstream);
    assert!(
        !admitted
            .windows(b"mysql_connect".len())
            .any(|w| w == b"mysql_connect"),
        "the cache entry still carries the leaked text: {}",
        String::from_utf8_lossy(&admitted)
    );
}

#[tokio::test]
async fn the_same_body_passes_through_when_the_category_is_off() {
    // The other half of the redaction criterion: the detector fires because it was
    // enabled, not because the pattern is unconditional.
    let waf = plugin(
        "category = \"waf\"\ncategories = { data_leakage = \"off\", web_shell = \
         \"off\" }\n",
    );
    let leak = b"<p>Warning: mysql_connect(): Access denied</p>";
    for side in [Side::Upstream, Side::Downstream] {
        let mut ctx = Ctx::default();
        let (out, result) = served(&waf, &mut ctx, leak, side);
        assert_eq!(out, leak.to_vec(), "an `off` category rewrote a body");
        assert_eq!(result, ResponseBodyPluginResult::Unchanged);
        assert!(
            ctx.extensions
                .get::<WafState>()
                .is_none_or(|state| !state.redacted),
            "an `off` category recorded a redaction"
        );
    }
}

#[tokio::test]
async fn a_benign_response_is_passed_through_untouched() {
    let waf = plugin(REDACTING);
    let body = br#"{"items":[{"id":1,"name":"widget"}],"total":1}"#;
    for side in [Side::Upstream, Side::Downstream] {
        let mut ctx = Ctx::default();
        let (out, result) = served(&waf, &mut ctx, body, side);
        assert_eq!(out, body.to_vec());
        assert_eq!(result, ResponseBodyPluginResult::Unchanged);
    }
}

#[tokio::test]
async fn a_response_side_category_cannot_be_set_to_block() {
    // The impossibility is enforced at config load, not merely documented. A `block`
    // that silently behaved as `redact` would tell an operator a leak is prevented
    // when it is only being rewritten on the way past.
    let err = match Waf::try_from(
        &toml::from_str::<PluginConf>(
            "category = \"waf\"\ncategories = { data_leakage = \"block\" }\n",
        )
        .expect("parses"),
    ) {
        Err(e) => e,
        Ok(_) => panic!("block on a response-side category must fail"),
    };
    let msg = err.to_string();
    assert!(msg.contains("data_leakage"), "names the category: {msg}");
    assert!(msg.contains("redact"), "names the alternative: {msg}");
}
