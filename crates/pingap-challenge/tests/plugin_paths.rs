//! Request-path tests for the challenge plugin: what `handle_request` returns
//! for a real request, not just the store in isolation.

use pingap_challenge::{ChallengeConfig, plugin::Challenge};
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use tokio_test::io::Builder;

fn plugin() -> Challenge {
    Challenge::new(ChallengeConfig {
        enabled: true,
        secret: "test-secret".into(),
        client_ip_from_peer: true,
        ..Default::default()
    })
    .expect("a valid challenge config builds")
}

async fn session_for(request: &str) -> Session {
    let io = Builder::new().read(request.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(io));
    session.read_request().await.expect("mock request reads");
    session
}

#[tokio::test]
async fn a_request_with_no_challenge_marker_is_never_challenged() {
    // The escalation ladder and behavioural score only ever modulate a marker
    // the policy already placed. With none, the request must pass through —
    // this is the cannot-originate guarantee asserted at the plugin surface.
    let plugin = plugin();
    let mut ctx = Ctx::default();
    let mut session =
        session_for("GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").await;
    let result = plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total");
    assert!(
        matches!(result, RequestPluginResult::Continue),
        "a request the policy did not mark must not be challenged"
    );
}

#[tokio::test]
async fn a_marked_request_is_answered_with_the_interstitial() {
    // A marker in ctx.extensions turns into a challenge response — the request
    // is answered by the plugin and never reaches the upstream.
    let plugin = plugin();
    let mut ctx = Ctx::default();
    ctx.extensions
        .insert(pingap_acl::ChallengeMarker::new("acl", "test"));
    let mut session =
        session_for("GET /account HTTP/1.1\r\nHost: a.test\r\n\r\n").await;
    let result = plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total");
    match result {
        RequestPluginResult::Respond(resp) => {
            assert_eq!(resp.status.as_u16(), 200);
            let body = String::from_utf8_lossy(&resp.body);
            assert!(body.contains("Checking your browser"));
            // The PoW page carries its solver — a browser passes without
            // typing a nonce by hand.
            assert!(body.contains("crypto.subtle.digest"));
        },
        RequestPluginResult::Continue | RequestPluginResult::Skipped => {
            panic!("a marked request must be answered")
        },
    }
    assert_eq!(
        ctx.get_variable("challenge_status"),
        Some("issued".to_string()).as_deref()
    );
}

#[tokio::test]
async fn the_challenge_outcome_renders_into_an_access_log_line() {
    // `{:challenge_status}` must reach a rendered log line, not just the variables map —
    // the map assertion above is the one that passes while the field renders empty. This
    // is the test the shared `{:name}` fallback exists to satisfy, and it is asserted on
    // the bytes `Parser::format` produces, mirroring the WAF's rendered-line test.
    use pingap_logger::Parser;

    let plugin = plugin();
    let mut ctx = Ctx::default();
    ctx.extensions
        .insert(pingap_acl::ChallengeMarker::new("acl", "test"));
    let mut session =
        session_for("GET /account HTTP/1.1\r\nHost: a.test\r\n\r\n").await;
    plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total");

    let parser: Parser = "status={:challenge_status}".into();
    let rendered = parser.format(&session, &ctx);
    assert_eq!(
        "status=issued",
        String::from_utf8_lossy(&rendered),
        "the challenge outcome must render as a log field"
    );

    // The allow path with no marker writes nothing, which a log format must tolerate —
    // the field renders empty rather than as a stray literal `{:challenge_status}`.
    let mut ctx = Ctx::default();
    let mut session =
        session_for("GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").await;
    plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total");
    let rendered = parser.format(&session, &ctx);
    assert_eq!("status=", String::from_utf8_lossy(&rendered));
}

#[tokio::test]
async fn the_key_identifier_travels_with_the_status_into_the_log_line() {
    // Two nodes sharing traffic with two different pass-cookie secrets produce
    // the same client-visible loop — solve on one, fail on the other — and the
    // only honest in-log discriminator is which secret's authority each node
    // acted under. `challenge_key_id` is this node's key identifier, published
    // beside every status so the mismatch reads as two different ids in the two
    // nodes' logs rather than as an unexplained solve rate.
    use pingap_logger::Parser;

    // A registered host of this test's own: the loop detector keys its counts
    // by classified label, and every other test in this binary lands in the
    // shared overflow bucket with the same mock identity — without a label of
    // our own, this test's two issues are what tips that shared bucket over
    // its threshold and a sibling's interstitial turns into a loop refusal.
    pingap_domainstate::set_registered_hosts(["key.test"]);
    let kid = pingap_challenge::cookie::key_id(b"test-secret");
    let plugin = plugin();

    let mut ctx = Ctx::default();
    ctx.extensions
        .insert(pingap_acl::ChallengeMarker::new("acl", "test"));
    let mut session =
        session_for("GET /account HTTP/1.1\r\nHost: key.test\r\n\r\n").await;
    plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total");
    assert_eq!(
        ctx.get_variable("challenge_key_id"),
        Some(kid.as_str()),
        "the key id is published beside the status"
    );

    // It renders as a log field, not just a variables-map entry.
    let parser: Parser = "key={:challenge_key_id}".into();
    let rendered = parser.format(&session, &ctx);
    assert_eq!(format!("key={kid}"), String::from_utf8_lossy(&rendered));

    // A different secret yields a different id, which is the entire signal: the
    // second node of the mismatched pair logs this row with the other value.
    let other = Challenge::new(ChallengeConfig {
        enabled: true,
        secret: "other-secret".into(),
        client_ip_from_peer: true,
        ..Default::default()
    })
    .expect("a valid challenge config builds");
    let mut ctx = Ctx::default();
    ctx.extensions
        .insert(pingap_acl::ChallengeMarker::new("acl", "test"));
    let mut session =
        session_for("GET /account HTTP/1.1\r\nHost: key.test\r\n\r\n").await;
    other
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total");
    assert_ne!(
        ctx.get_variable("challenge_key_id"),
        Some(kid.as_str()),
        "two secrets must yield two key ids, or the mismatch is invisible"
    );
}
