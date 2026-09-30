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
