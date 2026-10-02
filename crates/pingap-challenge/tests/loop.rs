//! The loop a client cannot escape: a client that keeps being challenged and
//! never solves stops being issued challenges, and what happens instead is the
//! configured direction. The default refuses — an unsolved-challenge loop is a
//! client that cannot pass, and serving it interstitials forever is a promise
//! neither side can keep — with an outcome and a reason of its own so the
//! counter distinguishes a loop refusal from an escalated one.

use pingap_challenge::config::LoopBypass;
use pingap_challenge::{ChallengeConfig, plugin::Challenge};
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use tokio_test::io::Builder;

/// Threshold 2, so the loop arrives within one test's driving. The bypass
/// direction is the per-instance part under test; the threshold itself is
/// fixed by the first construction into the process-global state, which is
/// why both plugins here share it.
fn plugin(bypass: LoopBypass) -> Challenge {
    Challenge::new(ChallengeConfig {
        enabled: true,
        secret: "loop-test-secret".into(),
        client_ip_from_peer: true,
        difficulty: 1,
        loop_threshold: 2,
        bypass_on_loop: bypass,
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

/// One marked request through the plugin, answered or allowed.
async fn marked(plugin: &Challenge, host: &str) -> RequestPluginResult {
    let mut ctx = Ctx::default();
    ctx.extensions
        .insert(pingap_acl::ChallengeMarker::new("acl", "loop-test"));
    let mut session =
        session_for(&format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n")).await;
    plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total")
}

#[tokio::test]
async fn past_the_threshold_the_configured_direction_decides() {
    // One registered host per direction: the loop detector keys on the
    // classified label, so the two legs cannot see each other's counts.
    pingap_domainstate::set_registered_hosts(["refuse.test", "allow.test"]);

    // The default direction refuses, and the refusal is not a challenge.
    let refuse = plugin(LoopBypass::Refuse);
    assert!(
        matches!(marked(&refuse, "refuse.test").await, RequestPluginResult::Respond(refusal)
            if refusal.status.as_u16() == 200),
        "the first challenge is an interstitial, not a loop refusal"
    );
    let second = match marked(&refuse, "refuse.test").await {
        RequestPluginResult::Respond(refusal) => refusal,
        _ => panic!("a looping client must be answered, not admitted"),
    };
    assert_eq!(
        second.status.as_u16(),
        403,
        "past the threshold the default direction refuses"
    );
    let body = String::from_utf8_lossy(&second.body).into_owned();
    assert!(
        body.contains("Challenge loop detected"),
        "the loop refusal carries its own body, not an interstitial: {body}"
    );
    let rows = pingap_challenge::counters_snapshot();
    let row = rows
        .get("refuse.test")
        .expect("the refusing domain keeps its own row");
    assert!(
        row.bypassed >= 1,
        "the loop refusal is counted as bypassed, not as issued: {row:?}"
    );
    assert_eq!(
        row.issued, 1,
        "the loop refusal must not count as a challenge issued"
    );

    // The configured direction can keep issuing instead: an operator who
    // would rather keep answering the loop than refuse it says so once, and
    // the same threshold then changes nothing about the response.
    let allow = plugin(LoopBypass::Allow);
    for _ in 0..3 {
        match marked(&allow, "allow.test").await {
            RequestPluginResult::Respond(response) => assert_eq!(
                response.status.as_u16(),
                200,
                "the allow direction keeps issuing interstitials"
            ),
            _ => panic!("the allow direction must keep answering"),
        }
    }
    let rows = pingap_challenge::counters_snapshot();
    let row = rows
        .get("allow.test")
        .expect("the allowing domain keeps its own row");
    assert_eq!(row.issued, 3, "every allowed-loop response is a challenge");
    assert_eq!(
        row.bypassed, 0,
        "nothing was bypassed under the allow direction"
    );
}
