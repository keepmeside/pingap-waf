//! One client's whole challenge session through the real plugin: the marker
//! becomes an interstitial, the interstitial's proof is solved and presented,
//! and the pass cookie the solve earns carries the next request through
//! unchallenged. Every step runs against `handle_request` with a real pingora
//! `Session`, so what is asserted is the path a browser takes, not the pieces
//! it is made of.

use pingap_challenge::pow::find_nonce;
use pingap_challenge::{ChallengeConfig, plugin::Challenge};
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use tokio_test::io::Builder;

/// Every host this binary's tests drive, registered as one set by every test.
/// The registered set is process-global and replaced whole, and the tests in a
/// binary run in parallel — a test registering only its own host would
/// unregister another test's mid-flight, its requests would relabel to the
/// overflow bucket, and its assertions would flake on scheduling. Registering
/// the same union everywhere makes the replace idempotent under any
/// interleaving; each test still drives only its own host, so loop buckets
/// and escalation state never meet across tests.
const HOSTS: [&str; 3] = ["flow.test", "spoof.test", "spoof-escalation.test"];

/// Difficulty 1, so the proof is a couple of hashes rather than a search —
/// the session shape is under test, not the cost curve.
fn plugin() -> Challenge {
    Challenge::new(ChallengeConfig {
        enabled: true,
        secret: "session-test-secret".into(),
        client_ip_from_peer: true,
        difficulty: 1,
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

/// The value of one hidden form input in the rendered interstitial. The
/// interstitial is the contract a browser's solver reads, so the test reads
/// the same way: out of the rendered HTML, not out of plugin internals.
fn hidden_input(body: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let start = body
        .find(&marker)
        .unwrap_or_else(|| panic!("no {name} input in the interstitial"))
        + marker.len();
    let end = start
        + body[start..]
            .find('"')
            .unwrap_or_else(|| panic!("{name} value is unterminated"));
    body[start..end].to_string()
}

#[tokio::test]
async fn a_full_session_issues_solves_and_passes_on_the_pass_cookie() {
    // A registered host of this test's own, so its loop-detection bucket is
    // not the overflow bucket every other test in the crate shares.
    pingap_domainstate::set_registered_hosts(HOSTS);
    let plugin = plugin();

    // 1. A marked request is answered with the interstitial.
    let mut ctx = Ctx::default();
    ctx.extensions
        .insert(pingap_acl::ChallengeMarker::new("acl", "test"));
    let mut session =
        session_for("GET /account HTTP/1.1\r\nHost: flow.test\r\n\r\n").await;
    let response = match plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total")
    {
        RequestPluginResult::Respond(resp) => resp,
        _ => panic!("a marked request must be answered"),
    };
    assert_eq!(response.status.as_u16(), 200);
    let body = String::from_utf8_lossy(&response.body).into_owned();
    let token = hidden_input(&body, "challenge_token");
    let salt = hidden_input(&body, "challenge_salt");
    let difficulty: u8 = hidden_input(&body, "challenge_difficulty")
        .parse()
        .expect("difficulty renders as a number");

    // 2. The proof is solved the way the page's solver solves it, and
    //    presented to the verify endpoint the form points at.
    let nonce = find_nonce(&salt, difficulty, 1_000_000)
        .expect("difficulty 1 has a solution");
    let mut ctx = Ctx::default();
    let mut session = session_for(&format!(
        "GET /.pingap/challenge/verify?challenge_token={token}&nonce={nonce} \
         HTTP/1.1\r\nHost: flow.test\r\n\r\n"
    ))
    .await;
    let response = match plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total")
    {
        RequestPluginResult::Respond(resp) => resp,
        _ => panic!("a presented proof must be answered"),
    };
    assert_eq!(
        response.status.as_u16(),
        303,
        "a solved proof redirects back to where the client was going"
    );
    let set_cookie = response
        .headers
        .unwrap_or_default()
        .into_iter()
        .find(|(name, _)| name == http::header::SET_COOKIE)
        .and_then(|(_, value)| {
            String::from_utf8(value.as_bytes().to_vec()).ok()
        })
        .expect("a solved proof earns a pass cookie");
    assert!(set_cookie.starts_with("pingap_challenge="));
    let value = set_cookie
        .trim_start_matches("pingap_challenge=")
        .split(';')
        .next()
        .unwrap_or_default()
        .to_string();

    // 3. The next request carries the pass cookie and is not challenged.
    let mut ctx = Ctx::default();
    ctx.extensions
        .insert(pingap_acl::ChallengeMarker::new("acl", "test"));
    let mut session = session_for(&format!(
        "GET /account HTTP/1.1\r\nHost: flow.test\r\nCookie: \
         pingap_challenge={value}\r\n\r\n"
    ))
    .await;
    let result = plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total");
    assert!(
        matches!(result, RequestPluginResult::Continue),
        "a valid pass cookie must carry the request through unchallenged"
    );
    assert_eq!(
        ctx.get_variable("challenge_status"),
        Some("solved".to_string()).as_deref()
    );
}

/// A forwarded header the client chose cannot move a challenge binding under
/// the explicit peer assertion: the identity a token is bound to is the TCP
/// peer, so a spoofed `X-Forwarded-For` is never the key. The discriminating
/// shape is the header **changing** between the issue and the verify — if the
/// plugin keyed on the header, the verify would present a token bound to one
/// address from another and be refused; keyed on the peer, it solves.
#[tokio::test]
async fn a_spoofed_forwarded_header_cannot_move_the_binding() {
    pingap_domainstate::set_registered_hosts(HOSTS);
    let plugin = plugin();

    // Issued with one spoofed header value present.
    let mut ctx = Ctx::default();
    ctx.extensions
        .insert(pingap_acl::ChallengeMarker::new("acl", "test"));
    let mut session = session_for(
        "GET /account HTTP/1.1\r\nHost: spoof.test\r\nX-Forwarded-For: \
         6.6.6.6\r\n\r\n",
    )
    .await;
    let response = match plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total")
    {
        RequestPluginResult::Respond(resp) => resp,
        _ => panic!("a marked request must be answered"),
    };
    let body = String::from_utf8_lossy(&response.body).into_owned();
    let token = hidden_input(&body, "challenge_token");
    let salt = hidden_input(&body, "challenge_salt");
    let difficulty: u8 = hidden_input(&body, "challenge_difficulty")
        .parse()
        .expect("difficulty renders as a number");

    // Solved and presented under a different spoofed value. The mock session
    // has no socket, so the peer identity is the same absent value on both
    // legs — the only value that could differ is the header's, and it did.
    let nonce = find_nonce(&salt, difficulty, 1_000_000)
        .expect("difficulty 1 has a solution");
    let mut ctx = Ctx::default();
    let mut session = session_for(&format!(
        "GET /.pingap/challenge/verify?challenge_token={token}&nonce={nonce} \
         HTTP/1.1\r\nHost: spoof.test\r\nX-Forwarded-For: 7.7.7.7\r\n\r\n"
    ))
    .await;
    let response = match plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total")
    {
        RequestPluginResult::Respond(resp) => resp,
        _ => panic!("a presented proof must be answered"),
    };
    assert_eq!(
        response.status.as_u16(),
        303,
        "the binding is the peer, so the header changing between the issue \
         and the verify cannot refuse the solve"
    );
}

/// A spoofed forwarded header cannot accrue escalation against the spoofed
/// address either. Escalation keys on the same identity the token store does,
/// so under the explicit peer assertion a header the client chose is never
/// the key. The discriminating shape is again the header **changing** between
/// requests: keyed on the peer, the failures pile up on one identity and the
/// ladder climbs; keyed on the header, each spoofed value would start a fresh
/// identity at the floor and the ladder would never move. The ladder `[1, 2]`
/// makes the climb visible in the page itself — two failures reach tier 1,
/// and tier 1 renders the silent fingerprint page, whose difficulty input is
/// the template's `0`, not the proof-of-work page's real difficulty.
#[tokio::test]
async fn a_spoofed_forwarded_header_cannot_accrue_escalation() {
    pingap_domainstate::set_registered_hosts(HOSTS);
    let plugin = Challenge::new(ChallengeConfig {
        enabled: true,
        secret: "session-test-secret".into(),
        client_ip_from_peer: true,
        difficulty: 1,
        ladder: vec![1, 2],
        ..Default::default()
    })
    .expect("a valid challenge config builds");

    // First failure, with one spoofed header value present.
    let mut ctx = Ctx::default();
    ctx.extensions
        .insert(pingap_acl::ChallengeMarker::new("acl", "test"));
    let mut session = session_for(
        "GET /account HTTP/1.1\r\nHost: spoof-escalation.test\r\
         \nX-Forwarded-For: 6.6.6.6\r\n\r\n",
    )
    .await;
    let response = match plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total")
    {
        RequestPluginResult::Respond(resp) => resp,
        _ => panic!("a marked request must be answered"),
    };
    assert_eq!(response.status.as_u16(), 200);
    let body = String::from_utf8_lossy(&response.body).into_owned();
    assert_eq!(
        hidden_input(&body, "challenge_difficulty"),
        "1",
        "the first failure is still the proof-of-work page at the base \
         difficulty"
    );

    // Second failure, under a different spoofed value. Keyed on the peer,
    // this is the same client's second failure: the ladder climbs to tier 1
    // and the page goes silent. Keyed on the header, it would be a fresh
    // identity's first — and the page would render the same proof-of-work
    // difficulty again.
    let mut ctx = Ctx::default();
    ctx.extensions
        .insert(pingap_acl::ChallengeMarker::new("acl", "test"));
    let mut session = session_for(
        "GET /account HTTP/1.1\r\nHost: spoof-escalation.test\r\
         \nX-Forwarded-For: 7.7.7.7\r\n\r\n",
    )
    .await;
    let response = match plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total")
    {
        RequestPluginResult::Respond(resp) => resp,
        _ => panic!("a marked request must be answered"),
    };
    assert_eq!(
        response.status.as_u16(),
        200,
        "escalation changes the page, never the verdict"
    );
    let body = String::from_utf8_lossy(&response.body).into_owned();
    assert_eq!(
        hidden_input(&body, "challenge_difficulty"),
        "0",
        "the second failure climbed the ladder on the peer identity, so the \
         header changing between requests moved nothing"
    );
}
