//! The recorded verdict: every challenge decision leaves a log line naming
//! the domain and the reason, on the solved paths as well as the refused
//! ones. Asserted on emitted bytes under a capturing subscriber, because the
//! assertion that matters is that the line exists with its fields — not that
//! a helper was called.

use pingap_challenge::pow::find_nonce;
use pingap_challenge::{ChallengeConfig, plugin::Challenge};
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tokio_test::io::Builder;

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn plugin() -> Challenge {
    Challenge::new(ChallengeConfig {
        enabled: true,
        secret: "verdict-test-secret".into(),
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

/// The value of one hidden form input in the rendered interstitial, read the
/// way the page's own solver reads it: out of the rendered HTML.
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

/// The captured bytes as text, for field assertions.
fn text_of(captured: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8(
        captured
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone(),
    )
    .expect("captured log bytes are UTF-8")
}

/// A capturing subscriber installed as this thread's default. The
/// current-thread test runtime polls the plugin on this thread, so every
/// decision a test provokes lands in that test's own capture — tests in this
/// binary can run in parallel without reading each other's lines.
fn capture() -> (Arc<Mutex<Vec<u8>>>, tracing::subscriber::DefaultGuard) {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(Capture(Arc::clone(&captured)))
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    (captured, guard)
}

/// Every host this binary's tests drive, registered as one set by every test.
/// The registered set is process-global and replaced whole, and the tests in a
/// binary run in parallel — a test registering only its own host would
/// unregister another test's mid-flight, its requests would relabel to the
/// overflow bucket, and its log-line assertions would flake on scheduling.
/// Registering the same union everywhere makes the replace idempotent under
/// any interleaving; each test still drives only its own host.
const HOSTS: [&str; 3] =
    ["verdict.test", "verdict-exempt.test", "verdict-loop.test"];

#[tokio::test]
async fn every_decision_names_its_domain_and_reason_solved_and_refused() {
    let (captured, _guard) = capture();

    // A registered host of this test's own, so its loop-detection bucket and
    // its log lines are not shared with any other test in the crate.
    pingap_domainstate::set_registered_hosts(HOSTS);
    let plugin = plugin();

    // Issued: a marked request, with a marker reason distinctive enough to
    // assert on.
    let mut ctx = Ctx::default();
    ctx.extensions
        .insert(pingap_acl::ChallengeMarker::new("acl", "verdict-marker"));
    let mut session =
        session_for("GET /account HTTP/1.1\r\nHost: verdict.test\r\n\r\n")
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

    // Solved: the proof is solved and presented.
    let nonce = find_nonce(&salt, difficulty, 1_000_000)
        .expect("difficulty 1 has a solution");
    let mut ctx = Ctx::default();
    let mut session = session_for(&format!(
        "GET /.pingap/challenge/verify?challenge_token={token}&nonce={nonce} \
         HTTP/1.1\r\nHost: verdict.test\r\n\r\n"
    ))
    .await;
    match plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total")
    {
        RequestPluginResult::Respond(resp) => {
            assert_eq!(resp.status.as_u16(), 303);
        },
        _ => panic!("a presented proof must be answered"),
    }

    // Refused: a fresh challenge whose proof is presented wrong.
    let mut ctx = Ctx::default();
    ctx.extensions
        .insert(pingap_acl::ChallengeMarker::new("acl", "verdict-marker"));
    let mut session =
        session_for("GET /account HTTP/1.1\r\nHost: verdict.test\r\n\r\n")
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
    let mut ctx = Ctx::default();
    let mut session = session_for(&format!(
        "GET /.pingap/challenge/verify?challenge_token={token}&nonce=0 \
         HTTP/1.1\r\nHost: verdict.test\r\n\r\n"
    ))
    .await;
    match plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total")
    {
        RequestPluginResult::Respond(resp) => {
            assert_eq!(resp.status.as_u16(), 403);
        },
        _ => panic!("a failed proof must be answered"),
    }

    let text = text_of(&captured);
    for field in [
        "domain=\"verdict.test\"",
        "outcome=\"issued\"",
        "reason=\"verdict-marker\"",
        "outcome=\"solved\"",
        "reason=\"pow\"",
        "outcome=\"failed\"",
        "reason=\"proof-failed\"",
    ] {
        assert!(
            text.contains(field),
            "the recorded verdict is missing `{field}`; captured: {text}"
        );
    }
}

/// The exempt promise is logged per hit, under an outcome of its own. The
/// counters count every exempt hit; this is the attributable half — an
/// operator reading the log can tell an exempt pass from a solved one, so a
/// promise silently broken (an exempt list that stopped matching) is visible
/// as the line's absence, not only as the counter's presence.
#[tokio::test]
async fn an_exempt_hit_is_logged_per_hit_under_its_own_outcome() {
    let (captured, _guard) = capture();
    pingap_domainstate::set_registered_hosts(HOSTS);
    // The identity anchor here is the resolved client IP, so the address
    // under test is one the test chooses: the trusted-proxy list makes the
    // resolution legal to construct, and the pre-seeded `client_ip` is what
    // the gateway's own resolver would have left for the plugin to reuse.
    pingap_core::set_trusted_proxies(&Some(vec!["192.0.2.10".to_string()]));
    let plugin = Challenge::new(ChallengeConfig {
        enabled: true,
        secret: "verdict-test-secret".into(),
        exempt: vec!["203.0.113.7".into()],
        ..Default::default()
    })
    .expect("a valid challenge config builds");

    for _ in 0..2 {
        let mut ctx = Ctx::default();
        ctx.conn.client_ip = Some("203.0.113.7".to_string());
        ctx.extensions
            .insert(pingap_acl::ChallengeMarker::new("acl", "verdict-marker"));
        let mut session =
            session_for("GET / HTTP/1.1\r\nHost: verdict-exempt.test\r\n\r\n")
                .await;
        let result = plugin
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .expect("handle_request is total");
        assert!(
            matches!(result, RequestPluginResult::Continue),
            "an exempt address must never be challenged"
        );
        assert_eq!(
            ctx.get_variable("challenge_status"),
            Some("exempt".to_string()).as_deref(),
            "the exempt outcome is published like every other"
        );
    }

    let text = text_of(&captured);
    assert_eq!(
        text.matches("outcome=\"exempt\"").count(),
        2,
        "every exempt hit is logged, not only the first: {text}"
    );
    assert!(
        text.contains("domain=\"verdict-exempt.test\""),
        "the exempt line names the domain: {text}"
    );
}

/// The loop refusal is logged under its own outcome and its own reason, so a
/// client refused for looping reads differently in the log from one refused
/// for a failed proof. The two refusals mean different things to an operator:
/// one is a client that cannot solve, the other is a client that will not.
#[tokio::test]
async fn a_loop_refusal_is_logged_with_its_own_reason() {
    let (captured, _guard) = capture();
    pingap_domainstate::set_registered_hosts(HOSTS);
    let plugin = plugin();

    // The default threshold is three: two interstitials, then the loop
    // closes and the default direction refuses.
    for round in 1..=3u8 {
        let mut ctx = Ctx::default();
        ctx.extensions
            .insert(pingap_acl::ChallengeMarker::new("acl", "verdict-marker"));
        let mut session =
            session_for("GET / HTTP/1.1\r\nHost: verdict-loop.test\r\n\r\n")
                .await;
        let response = match plugin
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .expect("handle_request is total")
        {
            RequestPluginResult::Respond(resp) => resp,
            _ => panic!("a marked request must be answered"),
        };
        if round < 3 {
            assert_eq!(
                response.status.as_u16(),
                200,
                "below the threshold the loop is still answered with \
                 challenges"
            );
        } else {
            assert_eq!(
                response.status.as_u16(),
                403,
                "past the threshold the default direction refuses"
            );
        }
    }

    let text = text_of(&captured);
    for field in [
        "domain=\"verdict-loop.test\"",
        "outcome=\"bypassed\"",
        "reason=\"loop-detected\"",
    ] {
        assert!(
            text.contains(field),
            "the loop refusal is missing `{field}`; captured: {text}"
        );
    }
}
