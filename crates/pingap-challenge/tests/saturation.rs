//! Saturation: what the tier does when its bounded stores are full. The
//! store-level tests pin the two error variants; the plugin-surface test
//! drives the real issue and verify paths against them — a full domain set
//! refuses toward the configured policy, and a full entry set falls back to
//! the stateless cookie, which still verifies a client that can carry one.

use pingap_challenge::pow::find_nonce;
use pingap_challenge::token::{ChallengeRecord, TokenError, TokenStore};
use pingap_challenge::{ChallengeConfig, plugin::Challenge};
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use std::time::{Duration, SystemTime};
use tokio_test::io::Builder;

#[test]
fn a_full_store_reports_saturation_instead_of_displacing_a_live_token() {
    let store = TokenStore::new(1);
    let record = || ChallengeRecord {
        domain: "a.test".into(),
        identity: "203.0.113.1".into(),
        salt: "s".into(),
        difficulty: 1,
        target: "/".into(),
        kind: "pow".into(),
        attempts: 0,
        expires_at: SystemTime::now() + Duration::from_secs(60),
    };
    store.issue("one".into(), record()).expect("room");
    assert_eq!(
        store.issue("two".into(), record()),
        Err(TokenError::FullEntries)
    );
    assert!(
        store
            .take("one", "a.test", "203.0.113.1", SystemTime::now())
            .is_some()
    );
}

#[test]
fn domain_capacity_is_reported_separately() {
    let store = TokenStore::with_limits(1, 4);
    let record = |domain: &str| ChallengeRecord {
        domain: domain.into(),
        identity: "203.0.113.1".into(),
        salt: "s".into(),
        difficulty: 1,
        target: "/".into(),
        kind: "pow".into(),
        attempts: 0,
        expires_at: SystemTime::now() + Duration::from_secs(60),
    };
    store.issue("one".into(), record("a.test")).expect("room");
    assert_eq!(
        store.issue("two".into(), record("b.test")),
        Err(TokenError::FullDomains)
    );
}

/// Three entries, one domain, a threshold no honest driving can reach. The
/// loop detector's capacity is the entry cap, and it fails closed when a new
/// client arrives at capacity — a refusal that would answer for the wrong arm
/// — so the config leaves it room: this flow mints two loop keys at most. The
/// ladder is pinned flat for the same reason: an escalated issue would render
/// the silent page, whose proof is a fingerprint rather than a nonce, and
/// saturation is under test here, not escalation.
fn plugin() -> Challenge {
    Challenge::new(ChallengeConfig {
        enabled: true,
        secret: "saturation-test-secret".into(),
        client_ip_from_peer: true,
        difficulty: 1,
        max_entries: 3,
        max_domains: 1,
        loop_threshold: 100,
        ladder: vec![100],
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

/// One marked request through the plugin, answered or allowed.
async fn marked(plugin: &Challenge, host: &str) -> RequestPluginResult {
    let mut ctx = Ctx::default();
    ctx.extensions
        .insert(pingap_acl::ChallengeMarker::new("acl", "saturation-test"));
    let mut session =
        session_for(&format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n")).await;
    plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total")
}

/// Both saturation arms, driven through the real issue and verify paths.
///
/// The entry arm runs first, under the domain that filled the store: the
/// store checks domains before entries, so a full store under a *new* domain
/// would refuse for the domain's reason before the entry reason could fire.
/// A full entry set falls back to the stateless cookie, and the client that
/// solves it is still verified rather than admitted: the stateless token
/// carries the same binding and the same proof, so the cap costs the attacker
/// the store, not the tier its verification.
///
/// The domain arm runs last, against the store the first domain still holds:
/// a second domain arriving while the first holds the only slot is answered
/// toward the configured policy, never admitted — a 503 is a refusal the
/// operator can see, not a challenge issued to a store that cannot hold it.
#[tokio::test]
async fn a_full_domain_refuses_and_a_full_store_falls_back_and_still_verifies()
{
    pingap_domainstate::set_registered_hosts(["sat-a.test", "sat-c.test"]);
    let plugin = plugin();

    // The attacker-shaped traffic that holds the caps: three live, unsolved
    // tokens under the first domain.
    for _ in 0..3 {
        match marked(&plugin, "sat-a.test").await {
            RequestPluginResult::Respond(response) => assert_eq!(
                response.status.as_u16(),
                200,
                "the store-filling issues are interstitials"
            ),
            _ => panic!("a marked request must be answered"),
        }
    }

    // The entry arm: the store is full and the domain is not new, so the next
    // issue falls back to the stateless cookie rather than displacing a live
    // token, and the fallback is counted by its own variant.
    let stateless = match marked(&plugin, "sat-a.test").await {
        RequestPluginResult::Respond(response) => response,
        _ => panic!("a marked request must be answered"),
    };
    assert_eq!(
        stateless.status.as_u16(),
        200,
        "the stateless fallback is still an interstitial"
    );
    let rows = pingap_challenge::counters_snapshot();
    let row = rows
        .get("sat-a.test")
        .expect("the falling-back domain keeps its own row");
    assert!(
        row.saturated_entries >= 1,
        "the entry arm is counted by its variant, not the domain one: {row:?}"
    );
    assert!(
        row.stateless_fallback >= 1,
        "the fallback is counted so saturation cannot read as normal traffic"
    );

    // And the stateless client is still verified rather than admitted: the
    // fallback token carries the same proof, and solving it earns the pass
    // cookie through the same verify path.
    let body = String::from_utf8_lossy(&stateless.body).into_owned();
    let token = hidden_input(&body, "challenge_token");
    let salt = hidden_input(&body, "challenge_salt");
    let difficulty: u8 = hidden_input(&body, "challenge_difficulty")
        .parse()
        .expect("difficulty renders as a number");
    let nonce =
        find_nonce(&salt, difficulty, 1_000_000).expect("difficulty 1 solves");
    let mut ctx = Ctx::default();
    let mut session = session_for(&format!(
        "GET /.pingap/challenge/verify?challenge_token={token}&nonce={nonce} \
         HTTP/1.1\r\nHost: sat-a.test\r\n\r\n"
    ))
    .await;
    match plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total")
    {
        RequestPluginResult::Respond(solved) => {
            assert_eq!(
                solved.status.as_u16(),
                303,
                "a solved stateless proof redirects like a stateful one"
            );
            let set_cookie = solved
                .headers
                .unwrap_or_default()
                .into_iter()
                .find(|(name, _)| name == http::header::SET_COOKIE)
                .and_then(|(_, value)| {
                    String::from_utf8(value.as_bytes().to_vec()).ok()
                })
                .expect("a solved stateless proof earns a pass cookie");
            assert!(set_cookie.starts_with("pingap_challenge="));
        },
        _ => panic!("a presented proof must be answered"),
    }

    // The domain arm: the first domain still holds the only slot, so a second
    // domain is refused toward the policy, and the refusal is counted by its
    // variant.
    let second = match marked(&plugin, "sat-c.test").await {
        RequestPluginResult::Respond(response) => response,
        _ => panic!("a marked request must be answered, not admitted"),
    };
    assert_eq!(
        second.status.as_u16(),
        503,
        "a full domain set fails toward the configured policy"
    );
    let body = String::from_utf8_lossy(&second.body).into_owned();
    assert!(
        body.contains("domain capacity"),
        "the domain-cap refusal names its arm: {body}"
    );
    let rows = pingap_challenge::counters_snapshot();
    let row = rows
        .get("sat-c.test")
        .expect("the refused domain keeps its own row");
    assert!(row.saturated >= 1, "the refusal is counted as saturation");
    assert!(
        row.saturated_domains >= 1,
        "the domain arm is counted by its variant, not the entry one: {row:?}"
    );
    assert_eq!(
        row.issued, 0,
        "a refused domain was never issued a challenge"
    );
}
