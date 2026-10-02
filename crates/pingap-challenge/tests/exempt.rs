//! Exemption: an address the operator has promised not to challenge. The
//! promise is narrow on purpose — the exempt list lives in this plugin and
//! nowhere else, so it never reaches the WAF's refusals (that cross-crate
//! assertion lives in the WAF's own tests) — and it is refused at
//! construction when it cannot be parsed, because an entry that silently
//! fails to match is a promise that looks made and was not.

use pingap_challenge::exempt::Exemptions;
use pingap_challenge::{ChallengeConfig, plugin::Challenge};
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use tokio_test::io::Builder;

#[test]
fn exemptions_validate_every_entry_and_match_only_listed_addresses() {
    let exemptions =
        Exemptions::new(&["203.0.113.0/24".to_string()]).expect("valid");
    assert!(exemptions.contains("203.0.113.8"));
    assert!(!exemptions.contains("198.51.100.8"));
    assert!(Exemptions::new(&["not-an-ip".to_string()]).is_err());
}

/// An unparsable exempt entry refuses construction and names the entry. The
/// plugin is the wrong place to narrow a promise silently: an operator who
/// wrote `exempt = ["10.0.0/24"]` meant a range, and a plugin that skips the
/// entry and serves challenges to it has broken the promise without saying
/// so. Refusing to exist names the entry and leaves the location's failure
/// handling to say what happens next.
#[test]
fn an_unparsable_exempt_entry_refuses_construction_and_names_the_entry() {
    let err = match Challenge::new(ChallengeConfig {
        enabled: true,
        secret: "exempt-test-secret".into(),
        client_ip_from_peer: true,
        exempt: vec!["203.0.113.0/24".into(), "not-an-ip".into()],
        ..Default::default()
    }) {
        Ok(_) => panic!("an unparsable exempt entry must not construct"),
        Err(err) => err,
    };
    let message = err.to_string();
    assert!(
        message.contains("not-an-ip"),
        "the refusal names the entry: {message}"
    );
    assert!(
        message.contains("exempt"),
        "the refusal names the key: {message}"
    );
}

/// The exempt surface: a marked request from an exempt address is never
/// answered with a challenge, never accrues escalation state, and every hit
/// is counted. The identity here comes from the resolved client IP — the
/// plugin's other anchor — so the address is one the test chooses rather
/// than the mock peer's absent one.
fn exempt_plugin() -> Challenge {
    pingap_core::set_trusted_proxies(&Some(vec!["192.0.2.10".to_string()]));
    Challenge::new(ChallengeConfig {
        enabled: true,
        secret: "exempt-test-secret".into(),
        exempt: vec!["203.0.113.1".into()],
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

/// One marked request from `client_ip` through the plugin.
async fn marked_from(
    plugin: &Challenge,
    client_ip: &str,
) -> (RequestPluginResult, Ctx) {
    let mut ctx = Ctx::default();
    ctx.conn.client_ip = Some(client_ip.to_string());
    ctx.extensions
        .insert(pingap_acl::ChallengeMarker::new("acl", "exempt-test"));
    let mut session =
        session_for("GET / HTTP/1.1\r\nHost: exempt.test\r\n\r\n").await;
    let result = plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total");
    (result, ctx)
}

#[tokio::test]
async fn an_exempt_address_is_never_challenged_and_every_hit_is_counted() {
    pingap_domainstate::set_registered_hosts(["exempt.test"]);
    let plugin = exempt_plugin();

    // The exempt address: the marker is present and the tier is enabled, and
    // the request is still allowed through — the promise is kept on the very
    // request the marker asked the tier to answer.
    let (result, ctx) = marked_from(&plugin, "203.0.113.1").await;
    assert!(
        matches!(result, RequestPluginResult::Continue),
        "an exempt address must never be challenged"
    );
    assert_eq!(
        ctx.get_variable("challenge_status"),
        Some("exempt".to_string()).as_deref(),
        "the exempt outcome is published like every other"
    );
    // Every hit is counted, so an operator can see the promise being kept —
    // an exempt list that never matches is as broken as one that over-matches.
    let (result, _) = marked_from(&plugin, "203.0.113.1").await;
    assert!(matches!(result, RequestPluginResult::Continue));
    let rows = pingap_challenge::counters_snapshot();
    let row = rows
        .get("exempt.test")
        .expect("the exempt domain keeps its own row");
    assert!(
        row.exempt_hit >= 2,
        "every exempt hit increments the counter: {row:?}"
    );
    assert_eq!(
        row.issued, 0,
        "an exempt address was issued a challenge: {row:?}"
    );

    // The control: an address outside the list is answered with the
    // interstitial, so the pass above is the exemption and not a gate that
    // never fired.
    let (result, _) = marked_from(&plugin, "198.51.100.8").await;
    assert!(
        matches!(result, RequestPluginResult::Respond(_)),
        "a non-exempt address must still be challenged"
    );
}
