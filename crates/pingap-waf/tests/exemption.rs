//! The challenge tier's exempt promise is narrow to the tier that made it.
//!
//! `exempt` lives in the challenge's config and nowhere else, so an address the
//! operator promised not to challenge is still inspected — and still refused —
//! by the WAF: the two lists are different promises about different things, and
//! an operator who wants an address truly past the gateway must say so to every
//! tier that enforces. This is the cross-crate half of the exemption tests; the
//! challenge-side half — the promise being kept, counted and logged — lives in
//! `pingap-challenge`'s own tests.
#![cfg(feature = "plugin")]

use pingap_challenge::{ChallengeConfig, plugin::Challenge};
use pingap_config::PluginConf;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingap_waf::plugin::{Waf, WafState};
use pingora::proxy::Session;
use tokio_test::io::Builder;

/// Benign on purpose. A rule hit would refuse the request for the wrong reason
/// and the assertions below would pass vacuously — the refusals have to come
/// from the list and the intelligence, or they prove nothing about the exempt
/// promise.
const BENIGN: &str = "GET /products?page=2&sort=price HTTP/1.1\r\nHost: exempt-crossover.test\r\n\r\n";

/// The address the challenge exempts, seeded the way the gateway's own
/// resolver would leave it. The trusted-proxy list is what makes an
/// IP-derived control legal to construct at all — for the challenge's
/// identity anchor and for the WAF's list alike.
const EXEMPT_ADDRESS: &str = "203.0.113.1";

fn waf(conf: &str) -> Waf {
    Waf::try_from(
        &toml::from_str::<PluginConf>(conf).expect("test config parses"),
    )
    .expect("test config builds")
}

async fn session_for(request: &str) -> Session {
    let io = Builder::new().read(request.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(io));
    session.read_request().await.expect("mock request reads");
    session
}

/// One request's context: the client IP both tiers enforce on, and the marker
/// that asks the challenge tier to answer this request.
fn marked_ctx() -> Ctx {
    let mut ctx = Ctx::default();
    ctx.conn.client_ip = Some(EXEMPT_ADDRESS.to_string());
    ctx.extensions
        .insert(pingap_acl::ChallengeMarker::new("acl", "exempt-crossover"));
    ctx
}

#[tokio::test]
async fn the_address_the_challenge_exempts_is_still_refused_by_the_waf() {
    pingap_core::set_trusted_proxies(&Some(vec!["192.0.2.10".to_string()]));
    pingap_domainstate::set_registered_hosts(["exempt-crossover.test"]);

    let challenge = Challenge::new(ChallengeConfig {
        enabled: true,
        secret: "exempt-crossover-secret".into(),
        exempt: vec![EXEMPT_ADDRESS.into()],
        ..Default::default()
    })
    .expect("a valid challenge config builds");
    // An allow list the exempt address is not on: the address-derived policy
    // that must refuse it.
    let allow_list = waf(
        "category = \"waf\"\nprofile = \"edge\"\nip_list_mode = \"allow\"\n\
         ip_list = [\"10.0.0.0/8\"]\n",
    );
    // Intelligence the exempt address is on: the other enforcement surface,
    // selected by policy rather than derived from the address alone.
    let intel = waf(
        "category = \"waf\"\nprofile = \"intel-crossover\"\n[intel]\nmanual = \
         [\"203.0.113.1\"]\n",
    );

    // The challenge keeps its promise on the very request both WAFs refuse:
    // allowed through, published as exempt, never answered with an
    // interstitial.
    let mut ctx = marked_ctx();
    let mut session = session_for(BENIGN).await;
    let result = challenge
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total");
    assert!(
        matches!(result, RequestPluginResult::Continue),
        "the challenge broke its exempt promise"
    );
    assert_eq!(
        ctx.get_variable("challenge_status"),
        Some("exempt".to_string()).as_deref(),
        "the exempt outcome is published beside the pass"
    );

    // The allow list never heard the promise: the same address, on the same
    // request shape, is refused — and by the list, not by a rule hit.
    let mut ctx = marked_ctx();
    let mut session = session_for(BENIGN).await;
    let result = allow_list
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("evaluation is total");
    assert!(
        matches!(result, RequestPluginResult::Respond(_)),
        "the allow list honoured an exempt promise it was never given"
    );
    let state = ctx.extensions.get::<WafState>().expect("state recorded");
    assert!(
        state.hits.is_empty(),
        "a rule refused a benign request: {state:?}"
    );

    // The intelligence neither: the refusal is attributed to the selected
    // intelligence, which is what makes it diagnosable rather than mysterious.
    let mut ctx = marked_ctx();
    let mut session = session_for(BENIGN).await;
    let result = intel
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("evaluation is total");
    assert!(
        matches!(result, RequestPluginResult::Respond(_)),
        "the intelligence honoured an exempt promise it was never given"
    );
    let state = ctx.extensions.get::<WafState>().expect("state recorded");
    assert_eq!(
        state.intel_category.as_deref(),
        Some("manual"),
        "the refusal is attributed to the intelligence: {state:?}"
    );
    assert!(
        state.hits.is_empty(),
        "a rule refused a benign request: {state:?}"
    );
}
