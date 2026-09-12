//! Three domains on one listener, three policies, one byte-identical request.
//!
//! This is the whole claim of the domain model: a domain's policy *is* its Location's
//! plugin list, so nothing in pingap's routing has to change for two hostnames on the
//! same listener to enforce completely different things. The test drives an ordered
//! plugin list the way `handle_request_plugin` does — first `Respond` wins, and a
//! `Skipped` or `Continue` moves to the next — so the composition being asserted is the
//! one the proxy actually performs.
#![cfg(feature = "plugin")]

use pingap_acl::plugin::{Acl, AclState};
use pingap_config::PluginConf;
use pingap_core::{Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult};
use pingap_waf::plugin::{Waf, WafState};
use pingora::proxy::Session;
use std::sync::Arc;
use tokio_test::io::Builder;

/// Blocks on a single hit.
const WAF_STRICT: &str = r#"
category = "waf"
profile = "strict"
anomaly_threshold = 1
categories = { sql_injection = "block", xss = "block" }
"#;

/// Same rules, records only.
const WAF_AUDIT: &str = r#"
category = "waf"
profile = "audit-only"
anomaly_threshold = 1
categories = { sql_injection = "detect", xss = "detect" }
"#;

/// Refuses everything: no rule can allow, and the default is deny.
const ACL_CLOSED: &str = r#"
category = "acl"
default_action = "deny"
"#;

/// Lets this request through, so a WAF sitting behind it is what decides.
const ACL_OPEN_TO_GET: &str = r#"
category = "acl"
default_action = "deny"
rules = [
  { field = "method", operator = "in_list", values = ["GET", "HEAD"], action = "allow" },
]
"#;

const MALICIOUS: &str =
    "GET /s?q=%27+UNION+SELECT+pw+FROM+users+--+ HTTP/1.1\r\n\r\n";

fn waf(conf: &str) -> Arc<dyn Plugin> {
    Arc::new(
        Waf::try_from(
            &toml::from_str::<PluginConf>(conf).expect("waf config parses"),
        )
        .expect("waf config builds"),
    )
}

fn acl(conf: &str) -> Arc<dyn Plugin> {
    Arc::new(
        Acl::try_from(
            &toml::from_str::<PluginConf>(conf).expect("acl config parses"),
        )
        .expect("acl config builds"),
    )
}

/// Run a Location's plugin list over one request, stopping at the first `Respond`.
///
/// Mirrors `Server::handle_request_plugin`: the list is ordered, a plugin that responds
/// terminates the request, and everything else continues to the next.
async fn serve(
    plugins: &[Arc<dyn Plugin>],
    request: &str,
) -> (Option<HttpResponse>, Ctx) {
    let io = Builder::new().read(request.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(io));
    session.read_request().await.expect("mock request reads");

    let mut ctx = Ctx::default();
    for plugin in plugins {
        let result = plugin
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .expect("evaluation is total");
        if let RequestPluginResult::Respond(resp) = result {
            return (Some(resp), ctx);
        }
    }
    (None, ctx)
}

#[tokio::test]
async fn three_domains_reach_three_verdicts_for_the_same_request() {
    // tenant-a.example — strict WAF behind a deny-by-default ACL.
    let strict = vec![acl(ACL_CLOSED), waf(WAF_STRICT)];
    // tenant-b.example — audit-only WAF, no ACL.
    let audit = vec![waf(WAF_AUDIT)];
    // tenant-c.example — no policy at all.
    let open: Vec<Arc<dyn Plugin>> = vec![];

    let (response, ctx) = serve(&strict, MALICIOUS).await;
    assert_eq!(
        response.map(|r| r.status.as_u16()),
        Some(403),
        "the strict domain served a request both of its policies refuse"
    );
    let acl_state = ctx.extensions.get::<AclState>().expect("acl recorded");
    assert!(acl_state.denied);
    assert_eq!(
        acl_state.decided_by, None,
        "deny-by-default decided, and it is not a rule"
    );
    assert!(
        ctx.extensions.get::<WafState>().is_none(),
        "the ACL refused first, so the WAF should not have run — a second \
         evaluation of a request already refused is wasted work on the cheapest \
         path an attacker can reach"
    );

    let (response, ctx) = serve(&audit, MALICIOUS).await;
    assert!(
        response.is_none(),
        "the audit-only domain refused a request it is only meant to record"
    );
    let waf_state = ctx.extensions.get::<WafState>().expect("waf recorded");
    assert_eq!(waf_state.profile, "audit-only");
    assert!(!waf_state.blocked);
    assert!(!waf_state.hits.is_empty(), "detect recorded nothing");

    let (response, ctx) = serve(&open, MALICIOUS).await;
    assert!(
        response.is_none(),
        "a domain with no policy refused a request"
    );
    assert!(ctx.extensions.get::<WafState>().is_none());
    assert!(ctx.extensions.get::<AclState>().is_none());
}

#[tokio::test]
async fn the_waf_behind_a_permissive_acl_is_still_what_refuses() {
    // The previous test's strict domain is refused by its ACL, which hides whether the
    // WAF behind it works. Opening the ACL to this method puts the WAF back in the
    // deciding position, so the composition is proven in both orders.
    let plugins = vec![acl(ACL_OPEN_TO_GET), waf(WAF_STRICT)];
    let (response, ctx) = serve(&plugins, MALICIOUS).await;
    assert_eq!(response.map(|r| r.status.as_u16()), Some(403));
    let acl_state = ctx.extensions.get::<AclState>();
    assert!(
        acl_state.is_none_or(|s| !s.denied),
        "the ACL refused, so this is not testing the WAF"
    );
    let waf_state = ctx.extensions.get::<WafState>().expect("waf recorded");
    assert!(waf_state.blocked);
    assert_eq!(waf_state.profile, "strict");
}

#[tokio::test]
async fn a_benign_request_reaches_every_domain() {
    // The other half of divergence: policies that differ on an attack must agree on
    // ordinary traffic, or the strict domain is simply broken.
    let benign = "GET /products?page=2&sort=price HTTP/1.1\r\n\r\n";
    for (label, plugins) in [
        ("strict", vec![acl(ACL_OPEN_TO_GET), waf(WAF_STRICT)]),
        ("audit", vec![waf(WAF_AUDIT)]),
        ("open", vec![]),
    ] {
        let (response, _) = serve(&plugins, benign).await;
        assert!(
            response.is_none(),
            "the {label} domain refused an ordinary request"
        );
    }
}
