//! Two domains, one plugin, no leakage between them.
//!
//! Plugin instances are process-global and keyed by config-entry name: every Location
//! listing `waf:strict` resolves the *same* `Arc<dyn Plugin>`, and every `Plugin` trait
//! method takes `&self`, so any mutable state inside an instance is shared by every
//! domain that binds it. A counter, anomaly tally or rate accumulator held there would
//! be cross-domain — traffic against one tenant advancing another tenant's totals, so
//! that tenant's clients get blocked by traffic they never sent.
//!
//! This crate's answer is that **there is no per-request state inside the instance**.
//! Verdicts accumulate on `Ctx`, which is per request by construction, and the only
//! interior mutability the plugin holds is the `ArcSwap` guarding its compiled ruleset —
//! configuration, replaced on reload, never written by a request. That is a stronger
//! guarantee than keying state by domain, but it is only worth anything if it is
//! actually checked, because the natural way to add a counter later is to put it on the
//! plugin.
//!
//! **That answer holds for this plugin and is no longer the fork's only answer.** The
//! intelligence, challenge, behavioural and adaptive controls do hold verdict-affecting state,
//! and they isolate by *keying* on `(domain, client identity)` rather than by holding nothing.
//! Keying is the strictly weaker guarantee, so it carries the strictly stronger test: see
//! `crates/pingap-domainstate/tests/isolation.rs`, which asserts isolation against a
//! process-global store rather than a local one. This file keeps its own criterion intact and
//! unchanged — a WAF verdict must still not depend on anything but the request.
#![cfg(feature = "plugin")]

use pingap_config::PluginConf;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingap_waf::plugin::{Waf, WafState};
use pingora::proxy::Session;
use tokio_test::io::Builder;

/// Blocks, and says so on every verdict.
///
/// `budget_ms` is far above the 10 ms default on purpose. What these tests compare is one
/// request's score against another's, and the budget is the one thing that can legitimately
/// change a score between two identical requests: exhaust it and evaluation stops early
/// with fewer hits. On a machine running the rest of the suite in parallel that happens
/// often enough to matter, and it would read as the accumulation this file exists to catch.
/// The budget has its own tests; here it must simply never fire.
const STRICT: &str = r#"
category = "waf"
profile = "strict"
anomaly_threshold = 1
budget_ms = 5000
categories = { sql_injection = "block", xss = "block" }
"#;

/// Same rules, records only. The pair a staged rollout uses.
const AUDIT_ONLY: &str = r#"
category = "waf"
profile = "audit-only"
anomaly_threshold = 1
budget_ms = 5000
categories = { sql_injection = "detect", xss = "detect" }
"#;

/// A request no benign corpus would produce, so both profiles certainly hit on it.
const MALICIOUS: &str =
    "GET /s?q=%27+UNION+SELECT+pw+FROM+users+--+ HTTP/1.1\r\n\r\n";
const BENIGN: &str = "GET /products?page=2&sort=price HTTP/1.1\r\n\r\n";

/// The same two requests, under two `Host` values.
///
/// The pair above carries no `Host` at all, so it cannot distinguish a plugin that keys on
/// nothing from one that keys on a host it never sees vary. These can. Alternating two tenants
/// through one instance is also what a shared named profile actually sees in production, which
/// makes this the driver the stateful controls extend rather than a new idea.
const MALICIOUS_TENANT_A: &str = "GET /s?q=%27+UNION+SELECT+pw+FROM+users+--+ HTTP/1.1\r\n\
     Host: tenant-a.example\r\n\r\n";
const MALICIOUS_TENANT_B: &str = "GET /s?q=%27+UNION+SELECT+pw+FROM+users+--+ HTTP/1.1\r\n\
     Host: tenant-b.example\r\n\r\n";
const BENIGN_TENANT_A: &str = "GET /products?page=2&sort=price HTTP/1.1\r\n\
     Host: tenant-a.example\r\n\r\n";
const BENIGN_TENANT_B: &str = "GET /products?page=2&sort=price HTTP/1.1\r\n\
     Host: tenant-b.example\r\n\r\n";

fn plugin(conf: &str) -> Waf {
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

/// One request through one instance, returning the verdict and the state it recorded.
async fn run(waf: &Waf, request: &str) -> (bool, Option<WafState>) {
    let mut ctx = Ctx::default();
    let mut session = session_for(request).await;
    let result = waf
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("evaluation is total");
    let blocked = matches!(result, RequestPluginResult::Respond(_));
    (blocked, ctx.extensions.get::<WafState>().cloned())
}

#[tokio::test]
async fn two_named_profiles_coexist_and_reach_different_verdicts() {
    let strict = plugin(STRICT);
    let audit = plugin(AUDIT_ONLY);

    let (blocked, state) = run(&strict, MALICIOUS).await;
    assert!(blocked, "the strict profile did not block");
    let state = state.expect("state recorded");
    assert_eq!(state.profile, "strict");
    assert!(state.blocked);

    let (blocked, state) = run(&audit, MALICIOUS).await;
    assert!(!blocked, "the audit-only profile blocked");
    let state = state.expect("state recorded");
    assert_eq!(state.profile, "audit-only");
    assert!(!state.blocked);
    assert!(
        !state.hits.is_empty(),
        "detect must still record what it saw, or it is just off"
    );
}

#[tokio::test]
async fn a_verdict_names_the_profile_that_produced_it() {
    // Without this an operator running two profiles sees a block and has two candidate
    // policies to guess between. The attribution has to hold on every refusal path, not
    // just the pattern one — an IP-list refusal is equally in need of triage.
    // Construction refuses an IP-derived control when no trusted-proxy list is set, so
    // this has to happen before the plugin is built rather than before the request.
    pingap_core::set_trusted_proxies(&Some(vec!["192.0.2.10".to_string()]));
    let ip_refusal = plugin(
        "category = \"waf\"\nprofile = \"edge\"\nip_list_mode = \"allow\"\n\
         ip_list = [\"203.0.113.0/24\"]\n",
    );
    let (blocked, state) = run(&ip_refusal, BENIGN).await;
    assert!(blocked, "an address outside the allow list was not refused");
    assert_eq!(state.expect("state recorded").profile, "edge");
}

#[tokio::test]
async fn traffic_against_one_domain_does_not_advance_another_domain_s_totals() {
    // The criterion this file exists for. One instance, as two Locations sharing a
    // profile name would resolve, driven with a hundred malicious requests. If any
    // per-request state lived on the plugin, the hundred-and-first request would carry
    // the accumulation — its score would climb and a benign request would eventually be
    // refused by traffic it had nothing to do with.
    let shared = plugin(AUDIT_ONLY);

    let (_, first) = run(&shared, MALICIOUS).await;
    let first = first.expect("state recorded");

    for _ in 0..100 {
        let (_, other) = run(&shared, MALICIOUS).await;
        let other = other.expect("state recorded");
        assert_eq!(
            other.score, first.score,
            "the score moved between requests, so the instance is accumulating"
        );
        assert_eq!(other.hits.len(), first.hits.len());
    }

    // And a benign request through the same instance is untouched by all of it.
    let (blocked, state) = run(&shared, BENIGN).await;
    assert!(!blocked);
    assert!(
        state.is_none_or(|s| s.hits.is_empty() && s.score == 0),
        "a benign request inherited findings from the traffic before it"
    );
}

#[tokio::test]
async fn a_blocking_profile_and_an_audit_profile_do_not_share_a_threshold() {
    // Two instances, driven alternately, to catch the other shape of the same bug:
    // state held in a process-global rather than on the instance. Alternating rather
    // than running each to completion is what would expose it.
    let strict = plugin(STRICT);
    let audit = plugin(AUDIT_ONLY);
    for _ in 0..20 {
        let (blocked, state) = run(&strict, MALICIOUS).await;
        assert!(blocked);
        assert_eq!(state.expect("state recorded").profile, "strict");

        let (blocked, state) = run(&audit, MALICIOUS).await;
        assert!(
            !blocked,
            "the audit profile blocked, so a threshold crossed elsewhere reached it"
        );
        assert_eq!(state.expect("state recorded").profile, "audit-only");
    }
}

#[tokio::test]
async fn alternating_hosts_through_one_instance_do_not_move_a_verdict() {
    // The stronger form of the criterion above, and the driver a stateful control has to
    // survive too. This one passes because the instance still holds nothing to key; the same
    // shape pointed at the keyed container is what proves the keying, and that test lives with
    // the container.
    let shared = plugin(AUDIT_ONLY);

    let (_, first) = run(&shared, MALICIOUS_TENANT_A).await;
    let first = first.expect("state recorded");

    for round in 0..100 {
        let request = if round % 2 == 0 {
            MALICIOUS_TENANT_A
        } else {
            MALICIOUS_TENANT_B
        };
        let (_, other) = run(&shared, request).await;
        let other = other.expect("state recorded");
        assert_eq!(
            other.score, first.score,
            "the score moved between requests, so the instance is accumulating per host"
        );
        assert_eq!(other.hits.len(), first.hits.len());
    }

    // Neither tenant's benign traffic inherits anything from the other's attack traffic.
    for request in [BENIGN_TENANT_A, BENIGN_TENANT_B] {
        let (blocked, state) = run(&shared, request).await;
        assert!(!blocked);
        assert!(
            state.is_none_or(|s| s.hits.is_empty() && s.score == 0),
            "a benign request inherited findings from the traffic before it"
        );
    }
}

/// A policy that selects intelligence, and one that selects none. The pair the
/// feed-isolation criterion needs: the same client address, refused by the
/// policy that selected it and passed by the policy that did not.
const INTEL_TENANT: &str = r#"
category = "waf"
profile = "intel-tenant"
[intel]
manual = ["198.51.100.7"]
"#;

/// A policy that both selects a named feed and blocks on static rules, so one
/// instance can produce the two refusal kinds the verdict has to tell apart.
const FEED_TENANT: &str = r#"
category = "waf"
profile = "feed-tenant"
anomaly_threshold = 1
budget_ms = 5000
categories = { sql_injection = "block", xss = "block" }
[[intel.feed]]
name = "blocklist"
url = "https://feeds.example.test/blocklist"
category = "drop"
"#;

/// Intelligence selected by one tenant's policy is not enforced against a
/// request routed to another tenant's policy. The refresh task is
/// process-global — every installed registry is refreshed — but matching
/// reads the instance's own registry, so an address one tenant's policy
/// selected can never refuse a request another tenant's policy serves. The
/// registry content here is a manual entry, which lands in the same snapshot
/// a feed's results are swapped into and is matched by the same call; the
/// feed-shaped half — results landing per-registry — is the refresh tests'
/// own criterion in `pingap-intel`.
#[tokio::test]
async fn intelligence_selected_by_one_policy_is_not_enforced_against_another() {
    // Construction refuses an intel-bearing policy when no trusted-proxy list
    // is set, so this has to happen before the plugin is built rather than
    // before the request.
    pingap_core::set_trusted_proxies(&Some(vec!["192.0.2.10".to_string()]));
    let intel_tenant = plugin(INTEL_TENANT);
    let audit = plugin(AUDIT_ONLY);

    // The address is refused by the policy that selected it, and the refusal
    // is attributed to the intelligence rather than to a rule hit — the
    // request is benign, so a rule hit would mean the wrong thing moved.
    let mut ctx = Ctx::default();
    ctx.conn.client_ip = Some("198.51.100.7".to_string());
    let mut session = session_for(BENIGN).await;
    let result = intel_tenant
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("evaluation is total");
    assert!(
        matches!(result, RequestPluginResult::Respond(_)),
        "the policy that selected the address did not refuse it"
    );
    let state = ctx.extensions.get::<WafState>().expect("state recorded");
    assert_eq!(state.intel_category.as_deref(), Some("manual"));
    assert!(
        state.hits.is_empty(),
        "a rule hit was recorded for a benign request: {state:?}"
    );

    // The same address through the policy that selected nothing passes. The
    // client IP is seeded the way the gateway's own resolver would leave it,
    // so both policies enforce on the same address — the only difference is
    // which registry they consult.
    let mut ctx = Ctx::default();
    ctx.conn.client_ip = Some("198.51.100.7".to_string());
    let mut session = session_for(BENIGN).await;
    let result = audit
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("evaluation is total");
    assert!(
        matches!(result, RequestPluginResult::Continue),
        "an address another policy selected was enforced against this one"
    );
}

/// A feed-sourced refusal is distinguishable from a static one in the recorded
/// verdict, and names its feed. Asserted on the emitted log variables — the
/// strings an operator's `{:waf_intel_feed}` tag resolves — rather than on the
/// structured state, because the variable names are the contract: a rename
/// that moved a constant and the state together would still pass, but the
/// operator's log field would silently empty.
#[tokio::test]
async fn a_feed_sourced_refusal_names_its_feed_in_the_verdict() {
    // Same construction precondition as the manual-entry policy above: the
    // intel gate needs a trust anchor before the plugin is built.
    pingap_core::set_trusted_proxies(&Some(vec!["192.0.2.10".to_string()]));
    let waf = plugin(FEED_TENANT);
    // The refresh half lands a feed's results; here the same swap is driven
    // by hand so the verdict, not the fetch, is what is under test.
    let registry = waf
        .intel_registry()
        .expect("a policy with a feed holds a registry");
    registry.apply(
        Ok(pingap_intel::feed::FeedResult {
            name: "blocklist".into(),
            parsed: pingap_intel::parse::Parsed::parse("203.0.113.9\n", 100),
            fetched_at: std::time::SystemTime::now(),
        }),
        0,
        std::time::SystemTime::now(),
    );

    // A benign request from the feed's address: nothing but the feed can
    // refuse it, so the refusal is attributable to the feed and nothing else.
    let mut ctx = Ctx::default();
    ctx.conn.client_ip = Some("203.0.113.9".to_string());
    let mut session = session_for(BENIGN).await;
    let result = waf
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("evaluation is total");
    assert!(
        matches!(result, RequestPluginResult::Respond(_)),
        "the feed-sourced address was not refused"
    );
    assert_eq!(
        ctx.get_variable("waf_intel_feed"),
        Some("blocklist"),
        "the verdict does not name the feed"
    );
    assert_eq!(
        ctx.get_variable("waf_intel_category"),
        Some("drop"),
        "the verdict does not carry the configured category"
    );
    assert!(
        ctx.get_variable("waf_rules").is_none(),
        "a rule set was named beside the feed attribution"
    );

    // The static refusal on the same instance: the intel variables stay
    // absent, so the two refusal kinds are distinguishable in the log line
    // an operator actually reads.
    let mut ctx = Ctx::default();
    let mut session = session_for(MALICIOUS).await;
    let result = waf
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("evaluation is total");
    assert!(
        matches!(result, RequestPluginResult::Respond(_)),
        "the static rule did not refuse the malicious request"
    );
    assert_eq!(
        ctx.get_variable("waf_action"),
        Some("block"),
        "the static refusal is not recorded as a block"
    );
    assert!(
        ctx.get_variable("waf_intel_feed").is_none(),
        "a static refusal carries a feed attribution"
    );
    assert!(
        ctx.get_variable("waf_intel_category").is_none(),
        "a static refusal carries an intel category"
    );
    assert_ne!(
        ctx.get_variable("waf_rules"),
        Some(""),
        "the static refusal names no rule"
    );
}
