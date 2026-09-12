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
