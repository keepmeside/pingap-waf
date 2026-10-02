//! Which identity a behavioural profile accrues under, and what survives a
//! config apply. Both are properties of the process-global store the plugin
//! shares across instances, so both are asserted through the plugin surface —
//! `handle_request` plus the response hook that lands the observation — not
//! against the store in isolation.

// The one deliberate guard-across-await in this file: the HOSTS_LOCK guard
// below must span the driven requests, because the set it protects is
// process-global and tests in this binary run on separate threads —
// releasing it mid-test would let another test rewrite the set under a
// driven request. The mock sessions are always ready, so the awaits never
// actually suspend.
#![allow(clippy::await_holding_lock)]

use pingap_behaviour::Behaviour;
use pingap_config::PluginConf;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use tokio_test::io::Builder;

/// Serialises the registered-host rewrites below: the registered set is
/// process-global, so two tests rewriting it while a third classifies would
/// classify against another test's set.
static HOSTS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn plugin(conf: &str) -> Behaviour {
    let conf: PluginConf = toml::from_str(conf).expect("test config parses");
    Behaviour::try_from(&conf).expect("test config builds")
}

async fn session_for(request: &str) -> Session {
    let io = Builder::new().read(request.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(io));
    session.read_request().await.expect("mock request reads");
    session
}

/// One request through both hooks, so the observation lands in the store the
/// way a served request lands it.
async fn drive(plugin: &Behaviour, host: &str, extra_headers: &str) {
    let mut ctx = Ctx::default();
    let mut session = session_for(&format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\n{extra_headers}\r\n"
    ))
    .await;
    let result = plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total");
    assert!(matches!(result, RequestPluginResult::Continue));
    let mut response =
        ResponseHeader::build(200, None).expect("response header builds");
    plugin
        .handle_response(&mut session, &mut ctx, &mut response)
        .await
        .expect("handle_response is total");
}

/// A forwarded header the client chose cannot mint or advance a profile under
/// the spoofed identity: with the explicit peer assertion the profile key is
/// the TCP peer, so a spoofed `X-Forwarded-For` is never the key. The
/// discriminating shape is the header being *present and distinct* — a plugin
/// that keyed on the header would leave the profile under `6.6.6.6`, and the
/// victim that address belongs to would inherit the attacker's observations.
#[tokio::test]
async fn a_spoofed_forwarded_header_cannot_advance_a_profile_under_it() {
    let _guard = HOSTS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    pingap_domainstate::set_registered_hosts(["xff.test"]);
    let plugin = plugin(
        "category = \"behaviour\"\nenabled = true\nclient_ip_from_peer = true\n\
         budget_ms = 60000\n",
    );

    drive(&plugin, "xff.test", "X-Forwarded-For: 6.6.6.6\r\n").await;
    drive(&plugin, "xff.test", "X-Forwarded-For: 6.6.6.6\r\n").await;

    // The spoofed address has no profile: nothing accrued under it.
    assert!(
        plugin.store().get("xff.test", "6.6.6.6").is_none(),
        "a profile exists under the spoofed identity"
    );
    // The observations landed under the peer key — the mock session has no
    // socket, so the peer identity is the absent address, and that is the
    // profile the attacker's own traffic built.
    let profile = plugin
        .store()
        .get("xff.test", "")
        .expect("the peer-keyed profile exists");
    assert!(
        profile.observed >= 2,
        "the observations did not accrue under the peer: {profile:?}"
    );

    pingap_domainstate::set_registered_hosts::<[&str; 0], &str>([]);
}

/// The distinct-identity count is published, so a false peer assertion is
/// detectable from metrics alone. Every request the mock session sends has
/// the same absent peer address — exactly the shape a site gets when its one
/// proxy is trusted without being one: all traffic on a single identity. The
/// gauge must pin while the request counters for the same label climb; a
/// climbing counter under a pinned gauge is the signal.
#[tokio::test]
async fn one_peer_many_requests_pins_the_tracked_gauge_while_counters_climb() {
    let _guard = HOSTS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    pingap_domainstate::set_registered_hosts(["pin.test"]);
    let plugin = plugin(
        "category = \"behaviour\"\nenabled = true\nclient_ip_from_peer = true\n\
         budget_ms = 60000\n",
    );

    drive(&plugin, "pin.test", "").await;
    let tracked = pingap_behaviour::tracked_snapshot();
    assert_eq!(
        tracked.get("pin.test"),
        Some(&1),
        "one identity must read as one tracked client: {tracked:?}"
    );

    drive(&plugin, "pin.test", "").await;
    drive(&plugin, "pin.test", "").await;
    let tracked = pingap_behaviour::tracked_snapshot();
    assert_eq!(
        tracked.get("pin.test"),
        Some(&1),
        "the gauge counts clients, not requests: {tracked:?}"
    );
    let counters = pingap_behaviour::counters_snapshot();
    let row = counters
        .get("pin.test")
        .expect("the classified label has a counter row");
    let classified =
        row.human + row.suspicious + row.bot + row.ddos + row.insufficient;
    assert_eq!(
        classified, 3,
        "three requests moved the counters under the pinned gauge"
    );

    pingap_domainstate::set_registered_hosts::<[&str; 0], &str>([]);
}

/// Profile state survives a config apply. A config change constructs a new
/// plugin instance, but the profiles live in the process-global store, so a
/// client's window is not reset by the reload — the observations from before
/// the apply and after it are one window. Asserted by driving a window across
/// two instances built from two different configs, the shape a reload takes.
#[tokio::test]
async fn profile_state_survives_a_config_apply() {
    let _guard = HOSTS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    pingap_domainstate::set_registered_hosts(["reload.test"]);
    // Both budgets are pinned far above any real elapsed time — the same
    // precaution the sibling test files take — so the budget can never be the
    // difference between two identical requests under suite load. The entries
    // still differ (the apply tightens the budget), so the apply still
    // constructs a new instance, which is what the test exists to prove.
    let before = plugin(
        "category = \"behaviour\"\nenabled = true\nclient_ip_from_peer = true\n\
         budget_ms = 60000\n",
    );
    drive(&before, "reload.test", "").await;
    drive(&before, "reload.test", "").await;
    drive(&before, "reload.test", "").await;

    // The config apply: a different entry, so a different instance — the
    // store it resolves is the same process-global one.
    let after = plugin(
        "category = \"behaviour\"\nenabled = true\nclient_ip_from_peer = \
         true\nbudget_ms = 30000\n",
    );
    drive(&after, "reload.test", "").await;
    drive(&after, "reload.test", "").await;
    drive(&after, "reload.test", "").await;

    let profile = after
        .store()
        .get("reload.test", "")
        .expect("the profile exists after the apply");
    assert_eq!(
        profile.observed, 6,
        "the window did not span the config apply: {profile:?}"
    );

    pingap_domainstate::set_registered_hosts::<[&str; 0], &str>([]);
}
