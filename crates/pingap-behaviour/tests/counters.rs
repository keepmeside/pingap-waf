//! Per-domain counter tests for the behaviour plugin: counters are keyed by the
//! classified domain label, never a raw `Host` value, and unregistered hosts
//! collapse into the one shared overflow row instead of minting a key each.

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
use pingora::proxy::Session;
use std::sync::Mutex;
use tokio_test::io::Builder;

/// Serialises the registered-host rewrites: the registered set is
/// process-global, so a test rewriting it while another classifies would
/// classify against the other test's set.
static HOSTS_LOCK: Mutex<()> = Mutex::new(());

fn plugin() -> Behaviour {
    let conf: PluginConf = toml::from_str(
        r#"category = "behaviour"
           enabled = true
           client_ip_from_peer = true
           budget_ms = 60000
        "#,
    )
    .expect("config parses");
    Behaviour::try_from(&conf).expect("builds")
}

async fn session_for(request: &str) -> Session {
    let io = Builder::new().read(request.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(io));
    session.read_request().await.expect("mock request reads");
    session
}

/// Drive one request for `host`. A first request from a fresh identity has no
/// samples, so it settles on `insufficient` — the deterministic classification
/// to count, with no profile to build up first.
async fn classify_one(plugin: &Behaviour, host: &str) {
    let mut ctx = Ctx::default();
    let mut session =
        session_for(&format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n")).await;
    let result = plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total");
    assert!(
        matches!(result, RequestPluginResult::Continue),
        "a behavioural score must never refuse a request"
    );
    assert_eq!(
        ctx.get_variable("behaviour_profile"),
        Some("insufficient"),
        "a first request from a fresh identity is insufficient"
    );
}

#[tokio::test]
async fn counters_key_by_classified_label_and_overflow_collapses() {
    let _guard = HOSTS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    pingap_domainstate::set_registered_hosts(["a.test"]);

    let plugin = plugin();
    // The registered host: its own row, under its canonical spelling.
    classify_one(&plugin, "a.test").await;
    // Two unregistered hosts, one with a port: one shared overflow row between
    // them, and no key minted for either spelling.
    classify_one(&plugin, "x.test").await;
    classify_one(&plugin, "y.test:8443").await;

    let rows = pingap_behaviour::counters_snapshot();
    let overflow = rows
        .get(pingap_domainstate::OVERFLOW_LABEL)
        .expect("unregistered traffic lands in the one overflow row");
    assert!(
        overflow.insufficient >= 2,
        "both unregistered hosts counted into the shared row, got {overflow:?}"
    );
    let registered = rows
        .get("a.test")
        .expect("a registered host keeps its own row");
    assert!(
        registered.insufficient >= 1,
        "the registered host counted into its own row, got {registered:?}"
    );
    // The bounded-key property: no row can exist outside the registered set
    // plus the one overflow label, whatever Host values arrive.
    for key in rows.keys() {
        assert!(
            key == "a.test" || key == pingap_domainstate::OVERFLOW_LABEL,
            "counter key {key:?} is neither a registered host nor the overflow label"
        );
    }

    // Leave the set empty for any test that runs after this one.
    pingap_domainstate::set_registered_hosts::<[&str; 0], &str>([]);
}

/// No counter name this crate publishes is also a name `pingap-bot` publishes.
/// The two vocabularies live in one admin surface and one log-variable
/// namespace: a name shared between them would read as one concept and be two,
/// which is exactly the ambiguity a metrics document cannot afford. The
/// behaviour side is enumerated from the serialized counter struct — a field
/// added later joins the check by itself — and the bot side from its verdict
/// set, compared with case and underscore normalization so `Bot` and `bot`
/// or `known_bot` and `knownbot` cannot slip past as different names.
#[test]
fn no_counter_name_is_also_a_pingap_bot_name() {
    let rows = pingap_behaviour::counters_snapshot();
    let sample = rows.values().next().cloned().unwrap_or_default();
    let table = toml::Value::try_from(&sample).expect("counters serialize");
    let names: Vec<String> = table
        .as_table()
        .expect("counters serialize to a table")
        .keys()
        .map(|name| name.to_lowercase().replace('_', ""))
        .collect();
    assert!(
        !names.is_empty(),
        "the counter struct serialized to no fields"
    );

    let bot_names: Vec<String> = [
        pingap_bot::Verdict::Allowed,
        pingap_bot::Verdict::Denied,
        pingap_bot::Verdict::WouldDeny,
        pingap_bot::Verdict::KnownBot,
        pingap_bot::Verdict::Missed,
    ]
    .iter()
    .map(|verdict| format!("{verdict:?}").to_lowercase().replace('_', ""))
    .collect();

    for name in &names {
        assert!(
            !bot_names.contains(name),
            "counter name {name:?} is also published by pingap-bot"
        );
    }
}
