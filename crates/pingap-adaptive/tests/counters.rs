//! Per-domain counter tests for the adaptive plugin: state is keyed by the
//! classified domain label, never a raw `Host` value, and unregistered hosts
//! collapse into the one shared overflow row instead of minting a key each.

// The one deliberate guard-across-await in this file: the HOSTS_LOCK guard
// below must span the driven requests, because the set it protects is
// process-global and tests in this binary run on separate threads —
// releasing it mid-test would let another test rewrite the set under a
// driven request. The mock sessions are always ready, so the awaits never
// actually suspend.
#![allow(clippy::await_holding_lock)]

use pingap_adaptive::plugin::Adaptive;
use pingap_config::PluginConf;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use std::sync::Mutex;
use tokio_test::io::Builder;

/// Serialises the registered-host rewrites: the registered set is
/// process-global, so a test rewriting it while another classifies would
/// classify against the other test's set.
static HOSTS_LOCK: Mutex<()> = Mutex::new(());

fn plugin() -> Adaptive {
    let conf: PluginConf = toml::from_str(
        r#"category = "adaptive"
           enabled = true
           client_ip_from_peer = true
        "#,
    )
    .expect("config parses");
    Adaptive::try_from(&conf).expect("builds")
}

async fn session_for(request: &str) -> Session {
    let io = Builder::new().read(request.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(io));
    session.read_request().await.expect("mock request reads");
    session
}

async fn drive(plugin: &Adaptive, host: &str) {
    let mut ctx = Ctx::default();
    let mut session =
        session_for(&format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n")).await;
    let result = plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total");
    assert!(
        matches!(result, RequestPluginResult::Continue),
        "an adaptive decision must never refuse a request"
    );
}

#[tokio::test]
async fn state_keys_by_classified_label_and_overflow_collapses() {
    let _guard = HOSTS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    pingap_domainstate::set_registered_hosts(["a.test"]);

    let plugin = plugin();
    // The registered host: its own row, under its canonical spelling.
    drive(&plugin, "a.test").await;
    // Two unregistered hosts, one with a port: one shared overflow row between
    // them, and no key minted for either spelling.
    drive(&plugin, "x.test").await;
    drive(&plugin, "y.test:8443").await;

    let rows = pingap_adaptive::domain_state_snapshot();
    assert!(
        rows.contains_key("a.test"),
        "a registered host keeps its own row, got {rows:?}"
    );
    assert!(
        rows.contains_key(pingap_domainstate::OVERFLOW_LABEL),
        "unregistered traffic lands in the one overflow row, got {rows:?}"
    );
    // The bounded-key property: no row can exist outside the registered set
    // plus the one overflow label, whatever Host values arrive.
    for key in rows.keys() {
        assert!(
            key == "a.test" || key == pingap_domainstate::OVERFLOW_LABEL,
            "state key {key:?} is neither a registered host nor the overflow label"
        );
    }

    // Leave the set empty for any test that runs after this one.
    pingap_domainstate::set_registered_hosts::<[&str; 0], &str>([]);
}
