//! Per-domain counter tests: the published counters are keyed by the classified
//! domain label, never a raw `Host` value, and unregistered hosts collapse into
//! the one shared overflow row instead of minting a key each.

// The one deliberate guard-across-await in this file: the HOSTS_LOCK guard
// below must span the driven requests, because the set it protects is
// process-global and tests in this binary run on separate threads —
// releasing it mid-test would let another test rewrite the set under a
// driven request. The mock sessions are always ready, so the awaits never
// actually suspend.
#![allow(clippy::await_holding_lock)]

use pingap_acl::ChallengeMarker;
use pingap_challenge::{
    ChallengeConfig, ChallengeRecord, TokenStore, counters_snapshot,
    plugin::Challenge,
};
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use tokio_test::io::Builder;

/// Serialises the registered-host rewrites: the registered set is process-global,
/// so a test rewriting it while another classifies would classify against the
/// other test's set.
static HOSTS_LOCK: Mutex<()> = Mutex::new(());

fn plugin() -> Challenge {
    Challenge::new(ChallengeConfig {
        enabled: true,
        secret: "test-secret".into(),
        client_ip_from_peer: true,
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

/// Drive one marked request for `host` and assert the plugin answered it, which
/// is the path that counts an `issued`.
async fn issue_for(plugin: &Challenge, host: &str) {
    let mut ctx = Ctx::default();
    ctx.extensions.insert(ChallengeMarker::new("acl", "test"));
    let mut session =
        session_for(&format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n")).await;
    let result = plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total");
    assert!(
        matches!(result, RequestPluginResult::Respond(_)),
        "a marked request is answered by the plugin, whatever the host"
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
    issue_for(&plugin, "a.test").await;
    // Two unregistered hosts, one with a port: one shared overflow row between
    // them, and no key minted for either spelling.
    issue_for(&plugin, "x.test").await;
    issue_for(&plugin, "y.test:8443").await;

    let rows = counters_snapshot();
    let overflow = rows
        .get(pingap_domainstate::OVERFLOW_LABEL)
        .expect("unregistered traffic lands in the one overflow row");
    assert!(
        overflow.issued >= 2,
        "both unregistered hosts counted into the shared row, got {overflow:?}"
    );
    let registered = rows
        .get("a.test")
        .expect("a registered host keeps its own row");
    assert!(
        registered.issued >= 1,
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

fn stale_record(domain: &str) -> ChallengeRecord {
    ChallengeRecord {
        domain: domain.to_string(),
        identity: "identity".to_string(),
        salt: String::new(),
        difficulty: 1,
        target: "/".to_string(),
        kind: "pow".to_string(),
        attempts: 0,
        expires_at: SystemTime::now() - Duration::from_secs(1),
    }
}

fn live_record(domain: &str) -> ChallengeRecord {
    ChallengeRecord {
        expires_at: SystemTime::now() + Duration::from_secs(60),
        ..stale_record(domain)
    }
}

#[test]
fn expiry_attribution_is_per_domain_and_sums_to_the_total() {
    let store = TokenStore::with_limits(8, 64);
    store
        .issue("stale-a1".to_string(), stale_record("a.test"))
        .expect("capacity is not the subject here");
    store
        .issue("stale-a2".to_string(), stale_record("a.test"))
        .expect("capacity is not the subject here");
    store
        .issue("stale-c".to_string(), stale_record("c.test"))
        .expect("capacity is not the subject here");
    // The next issue sweeps the stale records out, attributing each drop to the
    // domain that owned it.
    store
        .issue("live".to_string(), live_record("a.test"))
        .expect("the live token is issued");
    // A token presented past its expiry expires in hand on the take path, and
    // is attributed there too, not only in the sweep.
    assert!(
        store
            .take("stale-c", "c.test", "identity", SystemTime::now())
            .is_none(),
        "a stale token is not taken"
    );

    let by_domain = store.expired_by_domain();
    assert_eq!(by_domain.get("a.test"), Some(&2), "swept drops, a.test");
    assert_eq!(by_domain.get("c.test"), Some(&1), "the in-hand expiry");
    assert_eq!(
        by_domain.values().sum::<u64>() as usize,
        store.expired_count(),
        "the per-domain attribution sums to the same total the atom counts"
    );
}
