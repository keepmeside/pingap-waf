use pingap_behaviour::decisions::{Admission, Registry, ScenarioProfile};
use pingap_domainstate::{Limits, ManualClock};
use pingap_events::{EventQueue, NativeKind, Notification};
use std::sync::Arc;
use std::time::Duration;

fn profile(mode: &str) -> ScenarioProfile {
    let config = toml::from_str(&format!(
        r#"enabled=true
[scan]
mode="{mode}"
window="10s"
threshold=2
ban_ttl="1s"
"#
    ))
    .expect("test fixture succeeds");
    ScenarioProfile::new("behaviour:test", config, 8, 8, 8)
        .expect("test fixture succeeds")
}
fn observe(r: &Registry<ManualClock>, path: &str) {
    let Admission::Allowed(Some(t)) =
        r.admit("behaviour:test", "a.test", "::1", "GET", path, true)
    else {
        panic!("admitted")
    };
    r.observe(&t, 404, false);
}
#[test]
fn creation_and_lazy_expiry_are_once_and_do_not_fabricate_block_requests() {
    let q = Arc::new(EventQueue::new(16).expect("test fixture succeeds"));
    let clock = ManualClock::at(0);
    let r = Registry::with_clock(Limits::default(), clock.clone())
        .with_event_queue(q.clone());
    r.activate(vec![profile("block")]);
    observe(&r, "/one?password=never-store");
    observe(&r, "/two");
    let events = q.drain_notifications(16);
    assert_eq!(events.len(), 1);
    assert!(
        matches!(&events[0],Notification::Native(e) if e.kind==NativeKind::Created)
    );
    clock.advance(Duration::from_secs(2));
    assert!(r.active_decisions(0, 100).is_empty());
    assert!(r.active_decisions(0, 100).is_empty());
    let events = q.drain_notifications(16);
    assert_eq!(events.len(), 1);
    assert!(
        matches!(&events[0],Notification::Native(e) if e.kind==NativeKind::Expired && e.observed_at_ms>e.expires_at_ms.expect("test fixture succeeds"))
    );
    assert!(!format!("{events:?}").contains("password"));
}
#[test]
fn bounded_history_loss_is_explicit_while_runtime_still_blocks() {
    let q = Arc::new(EventQueue::new(1).expect("test fixture succeeds"));
    let r = Registry::with_clock(Limits::default(), ManualClock::at(0))
        .with_event_queue(q.clone());
    r.activate(vec![profile("detect")]);
    observe(&r, "/one");
    observe(&r, "/two");
    r.activate(vec![profile("block")]);
    observe(&r, "/one");
    observe(&r, "/two");
    assert_eq!(q.len(), 1);
    assert_eq!(q.dropped_lifecycle(), 1);
    assert!(matches!(
        r.admit("behaviour:test", "a.test", "::1", "GET", "/", true),
        Admission::Blocked(_)
    ));
}

#[test]
fn only_a_real_block_request_emits_block_telemetry_with_the_existing_node_identity()
 {
    let q = Arc::new(EventQueue::new(8).expect("queue"));
    let r = Registry::with_clock(Limits::default(), ManualClock::at(0))
        .with_event_queue(q.clone());
    r.activate(vec![profile("block")]);
    observe(&r, "/one");
    observe(&r, "/two");
    let created = q.drain_notifications(8);
    assert_eq!(created.len(), 1);
    let Admission::Blocked(ban) =
        r.admit("behaviour:test", "a.test", "::1", "GET", "/", true)
    else {
        panic!("active decision")
    };
    r.record_block(&ban);
    let events = q.drain_notifications(8);
    let [Notification::Waf(event)] = events.as_slice() else {
        panic!("one real block finding")
    };
    assert_eq!(event.node, "a.test");
    assert_eq!(event.domain, "a.test");
    assert_eq!(event.category.as_deref(), Some("native.abuse.scan"));
    assert_eq!(event.score, 0);
    assert_eq!(event.rule_id, None);
    assert_eq!(event.uri, None);
    assert!(event.blocked_flag());
}
