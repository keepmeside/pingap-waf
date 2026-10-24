use pingap_behaviour::{
    decisions::{Admission, Registry, ScenarioProfile},
    scenario::AbuseConfig,
};
use pingap_domainstate::{Limits, ManualClock};
use pingap_events::NativeAbuse;
use std::sync::Arc;
use std::time::Duration;
fn profile(name: &str, ttl: u64) -> ScenarioProfile {
    let c: AbuseConfig = toml::from_str(&format!(
        r#"enabled=true
[scan]
mode="block"
window="10s"
threshold=2
ban_ttl="{ttl}s"
"#
    ))
    .expect("test fixture");
    ScenarioProfile::new(name, c, 5000, 32, 64).expect("test fixture")
}
fn admit(
    r: &Registry<ManualClock>,
    ns: &str,
    ip: &str,
    path: &str,
) -> pingap_behaviour::decisions::Ticket {
    let Admission::Allowed(Some(t)) =
        r.admit(ns, "a.test", ip, "GET", path, true)
    else {
        panic!("not admitted")
    };
    t
}
fn ban(r: &Registry<ManualClock>, ns: &str, ip: &str) -> String {
    r.observe(&admit(r, ns, ip, "/a"), 404, false);
    assert!(r.observe(&admit(r, ns, ip, "/b"), 404, false).ban_created);
    let Admission::Blocked(b) = r.admit(ns, "a.test", ip, "GET", "/", true)
    else {
        panic!("not blocked")
    };
    b.id
}
#[test]
fn release_expiry_and_aba_invalidate_all_pre_boundary_responses() {
    for expire in [false, true] {
        let c = ManualClock::at(1000);
        let r = Registry::with_clock(Limits::default(), c.clone());
        r.activate(vec![profile("behaviour:a", 20)]);
        let slow = admit(&r, "behaviour:a", "::1", "/slow");
        let old = ban(&r, "behaviour:a", "::1");
        if expire {
            c.advance(Duration::from_secs(20));
        } else {
            assert!(r.release("behaviour:a", "a.test", "::1", &old));
        }
        assert!(!r.observe(&slow, 404, false).detected);
        let new = ban(&r, "behaviour:a", "::1");
        assert_ne!(old, new);
        assert!(!r.release("behaviour:a", "a.test", "::1", &old));
        assert!(matches!(
            r.admit("behaviour:a", "a.test", "::1", "GET", "/", true),
            Admission::Blocked(_)
        ));
        assert!(r.release("behaviour:a", "a.test", "::1", &new));
        assert!(!r.release("behaviour:a", "a.test", "::1", &new));
    }
}
#[test]
fn admission_after_reset_can_trigger_normally_but_old_generation_cannot() {
    let c = ManualClock::at(1000);
    let r = Registry::with_clock(Limits::default(), c);
    r.activate(vec![profile("behaviour:a", 20)]);
    let slow = admit(&r, "behaviour:a", "1.2.3.4", "/slow");
    r.activate(vec![profile("behaviour:a", 30)]);
    assert!(!r.observe(&slow, 404, false).detected);
    ban(&r, "behaviour:a", "1.2.3.4");
    r.activate(vec![profile("behaviour:a", 30)]);
    assert!(matches!(
        r.admit("behaviour:a", "a.test", "1.2.3.4", "GET", "/", true),
        Admission::Blocked(_)
    ));
    r.activate(vec![]);
    assert!(matches!(
        r.admit("behaviour:a", "a.test", "1.2.3.4", "GET", "/", true),
        Admission::Allowed(None)
    ));
}
#[test]
fn capacity_is_shared_between_namespaces_and_never_evicts_live_bans() {
    let c = ManualClock::at(1000);
    let r = Registry::with_clock(
        Limits {
            max_domains: 1,
            max_entries_per_domain: 1,
        },
        c.clone(),
    );
    r.activate(vec![profile("behaviour:a", 20), profile("behaviour:b", 20)]);
    ban(&r, "behaviour:a", "1.2.3.4");
    assert!(matches!(
        r.admit("behaviour:b", "a.test", "1.2.3.4", "GET", "/a", true),
        Admission::Saturated
    ));
    assert!(matches!(
        r.admit("behaviour:a", "evil.test", "9.9.9.9", "GET", "/", false),
        Admission::Unregistered
    ));
    assert!(matches!(
        r.admit("behaviour:a", "a.test", "1.2.3.4", "GET", "/", true),
        Admission::Blocked(_)
    ));
    c.advance(Duration::from_secs(21));
    assert!(matches!(
        r.admit("behaviour:b", "a.test", "1.2.3.4", "GET", "/a", true),
        Admission::Allowed(Some(_))
    ));
    assert!(r.counters().saturated > 0);
}
#[test]
fn evicted_incarnation_and_concurrent_completions_do_not_recreate_state() {
    let c = ManualClock::at(1000);
    let r = Arc::new(Registry::with_clock(
        Limits {
            max_domains: 1,
            max_entries_per_domain: 1,
        },
        c.clone(),
    ));
    r.activate(vec![profile("behaviour:a", 20)]);
    let old = admit(&r, "behaviour:a", "1.2.3.4", "/old");
    c.advance(Duration::from_secs(21));
    let _ = admit(&r, "behaviour:a", "5.6.7.8", "/other");
    assert!(!r.observe(&old, 404, false).detected);
    c.advance(Duration::from_secs(21));
    let _ = admit(&r, "behaviour:a", "1.2.3.4", "/new");
    assert!(!r.observe(&old, 404, false).detected);
    let tickets: Vec<_> = (0..8)
        .map(|i| admit(&r, "behaviour:a", "1.2.3.4", &format!("/p{i}")))
        .collect();
    let tasks: Vec<_> = tickets
        .into_iter()
        .map(|t| {
            let r = r.clone();
            std::thread::spawn(move || r.observe(&t, 404, false).ban_created)
        })
        .collect();
    assert_eq!(
        tasks
            .into_iter()
            .filter_map(|h| h.join().ok())
            .filter(|b| *b)
            .count(),
        1
    );
}

#[test]
fn old_request_instances_cannot_admit_into_replacement_generation() {
    let c = ManualClock::at(1000);
    let r = Registry::with_clock(Limits::default(), c);
    let old = profile("behaviour:a", 20);
    let new = profile("behaviour:a", 30);
    r.activate(vec![old.clone()]);
    assert!(matches!(
        r.admit_profile(&new, "a.test", "1.2.3.4", "GET", "/a", true),
        Admission::Unavailable
    ));
    r.activate(vec![new.clone()]);
    assert!(matches!(
        r.admit_profile(&old, "a.test", "1.2.3.4", "GET", "/a", true),
        Admission::Unavailable
    ));
    assert!(matches!(
        r.admit_profile(&new, "a.test", "1.2.3.4", "GET", "/a", true),
        Admission::Allowed(Some(_))
    ));
}

#[test]
fn removed_registered_domain_releases_capacity_and_old_admission_cannot_recreate_it()
 {
    let clock = ManualClock::at(100);
    let r = Registry::with_clock(
        Limits {
            max_domains: 1,
            max_entries_per_domain: 1,
        },
        clock,
    );
    r.activate(vec![profile("behaviour:a", 60)]);
    let old = admit(&r, "behaviour:a", "1.2.3.4", "/slow");
    r.retain_hosts(pingap_domainstate::HostPolicy::new(["b.test"]));
    assert!(!r.observe(&old, 404, false).detected);
    assert!(matches!(
        r.admit("behaviour:a", "a.test", "1.2.3.4", "GET", "/x", true),
        Admission::Unregistered
    ));
    assert!(matches!(
        r.admit("behaviour:a", "b.test", "1.2.3.4", "GET", "/x", true),
        Admission::Allowed(Some(_))
    ));
}

#[test]
fn eligible_slow_response_extends_evidence_retention_under_capacity_pressure() {
    let clock = ManualClock::at(0);
    let r = Registry::with_clock(
        Limits {
            max_domains: 1,
            max_entries_per_domain: 1,
        },
        clock.clone(),
    );
    r.activate(vec![profile("behaviour:a", 1)]);
    let slow = admit(&r, "behaviour:a", "1.2.3.4", "/slow");
    clock.advance(Duration::from_secs(9));
    assert!(!r.observe(&slow, 404, false).ban_created);
    clock.advance(Duration::from_secs(2));
    assert!(matches!(
        r.admit("behaviour:a", "a.test", "5.6.7.8", "GET", "/other", true),
        Admission::Saturated
    ));
    assert!(
        r.observe(&admit(&r, "behaviour:a", "1.2.3.4", "/second"), 404, false)
            .ban_created
    );
}

#[test]
fn login_timestamp_capacity_is_independent_of_scan_path_capacity() {
    let conf: pingap_config::PluginConf = toml::from_str(
        r#"category="behaviour"
enabled=true
client_ip_from_peer=true
abuse_namespace="behaviour:capacity"
max_interval_samples=64
max_url_keys=1
[abuse]
enabled=true
[abuse.failed_login]
mode="block"
threshold=5
window="1m"
ban_ttl="1m"
path="/login"
method="POST"
statuses=[401]
"#,
    )
    .expect("config");
    assert!(pingap_behaviour::Behaviour::try_from(&conf).is_ok());
}

#[test]
fn ban_index_pages_live_decisions_after_batched_expiry() {
    let clock = ManualClock::at(0);
    let registry = Registry::with_clock(Limits::default(), clock.clone());
    registry.activate(vec![
        profile("behaviour:short", 1),
        profile("behaviour:long", 60),
    ]);
    for i in 1..=128 {
        ban(&registry, "behaviour:short", &format!("10.0.0.{i}"));
        ban(&registry, "behaviour:long", &format!("10.0.1.{i}"));
    }
    clock.advance(Duration::from_secs(2));

    let page = NativeAbuse::list(
        &registry,
        Some("behaviour:long"),
        Some("a.test"),
        0,
        100,
    );
    assert_eq!(page.items.len(), 100);
    assert_eq!(registry.counters().expired, 128);
    assert!(page.items.iter().all(|ban| ban.profile == "behaviour:long"));
    let after: u64 = page
        .next_cursor
        .as_deref()
        .expect("first page has a cursor")
        .rsplit(':')
        .next()
        .expect("cursor sequence")
        .parse()
        .expect("numeric cursor");
    let second = NativeAbuse::list(
        &registry,
        Some("behaviour:long"),
        Some("a.test"),
        after,
        100,
    );
    assert_eq!(second.items.len(), 28);
    assert!(second.next_cursor.is_none());
    assert_eq!(registry.counters().expired, 128);
    assert_eq!(registry.active_decisions(0, 256).len(), 128);
    let released = &second.items[0];
    assert!(registry.release(
        "behaviour:long",
        "a.test",
        &released.client_ip,
        &released.id,
    ));
    assert_eq!(registry.active_decisions(0, 256).len(), 127);
}
