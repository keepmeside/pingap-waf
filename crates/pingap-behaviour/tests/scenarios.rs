use pingap_behaviour::decisions::{Admission, Registry, ScenarioProfile};
use pingap_behaviour::scenario::{AbuseConfig, Evidence};
use pingap_domainstate::{Limits, ManualClock};
use std::time::Duration;

fn config(mode: &str) -> AbuseConfig {
    toml::from_str(&format!(
        r#"enabled=true
[failed_login]
mode="{mode}"
window="10s"
threshold=3
ban_ttl="20s"
path="/login"
method="POST"
statuses=[401]
"#
    ))
    .expect("test fixture")
}
fn registry(mode: &str) -> (Registry<ManualClock>, ManualClock) {
    let clock = ManualClock::at(100_000);
    let registry = Registry::with_clock(
        Limits {
            max_domains: 256,
            max_entries_per_domain: 5000,
        },
        clock.clone(),
    );
    registry.activate(vec![
        ScenarioProfile::new("behaviour:a", config(mode), 5000, 32, 64)
            .expect("test fixture"),
    ]);
    (registry, clock)
}
fn fail(
    r: &Registry<ManualClock>,
    path: &str,
    method: &str,
    status: u16,
    local: bool,
) -> Evidence {
    let Admission::Allowed(Some(ticket)) =
        r.admit("behaviour:a", "a.test", "1.2.3.4", method, path, true)
    else {
        panic!("not admitted")
    };
    r.observe(&ticket, status, local)
}
#[test]
fn threshold_blocks_only_subsequent_request_and_ttl_never_slides() {
    let (r, c) = registry("block");
    assert!(!fail(&r, "/login", "POST", 401, false).ban_created);
    assert!(!fail(&r, "/login", "POST", 401, false).ban_created);
    assert!(fail(&r, "/login", "POST", 401, false).ban_created);
    c.advance(Duration::from_secs(19));
    assert!(matches!(
        r.admit("behaviour:a", "a.test", "1.2.3.4", "GET", "/", true),
        Admission::Blocked(_)
    ));
    c.advance(Duration::from_secs(1));
    assert!(matches!(
        r.admit("behaviour:a", "a.test", "1.2.3.4", "POST", "/login", true),
        Admission::Allowed(Some(_))
    ));
    assert!(!fail(&r, "/login", "POST", 401, false).ban_created);
}
#[test]
fn provenance_exact_predicates_and_inclusive_window() {
    let (r, c) = registry("block");
    for (path, method, status, local) in [
        ("/other", "POST", 401, false),
        ("/login", "GET", 401, false),
        ("/login", "POST", 404, false),
        ("/login", "POST", 401, true),
    ] {
        // Non-matching admissions may have no response ticket.
        if let Admission::Allowed(Some(t)) =
            r.admit("behaviour:a", "a.test", "1.2.3.4", method, path, true)
        {
            assert!(!r.observe(&t, status, local).detected);
        }
    }
    fail(&r, "/login", "POST", 401, false);
    c.advance(Duration::from_secs(10));
    fail(&r, "/login", "POST", 401, false);
    assert!(fail(&r, "/login", "POST", 401, false).ban_created);
}
#[test]
fn detect_crossing_rearms_after_window_without_banning() {
    let (r, c) = registry("detect");
    for i in 0..6 {
        let e = fail(&r, "/login", "POST", 401, false);
        assert_eq!(e.detected, i == 2);
        assert!(!e.ban_created);
    }
    c.advance(Duration::from_secs(11));
    for i in 0..3 {
        assert_eq!(fail(&r, "/login", "POST", 401, false).detected, i == 2);
    }
}
#[test]
fn scan_counts_distinct_paths_not_query_churn_or_other_statuses() {
    let clock = ManualClock::at(100);
    let r = Registry::with_clock(Limits::default(), clock);
    let conf: AbuseConfig = toml::from_str(
        r#"enabled=true
[scan]
mode="block"
window="10s"
threshold=3
ban_ttl="20s"
"#,
    )
    .expect("test fixture");
    r.activate(vec![
        ScenarioProfile::new("behaviour:a", conf, 5000, 32, 64)
            .expect("test fixture"),
    ]);
    for i in 0..100 {
        assert!(!fail(&r, &format!("/x?q={i}"), "GET", 404, false).detected);
    }
    assert!(!fail(&r, "/y", "GET", 200, false).detected);
    assert!(!fail(&r, "/y", "GET", 404, false).detected);
    assert!(fail(&r, "/z", "GET", 404, false).ban_created);
}
