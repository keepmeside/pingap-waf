use pingap_behaviour::{BehaviourStore, Observation};
use std::time::{Duration, Instant};

#[test]
fn unique_url_flood_keeps_every_collection_bounded() {
    let store = BehaviourStore::new(2, 8, 2, 16, Duration::from_secs(900));
    let now = Instant::now();
    for index in 0..100_000 {
        let _ = store.record(
            "a.test",
            "203.0.113.1",
            Observation {
                at: now,
                uri: format!("/{index}"),
                user_agent: format!("ua-{index}"),
                status: 200,
                denied: false,
                challenged: false,
                bot: false,
            },
        );
    }
    let profile = store.get("a.test", "203.0.113.1").expect("profile");
    assert!(profile.url_counts.len() <= 8);
    assert!(profile.user_agents.len() <= 2);
    assert!(profile.samples.len() <= 16);
    assert!(profile.overflow_urls > 0);
}

#[test]
fn window_pruning_rebuilds_signal_aggregates() {
    let store = BehaviourStore::new(2, 8, 8, 16, Duration::from_secs(1));
    let start = Instant::now();
    store.record(
        "a.test",
        "203.0.113.1",
        Observation {
            at: start,
            uri: "/old".into(),
            user_agent: "old".into(),
            status: 500,
            denied: false,
            challenged: false,
            bot: false,
        },
    );
    store.record(
        "a.test",
        "203.0.113.1",
        Observation {
            at: start + Duration::from_millis(500),
            uri: "/new".into(),
            user_agent: "new".into(),
            status: 200,
            denied: false,
            challenged: false,
            bot: false,
        },
    );
    store.record(
        "a.test",
        "203.0.113.1",
        Observation {
            at: start + Duration::from_secs(2),
            uri: "/latest".into(),
            user_agent: "latest".into(),
            status: 200,
            denied: false,
            challenged: false,
            bot: false,
        },
    );
    let profile = store.get("a.test", "203.0.113.1").expect("profile");
    assert!(!profile.url_counts.contains_key("/old"));
    assert_eq!(profile.errors, 0);
}

#[test]
fn ring_eviction_rebuilds_error_and_window_counts() {
    let store = BehaviourStore::new(2, 8, 8, 2, Duration::from_secs(900));
    let start = Instant::now();
    for (offset, status) in [(0, 500), (1, 200), (2, 200)] {
        store.record(
            "a.test",
            "203.0.113.1",
            Observation {
                at: start + Duration::from_secs(offset),
                uri: format!("/{offset}"),
                user_agent: "ua".into(),
                status,
                denied: false,
                challenged: false,
                bot: false,
            },
        );
    }
    let profile = store.get("a.test", "203.0.113.1").expect("profile");
    assert_eq!(profile.len(), 2);
    assert_eq!(profile.errors, 0);
    assert_eq!(profile.observed, 2);
    assert_eq!(profile.total, 2);
}
