use pingap_behaviour::{BehaviourStore, Observation};
use std::time::{Duration, Instant};

#[test]
fn domains_and_identities_do_not_share_profiles() {
    let store = BehaviourStore::new(4, 8, 4, 16, Duration::from_secs(900));
    let observation = || Observation {
        at: Instant::now(),
        uri: "/a".into(),
        user_agent: "ua".into(),
        status: 200,
        denied: false,
        challenged: false,
        bot: false,
    };
    store.record("a.test", "203.0.113.1", observation());
    assert!(store.get("b.test", "203.0.113.1").is_none());
    assert!(store.get("a.test", "198.51.100.1").is_none());
}

#[test]
fn an_idle_client_slot_is_reclaimed_before_the_client_cap_is_reported() {
    let store = BehaviourStore::new(1, 8, 4, 16, Duration::from_secs(1));
    let start = Instant::now();
    let observation = |at: Instant, uri: &str| Observation {
        at,
        uri: uri.into(),
        user_agent: "ua".into(),
        status: 200,
        denied: false,
        challenged: false,
        bot: false,
    };
    store.record("a.test", "203.0.113.1", observation(start, "/old"));
    assert!(
        store
            .record(
                "a.test",
                "203.0.113.2",
                observation(start + Duration::from_secs(2), "/new")
            )
            .is_some()
    );
}

#[test]
fn client_cap_is_scoped_per_domain() {
    let store = BehaviourStore::new(1, 8, 4, 16, Duration::from_secs(900));
    let observation = |uri: &str| Observation {
        at: Instant::now(),
        uri: uri.into(),
        user_agent: "ua".into(),
        status: 200,
        denied: false,
        challenged: false,
        bot: false,
    };
    assert!(
        store
            .record("a.test", "203.0.113.1", observation("/a"))
            .is_some()
    );
    assert!(
        store
            .record("b.test", "203.0.113.1", observation("/b"))
            .is_some()
    );
    assert_eq!(store.len(), 2);
}

#[test]
fn snapshot_reclaims_an_idle_profile_before_scoring() {
    let store = BehaviourStore::new(1, 8, 4, 16, Duration::from_secs(1));
    let start = Instant::now();
    let observation = |at: Instant, uri: &str| Observation {
        at,
        uri: uri.into(),
        user_agent: "ua".into(),
        status: 200,
        denied: false,
        challenged: false,
        bot: false,
    };
    store.record("a.test", "203.0.113.1", observation(start, "/old"));
    assert!(
        store
            .snapshot("a.test", "203.0.113.1", start + Duration::from_secs(2))
            .is_none()
    );
    assert_eq!(store.len(), 0);
    assert!(
        store
            .record(
                "a.test",
                "203.0.113.2",
                observation(start + Duration::from_secs(2), "/new")
            )
            .is_some()
    );
}
