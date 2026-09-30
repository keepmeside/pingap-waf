use pingap_challenge::token::{ChallengeRecord, TokenError, TokenStore};
use std::time::{Duration, SystemTime};

#[test]
fn a_full_store_reports_saturation_instead_of_displacing_a_live_token() {
    let store = TokenStore::new(1);
    let record = || ChallengeRecord {
        domain: "a.test".into(),
        identity: "203.0.113.1".into(),
        salt: "s".into(),
        difficulty: 1,
        target: "/".into(),
        kind: "pow".into(),
        attempts: 0,
        expires_at: SystemTime::now() + Duration::from_secs(60),
    };
    store.issue("one".into(), record()).expect("room");
    assert_eq!(
        store.issue("two".into(), record()),
        Err(TokenError::FullEntries)
    );
    assert!(
        store
            .take("one", "a.test", "203.0.113.1", SystemTime::now())
            .is_some()
    );
}

#[test]
fn domain_capacity_is_reported_separately() {
    let store = TokenStore::with_limits(1, 4);
    let record = |domain: &str| ChallengeRecord {
        domain: domain.into(),
        identity: "203.0.113.1".into(),
        salt: "s".into(),
        difficulty: 1,
        target: "/".into(),
        kind: "pow".into(),
        attempts: 0,
        expires_at: SystemTime::now() + Duration::from_secs(60),
    };
    store.issue("one".into(), record("a.test")).expect("room");
    assert_eq!(
        store.issue("two".into(), record("b.test")),
        Err(TokenError::FullDomains)
    );
}
