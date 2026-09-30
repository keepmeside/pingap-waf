use pingap_challenge::token::{ChallengeRecord, TokenStore};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

#[test]
fn concurrent_presentations_are_single_use() {
    let store = Arc::new(TokenStore::new(4));
    store
        .issue(
            "token".to_string(),
            ChallengeRecord {
                domain: "a.test".into(),
                identity: "203.0.113.1".into(),
                salt: "s".into(),
                difficulty: 1,
                target: "/".into(),
                kind: "pow".into(),
                attempts: 0,
                expires_at: SystemTime::now() + Duration::from_secs(60),
            },
        )
        .expect("room");
    let a = Arc::clone(&store);
    let b = Arc::clone(&store);
    let first = thread::spawn(move || {
        a.take("token", "a.test", "203.0.113.1", SystemTime::now())
            .is_some()
    });
    let second = thread::spawn(move || {
        b.take("token", "a.test", "203.0.113.1", SystemTime::now())
            .is_some()
    });
    assert_ne!(
        first.join().expect("thread"),
        second.join().expect("thread")
    );
}

#[test]
fn failed_attempts_are_incremented_atomically_before_the_bound_is_applied() {
    let store = TokenStore::new(4);
    store
        .issue(
            "token".to_string(),
            ChallengeRecord {
                domain: "a.test".into(),
                identity: "203.0.113.1".into(),
                salt: "s".into(),
                difficulty: 1,
                target: "/".into(),
                kind: "pow".into(),
                attempts: 0,
                expires_at: SystemTime::now() + Duration::from_secs(60),
            },
        )
        .expect("room");
    assert_eq!(store.increment_attempts("token"), Some(1));
    assert_eq!(store.increment_attempts("token"), Some(2));
}

#[test]
fn an_expired_token_is_refused_for_read_and_for_solve() {
    // Issued with a short TTL, then presented after it lapses — `get` (the read
    // path) and `take` (the consuming solve) must both refuse, so an expired
    // challenge is unrecoverable rather than replayable.
    let store = TokenStore::new(4);
    store
        .issue(
            "token".to_string(),
            ChallengeRecord {
                domain: "a.test".into(),
                identity: "203.0.113.1".into(),
                salt: "s".into(),
                difficulty: 1,
                target: "/".into(),
                kind: "pow".into(),
                attempts: 0,
                expires_at: SystemTime::now() + Duration::from_millis(10),
            },
        )
        .expect("room");
    let after = SystemTime::now() + Duration::from_secs(60);
    assert!(
        store.get("token", "a.test", "203.0.113.1", after).is_none(),
        "an expired token is still readable"
    );
    assert!(
        store
            .take("token", "a.test", "203.0.113.1", after)
            .is_none(),
        "an expired token is still solvable"
    );
}
