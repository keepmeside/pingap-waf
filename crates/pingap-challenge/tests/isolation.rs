use pingap_challenge::token::{ChallengeRecord, TokenStore};
use std::time::{Duration, SystemTime};

#[test]
fn a_token_is_not_valid_on_another_domain_or_identity() {
    let store = TokenStore::new(4);
    let record = ChallengeRecord {
        domain: "a.test".to_string(),
        identity: "203.0.113.1".to_string(),
        salt: "salt".to_string(),
        difficulty: 1,
        target: "/".to_string(),
        kind: "pow".to_string(),
        attempts: 0,
        expires_at: SystemTime::now() + Duration::from_secs(60),
    };
    store.issue("token".to_string(), record).expect("room");
    assert!(
        store
            .take("token", "b.test", "203.0.113.1", SystemTime::now())
            .is_none()
    );
    assert!(
        store
            .take("token", "a.test", "203.0.113.1", SystemTime::now())
            .is_some()
    );
}
