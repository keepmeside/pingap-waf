use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pingap_intel::config::{Definition, Limits, Plan};
use pingap_intel::feed::FeedResult;
use pingap_intel::parse::Parsed;
use pingap_intel::set::FeedRegistry;
use url::Url;

fn registry(staleness: Duration) -> FeedRegistry {
    FeedRegistry::new(Plan {
        definitions: vec![Definition {
            name: "one".into(),
            url: Url::parse("http://example.test/list")
                .expect("valid test URL"),
            category: "test".into(),
            allow_private_targets: false,
        }],
        manual: vec![],
        limits: Limits {
            staleness,
            ..Limits::default()
        },
    })
}

fn result(body: &str, at: SystemTime) -> FeedResult {
    FeedResult {
        name: "one".into(),
        parsed: Parsed::parse(body, 100),
        fetched_at: at,
    }
}

#[test]
fn a_successful_swap_releases_an_address_removed_by_the_next_cycle() {
    let registry = registry(Duration::from_secs(60));
    let start = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    registry.apply(Ok(result("10.0.0.1\n10.0.0.2\n", start)), start);
    assert!(
        registry
            .matches(&"10.0.0.1".parse().expect("valid IP"))
            .is_some()
    );

    let next = start + Duration::from_secs(1);
    registry.apply(Ok(result("10.0.0.2\n", next)), next);
    assert!(
        registry
            .matches(&"10.0.0.1".parse().expect("valid IP"))
            .is_none()
    );
    assert!(
        registry
            .matches(&"10.0.0.2".parse().expect("valid IP"))
            .is_some()
    );
}

#[test]
fn a_failed_refresh_keeps_the_last_good_set_until_it_is_stale() {
    let registry = registry(Duration::from_secs(60));
    let start = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    registry.apply(Ok(result("10.0.0.1\n", start)), start);

    let within = start + Duration::from_secs(30);
    registry.apply(
        Err(pingap_intel::feed::FeedError::BodyTooLarge {
            feed: "one".into(),
            limit: 1,
        }),
        within,
    );
    assert!(
        registry
            .matches(&"10.0.0.1".parse().expect("valid IP"))
            .is_some()
    );
    assert_eq!(registry.snapshot().stats.fetch_errors, 1);

    let stale = start + Duration::from_secs(61);
    registry.apply(
        Err(pingap_intel::feed::FeedError::BodyTooLarge {
            feed: "one".into(),
            limit: 1,
        }),
        stale,
    );
    assert!(
        registry
            .matches(&"10.0.0.1".parse().expect("valid IP"))
            .is_none()
    );
    assert_eq!(registry.snapshot().stats.stale_drops, 1);
}

#[test]
fn readers_see_a_complete_snapshot_after_each_swap() {
    let registry = Arc::new(registry(Duration::from_secs(60)));
    let start = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    registry.apply(Ok(result("10.0.0.1\n10.0.0.2\n", start)), start);
    let before = registry.snapshot();
    registry.apply(
        Ok(result(
            "192.0.2.1\n192.0.2.2\n",
            start + Duration::from_secs(1),
        )),
        start + Duration::from_secs(1),
    );
    let after = registry.snapshot();
    assert_eq!(before.feeds.get("one").map(|v| v.entries), Some(2));
    assert_eq!(after.feeds.get("one").map(|v| v.entries), Some(2));
    assert_ne!(before.generation, after.generation);
}
