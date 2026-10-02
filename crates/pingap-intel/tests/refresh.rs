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
    registry.apply(Ok(result("10.0.0.1\n10.0.0.2\n", start)), 0, start);
    assert!(
        registry
            .matches(&"10.0.0.1".parse().expect("valid IP"))
            .is_some()
    );

    let next = start + Duration::from_secs(1);
    registry.apply(Ok(result("10.0.0.2\n", next)), 0, next);
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
    registry.apply(Ok(result("10.0.0.1\n", start)), 0, start);

    let within = start + Duration::from_secs(30);
    registry.apply(
        Err(pingap_intel::feed::FeedError::BodyTooLarge {
            feed: "one".into(),
            limit: 1,
        }),
        0,
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
        0,
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
    registry.apply(Ok(result("10.0.0.1\n10.0.0.2\n", start)), 0, start);
    let before = registry.snapshot();
    registry.apply(
        Ok(result(
            "192.0.2.1\n192.0.2.2\n",
            start + Duration::from_secs(1),
        )),
        0,
        start + Duration::from_secs(1),
    );
    let after = registry.snapshot();
    assert_eq!(before.feeds.get("one").map(|v| v.entries), Some(2));
    assert_eq!(after.feeds.get("one").map(|v| v.entries), Some(2));
    assert_ne!(before.generation, after.generation);
}

#[test]
fn the_stats_projection_is_serialisable_and_carries_no_rules() {
    // What the metrics surface publishes is the aggregate projection: feed
    // names from the fixed configured enumeration, entry counts, refresh
    // stats — never the rules themselves, and never anything read from a
    // request.
    let registry = registry(Duration::from_secs(60));
    let start = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    registry.apply(Ok(result("10.0.0.1\n10.0.0.2\n", start)), 0, start);

    let projection = registry.snapshot().stats_projection();
    assert_eq!(projection.generation, 1, "one applied refresh");
    let unix_start = 10u64;
    assert_eq!(projection.refreshed_at, Some(unix_start));
    let feed = projection
        .feeds
        .get("one")
        .expect("the configured feed is published under its configured name");
    assert_eq!(feed.category, "test");
    assert_eq!(feed.entries, 2);
    assert_eq!(feed.fetched_at, unix_start);

    // The projection serialises — it is the payload the metrics route serves.
    let json = serde_json::to_string(&projection).expect("serialises");
    assert!(
        json.contains("\"one\""),
        "the feed name is a JSON key, got {json}"
    );
    assert!(
        !json.contains("10.0.0."),
        "no address from the rules may appear in the published stats"
    );
}

#[test]
fn feed_stats_snapshot_is_none_without_an_installed_registry() {
    // `feed_stats_snapshot` reads the process-global registry; this test
    // binary installs none, so the honest answer is `None`, not a default.
    assert!(pingap_intel::feed_stats_snapshot().is_none());
}

#[test]
fn the_opt_out_counter_accumulates_on_both_arms_of_a_refresh() {
    // The published `allow_private_targets` stat is the audit signal for the
    // egress opt-out: every reserved-address decision a fetch permitted is
    // counted, and a fetch that reached a private mirror before failing
    // permitted the same decision a successful one did, so both arms
    // accumulate. Without this the published counter stays at zero forever
    // and the opt-out is merely permitted, never observed.
    let registry = registry(Duration::from_secs(60));
    let start = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    registry.apply(Ok(result("10.0.0.1\n", start)), 1, start);
    assert_eq!(
        registry.snapshot().stats.allow_private_targets,
        1,
        "a successful opted-out fetch counts its permitted decision"
    );

    let next = start + Duration::from_secs(1);
    registry.apply(
        Err(pingap_intel::feed::FeedError::BodyTooLarge {
            feed: "one".into(),
            limit: 1,
        }),
        2,
        next,
    );
    let stats = &registry.snapshot().stats;
    assert_eq!(
        stats.allow_private_targets, 3,
        "the failed arm accumulates its permitted decisions too"
    );
    assert_eq!(stats.fetch_errors, 1);
}
