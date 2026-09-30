//! Expiry, with a clock the test advances by hand.
//!
//! No test here sleeps. A sleeping expiry test is slow, flaky under parallel load, and — in this
//! fork specifically — a clock that needed a background thread would not survive daemonisation:
//! pingora's `fork()` carries only the calling thread, so anything started before it does not
//! exist in the daemon. That is why the gateway's own clock helpers read the system time
//! directly rather than caching it, and why the container takes its clock as a parameter.
//!
//! Reclaim is lazy, on access, and there is no eager sweep. A sweep needs a trigger and an
//! owner, and promising one that nobody runs is how a bound quietly stops being a bound. What
//! is guaranteed instead: an expired entry is unreachable through every accessor, and a domain
//! that goes quiet reclaims its entries the next time it receives any request.

use pingap_domainstate::{
    Domain, HostPolicy, Limits, ManualClock, ScopedStore,
};
use std::time::Duration;

const TTL: Duration = Duration::from_secs(100);

fn store() -> (
    ScopedStore<String, ManualClock>,
    ManualClock,
    Domain,
    Domain,
) {
    let clock = ManualClock::at(1_000);
    let hosts = HostPolicy::new(["a.example", "b.example"]);
    let limits = Limits {
        max_domains: 8,
        max_entries_per_domain: 4,
    };
    let scoped = ScopedStore::with_clock(hosts, limits, clock.clone());
    let a = scoped.hosts().classify("a.example");
    let b = scoped.hosts().classify("b.example");
    (scoped, clock, a, b)
}

#[test]
fn an_idle_entry_is_unreachable_through_every_accessor_after_its_ttl() {
    let (store, clock, domain, _) = store();
    store
        .insert(domain, "client", "token".to_string(), TTL)
        .expect("room");

    assert_eq!(store.get(domain, "client").as_deref(), Some("token"));
    clock.advance(TTL);

    // All five accessors, because a value that is gone from one and present in another is
    // worse than one that never expired at all.
    assert_eq!(
        store.get(domain, "client"),
        None,
        "`get` returned an expired entry"
    );
    assert!(
        !store.contains(domain, "client"),
        "`contains` saw an expired entry"
    );
    assert!(
        store.with(domain, "client", |value| value.len()).is_none(),
        "`with` reached an expired entry"
    );
    assert!(
        store
            .update(domain, "client", |value| value.push('x'))
            .is_none(),
        "`update` reached an expired entry"
    );
    assert_eq!(
        store.entries(domain),
        0,
        "`entries` counted an expired entry"
    );
}

#[test]
fn an_expired_entry_is_not_returned_by_remove() {
    let (store, clock, domain, _) = store();
    store
        .insert(domain, "client", "bearer-token".to_string(), TTL)
        .expect("room");
    clock.advance(TTL);

    // Reclaim must not be a read path. An eviction or a removal that hands an expired value
    // back to its caller makes the TTL advisory, and in the consumer that holds tokens it
    // would let a spent credential be replayed.
    assert_eq!(store.remove(domain, "client"), None);
    assert_eq!(store.counters().expired_reclaimed, 1);
}

#[test]
fn an_entry_is_live_up_to_the_instant_before_it_expires() {
    let (store, clock, domain, _) = store();
    store
        .insert(domain, "client", "value".to_string(), TTL)
        .expect("room");

    clock.advance(TTL - Duration::from_millis(1));
    assert_eq!(
        store.get(domain, "client").as_deref(),
        Some("value"),
        "expired early"
    );

    clock.advance(Duration::from_millis(1));
    assert_eq!(store.get(domain, "client"), None, "outlived its TTL");
}

#[test]
fn refreshing_an_entry_extends_its_ttl_from_the_refresh() {
    let (store, clock, domain, _) = store();
    store
        .insert(domain, "client", "value".to_string(), TTL)
        .expect("room");

    clock.advance(TTL / 2);
    store
        .insert(domain, "client", "refreshed".to_string(), TTL)
        .expect("room");

    // Measured from the refresh, not from the original insert: a client that keeps arriving
    // must not be dropped mid-session because of when it first did.
    clock.advance(TTL / 2 + Duration::from_millis(1));
    assert_eq!(store.get(domain, "client").as_deref(), Some("refreshed"));

    clock.advance(TTL);
    assert_eq!(store.get(domain, "client"), None);
}

#[test]
fn a_domain_that_goes_quiet_reclaims_its_expired_entries_on_its_next_request() {
    let (store, clock, a, b) = store();
    for id in ["one", "two", "three"] {
        store.insert(a, id, id.to_string(), TTL).expect("room");
    }
    store
        .insert(b, "other", "other".to_string(), TTL)
        .expect("room");

    clock.advance(TTL);

    // Nothing swept A while it was idle — there is no sweep — so the reclaim has to happen
    // here, on the first access, and it has to happen without the caller naming what to drop.
    assert_eq!(store.entries(a), 0);
    store
        .insert(a, "four", "four".to_string(), TTL)
        .expect("room after reclaim");
    assert_eq!(store.entries(a), 1);
    assert_eq!(store.counters().expired_reclaimed, 3);

    // B is untouched by A's reclaim.
    assert_eq!(store.entries(b), 0, "B was already expired on access");
}

#[test]
fn the_entry_cap_is_not_consumed_by_stale_entries() {
    let (store, clock, domain, _) = store();
    // Fill to the cap with entries that are about to expire.
    for id in ["stale-1", "stale-2", "stale-3", "stale-4"] {
        store.insert(domain, id, id.to_string(), TTL).expect("room");
    }
    assert!(
        store
            .insert(domain, "blocked", "x".to_string(), TTL)
            .is_err(),
        "the cap did not engage while every entry was still live"
    );

    clock.advance(TTL);

    // A new client must be admitted. If stale entries still held the cap, a domain would
    // lock out every new client for the length of its TTL after any burst — an availability
    // failure an attacker could cause by simply filling the bucket once and waiting.
    store
        .insert(domain, "fresh-client", "fresh".to_string(), TTL)
        .expect("stale entries must not hold the cap");
    assert_eq!(store.get(domain, "fresh-client").as_deref(), Some("fresh"));
    assert_eq!(store.entries(domain), 1);
}

#[test]
fn reclaim_is_deterministic_across_identically_driven_stores() {
    // Asserted twice, from the same starting state, because a nondeterministic reclaim makes a
    // cross-domain leak look intermittent — the hardest failure to diagnose and the one the
    // isolation test exists to avoid. Hash-map iteration order varies per process, so anything
    // decided by it would pass here and fail in production.
    for attempt in 0..2 {
        let (store, clock, a, b) = store();

        // Interleave two domains, two TTLs and three reclaim triggers, so the sequence
        // exercises admission, refresh, expiry and eviction in one pass.
        for round in 0..6u32 {
            let domain = if round % 2 == 0 { a } else { b };
            let ttl = if round % 3 == 0 { TTL } else { TTL * 3 };
            let outcome = store.insert(
                domain,
                &format!("id-{round}"),
                round.to_string(),
                ttl,
            );
            assert!(
                outcome.is_ok(),
                "attempt {attempt} round {round} was refused"
            );
            clock.advance(Duration::from_secs(40));
            store.entries(domain);
        }

        let surviving: Vec<String> = ["a.example", "b.example"]
            .iter()
            .flat_map(|host| {
                let domain = store.hosts().classify(host);
                (0..8)
                    .filter_map(|round| {
                        let id = format!("id-{round}");
                        store
                            .get(domain, &id)
                            .map(|value| format!("{host}/{id}={value}"))
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        // Rounds 0 and 3 carry the short TTL and have expired by the end; the rest survive.
        assert_eq!(
            surviving,
            [
                "a.example/id-2=2",
                "a.example/id-4=4",
                "b.example/id-1=1",
                "b.example/id-5=5",
            ],
            "attempt {attempt} reclaimed a different set"
        );
    }
}

#[test]
fn the_reclaimed_counter_counts_entries_and_not_operations() {
    let (store, clock, domain, _) = store();
    for id in ["one", "two"] {
        store.insert(domain, id, id.to_string(), TTL).expect("room");
    }
    clock.advance(TTL);

    // Reading the same expired key five times must report two reclaimations, not five: the
    // number is published, and a counter that moves on repeats cannot be reasoned about.
    for _ in 0..5 {
        assert_eq!(store.get(domain, "one"), None);
        assert_eq!(store.get(domain, "two"), None);
    }
    assert_eq!(store.counters().expired_reclaimed, 2);
}

#[test]
fn expiry_in_one_domain_does_not_expire_another_domain_s_entry() {
    // A shared clock reading is fine; a shared expiry computation is not.
    let (store, clock, a, b) = store();
    store
        .insert(a, "client", "short".to_string(), TTL)
        .expect("room");
    store
        .insert(b, "client", "long".to_string(), TTL * 10)
        .expect("room");

    clock.advance(TTL);
    assert_eq!(store.get(a, "client"), None);
    assert_eq!(store.get(b, "client").as_deref(), Some("long"));
}
