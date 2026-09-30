//! Traffic against one domain does not reach another domain's state.
//!
//! The property the platform plan states as an invariant of the domain policy model: where
//! one named profile is shared across domains, per-domain mutable state must be keyed by an
//! identifier read from the request, never by instance identity. Keying is a weaker guarantee
//! than holding no state at all, which is why it is proved here rather than assumed — a
//! `HashMap` keyed on the client alone, wrapped by a plugin that forgets the domain argument,
//! passes every single-domain test ever written.
//!
//! Asserted against a **process-global** store, not a local one. That is the shape that ships:
//! plugin instances are rebuilt whenever the config hash changes, so state held on an instance
//! dies routinely, and the container is therefore instantiated once and owned by nothing. A
//! local store would prove the map is keyed; a global one proves the deployed arrangement is.

use pingap_domainstate::{
    Domain, HostPolicy, Limits, ManualClock, ScopedStore,
};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Long enough that nothing in this file expires by accident. Expiry has its own file.
const TTL: Duration = Duration::from_secs(3600);

fn hosts() -> HostPolicy {
    HostPolicy::new(["a.example", "b.example"])
}

fn limits() -> Limits {
    Limits {
        max_domains: 8,
        max_entries_per_domain: 64,
    }
}

/// One store for the whole process, as a plugin would hold it.
static GLOBAL: OnceLock<Arc<ScopedStore<Vec<u8>>>> = OnceLock::new();

fn global() -> Arc<ScopedStore<Vec<u8>>> {
    GLOBAL
        .get_or_init(|| Arc::new(ScopedStore::new(hosts(), limits())))
        .clone()
}

#[test]
fn operations_against_one_domain_leave_another_domain_s_entry_byte_identical() {
    let store =
        ScopedStore::with_clock(hosts(), limits(), ManualClock::at(1_000));
    let a = store.hosts().classify("a.example");
    let b = store.hosts().classify("b.example");

    // B's entry is written first and never touched again.
    let before = vec![1u8, 2, 3, 4, 5];
    store
        .insert(b, "victim", before.clone(), TTL)
        .expect("room");

    // A is then driven hard: many identities, overwrites, removals, and a read of B's key
    // under A's domain, which must miss rather than reach across.
    for round in 0..200u32 {
        let id = format!("attacker-{round}");
        store.insert(a, &id, vec![9, 9, 9], TTL).expect("room");
        store.update(a, &id, |value| value.push(round as u8));
        store.remove(a, &id);
    }
    assert!(
        store.get(a, "victim").is_none(),
        "B's key was readable under A's domain, so the key is not really two-part"
    );

    assert_eq!(
        store.get(b, "victim").expect("B's entry survives"),
        before,
        "A's traffic altered B's entry"
    );
    assert_eq!(store.entries(b), 1, "A's traffic changed B's entry count");
}

#[test]
fn a_domain_s_counters_are_not_moved_by_another_domain_s_traffic() {
    let store =
        ScopedStore::with_clock(hosts(), limits(), ManualClock::at(1_000));
    let a = store.hosts().classify("a.example");
    let b = store.hosts().classify("b.example");

    store.insert(b, "one", 1u32, TTL).expect("room");
    let b_entries = store.entries(b);

    for round in 0..50 {
        store
            .insert(a, &format!("id-{round}"), round, TTL)
            .expect("room");
    }

    assert_eq!(store.entries(b), b_entries, "A's inserts moved B's count");
    assert_eq!(store.entries(a), 50);
}

#[test]
fn the_overflow_bucket_does_not_leak_into_a_registered_domain() {
    let store =
        ScopedStore::with_clock(hosts(), limits(), ManualClock::at(1_000));
    let registered = store.hosts().classify("a.example");
    let unregistered = store.hosts().classify("not-configured.example");

    assert!(
        unregistered.is_overflow(),
        "an unconfigured host must collapse"
    );
    store
        .insert(unregistered, "shared-key", "overflow", TTL)
        .expect("room");

    // Same identity string, different domain: the registered side must not see it.
    assert!(
        store.get(registered, "shared-key").is_none(),
        "the overflow bucket and a registered domain share keys"
    );
    assert_eq!(store.get(unregistered, "shared-key"), Some("overflow"));
}

#[test]
fn the_same_identity_on_two_domains_holds_two_independent_values() {
    let store =
        ScopedStore::with_clock(hosts(), limits(), ManualClock::at(1_000));
    let a = store.hosts().classify("a.example");
    let b = store.hosts().classify("b.example");

    store.insert(a, "client", "on-a", TTL).expect("room");
    store.insert(b, "client", "on-b", TTL).expect("room");

    assert_eq!(store.get(a, "client"), Some("on-a"));
    assert_eq!(store.get(b, "client"), Some("on-b"));
}

#[test]
fn a_process_global_store_keeps_domains_isolated() {
    // The deployed shape: one instance for the process, reached through an `Arc`, surviving
    // every rebuild of whatever holds it.
    let store = global();
    let a = store.hosts().classify("a.example");
    let b = store.hosts().classify("b.example");

    store
        .insert(b, "global-victim", vec![7u8; 4], TTL)
        .expect("room");
    // Inside the entry cap on purpose: what this drives is A's traffic, not A's saturation,
    // and `bounds.rs` owns the other question.
    for round in 0..50 {
        store
            .insert(a, &format!("global-{round}"), vec![0u8; 4], TTL)
            .expect("room");
    }

    assert_eq!(
        store.get(b, "global-victim").expect("present"),
        vec![7u8; 4]
    );
    assert_eq!(store.entries(b), 1);
    assert!(Arc::strong_count(&store) >= 1);
}

#[test]
fn two_handles_on_one_store_see_the_same_domain_keys() {
    // Domain keys are values, not references into a particular store instance, so a key
    // classified through one handle works on another built from the same host set. Without
    // that, a config rebuild would invalidate every outstanding key.
    let first: ScopedStore<u8, ManualClock> =
        ScopedStore::with_clock(hosts(), limits(), ManualClock::at(1_000));
    let second =
        ScopedStore::with_clock(hosts(), limits(), ManualClock::at(1_000));
    let key: Domain = first.hosts().classify("a.example");

    second.insert(key, "client", 1u8, TTL).expect("room");
    assert_eq!(second.get(key, "client"), Some(1));
    assert_eq!(
        key,
        first.hosts().classify("A.EXAMPLE"),
        "host matching is case-sensitive"
    );
}

#[test]
fn a_store_is_send_and_sync_so_it_can_be_shared_across_workers() {
    // Load-bearing for process-global ownership: every `Plugin` method takes `&self` and the
    // server runs many workers, so a container that is not `Sync` cannot be shared and the
    // design falls back to per-instance state, which a config rebuild destroys.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ScopedStore<Vec<u8>>>();
    assert_send_sync::<ScopedStore<String, ManualClock>>();
    assert_send_sync::<HostPolicy>();
    assert_send_sync::<Domain>();
}
