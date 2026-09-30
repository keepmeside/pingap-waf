//! Every map the container holds is bounded, and the bound an attacker can reach is not the
//! bound that locks honest clients out.
//!
//! The domain key derives from a `Host` header, which is client-supplied, and a Location with
//! no host restriction matches every value of it. So a naive cap on distinct domains is worse
//! than no cap: a flood of generated hosts consumes it, after which every genuinely new client
//! on every real domain is refused a state entry. That converts a memory-exhaustion vector into
//! an authentication-bypass vector. Host collapsing is what stops it, and these tests are the
//! reason it is a mechanism rather than a comment.

use pingap_domainstate::{Full, HostPolicy, Limits, ManualClock, ScopedStore};
use std::time::Duration;

/// Long enough that nothing here expires. Expiry has its own file.
const TTL: Duration = Duration::from_secs(3600);

fn store(
    max_domains: usize,
    max_entries: usize,
    hosts: &[&str],
) -> ScopedStore<u32, ManualClock> {
    ScopedStore::with_clock(
        HostPolicy::new(hosts.iter().copied()),
        Limits {
            max_domains,
            max_entries_per_domain: max_entries,
        },
        ManualClock::at(1_000),
    )
}

/// A host no operator configured. Generated rather than fixed, because a fixed one would let
/// an implementation pass by special-casing it.
fn unregistered(round: u32) -> String {
    format!("generated-{round:08x}.invalid")
}

#[test]
fn a_flood_of_distinct_unregistered_hosts_consumes_one_bucket_and_no_domain_slot()
 {
    let store = store(4, 100, &["a.example"]);
    let registered = store.hosts().classify("a.example");

    for round in 0..500 {
        let domain = store.hosts().classify(&unregistered(round));
        assert!(domain.is_overflow(), "an unconfigured host must collapse");
        // Every one of them gets the same identity string, so they contend for the one
        // bucket rather than each being able to claim a fresh one.
        let _ = store.insert(domain, "same-client", round, TTL);
    }

    assert_eq!(
        store.domains_live(),
        0,
        "unregistered hosts allocated domain slots, so the cap is attacker-reachable"
    );
    assert_eq!(
        store.total_entries(),
        1,
        "the flood grew the store; one shared bucket means one entry under one identity"
    );
    assert_eq!(store.entries(registered), 0);
}

#[test]
fn a_flood_of_unregistered_hosts_under_distinct_identities_still_stays_bounded()
{
    // The shape that actually grows the map: a distinct identity per request, as a scanner
    // rotating source addresses presents. The bucket must stop at its cap and report it.
    let store = store(4, 100, &["a.example"]);

    let mut refused = 0;
    for round in 0..1_000 {
        let domain = store.hosts().classify(&unregistered(round));
        if store
            .insert(domain, &format!("client-{round}"), round, TTL)
            .is_err()
        {
            refused += 1;
        }
    }

    assert_eq!(
        store.total_entries(),
        100,
        "the overflow bucket is unbounded"
    );
    assert_eq!(refused, 900, "saturation was not reported to the caller");
    assert_eq!(store.counters().entry_saturation, 900);
    assert_eq!(
        store.counters().domain_saturation,
        0,
        "unregistered hosts reached the domain cap, which is the bypass this exists to stop"
    );
    assert!(
        store.counters().overflow_ops > 0,
        "use of the overflow bucket is invisible, so a host-less Location looks like a working one"
    );

    // And a real domain is still usable afterwards, which is the whole point.
    let registered = store.hosts().classify("a.example");
    store
        .insert(registered, "honest-client", 1, TTL)
        .expect("room");
}

#[test]
fn the_domain_cap_is_reached_only_by_hosts_the_operator_configured() {
    let store =
        store(2, 16, &["a.example", "b.example", "c.example", "d.example"]);

    for host in ["a.example", "b.example"] {
        let domain = store.hosts().classify(host);
        store
            .insert(domain, "client", 1, TTL)
            .expect("within the cap");
    }
    assert_eq!(store.domains_live(), 2);

    // The third configured host has nowhere to go. This is a configuration fault — the host
    // list is larger than the domain cap the operator set — not something traffic can cause.
    let over = store.hosts().classify("c.example");
    assert_eq!(store.insert(over, "client", 1, TTL), Err(Full::Domains));
    assert_eq!(store.counters().domain_saturation, 1);

    // A domain already admitted keeps working, so the fault does not take the node down.
    let admitted = store.hosts().classify("a.example");
    store
        .insert(admitted, "another", 2, TTL)
        .expect("already admitted");
}

#[test]
fn the_entry_cap_reports_saturation_rather_than_displacing_a_live_entry() {
    let store = store(4, 3, &["a.example"]);
    let domain = store.hosts().classify("a.example");

    for id in ["first", "second", "third"] {
        store.insert(domain, id, 1, TTL).expect("within the cap");
    }

    // Admitting a fourth by evicting a live entry would let an attacker flush honest clients'
    // state on demand, and would hide saturation from the caller, whose fallback exists
    // precisely for this moment. So: refuse, and leave the incumbents alone.
    assert_eq!(store.insert(domain, "fourth", 1, TTL), Err(Full::Entries));
    for id in ["first", "second", "third"] {
        assert!(
            store.contains(domain, id),
            "`{id}` was displaced by a newer identity"
        );
    }
    assert_eq!(store.counters().entry_saturation, 1);
}

#[test]
fn refreshing_an_identity_that_already_has_an_entry_needs_no_room() {
    let store = store(4, 2, &["a.example"]);
    let domain = store.hosts().classify("a.example");
    store.insert(domain, "first", 1, TTL).expect("room");
    store.insert(domain, "second", 2, TTL).expect("room");

    // The bucket is at its cap, but this is not a new identity: it takes no additional slot,
    // so refusing it would freeze every existing client's state at whatever it first held.
    store
        .insert(domain, "first", 99, TTL)
        .expect("a refresh is not an admission");
    assert_eq!(store.get(domain, "first"), Some(99));
    assert_eq!(store.total_entries(), 2);
    assert_eq!(store.counters().entry_saturation, 0);
}

#[test]
fn an_entry_cap_of_zero_disables_state_instead_of_growing_unbounded() {
    let store = store(4, 0, &["a.example"]);
    let domain = store.hosts().classify("a.example");

    for round in 0..50 {
        assert_eq!(
            store.insert(domain, &format!("id-{round}"), round, TTL),
            Err(Full::Entries)
        );
    }
    assert_eq!(store.total_entries(), 0);
}

#[test]
fn the_distinct_identity_count_is_observable() {
    // The detector for a false peer-address assertion. Behind a proxy that was wrongly
    // declared directly-exposed, every client resolves to the proxy's one address and this
    // reads 1 no matter how much traffic arrives — a number on a dashboard rather than an
    // incident to reconstruct afterwards.
    let store = store(4, 64, &["a.example"]);
    let domain = store.hosts().classify("a.example");
    for round in 0..20 {
        store
            .insert(domain, &format!("client-{round}"), round, TTL)
            .expect("room");
    }

    assert_eq!(store.entries(domain), 20);
    assert_eq!(store.total_entries(), 20);

    // And one client sending twenty requests is visibly one identity.
    let other = store.hosts().classify("b.example");
    for round in 0..20 {
        store
            .insert(other, "only-client", round, TTL)
            .expect("room");
    }
    assert_eq!(store.entries(other), 1);
}

#[test]
fn host_matching_normalises_case_and_port() {
    let policy =
        HostPolicy::new(["A.Example", "b.example:8443", "[2001:db8::1]"]);

    // `get_host` strips a port from the `Host` header but returns a URI host verbatim, and
    // DNS names are case-insensitive, so two spellings of one host must be one key. Two keys
    // would mean a token solved under one is unrecognised under the other.
    let canonical = policy.classify("a.example");
    assert_eq!(policy.classify("A.EXAMPLE"), canonical);
    assert_eq!(policy.classify("a.example:443"), canonical);
    assert!(!canonical.is_overflow());

    assert!(
        !policy.classify("b.example").is_overflow(),
        "the port must not become part of the name"
    );
    assert!(!policy.classify("[2001:db8::1]:8080").is_overflow());

    assert!(policy.classify("c.example").is_overflow());
    assert_eq!(policy.registered(), 3);
}

#[test]
fn an_empty_host_set_collapses_everything_and_is_visible_as_such() {
    // A Location with no host restriction matches every `Host`, so an operator who configures
    // no hosts gets no per-domain state. That is a configuration they chose; what matters is
    // that it is discoverable rather than looking like a control that quietly never fires.
    let store = store(4, 16, &[]);
    assert_eq!(store.hosts().registered(), 0);

    for round in 0..10 {
        let domain = store.hosts().classify(&unregistered(round));
        assert!(domain.is_overflow());
        store.insert(domain, "client", round, TTL).expect("room");
    }

    assert_eq!(store.domains_live(), 0);
    assert_eq!(store.total_entries(), 1);
    assert!(store.counters().overflow_ops > 0);
}

#[test]
fn a_domain_gives_its_slot_back_once_nothing_live_is_left_in_it() {
    // Admission is lazy and bounded, so a slot held by an empty bucket is a slot a live tenant
    // cannot have. Without this a long tail of short-lived hosts exhausts the domain cap with
    // empty maps, and every later host is refused with what looks like a configuration fault
    // but is really exhaustion by traffic.
    let clock = ManualClock::at(1_000);
    let names: Vec<String> =
        (0..4).map(|round| format!("h{round}.example")).collect();
    let store: ScopedStore<u8, ManualClock> = ScopedStore::with_clock(
        HostPolicy::new(names.iter().map(String::as_str)),
        Limits {
            max_domains: 2,
            max_entries_per_domain: 8,
        },
        clock.clone(),
    );

    let first = store.hosts().classify(&names[0]);
    let second = store.hosts().classify(&names[1]);
    let third = store.hosts().classify(&names[2]);
    store.insert(first, "client", 1, TTL).expect("room");
    store.insert(second, "client", 1, TTL).expect("room");
    assert_eq!(store.domains_live(), 2);
    assert_eq!(store.insert(third, "client", 1, TTL), Err(Full::Domains));

    // Removing the last entry gives the slot back, so the third host is admitted after all.
    store.remove(first, "client");
    assert_eq!(
        store.domains_live(),
        1,
        "an emptied bucket still held a slot"
    );
    store
        .insert(third, "client", 1, TTL)
        .expect("the slot came back");

    // Expiry empties a bucket too, and the next access is what notices.
    clock.advance(TTL);
    assert_eq!(store.entries(second), 0);
    assert_eq!(
        store.domains_live(),
        1,
        "the expired domain still held a slot"
    );

    // The scanning read notices every domain at once rather than waiting for each in turn.
    assert_eq!(store.total_entries(), 0);
    assert_eq!(store.domains_live(), 0);
}

#[test]
fn a_duplicate_host_in_the_configured_set_occupies_one_slot() {
    let policy = HostPolicy::new([
        "a.example",
        "A.EXAMPLE",
        "a.example:443",
        "b.example",
    ]);
    assert_eq!(
        policy.registered(),
        2,
        "one host listed three ways took three slots"
    );
    assert_eq!(
        policy.classify("a.example"),
        policy.classify("A.EXAMPLE:8080")
    );
}

#[test]
fn the_domain_cap_counts_admitted_domains_not_configured_ones() {
    // Admission is lazy, so configuring a thousand hosts and serving two does not consume a
    // thousand slots. A store sized by the configured set would make the cap a function of how
    // verbose the config file is rather than of live memory.
    let hosts: Vec<String> = (0..1_000)
        .map(|round| format!("h{round}.example"))
        .collect();
    let store =
        store(4, 16, &hosts.iter().map(String::as_str).collect::<Vec<_>>());

    for (round, host) in hosts.iter().enumerate().take(4) {
        let domain = store.hosts().classify(host);
        store
            .insert(domain, "client", round as u32, TTL)
            .expect("within the cap");
    }
    assert_eq!(store.domains_live(), 4);
    assert_eq!(
        store.insert(store.hosts().classify(&hosts[9]), "client", 1, TTL),
        Err(Full::Domains)
    );
}

#[test]
fn a_stale_earliest_bound_costs_a_scan_and_never_a_missed_reclaim() {
    // A saturated write skips the reclaim scan when the bucket's earliest deadline is still
    // ahead. Skipping it when something *has* expired would wedge the domain permanently:
    // every later write refuses and nothing ever frees a slot. So the bound has to be
    // one-sided — cheap when nothing can have expired, correct when something has — and the
    // only way it can be wrong is by pointing at an entry that has since been removed.
    let clock = ManualClock::at(1_000);
    let store: ScopedStore<u8, ManualClock> = ScopedStore::with_clock(
        HostPolicy::new(["a.example"]),
        Limits {
            max_domains: 4,
            max_entries_per_domain: 2,
        },
        clock.clone(),
    );
    let domain = store.hosts().classify("a.example");

    // Removing `short` leaves the bound pointing at a deadline nothing in the bucket has.
    store
        .insert(domain, "short", 1, Duration::from_secs(10))
        .expect("room");
    store
        .insert(domain, "long", 2, Duration::from_secs(10_000))
        .expect("room");
    assert_eq!(store.remove(domain, "short"), Some(1));
    store
        .insert(domain, "mid", 3, Duration::from_secs(100))
        .expect("room");
    assert_eq!(store.entries(domain), 2);

    // At the cap with nothing expired. The stale bound says a deadline has passed, so the scan
    // runs and finds nothing — wasted work, and the safe kind. What must not happen is a live
    // entry being reclaimed to make room.
    clock.advance(Duration::from_secs(50));
    assert_eq!(
        store.insert(domain, "new", 4, Duration::from_secs(10)),
        Err(Full::Entries)
    );
    assert!(store.contains(domain, "long"), "a live entry was displaced");
    assert!(store.contains(domain, "mid"), "a live entry was displaced");

    // Once `mid` genuinely expires, the same path reclaims it and admits the write.
    clock.advance(Duration::from_secs(60));
    store
        .insert(domain, "newer", 5, Duration::from_secs(10))
        .expect("`mid` expired, so there is room");
    assert_eq!(store.get(domain, "mid"), None);
    assert_eq!(store.get(domain, "newer"), Some(5));
    assert_eq!(store.get(domain, "long"), Some(2));
}

#[test]
fn a_short_ttl_inserted_before_a_long_one_is_still_reclaimed_at_the_cap() {
    // The reclaim guard reads a lower bound on the bucket's earliest deadline. Were that bound
    // to track the most recent insert instead of the minimum, a bucket holding one short-lived
    // and one long-lived entry would report the long deadline, skip the scan, and refuse every
    // later write even though a slot was free — permanently, since nothing else reclaims.
    // Mixed TTLs are the normal case rather than an edge: a solved token lives for minutes
    // while an escalation record lives for hours.
    let clock = ManualClock::at(1_000);
    let store: ScopedStore<u8, ManualClock> = ScopedStore::with_clock(
        HostPolicy::new(["a.example"]),
        Limits {
            max_domains: 4,
            max_entries_per_domain: 2,
        },
        clock.clone(),
    );
    let domain = store.hosts().classify("a.example");

    store
        .insert(domain, "short", 1, Duration::from_secs(10))
        .expect("room");
    store
        .insert(domain, "long", 2, Duration::from_secs(10_000))
        .expect("room");

    clock.advance(Duration::from_secs(20));
    store
        .insert(domain, "newer", 3, Duration::from_secs(10))
        .expect("the expired short entry must free a slot");
    assert_eq!(store.get(domain, "short"), None);
    assert_eq!(
        store.get(domain, "long"),
        Some(2),
        "a live entry was displaced"
    );
    assert_eq!(store.get(domain, "newer"), Some(3));
}
