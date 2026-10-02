//! The registered-host classification every stateful subsystem resolves a request's
//! `Host` through.
//!
//! [`HostPolicy`] is the policy object — one instance per store, built from the hosts
//! configuration names. This module is the process-global instance of it, because the
//! registered set is a property of the *configuration the process is running*, not of
//! any one subsystem: two consumers keying the same host must resolve it to the same
//! label, or state written by one is invisible to the other.
//!
//! The set is derived from the hosts a `Location` names in its `host` restriction, so
//! it is re-derived at boot and on every config apply by the same code path that
//! rebuilds locations. A `Location` with no host restriction matches every host by
//! design, and its traffic is exactly the traffic that lands in the overflow bucket:
//! no per-domain state is available for it, which is the trade Phase 2 recorded, and
//! the overflow counter is what makes the trade visible rather than silent.
//!
//! **Label cardinality is a security property.** `get_host` reads a client-supplied
//! header, so an unbounded label is an attacker-shaped one: a flood of generated
//! `Host` values could mint a map entry — or a metric label — per request. A request
//! whose host is not registered resolves to the one shared [`OVERFLOW_LABEL`] instead,
//! so unregistered traffic costs one bucket, never N slots, and never appears in a
//! label.

use crate::store::{Domain, HostPolicy};
use std::sync::{LazyLock, RwLock};

/// The one label every unregistered host resolves to.
pub const OVERFLOW_LABEL: &str = "<unregistered-host>";

static REGISTERED: LazyLock<RwLock<HostPolicy>> =
    LazyLock::new(|| RwLock::new(HostPolicy::new::<[&str; 0], &str>([])));

/// Replace the registered set. Called when locations are (re)initialised, so the
/// classification follows the config the process is running rather than the one it
/// started with.
pub fn set_registered_hosts<I, S>(hosts: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let policy = HostPolicy::new(hosts);
    let mut guard = REGISTERED
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = policy;
}

/// How many distinct hosts are registered. Zero until the first location
/// initialisation, which is also the honest answer for a config that names no host
/// restrictions: everything is overflow.
pub fn registered_hosts() -> usize {
    REGISTERED
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .registered()
}

/// Resolve a request's host to a [`Domain`] key against the registered set.
///
/// An empty registered set classifies every host to overflow, which is the Phase 2
/// trade for hostless locations applied to the whole config — not a failure state.
pub fn classify(host: &str) -> Domain {
    REGISTERED
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .classify(host)
}

/// The label a host's state and counters are keyed and published under: the
/// registered host's canonical spelling, or [`OVERFLOW_LABEL`] for everything else.
///
/// The registered name is copied out rather than borrowed because the policy it lives
/// in is replaced on every config apply — a borrowed slice would dangle across a
/// reload for any reader that outlived the guard, which is every reader on a request
/// path that holds the label past this call.
pub fn label(host: &str) -> String {
    let guard = REGISTERED
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.name(guard.classify(host)).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the tests: both rewrite the process-global policy, and a reader
    /// running concurrently with a writer could classify against the other test's
    /// set. The same shape as `tests/common`'s `trusted_proxy_lock`.
    static HOSTS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn with_no_registered_hosts_every_host_lands_in_one_bucket() {
        let _guard = HOSTS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        set_registered_hosts::<[&str; 0], &str>([]);
        assert_eq!(label("a.test"), OVERFLOW_LABEL);
        assert_eq!(label("B.TEST:8443"), OVERFLOW_LABEL);
        assert_eq!(registered_hosts(), 0);
    }

    #[test]
    fn a_registered_host_resolves_to_its_canonical_name() {
        let _guard = HOSTS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        set_registered_hosts(["A.test", "b.test:443"]);
        assert_eq!(registered_hosts(), 2);
        assert_eq!(label("a.test"), "a.test");
        // Port stripped, case folded: one spelling, one key.
        assert_eq!(label("B.TEST:8443"), "b.test");
        // An unregistered host stays in the shared bucket, and does not mint a label.
        assert_eq!(label("c.test"), OVERFLOW_LABEL);
        // Leave the policy empty for any test that runs after this one.
        set_registered_hosts::<[&str; 0], &str>([]);
    }
}
