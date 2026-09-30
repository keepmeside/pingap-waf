//! The keyed container: bounds, expiry and eviction.
//!
//! Synchronisation is a `Mutex`, not a lock-free map. The container is read *and* written
//! per request under a key, so a `Mutex` is the simplest correct thing, and it is what makes
//! a take-once operation atomic: two concurrent presentations of the same entry produce
//! exactly one success, which a compare-and-swap loop over a whole entry would not. Sharding
//! is a local change to one type if measurement ever shows contention — the per-operation
//! cost is in `benches/store.rs` so that question can be answered with a number.

use std::collections::HashMap;
// Aliased: this module has its own `Entry`, the stored value and its deadline.
use std::collections::hash_map::Entry as MapEntry;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// Milliseconds since the Unix epoch, as [`pingap_core::now_ms`] reports.
pub type Millis = u64;

/// The slot every unregistered host shares.
const OVERFLOW: u32 = u32::MAX;

/// The label [`HostPolicy::name`] returns for the shared bucket, so a log line or a metric
/// can say what happened rather than printing a sentinel integer.
const OVERFLOW_NAME: &str = "<unregistered-host>";

/// Which bound a write hit.
///
/// Two variants because the two conditions have different causes and need different
/// responses; see the crate documentation. A consumer that matches them together has
/// collapsed a configuration fault into a traffic condition and will handle both wrongly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Full {
    /// Too many distinct registered domains are live at once.
    ///
    /// Reachable only when the configured host list is longer than `max_domains`, which is a
    /// configuration fault. An unregistered host cannot cause it, because unregistered hosts
    /// never allocate a slot. **Fail toward the configured policy**; never admit.
    Domains,
    /// Too many live entries within one domain.
    ///
    /// Reachable by traffic, and reported rather than papered over by displacing a live
    /// entry: displacement would let an attacker flush honest clients' state on demand, and
    /// would hide the saturation from a caller that has a cheaper fallback. **The caller
    /// decides.**
    Entries,
}

/// An opaque domain key.
///
/// Not `Default`, and not constructible from outside this module, so a call site that forgets
/// the domain argument does not compile and a consumer cannot invent a key that bypasses host
/// collapsing. The only way to obtain one is [`HostPolicy::classify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Domain {
    slot: u32,
}

impl Domain {
    /// Whether this is the bucket every unregistered host shares.
    ///
    /// A consumer should treat a `true` here as "no per-domain state is available for this
    /// request", not as a domain of its own: the bucket is shared by every host the operator
    /// did not configure, so nothing stored under it can be attributed.
    #[inline]
    pub fn is_overflow(&self) -> bool {
        self.slot == OVERFLOW
    }
}

/// The hosts this node serves, and the single bucket everything else collapses into.
///
/// Built once, from configuration, and immutable afterwards — which is what makes
/// [`Domain`] cheap to hand around and safe to share. The set of legitimate domain keys is
/// the set of hosts the server is configured to serve, and that set is knowable at config
/// load; a request whose host is not in it gets no slot of its own.
#[derive(Debug, Clone, Default)]
pub struct HostPolicy {
    names: Vec<Box<str>>,
    index: HashMap<Box<str>, u32>,
}

impl HostPolicy {
    /// Builds the registered set from configuration.
    ///
    /// Names are normalised and duplicates dropped, so one host listed three ways — upper
    /// case, lower case, with a port — occupies one slot. Two spellings of one host as two
    /// keys would mean state written under one is unrecognised under the other.
    pub fn new<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut names = Vec::new();
        let mut index = HashMap::new();
        for host in hosts {
            let key: Box<str> = normalise(host.as_ref()).into_boxed_str();
            if key.is_empty() || index.contains_key(&key) {
                continue;
            }
            let slot = names.len() as u32;
            names.push(key.clone());
            index.insert(key, slot);
        }
        Self { names, index }
    }

    /// Resolves a request's host to a key.
    ///
    /// An unregistered host collapses into one shared bucket rather than allocating a slot,
    /// so a flood of generated `Host` values cannot consume the domain cap and lock out every
    /// real domain. The raw lookup is tried first: a configured host in its canonical spelling
    /// is the common case and needs no allocation.
    pub fn classify(&self, host: &str) -> Domain {
        let slot = self
            .index
            .get(host)
            .or_else(|| self.index.get(&*normalise(host)))
            .copied()
            .unwrap_or(OVERFLOW);
        Domain { slot }
    }

    /// How many distinct hosts are registered.
    pub fn registered(&self) -> usize {
        self.names.len()
    }

    /// The host a key names, for log lines and metric labels.
    ///
    /// The overflow bucket has no name to give, and gets a fixed label instead — which also
    /// keeps an attacker-supplied `Host` value out of a label, where it would be unbounded
    /// cardinality.
    pub fn name(&self, domain: Domain) -> &str {
        if domain.is_overflow() {
            return OVERFLOW_NAME;
        }
        self.names
            .get(domain.slot as usize)
            .map(Box::as_ref)
            .unwrap_or(OVERFLOW_NAME)
    }
}

/// Lowercases a host and strips a port.
///
/// DNS names are case-insensitive and the resolver this pairs with returns a URI host without
/// a port but a `Host` header with one, so both spellings have to land on the same key. An
/// IPv6 literal is cut at its closing bracket, because splitting that on the first colon would
/// truncate the address itself.
fn normalise(host: &str) -> String {
    let trimmed = host.trim();
    let without_port = match trimmed.rfind(']') {
        Some(end) => &trimmed[..end + 1],
        None => trimmed.split(':').next().unwrap_or(trimmed),
    };
    without_port.to_ascii_lowercase()
}

/// Bounds on the two maps.
///
/// Both are required. A cap on entries alone lets a flood of hosts allocate unbounded
/// buckets; a cap on domains alone lets one domain fill memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// How many distinct registered domains may hold live state at once.
    ///
    /// Domains are admitted lazily and their bucket is dropped once it empties, so this
    /// bounds live memory rather than the length of the configured host list. Exceeding it
    /// reports [`Full::Domains`], a configuration fault.
    pub max_domains: usize,
    /// How many live entries one domain may hold.
    ///
    /// Exceeding it reports [`Full::Entries`], which is reachable by traffic and is therefore
    /// the caller's decision. Zero disables state for that domain: every admission is refused
    /// and nothing grows.
    pub max_entries_per_domain: usize,
}

impl Default for Limits {
    /// 256 domains and 5000 entries each.
    ///
    /// The domain figure is generous for a multi-tenant node while keeping the live map small.
    /// The entry figure is the one the per-client memory arithmetic elsewhere in this plan is
    /// written against, and it is what makes the "no traffic, no reclaim" residual survivable:
    /// a quiet tenant's worst case is its cap, not its history.
    fn default() -> Self {
        Self {
            max_domains: 256,
            max_entries_per_domain: 5000,
        }
    }
}

/// Where the container reads the time.
///
/// A parameter rather than a call to the system clock, so expiry is testable without sleeping.
pub trait Clock: Send + Sync {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> Millis;
}

/// Reads the system clock on every call.
///
/// That is what [`pingap_core::now_ms`] does, and what this fork settled on after a
/// background-updated coarse clock proved unsafe: it needed a thread, and pingora's `fork()`
/// carries only the calling thread, so a thread started before it does not exist in the
/// daemon. Delegating rather than re-reading `SystemTime` here keeps one clock in the tree.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    #[inline]
    fn now_ms(&self) -> Millis {
        pingap_core::now_ms()
    }
}

/// A clock a test advances by hand.
///
/// In the crate rather than in each test file because every expiry test here and in the
/// subsystems above this one needs the same thing, and a divergent copy is how an expiry test
/// starts sleeping. Cloning shares one reading, so a handle held by the test moves the clock
/// the container sees.
#[derive(Debug, Clone, Default)]
pub struct ManualClock {
    now: std::sync::Arc<AtomicU64>,
}

impl ManualClock {
    /// A clock starting at `ms`.
    pub fn at(ms: Millis) -> Self {
        Self {
            now: std::sync::Arc::new(AtomicU64::new(ms)),
        }
    }

    /// Moves the clock forward.
    pub fn advance(&self, by: Duration) {
        let delta = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        self.now.fetch_add(delta, Ordering::Relaxed);
    }

    /// Sets the clock outright. Moving it backwards is legal, and is how a test proves an
    /// entry is judged by its own deadline rather than by monotonic order of arrival.
    pub fn set(&self, ms: Millis) {
        self.now.store(ms, Ordering::Relaxed);
    }
}

impl Clock for ManualClock {
    #[inline]
    fn now_ms(&self) -> Millis {
        self.now.load(Ordering::Relaxed)
    }
}

/// Published counts, as a copyable snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    /// Operations that resolved to the shared unregistered-host bucket.
    ///
    /// The signal that a deployment is getting no per-domain state. A Location with no host
    /// restriction matches every `Host`, so without this counter that configuration is
    /// indistinguishable from a control that works.
    pub overflow_ops: u64,
    /// Writes refused with [`Full::Domains`], the configuration fault.
    pub domain_saturation: u64,
    /// Writes refused with [`Full::Entries`], the traffic condition.
    pub entry_saturation: u64,
    /// Entries dropped because their TTL had passed. Counts entries, not operations.
    pub expired_reclaimed: u64,
}

#[derive(Debug)]
struct Entry<V> {
    value: V,
    expires_at: Millis,
}

struct Bucket<V> {
    entries: HashMap<Box<str>, Entry<V>>,
    /// A lower bound on the earliest deadline among `entries`.
    ///
    /// Maintained as a running minimum on insert and recomputed after a reclaim. It can go
    /// stale in one direction only — pointing at an entry that has since been removed — which
    /// costs a scan that finds nothing and can never skip a scan that would have reclaimed.
    /// That one-sidedness is what makes it safe to guard the reclaim with, and guarding
    /// matters: a refused write is the one path an attacker can drive at will, and without the
    /// guard every one of them costs a full bucket scan — ~10 µs at the default cap.
    earliest: Option<Millis>,
}

/// Hand-written rather than derived: `#[derive(Default)]` would add a `V: Default` bound, and
/// an empty bucket needs nothing from its payload type. Requiring it would rule out storing a
/// payload that has no sensible default, which is most of them.
impl<V> Default for Bucket<V> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            earliest: None,
        }
    }
}

struct Inner<V> {
    /// Admitted registered domains, by slot. Bounded by `max_domains`.
    domains: HashMap<u32, Bucket<V>>,
    /// The one bucket every unregistered host shares. Always present, never a slot.
    overflow: Bucket<V>,
}

impl<V> Default for Inner<V> {
    fn default() -> Self {
        Self {
            domains: HashMap::new(),
            overflow: Bucket::default(),
        }
    }
}

#[derive(Default)]
struct CounterCell {
    overflow_ops: AtomicU64,
    domain_saturation: AtomicU64,
    entry_saturation: AtomicU64,
    expired_reclaimed: AtomicU64,
}

impl CounterCell {
    #[inline]
    fn bump(&self, counter: &AtomicU64, by: u64) {
        if by > 0 {
            counter.fetch_add(by, Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> Counters {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        Counters {
            overflow_ops: read(&self.overflow_ops),
            domain_saturation: read(&self.domain_saturation),
            entry_saturation: read(&self.entry_saturation),
            expired_reclaimed: read(&self.expired_reclaimed),
        }
    }
}

/// A bounded, domain-keyed, expiring container.
///
/// `Send + Sync` when `V: Send`, which is what lets one instance be shared across workers and
/// outlive the plugin instances that reach it.
pub struct ScopedStore<V, C: Clock = SystemClock> {
    hosts: HostPolicy,
    limits: Limits,
    counters: CounterCell,
    inner: Mutex<Inner<V>>,
    clock: C,
}

impl<V> ScopedStore<V, SystemClock> {
    /// A store reading the system clock.
    pub fn new(hosts: HostPolicy, limits: Limits) -> Self {
        Self::with_clock(hosts, limits, SystemClock)
    }
}

impl<V, C: Clock> ScopedStore<V, C> {
    /// A store reading `clock`, which is how a test controls expiry.
    pub fn with_clock(hosts: HostPolicy, limits: Limits, clock: C) -> Self {
        Self {
            hosts,
            limits,
            counters: CounterCell::default(),
            inner: Mutex::new(Inner::default()),
            clock,
        }
    }

    /// The registered-host set this store classifies against.
    pub fn hosts(&self) -> &HostPolicy {
        &self.hosts
    }

    /// Stores `value` under `(domain, identity)` for `ttl`.
    ///
    /// An identity that already has a live entry is refreshed, which needs no room and so is
    /// never refused at the cap — freezing existing clients at their first value would be
    /// worse than the saturation it avoided. A *new* identity at the cap reclaims expired
    /// entries and, if that is not enough, reports [`Full::Entries`] rather than displacing a
    /// live one.
    pub fn insert(
        &self,
        domain: Domain,
        identity: &str,
        value: V,
        ttl: Duration,
    ) -> Result<(), Full> {
        self.note_overflow(domain);
        let now = self.clock.now_ms();
        let expires_at = now.saturating_add(duration_ms(ttl));
        let key: Box<str> = identity.into();

        let mut inner = self.lock();
        let bucket = self.admit(&mut inner, domain)?;

        // Taking any previous entry out first does two jobs: a refresh then needs no room and
        // is never refused at the cap, and an expired entry under this identity is dropped
        // rather than left to occupy the bound. Two hash lookups either way, same as testing
        // for the key and then inserting it.
        let refreshing = bucket.entries.remove(&key).is_some();
        if !refreshing
            && bucket.entries.len() >= self.limits.max_entries_per_domain
        {
            // Skip the scan when nothing in the bucket can have expired yet.
            if bucket.earliest.is_none_or(|earliest| earliest <= now) {
                let reclaimed = reclaim(&mut bucket.entries, now);
                bucket.earliest = min_expiry(&bucket.entries);
                self.counters
                    .bump(&self.counters.expired_reclaimed, reclaimed as u64);
            }
            if bucket.entries.len() >= self.limits.max_entries_per_domain {
                self.counters.bump(&self.counters.entry_saturation, 1);
                return Err(Full::Entries);
            }
        }
        // A running minimum, never a recomputation. Removing the entry that held the old
        // minimum leaves the bound too low, which is the safe direction.
        bucket.earliest = Some(
            bucket
                .earliest
                .map_or(expires_at, |earliest| earliest.min(expires_at)),
        );
        bucket.entries.insert(key, Entry { value, expires_at });
        Ok(())
    }

    /// Reads the entry, cloning the payload.
    pub fn get(&self, domain: Domain, identity: &str) -> Option<V>
    where
        V: Clone,
    {
        self.with(domain, identity, V::clone)
    }

    /// Reads the entry without cloning it.
    ///
    /// An expired entry is reclaimed here and reported as absent, so there is no path through
    /// which a TTL is advisory. A key that was never present returns early without scanning
    /// the bucket: reclaim exists to free room, and a miss needs none, so paying an O(n) pass
    /// for one would put a bucket scan on the hot path of every new client.
    pub fn with<R>(
        &self,
        domain: Domain,
        identity: &str,
        read: impl FnOnce(&V) -> R,
    ) -> Option<R> {
        self.note_overflow(domain);
        let now = self.clock.now_ms();
        let mut inner = self.lock();
        let bucket = self.peek(&mut inner, domain)?;
        // Decided before the payload is touched, so the map borrow ends here and the reclaim
        // below can take it mutably.
        let expired = bucket
            .entries
            .get(identity)
            .is_some_and(|entry| entry.expires_at <= now);
        let found = bucket
            .entries
            .get(identity)
            .filter(|entry| entry.expires_at > now)
            .map(|entry| read(&entry.value));
        if expired {
            let reclaimed = reclaim(&mut bucket.entries, now);
            bucket.earliest = min_expiry(&bucket.entries);
            self.counters
                .bump(&self.counters.expired_reclaimed, reclaimed as u64);
            Self::drop_if_empty(&mut inner, domain);
        }
        found
    }

    /// Mutates the entry in place, under the same lock that guards admission.
    pub fn update<R>(
        &self,
        domain: Domain,
        identity: &str,
        change: impl FnOnce(&mut V) -> R,
    ) -> Option<R> {
        self.note_overflow(domain);
        let now = self.clock.now_ms();
        let mut inner = self.lock();
        let bucket = self.peek(&mut inner, domain)?;
        let expired = bucket
            .entries
            .get(identity)
            .is_some_and(|entry| entry.expires_at <= now);
        let found = bucket
            .entries
            .get_mut(identity)
            .filter(|entry| entry.expires_at > now)
            .map(|entry| change(&mut entry.value));
        if expired {
            let reclaimed = reclaim(&mut bucket.entries, now);
            bucket.earliest = min_expiry(&bucket.entries);
            self.counters
                .bump(&self.counters.expired_reclaimed, reclaimed as u64);
            Self::drop_if_empty(&mut inner, domain);
        }
        found
    }

    /// Removes the entry and returns its payload, at most once.
    ///
    /// The take-once primitive: the removal and the read happen under one lock hold, so two
    /// concurrent presentations of the same entry produce exactly one `Some`. An expired entry
    /// returns `None` rather than its value — reclaim must not double as a read path, or a
    /// spent credential could be replayed.
    pub fn remove(&self, domain: Domain, identity: &str) -> Option<V> {
        self.note_overflow(domain);
        let now = self.clock.now_ms();
        let mut inner = self.lock();
        let bucket = self.peek(&mut inner, domain)?;
        let taken = match bucket.entries.remove(identity) {
            Some(entry) if entry.expires_at > now => Some(entry.value),
            Some(_) => {
                self.counters.bump(&self.counters.expired_reclaimed, 1);
                None
            },
            None => None,
        };
        Self::drop_if_empty(&mut inner, domain);
        taken
    }

    /// Whether a live entry exists.
    pub fn contains(&self, domain: Domain, identity: &str) -> bool {
        self.note_overflow(domain);
        let now = self.clock.now_ms();
        let mut inner = self.lock();
        let Some(bucket) = self.peek(&mut inner, domain) else {
            return false;
        };
        let expired = bucket
            .entries
            .get(identity)
            .is_some_and(|entry| entry.expires_at <= now);
        let live = bucket
            .entries
            .get(identity)
            .is_some_and(|entry| entry.expires_at > now);
        if expired {
            let reclaimed = reclaim(&mut bucket.entries, now);
            bucket.earliest = min_expiry(&bucket.entries);
            self.counters
                .bump(&self.counters.expired_reclaimed, reclaimed as u64);
            Self::drop_if_empty(&mut inner, domain);
        }
        live
    }

    /// Live entries under one domain, reclaiming expired ones as it goes.
    pub fn entries(&self, domain: Domain) -> usize {
        self.note_overflow(domain);
        let now = self.clock.now_ms();
        let mut inner = self.lock();
        let Some(bucket) = self.peek(&mut inner, domain) else {
            return 0;
        };
        let reclaimed = reclaim(&mut bucket.entries, now);
        self.counters
            .bump(&self.counters.expired_reclaimed, reclaimed as u64);
        let count = bucket.entries.len();
        Self::drop_if_empty(&mut inner, domain);
        count
    }

    /// How many registered domains currently hold state.
    ///
    /// Bounded by `max_domains`. A domain whose entries have all expired gives its slot back,
    /// so this counts live tenants rather than every host ever seen.
    pub fn domains_live(&self) -> usize {
        self.lock().domains.len()
    }

    /// Live entries across every domain, including the shared bucket.
    ///
    /// Scans, so it belongs on a metrics path and not on a request path. This is the number
    /// that makes a false peer-address assertion visible: behind a proxy wrongly declared
    /// directly-exposed it reads one, however much traffic arrives.
    pub fn total_entries(&self) -> usize {
        let now = self.clock.now_ms();
        let mut inner = self.lock();
        let mut reclaimed = reclaim(&mut inner.overflow.entries, now);
        inner.overflow.earliest = min_expiry(&inner.overflow.entries);
        let mut total = inner.overflow.entries.len();

        let empty: Vec<u32> = inner
            .domains
            .iter()
            .filter(|(_, bucket)| {
                bucket.entries.iter().all(|(_, e)| e.expires_at <= now)
            })
            .map(|(slot, _)| *slot)
            .collect();
        for slot in empty {
            if let Some(bucket) = inner.domains.remove(&slot) {
                reclaimed += bucket.entries.len();
            }
        }
        for bucket in inner.domains.values_mut() {
            reclaimed += reclaim(&mut bucket.entries, now);
            bucket.earliest = min_expiry(&bucket.entries);
            total += bucket.entries.len();
        }
        self.counters
            .bump(&self.counters.expired_reclaimed, reclaimed as u64);
        total
    }

    /// A copy of the published counts.
    pub fn counters(&self) -> Counters {
        self.counters.snapshot()
    }

    /// Recovers from a poisoned lock rather than failing forever.
    ///
    /// A panic in one worker while it held the lock would otherwise make the container
    /// unusable for the life of the process, which turns one bad request into an outage. The
    /// invariants here are a bound and a deadline, and both are re-checked on every access, so
    /// continuing with the contents is safe.
    fn lock(&self) -> MutexGuard<'_, Inner<V>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The bucket for a write, admitting the domain if this is its first.
    ///
    /// Admission is where the domain cap is enforced, and only here: a read must never
    /// consume a slot, or a flood of lookups for hosts that were never registered would
    /// exhaust the cap on its own.
    fn admit<'a>(
        &self,
        inner: &'a mut Inner<V>,
        domain: Domain,
    ) -> Result<&'a mut Bucket<V>, Full> {
        if domain.is_overflow() {
            return Ok(&mut inner.overflow);
        }
        // Read before taking the entry: the cap is a property of the map, and holding an
        // `Entry` borrow while asking its length is a second mutable borrow.
        let at_cap = inner.domains.len() >= self.limits.max_domains;
        match inner.domains.entry(domain.slot) {
            MapEntry::Occupied(bucket) => Ok(bucket.into_mut()),
            MapEntry::Vacant(vacant) => {
                if at_cap {
                    self.counters.bump(&self.counters.domain_saturation, 1);
                    return Err(Full::Domains);
                }
                Ok(vacant.insert(Bucket::default()))
            },
        }
    }

    /// The bucket for a read, without admitting anything.
    fn peek<'a>(
        &self,
        inner: &'a mut Inner<V>,
        domain: Domain,
    ) -> Option<&'a mut Bucket<V>> {
        if domain.is_overflow() {
            return Some(&mut inner.overflow);
        }
        inner.domains.get_mut(&domain.slot)
    }

    /// Gives a domain its slot back once nothing live is left in it.
    ///
    /// Without this an emptied bucket still occupies a place against `max_domains` forever, so
    /// a long tail of short-lived hosts would exhaust the cap with empty maps.
    fn drop_if_empty(inner: &mut Inner<V>, domain: Domain) {
        if domain.is_overflow() {
            return;
        }
        if inner
            .domains
            .get(&domain.slot)
            .is_some_and(|b| b.entries.is_empty())
        {
            inner.domains.remove(&domain.slot);
        }
    }

    #[inline]
    fn note_overflow(&self, domain: Domain) {
        if domain.is_overflow() {
            self.counters.bump(&self.counters.overflow_ops, 1);
        }
    }
}

/// Drops every entry whose deadline has passed, returning how many went.
fn reclaim<V>(entries: &mut HashMap<Box<str>, Entry<V>>, now: Millis) -> usize {
    let before = entries.len();
    // An entry is live while `now` is strictly before its deadline, so a TTL of zero expires
    // immediately and one of `n` is still readable at `n - 1`.
    entries.retain(|_, entry| entry.expires_at > now);
    before - entries.len()
}

/// The earliest deadline in a bucket, recomputed after a reclaim.
///
/// Only called where an O(n) reclaim just ran, so it adds no asymptotic cost. Everywhere else
/// the bound is maintained as a running minimum instead.
fn min_expiry<V>(entries: &HashMap<Box<str>, Entry<V>>) -> Option<Millis> {
    entries.values().map(|entry| entry.expires_at).min()
}

/// A duration in milliseconds, saturating rather than wrapping.
fn duration_ms(ttl: Duration) -> Millis {
    u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX)
}
