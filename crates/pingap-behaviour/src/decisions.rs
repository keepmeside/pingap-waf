//! Process-local, bounded decisions. Monotonic time and admission tokens make
//! release/expiry/generation boundaries atomic with response observations.
use crate::scenario::{
    AbuseConfig, Counters, Evidence, Mode, millis, path_key,
};
use pingap_domainstate::{Clock, HostPolicy, Limits, ScopedStore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
static EPOCH: AtomicU64 = AtomicU64::new(1);

pub struct MonotonicClock {
    origin: Instant,
}
impl Default for MonotonicClock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}
impl Clock for MonotonicClock {
    fn now_ms(&self) -> u64 {
        millis(self.origin.elapsed())
    }
}
struct SharedClock<C>(Arc<C>);
impl<C: Clock> Clock for SharedClock<C> {
    fn now_ms(&self) -> u64 {
        self.0.now_ms()
    }
}
#[derive(Debug, Clone)]
pub struct ScenarioProfile {
    pub namespace: String,
    pub generation: String,
    pub config: AbuseConfig,
    pub max_clients: usize,
    pub max_paths: usize,
}
impl ScenarioProfile {
    pub fn new(
        namespace: &str,
        config: AbuseConfig,
        max_clients: usize,
        max_paths: usize,
    ) -> Result<Self, String> {
        config.validate(max_paths, max_paths)?;
        if namespace.trim().is_empty() || max_clients == 0 {
            return Err(
                "abuse requires namespace and positive client capacity".into(),
            );
        }
        let generation = digest_hex(
            format!(
                "{}:{max_clients}:{max_paths}",
                toml::to_string(&config)
                    .map_err(|_| "invalid abuse configuration")?
            )
            .as_bytes(),
        );
        Ok(Self {
            namespace: namespace.into(),
            generation,
            config,
            max_clients,
            max_paths,
        })
    }
    fn idle_ms(&self) -> u64 {
        self.config
            .failed_login
            .iter()
            .map(|s| &s.rule)
            .chain(self.config.scan.iter())
            .map(|r| millis(r.window).max(millis(r.ban_ttl)))
            .max()
            .unwrap_or(0)
    }
}
#[derive(Debug, Clone)]
pub struct Ticket {
    epoch: String,
    generation: String,
    incarnation: u64,
    reset: u64,
    namespace: String,
    domain: String,
    identity: String,
    key: String,
    login: bool,
    path: [u8; 32],
}
#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub id: String,
    pub epoch: String,
    pub profile: String,
    pub domain: String,
    pub client_ip: String,
    pub scenario: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    #[serde(skip)]
    pub deadline: u64,
}
#[derive(Debug)]
pub enum Admission {
    Allowed(Option<Ticket>),
    Blocked(Decision),
    Saturated,
    Unregistered,
    Unavailable,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct RegistryCounters {
    pub detected: u64,
    pub created: u64,
    pub expired: u64,
    pub released: u64,
    pub saturated: u64,
    pub stale_observations: u64,
}
struct Client {
    namespace: String,
    generation: String,
    incarnation: u64,
    reset: u64,
    counters: Counters,
    ban: Option<Decision>,
    idle_at: u64,
}
impl Client {
    fn settle(&mut self, now: u64) -> bool {
        if self.ban.as_ref().is_some_and(|b| b.deadline <= now) {
            self.reset += 1;
            self.counters = Counters::default();
            self.ban = None;
            return true;
        }
        false
    }
}
struct Bucket<C: Clock> {
    store: ScopedStore<Client, SharedClock<C>>,
    domain: pingap_domainstate::Domain,
    counts: BTreeMap<String, usize>,
}
struct Inner<C: Clock> {
    profiles: BTreeMap<String, ScenarioProfile>,
    hosts: Option<HostPolicy>,
    domains: BTreeMap<String, Bucket<C>>,
    sequence: u64,
    incarnation: u64,
    counters: RegistryCounters,
}
pub struct Registry<C: Clock = MonotonicClock> {
    epoch: String,
    clock: Arc<C>,
    limits: Limits,
    wall_origin: u64,
    mono_origin: u64,
    inner: Mutex<Inner<C>>,
}
impl<C: Clock> Registry<C> {
    pub fn with_clock(limits: Limits, clock: C) -> Self {
        let mono_origin = clock.now_ms();
        Self {
            epoch: format!(
                "{}-{}-{}",
                pingap_core::now_ms(),
                std::process::id(),
                EPOCH.fetch_add(1, Ordering::Relaxed)
            ),
            clock: Arc::new(clock),
            limits,
            wall_origin: pingap_core::now_ms(),
            mono_origin,
            inner: Mutex::new(Inner {
                profiles: BTreeMap::new(),
                hosts: None,
                domains: BTreeMap::new(),
                sequence: 0,
                incarnation: 0,
                counters: RegistryCounters::default(),
            }),
        }
    }
    pub fn epoch(&self) -> &str {
        &self.epoch
    }
    fn wall(&self, now: u64) -> u64 {
        self.wall_origin
            .saturating_add(now.saturating_sub(self.mono_origin))
    }
    pub fn counters(&self) -> RegistryCounters {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .counters
            .clone()
    }
    /// Called only after a runtime provider swap, never by candidate validation.
    pub fn retain_hosts(&self, hosts: HostPolicy) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner
            .domains
            .retain(|domain, _| !hosts.classify(domain).is_overflow());
        inner.hosts = Some(hosts);
    }
    pub fn activate(&self, profiles: Vec<ScenarioProfile>) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let profiles: BTreeMap<_, _> = profiles
            .into_iter()
            .filter(|p| p.config.enabled)
            .map(|p| (p.namespace.clone(), p))
            .collect();
        for bucket in inner.domains.values_mut() {
            bucket.store.retain(bucket.domain, |_, c| {
                profiles
                    .get(&c.namespace)
                    .is_some_and(|p| p.generation == c.generation)
            });
            bucket.counts.clear();
            bucket.store.visit(bucket.domain, |_, c| {
                *bucket.counts.entry(c.namespace.clone()).or_default() += 1;
            });
        }
        inner.domains.retain(|_, b| b.store.entries(b.domain) > 0);
        inner.profiles = profiles;
    }
    pub fn admit(
        &self,
        namespace: &str,
        domain: &str,
        identity: &str,
        method: &str,
        path: &str,
        registered: bool,
    ) -> Admission {
        self.admit_expected(
            namespace, None, domain, identity, method, path, registered,
        )
    }
    pub fn admit_profile(
        &self,
        profile: &ScenarioProfile,
        domain: &str,
        identity: &str,
        method: &str,
        path: &str,
        registered: bool,
    ) -> Admission {
        self.admit_expected(
            &profile.namespace,
            Some(&profile.generation),
            domain,
            identity,
            method,
            path,
            registered,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn admit_expected(
        &self,
        namespace: &str,
        expected: Option<&str>,
        domain: &str,
        identity: &str,
        method: &str,
        path: &str,
        registered: bool,
    ) -> Admission {
        if !registered || identity.parse::<std::net::IpAddr>().is_err() {
            return Admission::Unregistered;
        }
        let identity = identity
            .parse::<std::net::IpAddr>()
            .expect("validated IP")
            .to_string();
        let path_digest = path_key(path);
        let now = self.clock.now_ms();
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if inner
            .hosts
            .as_ref()
            .is_some_and(|hosts| hosts.classify(domain).is_overflow())
        {
            return Admission::Unregistered;
        }
        let Some(profile) = inner.profiles.get(namespace).cloned() else {
            return if expected.is_some() {
                Admission::Unavailable
            } else {
                Admission::Allowed(None)
            };
        };
        if expected.is_some_and(|generation| generation != profile.generation) {
            return Admission::Unavailable;
        }
        let login = profile.config.failed_login.as_ref().is_some_and(|s| {
            s.path == path.split('?').next().unwrap_or(path)
                && s.method == method
        });
        let key = format!("{}:{identity}", digest_hex(namespace.as_bytes()));
        if !inner.domains.contains_key(domain) {
            if inner.domains.len() >= self.limits.max_domains {
                inner.counters.saturated += 1;
                return Admission::Unavailable;
            }
            let hosts = HostPolicy::new([domain]);
            let key_domain = hosts.classify(domain);
            inner.domains.insert(
                domain.into(),
                Bucket {
                    store: ScopedStore::with_clock(
                        hosts,
                        self.limits,
                        SharedClock(self.clock.clone()),
                    ),
                    domain: key_domain,
                    counts: BTreeMap::new(),
                },
            );
        }
        let bucket = inner.domains.get_mut(domain).expect("domain admitted");
        let mut expired = 0;
        let existing = bucket.store.update(bucket.domain, &key, |c| {
            if c.settle(now) {
                expired += 1;
            }
            c.ban.clone()
        });
        if let Some(Some(ban)) = existing {
            inner.counters.expired += expired;
            return Admission::Blocked(ban);
        }
        if !login && profile.config.scan.is_none() {
            inner.counters.expired += expired;
            return Admission::Allowed(None);
        }
        if existing.is_none() {
            if bucket.store.entries(bucket.domain)
                >= self.limits.max_entries_per_domain
                || bucket.counts.get(namespace).copied().unwrap_or(0)
                    >= profile.max_clients
            {
                bucket.store.retain(bucket.domain, |_, c| {
                    if c.settle(now) {
                        expired += 1;
                    }
                    let keep = c.ban.is_some() || c.idle_at >= now;
                    if !keep
                        && let Some(count) = bucket.counts.get_mut(&c.namespace)
                    {
                        *count -= 1;
                    }
                    keep
                });
            }
            if bucket.counts.get(namespace).copied().unwrap_or(0)
                >= profile.max_clients
            {
                inner.counters.expired += expired;
                inner.counters.saturated += 1;
                return Admission::Saturated;
            }
            inner.incarnation += 1;
            let incarnation = inner.incarnation;
            let bucket =
                inner.domains.get_mut(domain).expect("domain admitted");
            let cell = Client {
                namespace: namespace.into(),
                generation: profile.generation.clone(),
                incarnation,
                reset: 0,
                counters: Counters::default(),
                ban: None,
                idle_at: now.saturating_add(profile.idle_ms()),
            };
            if bucket
                .store
                .insert(bucket.domain, &key, cell, Duration::MAX)
                .is_err()
            {
                inner.counters.expired += expired;
                inner.counters.saturated += 1;
                return Admission::Saturated;
            }
            *bucket.counts.entry(namespace.into()).or_default() += 1;
        }
        let bucket = inner.domains.get_mut(domain).expect("domain admitted");
        let ticket = bucket.store.update(bucket.domain, &key, |c| {
            c.idle_at = now.saturating_add(profile.idle_ms());
            Ticket {
                epoch: self.epoch.clone(),
                generation: profile.generation,
                incarnation: c.incarnation,
                reset: c.reset,
                namespace: namespace.into(),
                domain: domain.into(),
                identity,
                key: key.clone(),
                login,
                path: path_digest,
            }
        });
        inner.counters.expired += expired;
        Admission::Allowed(ticket)
    }
    pub fn observe(
        &self,
        ticket: &Ticket,
        status: u16,
        local_denial: bool,
    ) -> Evidence {
        if local_denial || ticket.epoch != self.epoch {
            return Evidence::default();
        }
        let now = self.clock.now_ms();
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let Some(profile) = inner
            .profiles
            .get(&ticket.namespace)
            .filter(|p| p.generation == ticket.generation)
            .cloned()
        else {
            inner.counters.stale_observations += 1;
            return Evidence::default();
        };
        // Allocate only a scalar ID reservation here; response completion must never
        // create a client slot or resurrect an evicted incarnation.
        let sequence = inner.sequence + 1;
        let Some(bucket) = inner.domains.get_mut(&ticket.domain) else {
            return Evidence::default();
        };
        let mut expired = false;
        let mut stale = false;
        let result = bucket
            .store
            .update(bucket.domain, &ticket.key, |c| {
                expired = c.settle(now);
                if c.generation != ticket.generation
                    || c.incarnation != ticket.incarnation
                    || c.reset != ticket.reset
                    || c.ban.is_some()
                {
                    stale = true;
                    return Evidence::default();
                }
                let crossings = c.counters.observe(
                    &profile.config,
                    now,
                    ticket.login,
                    ticket.path,
                    status,
                );
                let mut evidence = Evidence {
                    detected: !crossings.is_empty(),
                    ban_created: false,
                };
                if let Some((scenario, _, ttl)) =
                    crossings.iter().find(|(_, mode, _)| *mode == Mode::Block)
                {
                    let deadline = now.saturating_add(millis(*ttl));
                    c.ban = Some(Decision {
                        id: format!("{}-{sequence}", self.epoch),
                        epoch: self.epoch.clone(),
                        profile: ticket.namespace.clone(),
                        domain: ticket.domain.clone(),
                        client_ip: ticket.identity.clone(),
                        scenario: (*scenario).into(),
                        created_at_ms: self.wall(now),
                        expires_at_ms: self.wall(deadline),
                        deadline,
                    });
                    c.idle_at = c.idle_at.max(deadline);
                    evidence.ban_created = true;
                }
                evidence
            })
            .unwrap_or_default();
        if expired {
            inner.counters.expired += 1;
        }
        if stale {
            inner.counters.stale_observations += 1;
        }
        if result.detected {
            inner.counters.detected += 1;
        }
        if result.ban_created {
            inner.sequence = sequence;
            inner.counters.created += 1;
        }
        result
    }
    pub fn active_decisions(&self, after: u64, limit: usize) -> Vec<Decision> {
        if limit == 0 {
            return Vec::new();
        }
        let now = self.clock.now_ms();
        let mut rows = BTreeMap::new();
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut expired = 0;
        for bucket in inner.domains.values_mut() {
            bucket.store.retain(bucket.domain, |_, c| {
                if c.settle(now) {
                    expired += 1;
                }
                if let Some(ban) = &c.ban
                    && let Some(seq) = ban
                        .id
                        .rsplit('-')
                        .next()
                        .and_then(|s| s.parse::<u64>().ok())
                        .filter(|seq| *seq > after)
                    && (rows.len() < limit
                        || rows
                            .last_key_value()
                            .is_some_and(|(last, _)| seq < *last))
                {
                    rows.insert(seq, ban.clone());
                    if rows.len() > limit {
                        rows.pop_last();
                    }
                }
                true
            });
        }
        inner.counters.expired += expired;
        rows.into_values().collect()
    }
    /// Exact decision ID prevents a delayed release from removing a newer ban.
    pub fn release(
        &self,
        namespace: &str,
        domain: &str,
        identity: &str,
        id: &str,
    ) -> bool {
        let key = format!(
            "{}:{}",
            digest_hex(namespace.as_bytes()),
            identity
                .parse::<std::net::IpAddr>()
                .map(|i| i.to_string())
                .unwrap_or_default()
        );
        let now = self.clock.now_ms();
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let Some(bucket) = inner.domains.get_mut(domain) else {
            return false;
        };
        let mut expired = false;
        let released = bucket
            .store
            .update(bucket.domain, &key, |c| {
                expired = c.settle(now);
                if c.ban.as_ref().is_none_or(|b| b.id != id) {
                    return false;
                }
                c.reset += 1;
                c.ban = None;
                c.counters = Counters::default();
                true
            })
            .unwrap_or(false);
        if expired {
            inner.counters.expired += 1;
        }
        if released {
            inner.counters.released += 1;
        }
        released
    }
}
static GLOBAL: OnceLock<Registry> = OnceLock::new();
pub fn registry() -> &'static Registry {
    GLOBAL.get_or_init(|| {
        Registry::with_clock(Limits::default(), MonotonicClock::default())
    })
}

fn digest_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for b in Sha256::digest(bytes) {
        output.push(HEX[(b >> 4) as usize] as char);
        output.push(HEX[(b & 15) as usize] as char);
    }
    output
}
