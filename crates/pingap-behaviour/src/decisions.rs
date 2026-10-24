//! Process-local, bounded decisions. Monotonic time and admission tokens make
//! release/expiry/generation boundaries atomic with response observations.
use crate::scenario::{
    AbuseConfig, Counters, Evidence, Mode, millis, path_key,
};
use pingap_domainstate::{Clock, HostPolicy, Limits, ScopedStore};
use pingap_events::{
    AuditStatus, EventQueue, NativeAbuse, NativeActor, NativeBan,
    NativeBanPage, NativeKind, NativeLifecycle, NativeRelease, Verdict,
    WafEvent,
};
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
    pub max_logins: usize,
}
impl ScenarioProfile {
    pub fn new(
        namespace: &str,
        config: AbuseConfig,
        max_clients: usize,
        max_logins: usize,
        max_paths: usize,
    ) -> Result<Self, String> {
        config.validate(max_logins, max_paths)?;
        if namespace.trim().is_empty() || max_clients == 0 {
            return Err(
                "abuse requires namespace and positive client capacity".into(),
            );
        }
        let generation = digest_hex(
            format!(
                "{}:{max_clients}:{max_logins}:{max_paths}",
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
            max_logins,
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
#[derive(Debug, Clone)]
struct ActiveDecision {
    decision: Decision,
    domain: String,
    key: String,
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
    pub dropped_lifecycle: u64,
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
    fn settle(&mut self, now: u64) -> Option<Decision> {
        if self.ban.as_ref().is_some_and(|b| b.deadline <= now) {
            self.reset += 1;
            self.counters = Counters::default();
            return self.ban.take();
        }
        None
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
    /// Active block decisions keyed by their monotonic sequence. Listing uses this
    /// bounded index instead of scanning every client while holding the registry lock.
    active: BTreeMap<u64, ActiveDecision>,
    sequence: u64,
    incarnation: u64,
    counters: RegistryCounters,
}

fn decision_sequence(id: &str) -> Option<u64> {
    id.rsplit('-').next()?.parse().ok()
}

fn rebuild_active<C: Clock>(inner: &mut Inner<C>, now: u64) {
    let mut active = Vec::new();
    for (domain, bucket) in inner.domains.iter_mut() {
        let domain = domain.clone();
        bucket.store.visit(bucket.domain, |key, client| {
            if let Some(ban) = client.ban.as_ref()
                && ban.deadline > now
                && let Some(sequence) = decision_sequence(&ban.id)
            {
                active.push((
                    sequence,
                    ActiveDecision {
                        decision: ban.clone(),
                        domain: domain.clone(),
                        key: key.to_string(),
                    },
                ));
            }
        });
    }
    inner.active = active.into_iter().collect();
}
pub struct Registry<C: Clock = MonotonicClock> {
    epoch: String,
    clock: Arc<C>,
    limits: Limits,
    wall_origin: u64,
    mono_origin: u64,
    inner: Mutex<Inner<C>>,
    event_queue: Option<Arc<EventQueue>>,
    lost_lifecycle: AtomicU64,
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
            event_queue: None,
            lost_lifecycle: AtomicU64::new(0),
            inner: Mutex::new(Inner {
                profiles: BTreeMap::new(),
                hosts: None,
                domains: BTreeMap::new(),
                active: BTreeMap::new(),
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
    pub fn with_event_queue(mut self, queue: Arc<EventQueue>) -> Self {
        self.event_queue = Some(queue);
        self
    }
    fn queue(&self) -> Option<Arc<EventQueue>> {
        self.event_queue.clone().or_else(pingap_events::global)
    }
    fn emit(&self, event: NativeLifecycle) -> AuditStatus {
        let admitted = self.queue().map(|q| q.offer_native(event));
        if matches!(
            admitted,
            Some(
                pingap_events::Admission::Queued
                    | pingap_events::Admission::EvictedADetect
            )
        ) {
            AuditStatus::Queued
        } else {
            self.lost_lifecycle.fetch_add(1, Ordering::Relaxed);
            AuditStatus::Degraded
        }
    }
    fn transition(
        &self,
        kind: NativeKind,
        ban: &Decision,
        now: u64,
        actor: NativeActor,
    ) -> AuditStatus {
        self.emit(NativeLifecycle {
            version: 1,
            kind,
            id: ban.id.clone(),
            epoch: ban.epoch.clone(),
            profile: ban.profile.clone(),
            domain: ban.domain.clone(),
            client_ip: ban.client_ip.clone(),
            scenario: ban.scenario.clone(),
            mode: "block".into(),
            created_at_ms: ban.created_at_ms,
            expires_at_ms: Some(ban.expires_at_ms),
            observed_at_ms: self.wall(now),
            actor,
            reason: match kind {
                NativeKind::Created => "threshold",
                NativeKind::Released => "operator_release",
                NativeKind::Expired => "ttl_expired",
                NativeKind::Detected => "threshold",
            }
            .into(),
        })
    }
    fn telemetry(
        &self,
        profile: &str,
        domain: &str,
        ip: &str,
        scenario: &str,
        verdict: Verdict,
        now: u64,
    ) {
        if let Some(queue) = self.queue() {
            queue.offer(WafEvent {
                node: domain.into(),
                domain: domain.into(),
                profile: profile.into(),
                rule_id: None,
                category: Some(format!(
                    "native.abuse.{}",
                    if scenario == "failed_login" {
                        "login"
                    } else {
                        scenario
                    }
                )),
                severity: None,
                score: 0,
                verdict,
                client_ip: Some(ip.into()),
                method: None,
                uri: None,
                created_at: (self.wall(now) / 1000) as i64,
            });
        }
    }
    /// Only called when the request plugin actually returns403, never at creation.
    pub fn record_block(&self, ban: &Decision) {
        let now = self.clock.now_ms();
        self.telemetry(
            &ban.profile,
            &ban.domain,
            &ban.client_ip,
            &ban.scenario,
            Verdict::Block,
            now,
        );
    }
    pub fn counters(&self) -> RegistryCounters {
        let mut counters = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .counters
            .clone();
        counters.dropped_lifecycle =
            self.lost_lifecycle.load(Ordering::Relaxed);
        counters
    }
    /// Called only after a runtime provider swap, never by candidate validation.
    pub fn retain_hosts(&self, hosts: HostPolicy) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner
            .domains
            .retain(|domain, _| !hosts.classify(domain).is_overflow());
        inner.hosts = Some(hosts);
        rebuild_active(&mut inner, self.clock.now_ms());
    }
    pub fn activate(&self, profiles: Vec<ScenarioProfile>) {
        self.activate_with_retained(profiles, &[]);
    }

    pub fn activate_with_retained(
        &self,
        profiles: Vec<ScenarioProfile>,
        retained_namespaces: &[String],
    ) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut profiles: BTreeMap<_, _> = profiles
            .into_iter()
            .filter(|p| p.config.enabled)
            .map(|p| (p.namespace.clone(), p))
            .collect();
        for namespace in retained_namespaces {
            if let Some(previous) = inner.profiles.get(namespace).cloned() {
                profiles.entry(namespace.clone()).or_insert(previous);
            }
        }
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
        rebuild_active(&mut inner, self.clock.now_ms());
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
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = self.clock.now_ms();
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
        let mut expired = 0;
        let mut expired_bans = Vec::new();
        let existing = {
            let bucket =
                inner.domains.get_mut(domain).expect("domain admitted");
            bucket.store.update(bucket.domain, &key, |c| {
                if let Some(ban) = c.settle(now) {
                    expired_bans.push(ban.clone());
                    self.transition(
                        NativeKind::Expired,
                        &ban,
                        now,
                        NativeActor::default(),
                    );
                    expired += 1;
                }
                c.ban.clone()
            })
        };
        for ban in &expired_bans {
            if let Some(sequence) = decision_sequence(&ban.id) {
                inner.active.remove(&sequence);
            }
        }
        if let Some(Some(ban)) = existing {
            inner.counters.expired += expired;
            return Admission::Blocked(ban);
        }
        if !login && profile.config.scan.is_none() {
            inner.counters.expired += expired;
            return Admission::Allowed(None);
        }
        if existing.is_none() {
            let at_capacity = {
                let bucket =
                    inner.domains.get_mut(domain).expect("domain admitted");
                if bucket.store.entries(bucket.domain)
                    >= self.limits.max_entries_per_domain
                    || bucket.counts.get(namespace).copied().unwrap_or(0)
                        >= profile.max_clients
                {
                    bucket.store.retain(bucket.domain, |_, c| {
                        if let Some(ban) = c.settle(now) {
                            expired_bans.push(ban.clone());
                            self.transition(
                                NativeKind::Expired,
                                &ban,
                                now,
                                NativeActor::default(),
                            );
                            expired += 1;
                        }
                        let keep = c.ban.is_some() || c.idle_at >= now;
                        if !keep
                            && let Some(count) =
                                bucket.counts.get_mut(&c.namespace)
                        {
                            *count -= 1;
                        }
                        keep
                    });
                    true
                } else {
                    false
                }
            };
            for ban in &expired_bans {
                if let Some(sequence) = decision_sequence(&ban.id) {
                    inner.active.remove(&sequence);
                }
            }
            if at_capacity
                && inner
                    .domains
                    .get(domain)
                    .and_then(|bucket| bucket.counts.get(namespace))
                    .copied()
                    .unwrap_or(0)
                    >= profile.max_clients
            {
                inner.counters.expired += expired;
                inner.counters.saturated += 1;
                return Admission::Saturated;
            }
            inner.incarnation += 1;
            let incarnation = inner.incarnation;
            let inserted = {
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
                    .is_ok()
                {
                    *bucket.counts.entry(namespace.into()).or_default() += 1;
                    true
                } else {
                    false
                }
            };
            if !inserted {
                inner.counters.expired += expired;
                inner.counters.saturated += 1;
                return Admission::Saturated;
            }
        }
        let ticket = {
            let bucket =
                inner.domains.get_mut(domain).expect("domain admitted");
            bucket.store.update(bucket.domain, &key, |c| {
                c.idle_at = now.saturating_add(profile.idle_ms());
                Ticket {
                    epoch: self.epoch.clone(),
                    generation: profile.generation.clone(),
                    incarnation: c.incarnation,
                    reset: c.reset,
                    namespace: namespace.into(),
                    domain: domain.into(),
                    identity,
                    key: key.clone(),
                    login,
                    path: path_digest,
                }
            })
        };
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
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = self.clock.now_ms();
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
        let mut expired_ban = None;
        let mut created_ban = None;
        let mut stale = false;
        let result = bucket
            .store
            .update(bucket.domain, &ticket.key, |c| {
                if let Some(ban) = c.settle(now) {
                    expired_ban = Some(ban.clone());
                    self.transition(
                        NativeKind::Expired,
                        &ban,
                        now,
                        NativeActor::default(),
                    );
                    expired = true;
                }
                if c.generation != ticket.generation
                    || c.incarnation != ticket.incarnation
                    || c.reset != ticket.reset
                    || c.ban.is_some()
                {
                    stale = true;
                    return Evidence::default();
                }
                c.idle_at = now.saturating_add(profile.idle_ms());
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
                for (scenario, mode, _) in &crossings {
                    if *mode == Mode::Detect {
                        self.emit(NativeLifecycle {
                            version: 1,
                            kind: NativeKind::Detected,
                            id: format!("{}-{sequence}-{scenario}", self.epoch),
                            epoch: self.epoch.clone(),
                            profile: ticket.namespace.clone(),
                            domain: ticket.domain.clone(),
                            client_ip: ticket.identity.clone(),
                            scenario: (*scenario).into(),
                            mode: "detect".into(),
                            created_at_ms: self.wall(now),
                            expires_at_ms: None,
                            observed_at_ms: self.wall(now),
                            actor: NativeActor::default(),
                            reason: "threshold".into(),
                        });
                        self.telemetry(
                            &ticket.namespace,
                            &ticket.domain,
                            &ticket.identity,
                            scenario,
                            Verdict::Detect,
                            now,
                        );
                    }
                }
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
                    self.transition(
                        NativeKind::Created,
                        c.ban.as_ref().expect("created ban"),
                        now,
                        NativeActor::default(),
                    );
                    c.idle_at = c.idle_at.max(deadline);
                    created_ban = c.ban.clone();
                    evidence.ban_created = true;
                }
                evidence
            })
            .unwrap_or_default();
        if let Some(ban) = expired_ban.as_ref()
            && let Some(sequence) = decision_sequence(&ban.id)
        {
            inner.active.remove(&sequence);
        }
        if let Some(ban) = created_ban
            && let Some(sequence) = decision_sequence(&ban.id)
        {
            inner.active.insert(
                sequence,
                ActiveDecision {
                    decision: ban,
                    domain: ticket.domain.clone(),
                    key: ticket.key.clone(),
                },
            );
        }
        if expired {
            inner.counters.expired += 1;
        }
        if stale {
            inner.counters.stale_observations += 1;
        }
        if result.detected {
            inner.sequence = sequence;
            inner.counters.detected += 1;
        }
        if result.ban_created {
            inner.counters.created += 1;
        }
        result
    }
    pub fn active_decisions(&self, after: u64, limit: usize) -> Vec<Decision> {
        self.filtered_decisions(None, None, after, limit).0
    }
    fn filtered_decisions(
        &self,
        profile: Option<&str>,
        domain: Option<&str>,
        after: u64,
        limit: usize,
    ) -> (Vec<Decision>, u64) {
        if limit == 0 {
            return (Vec::new(), 0);
        }
        let mut rows = BTreeMap::new();
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = self.clock.now_ms();
        let expired: Vec<(u64, ActiveDecision)> = inner
            .active
            .iter()
            .filter(|(_, active)| active.decision.deadline <= now)
            .map(|(sequence, active)| (*sequence, active.clone()))
            .collect();

        // The active index bounds the read path to live decisions. Expired entries are removed
        // from their owning store by key so the lifecycle event is emitted once, without a
        // full registry scan under the global mutex.
        for (sequence, active) in expired {
            let mut expired_ban = None;
            if let Some(bucket) = inner.domains.get_mut(&active.domain) {
                // Settle the client in place so its slot and namespace count remain
                // reusable. Removing the whole entry here would make the count map
                // overstate occupancy until the next admission.
                bucket.store.update(bucket.domain, &active.key, |client| {
                    expired_ban = client.settle(now);
                });
            }
            if let Some(ban) = expired_ban {
                self.transition(
                    NativeKind::Expired,
                    &ban,
                    now,
                    NativeActor::default(),
                );
                inner.counters.expired += 1;
            }
            inner.active.remove(&sequence);
        }

        for (sequence, active) in &inner.active {
            let ban = &active.decision;
            if ban.deadline <= now
                || *sequence <= after
                || profile.is_some_and(|p| p != ban.profile)
                || domain.is_some_and(|d| d != ban.domain)
            {
                continue;
            }
            if rows.len() < limit
                || rows
                    .last_key_value()
                    .is_some_and(|(last, _)| *sequence < *last)
            {
                rows.insert(*sequence, ban.clone());
                if rows.len() > limit {
                    rows.pop_last();
                }
            }
        }
        (rows.into_values().collect(), self.wall(now))
    }
    /// Exact decision ID prevents a delayed release from removing a newer ban.
    pub fn release(
        &self,
        namespace: &str,
        domain: &str,
        identity: &str,
        id: &str,
    ) -> bool {
        self.release_as(namespace, domain, identity, id, NativeActor::default())
            .outcome
            == "released"
    }
    pub fn release_as(
        &self,
        namespace: &str,
        domain: &str,
        identity: &str,
        id: &str,
        actor: NativeActor,
    ) -> NativeRelease {
        let absent = NativeRelease {
            outcome: "already_absent",
            audit: AuditStatus::NotApplicable,
        };
        let key = format!(
            "{}:{}",
            digest_hex(namespace.as_bytes()),
            identity
                .parse::<std::net::IpAddr>()
                .map(|i| i.to_string())
                .unwrap_or_default()
        );
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = self.clock.now_ms();
        let Some(bucket) = inner.domains.get_mut(domain) else {
            return absent;
        };
        let mut expired = false;
        let mut expired_id = None;
        let mut audit = AuditStatus::NotApplicable;
        let mut released_id = None;
        let released = bucket
            .store
            .update(bucket.domain, &key, |c| {
                if let Some(ban) = c.settle(now) {
                    self.transition(
                        NativeKind::Expired,
                        &ban,
                        now,
                        NativeActor::default(),
                    );
                    expired = true;
                    expired_id = Some(ban.id);
                }
                if c.ban.as_ref().is_none_or(|b| b.id != id) {
                    return false;
                }
                audit = self.transition(
                    NativeKind::Released,
                    c.ban.as_ref().expect("matched ban"),
                    now,
                    actor.clone(),
                );
                released_id = Some(id.to_string());
                c.reset += 1;
                c.ban = None;
                c.counters = Counters::default();
                true
            })
            .unwrap_or(false);
        if let Some(expired_id) = expired_id
            && let Some(sequence) = decision_sequence(&expired_id)
        {
            inner.active.remove(&sequence);
            inner.counters.expired += 1;
        }
        if let Some(released_id) = released_id
            && let Some(sequence) = decision_sequence(&released_id)
        {
            inner.active.remove(&sequence);
        }
        if released {
            inner.counters.released += 1;
        }
        NativeRelease {
            outcome: if released {
                "released"
            } else {
                "already_absent"
            },
            audit,
        }
    }
}
impl<C: Clock> NativeAbuse for Registry<C> {
    fn epoch(&self) -> String {
        self.epoch.clone()
    }
    fn list(
        &self,
        profile: Option<&str>,
        domain: Option<&str>,
        after: u64,
        limit: usize,
    ) -> NativeBanPage {
        let (rows, now) =
            self.filtered_decisions(profile, domain, after, limit);
        let next_cursor = if rows.len() == limit {
            rows.last().map(|b| {
                format!(
                    "{}:{}",
                    self.epoch,
                    b.id.rsplit('-').next().unwrap_or("0")
                )
            })
        } else {
            None
        };
        NativeBanPage {
            epoch: self.epoch.clone(),
            next_cursor,
            items: rows
                .into_iter()
                .map(|b| NativeBan {
                    id: b.id,
                    epoch: b.epoch,
                    profile: b.profile,
                    domain: b.domain,
                    client_ip: b.client_ip,
                    scenario: b.scenario,
                    mode: "block",
                    created_at_ms: b.created_at_ms,
                    expires_at_ms: b.expires_at_ms,
                    remaining_ms: b.expires_at_ms.saturating_sub(now),
                })
                .collect(),
        }
    }
    fn release(
        &self,
        profile: &str,
        domain: &str,
        ip: &str,
        id: &str,
        actor: NativeActor,
    ) -> NativeRelease {
        self.release_as(profile, domain, ip, id, actor)
    }
}
/// Binary-owned adapter to the process registry; APIs never depend on detector code.
pub struct NativeRuntime;
impl NativeAbuse for NativeRuntime {
    fn epoch(&self) -> String {
        registry().epoch().into()
    }
    fn list(
        &self,
        profile: Option<&str>,
        domain: Option<&str>,
        after: u64,
        limit: usize,
    ) -> NativeBanPage {
        NativeAbuse::list(registry(), profile, domain, after, limit)
    }
    fn release(
        &self,
        profile: &str,
        domain: &str,
        ip: &str,
        id: &str,
        actor: NativeActor,
    ) -> NativeRelease {
        registry().release_as(profile, domain, ip, id, actor)
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

#[cfg(test)]
mod clock_order_tests {
    use super::*;
    use pingap_domainstate::ManualClock;
    use std::sync::Weak;
    #[derive(Clone)]
    struct LockCheckedClock {
        time: ManualClock,
        owner: Arc<Mutex<Option<Weak<Registry<LockCheckedClock>>>>>,
    }
    impl Clock for LockCheckedClock {
        fn now_ms(&self) -> u64 {
            let owner = self
                .owner
                .lock()
                .expect("clock owner")
                .as_ref()
                .and_then(Weak::upgrade);
            if let Some(owner) = owner {
                assert!(
                    matches!(
                        owner.inner.try_lock(),
                        Err(std::sync::TryLockError::WouldBlock)
                    ),
                    "state time must be sampled under the registry mutation lock"
                );
            }
            self.time.now_ms()
        }
    }
    #[test]
    fn clock_sampling_is_serialized_with_mutation_at_window_boundaries() {
        let clock = LockCheckedClock {
            time: ManualClock::at(0),
            owner: Arc::new(Mutex::new(None)),
        };
        let registry =
            Arc::new(Registry::with_clock(Limits::default(), clock.clone()));
        *clock.owner.lock().expect("clock owner") =
            Some(Arc::downgrade(&registry));
        let config=toml::from_str("enabled=true\n[failed_login]\nmode=\"block\"\nwindow=\"10ms\"\nthreshold=3\nban_ttl=\"1s\"\npath=\"/login\"\nmethod=\"POST\"\nstatuses=[401]").expect("config");
        registry.activate(vec![
            ScenarioProfile::new("behaviour:clock", config, 5000, 32, 64)
                .expect("profile"),
        ]);
        for at in [9, 11, 20] {
            clock.time.set(at);
            let Admission::Allowed(Some(ticket)) = registry.admit(
                "behaviour:clock",
                "a.test",
                "::1",
                "POST",
                "/login",
                true,
            ) else {
                panic!("admission")
            };
            assert!(
                !registry.observe(&ticket, 401, false).ban_created,
                "only observations at11 and20 remain valid"
            );
        }
        assert!(registry.active_decisions(0, 100).is_empty());
        assert!(!registry.release(
            "behaviour:clock",
            "a.test",
            "::1",
            "absent"
        ));
    }
}
