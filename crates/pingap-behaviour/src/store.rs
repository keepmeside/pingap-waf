use crate::profile::{Observation, Profile};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct BehaviourStore {
    inner: Arc<Mutex<HashMap<(String, String), Profile>>>,
    max_clients: usize,
    max_urls: usize,
    max_ua: usize,
    max_samples: usize,
    window: Duration,
}

impl BehaviourStore {
    pub fn new(
        max_clients: usize,
        max_urls: usize,
        max_ua: usize,
        max_samples: usize,
        window: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_clients: max_clients.max(1),
            max_urls,
            max_ua,
            max_samples,
            window,
        }
    }
    pub fn record(
        &self,
        domain: &str,
        identity: &str,
        observation: Observation,
    ) -> Option<Profile> {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = (domain.to_string(), identity.to_string());
        let now = observation.at;
        map.retain(|_, profile| {
            profile
                .last
                .is_none_or(|last| now.duration_since(last) <= self.window)
        });
        let domain_clients = map
            .keys()
            .filter(|(key_domain, _)| key_domain == domain)
            .count();
        if !map.contains_key(&key) && domain_clients >= self.max_clients {
            return None;
        }
        let profile = map.entry(key).or_insert_with(|| {
            Profile::new(
                self.max_samples,
                self.max_urls,
                self.max_ua,
                self.window,
            )
        });
        profile.record(observation);
        Some(profile.clone())
    }

    /// Returns a pruned snapshot without admitting a new client slot.
    pub fn snapshot(
        &self,
        domain: &str,
        identity: &str,
        now: std::time::Instant,
    ) -> Option<Profile> {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = (domain.to_string(), identity.to_string());
        let profile = map.get_mut(&key)?;
        profile.prune(now);
        if profile.is_empty() {
            map.remove(&key);
            None
        } else {
            Some(profile.clone())
        }
    }
    /// Distinct identities currently tracked, per domain label, after the
    /// same pruning `snapshot` applies — a gauge, not an event counter. It
    /// answers "how many clients does this domain hold right now", which
    /// the request counters cannot: every request one client sends moves
    /// those while this stays where it is.
    pub fn tracked_per_domain(
        &self,
        now: std::time::Instant,
    ) -> BTreeMap<String, u64> {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut tracked = BTreeMap::new();
        map.retain(|(domain, _), profile| {
            profile.prune(now);
            if profile.is_empty() {
                false
            } else {
                *tracked.entry(domain.clone()).or_insert(0u64) += 1;
                true
            }
        });
        tracked
    }

    pub fn get(&self, domain: &str, identity: &str) -> Option<Profile> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&(domain.to_string(), identity.to_string()))
            .cloned()
    }
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
