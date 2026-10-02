use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeRecord {
    pub domain: String,
    pub identity: String,
    pub salt: String,
    pub difficulty: u8,
    pub target: String,
    pub kind: String,
    pub attempts: u32,
    pub expires_at: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    FullDomains,
    FullEntries,
}

#[derive(Debug, Clone)]
pub struct TokenStore {
    inner: Arc<Mutex<HashMap<String, ChallengeRecord>>>,
    domains: Arc<Mutex<HashSet<String>>>,
    expired: Arc<AtomicUsize>,
    /// The same expiries the total counts, attributed to the domain each dropped
    /// record belonged to. A per-domain counter with no per-domain source would
    /// be a field that can never be written honestly, so the attribution is
    /// collected where the drop is observed.
    expired_by_domain: Arc<Mutex<BTreeMap<String, u64>>>,
    max_domains: usize,
    max_entries: usize,
}

impl TokenStore {
    pub fn new(max_entries: usize) -> Self {
        Self::with_limits(256, max_entries)
    }

    pub fn with_limits(max_domains: usize, max_entries: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            domains: Arc::new(Mutex::new(HashSet::new())),
            expired: Arc::new(AtomicUsize::new(0)),
            expired_by_domain: Arc::new(Mutex::new(BTreeMap::new())),
            max_domains: max_domains.max(1),
            max_entries: max_entries.max(1),
        }
    }

    /// How many records the store has evicted for being past `expires_at`.
    ///
    /// The store is the only place an expiry is observed — a record is dropped the
    /// moment it is found stale inside `issue`, `take`, or `get` — so the count lives
    /// here and the plugin's counter mirrors it, rather than the other way around. A
    /// record that ages out *between* calls is counted when the next call sweeps it.
    pub fn expired_count(&self) -> usize {
        self.expired.load(Ordering::Relaxed)
    }

    /// Evictions attributed per domain, so the published per-domain `expired`
    /// counter has a per-domain source. The caller merges this into the row keyed
    /// by the label the record's domain was classified under.
    pub fn expired_by_domain(&self) -> BTreeMap<String, u64> {
        self.expired_by_domain
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Record `count` expiries against `domain`: the total, and the per-domain
    /// attribution that mirrors it.
    fn count_expired(&self, domain: &str, count: u64) {
        self.expired.fetch_add(count as usize, Ordering::Relaxed);
        let mut by_domain = self
            .expired_by_domain
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *by_domain.entry(domain.to_string()).or_default() += count;
    }

    /// Drop every record whose `expires_at` is at or before `now`, counting each
    /// drop and attributing it to the domain that owned the record. Called inside
    /// `issue`'s sweep so expiry is measured, not silent.
    fn sweep_expired(
        &self,
        guard: &mut HashMap<String, ChallengeRecord>,
        now: SystemTime,
    ) {
        let mut dropped: BTreeMap<String, u64> = BTreeMap::new();
        guard.retain(|_, value| {
            if value.expires_at > now {
                return true;
            }
            *dropped.entry(value.domain.clone()).or_default() += 1;
            false
        });
        for (domain, count) in dropped {
            self.count_expired(&domain, count);
        }
    }

    pub fn issue(
        &self,
        token: String,
        record: ChallengeRecord,
    ) -> Result<(), TokenError> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = SystemTime::now();
        self.sweep_expired(&mut guard, now);
        let mut domains = self
            .domains
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        domains.retain(|domain| {
            guard.values().any(|record| &record.domain == domain)
        });
        let is_new_domain = !domains.contains(&record.domain);
        if is_new_domain && domains.len() >= self.max_domains {
            return Err(TokenError::FullDomains);
        }
        if !guard.contains_key(&token) && guard.len() >= self.max_entries {
            return Err(TokenError::FullEntries);
        }
        domains.insert(record.domain.clone());
        guard.insert(token, record);
        Ok(())
    }

    /// Atomically take a token. A concurrent second presentation sees `None`.
    pub fn get(
        &self,
        token: &str,
        domain: &str,
        identity: &str,
        now: SystemTime,
    ) -> Option<ChallengeRecord> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .get(token)
            .filter(|record| {
                record.expires_at > now
                    && record.domain == domain
                    && record.identity == identity
            })
            .cloned()
    }

    pub fn remove(&self, token: &str) -> Option<ChallengeRecord> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let result = guard.remove(token);
        if let Some(record) = &result
            && !guard.values().any(|entry| entry.domain == record.domain)
        {
            self.domains
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&record.domain);
        }
        result
    }

    /// Atomically take a token. A concurrent second presentation sees `None`.
    pub fn take(
        &self,
        token: &str,
        domain: &str,
        identity: &str,
        now: SystemTime,
    ) -> Option<ChallengeRecord> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let matches = guard.get(token).is_some_and(|record| {
            record.expires_at > now
                && record.domain == domain
                && record.identity == identity
        });
        if matches {
            let result = guard.remove(token);
            if let Some(record) = &result
                && !guard.values().any(|entry| entry.domain == record.domain)
            {
                self.domains
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&record.domain);
            }
            result
        } else {
            if let Some(stale) = guard
                .get(token)
                .filter(|record| record.expires_at <= now)
                .cloned()
            {
                guard.remove(token);
                // A token the client held out for verification is now proven stale:
                // it expired in hand, so it counts here, not only in the issue sweep,
                // attributed to the domain that owned it.
                self.count_expired(&stale.domain, 1);
            }
            None
        }
    }

    pub fn update_attempts(&self, token: &str, attempts: u32) -> bool {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .get_mut(token)
            .map(|record| {
                record.attempts = attempts;
                true
            })
            .unwrap_or(false)
    }

    pub fn increment_attempts(&self, token: &str) -> Option<u32> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let record = guard.get_mut(token)?;
        record.attempts = record.attempts.saturating_add(1);
        Some(record.attempts)
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

pub fn token_id(secret: &[u8], sequence: u64, target: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(secret);
    h.update(sequence.to_be_bytes());
    h.update(target.as_bytes());
    hex::encode(h.finalize())
}

pub fn record(
    target: String,
    domain: String,
    identity: String,
    salt: String,
    difficulty: u8,
    kind: String,
    ttl: Duration,
) -> ChallengeRecord {
    ChallengeRecord {
        domain,
        identity,
        salt,
        difficulty,
        target,
        kind,
        attempts: 0,
        expires_at: SystemTime::now() + ttl,
    }
}

pub fn stateless(
    secret: &[u8],
    domain: &str,
    identity: &str,
    target: &str,
    salt: &str,
    difficulty: u8,
    ttl: Duration,
) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let expires = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_add(ttl.as_secs());
    let payload =
        format!("{expires}|{difficulty}|{domain}|{identity}|{salt}|{target}");
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
        return String::new();
    };
    mac.update(payload.as_bytes());
    format!(
        "st.{}.{}",
        hex::encode(payload.as_bytes()),
        hex::encode(mac.finalize().into_bytes())
    )
}

pub fn parse_stateless(
    secret: &[u8],
    token: &str,
    domain: &str,
    identity: &str,
    now: SystemTime,
) -> Option<ChallengeRecord> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let rest = token.strip_prefix("st.")?;
    let (encoded, tag) = rest.rsplit_once('.')?;
    let payload = String::from_utf8(hex::decode(encoded).ok()?).ok()?;
    let mut parts = payload.splitn(6, '|');
    let expires = parts.next()?.parse::<u64>().ok()?;
    let difficulty = parts.next()?.parse::<u8>().ok()?;
    let token_domain = parts.next()?;
    let token_identity = parts.next()?;
    let salt = parts.next()?;
    let target = parts.next()?;
    let now_secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if token_domain != domain
        || token_identity != identity
        || expires <= now_secs
    {
        return None;
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).ok()?;
    mac.update(payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    if !pingap_core::constant_time_eq(expected.as_bytes(), tag.as_bytes()) {
        return None;
    }
    Some(ChallengeRecord {
        domain: domain.to_string(),
        identity: identity.to_string(),
        salt: salt.to_string(),
        difficulty,
        target: target.to_string(),
        kind: "pow".to_string(),
        attempts: 0,
        expires_at: now + Duration::from_secs(expires.saturating_sub(now_secs)),
    })
}
