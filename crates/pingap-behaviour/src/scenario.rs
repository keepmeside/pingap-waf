//! Fixed opt-in predicates. No request bodies or credentials enter this module.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Detect,
    Block,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub mode: Mode,
    #[serde(with = "humantime_serde")]
    pub window: Duration,
    pub threshold: usize,
    #[serde(with = "humantime_serde")]
    pub ban_ttl: Duration,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FailedLogin {
    #[serde(flatten)]
    pub rule: Rule,
    pub path: String,
    pub method: String,
    pub statuses: Vec<u16>,
}
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct AbuseConfig {
    #[serde(default)]
    pub enabled: bool,
    pub failed_login: Option<FailedLogin>,
    pub scan: Option<Rule>,
}
impl AbuseConfig {
    pub fn validate(
        &self,
        login_capacity: usize,
        path_capacity: usize,
    ) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.failed_login.is_none() && self.scan.is_none() {
            return Err("abuse requires at least one scenario".into());
        }
        for (rule, capacity) in self
            .failed_login
            .iter()
            .map(|s| (&s.rule, login_capacity))
            .chain(self.scan.iter().map(|s| (s, path_capacity)))
        {
            if rule.window.is_zero()
                || rule.ban_ttl.is_zero()
                || rule.threshold == 0
                || rule.threshold > capacity
            {
                return Err("abuse requires positive window/ban_ttl and threshold within configured scenario capacity".into());
            }
        }
        if let Some(s) = &self.failed_login
            && (!s.path.starts_with('/')
                || s.path.contains('?')
                || s.path.contains('#')
                || http::Method::from_bytes(s.method.as_bytes()).is_err()
                || s.statuses.is_empty()
                || s.statuses.iter().any(|s| !(400..=599).contains(s)))
        {
            return Err("failed_login requires exact path, valid method and explicit upstream failure statuses".into());
        }
        Ok(())
    }
    pub fn enforcing(&self) -> bool {
        self.enabled
            && (self
                .failed_login
                .as_ref()
                .is_some_and(|s| s.rule.mode == Mode::Block)
                || self.scan.as_ref().is_some_and(|s| s.mode == Mode::Block))
    }
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Evidence {
    pub detected: bool,
    pub ban_created: bool,
}
#[derive(Debug, Default)]
pub(crate) struct Counters {
    login: VecDeque<u64>,
    paths: BTreeMap<[u8; 32], u64>,
    login_crossed: bool,
    scan_crossed: bool,
}
pub(crate) fn millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}
pub(crate) fn path_key(path: &str) -> [u8; 32] {
    Sha256::digest(path.split('?').next().unwrap_or(path).as_bytes()).into()
}
impl Counters {
    pub fn observe(
        &mut self,
        config: &AbuseConfig,
        now: u64,
        login: bool,
        path: [u8; 32],
        status: u16,
    ) -> Vec<(&'static str, Mode, Duration)> {
        let mut crossings = Vec::new();
        if let Some(s) = &config.failed_login {
            let lower = now.saturating_sub(millis(s.rule.window));
            while self.login.front().is_some_and(|at| *at < lower) {
                self.login.pop_front();
            }
            if self.login.len() < s.rule.threshold {
                self.login_crossed = false;
            }
            if login && s.statuses.contains(&status) {
                if self.login.len() == s.rule.threshold {
                    self.login.pop_front();
                }
                self.login.push_back(now);
                if self.login.len() >= s.rule.threshold && !self.login_crossed {
                    self.login_crossed = true;
                    crossings.push((
                        "failed_login",
                        s.rule.mode,
                        s.rule.ban_ttl,
                    ));
                }
            }
        }
        if let Some(s) = &config.scan {
            let lower = now.saturating_sub(millis(s.window));
            self.paths.retain(|_, at| *at >= lower);
            if self.paths.len() < s.threshold {
                self.scan_crossed = false;
            }
            if status == 404 {
                // Only threshold distinct paths are needed to prove a crossing. At
                // capacity keep the most recent distinct evidence, never a raw URL.
                if !self.paths.contains_key(&path)
                    && self.paths.len() >= s.threshold
                    && let Some(old) = self
                        .paths
                        .iter()
                        .min_by_key(|(_, at)| **at)
                        .map(|(key, _)| *key)
                {
                    self.paths.remove(&old);
                }
                self.paths.insert(path, now);
                if self.paths.len() >= s.threshold && !self.scan_crossed {
                    self.scan_crossed = true;
                    crossings.push(("scan", s.mode, s.ban_ttl));
                }
            }
        }
        crossings
    }
}
