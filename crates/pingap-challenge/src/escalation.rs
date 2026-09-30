use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EscalationState {
    pub failures: u32,
    pub successes: u32,
    pub level: u8,
    pub last: Option<Instant>,
}

#[derive(Debug, Clone)]
pub struct Escalator {
    inner: Arc<Mutex<HashMap<(String, String), EscalationState>>>,
    max: usize,
}

impl Escalator {
    pub fn new(max: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max: max.max(1),
        }
    }
    pub fn failure(
        &self,
        domain: &str,
        identity: &str,
        ladder: &[u8],
        decay: Duration,
    ) -> EscalationState {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = (domain.to_string(), identity.to_string());
        if map.len() >= self.max && !map.contains_key(&key) {
            return EscalationState::default();
        }
        let state = map.entry(key).or_default();
        decay_state_at(state, decay, Instant::now());
        state.failures = state.failures.saturating_add(1);
        state.level = ladder
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, threshold)| {
                (state.failures >= u32::from(*threshold)).then_some(index as u8)
            })
            .unwrap_or(0);
        state.last = Some(Instant::now());
        *state
    }
    pub fn success(
        &self,
        domain: &str,
        identity: &str,
        decay: Duration,
    ) -> EscalationState {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(state) =
            map.get_mut(&(domain.to_string(), identity.to_string()))
        else {
            return EscalationState::default();
        };
        decay_state_at(state, decay, Instant::now());
        state.successes = state.successes.saturating_add(1);
        state.level = state.level.saturating_sub(1);
        state.last = Some(Instant::now());
        *state
    }
    pub fn get(
        &self,
        domain: &str,
        identity: &str,
        decay: Duration,
    ) -> EscalationState {
        self.get_at(domain, identity, decay, Instant::now())
    }

    /// `get` against an explicit instant. Exists so the decay path is testable
    /// with an injected clock instead of a sleeping test.
    pub fn get_at(
        &self,
        domain: &str,
        identity: &str,
        decay: Duration,
        now: Instant,
    ) -> EscalationState {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(state) =
            map.get_mut(&(domain.to_string(), identity.to_string()))
        else {
            return EscalationState::default();
        };
        decay_state_at(state, decay, now);
        *state
    }
}

fn decay_state_at(state: &mut EscalationState, decay: Duration, now: Instant) {
    if state
        .last
        .is_some_and(|last| now.saturating_duration_since(last) >= decay)
    {
        state.level = 0;
        state.failures = 0;
    }
}
