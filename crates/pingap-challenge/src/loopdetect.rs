use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type LoopKey = (String, String, String);

#[derive(Debug, Clone)]
pub struct LoopDetector {
    counts: Arc<Mutex<HashMap<LoopKey, u32>>>,
    threshold: u32,
    max_entries: usize,
}

impl LoopDetector {
    pub fn new(threshold: u32) -> Self {
        Self::with_capacity(threshold, 4096)
    }

    pub fn with_capacity(threshold: u32, max_entries: usize) -> Self {
        Self {
            counts: Arc::new(Mutex::new(HashMap::new())),
            threshold: threshold.max(1),
            max_entries: max_entries.max(1),
        }
    }
    pub fn issued(&self, domain: &str, identity: &str, kind: &str) -> u32 {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = (domain.to_string(), identity.to_string(), kind.to_string());
        if !counts.contains_key(&key) && counts.len() >= self.max_entries {
            return self.threshold;
        }
        let count = counts.entry(key).or_default();
        *count = count.saturating_add(1);
        *count
    }
    pub fn solved(&self, domain: &str, identity: &str, kind: &str) {
        self.counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&(
                domain.to_string(),
                identity.to_string(),
                kind.to_string(),
            ));
    }
    pub fn looping(&self, count: u32) -> bool {
        count >= self.threshold
    }
}
