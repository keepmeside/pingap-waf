use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Block,
    Redact,
    Detect,
}

impl Verdict {
    pub const fn droppable(self) -> bool {
        matches!(self, Self::Detect)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WafEvent {
    pub node: String,
    pub domain: String,
    pub profile: String,
    pub rule_id: Option<u32>,
    pub category: Option<String>,
    pub severity: Option<String>,
    pub score: u32,
    pub verdict: Verdict,
    pub client_ip: Option<String>,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub created_at: i64,
}

impl WafEvent {
    pub const fn blocked_flag(&self) -> bool {
        matches!(self.verdict, Verdict::Block)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Queued,
    EvictedADetect,
    Counted,
    Dropped,
}

#[derive(Debug, Default)]
pub struct Counters {
    offered: AtomicU64,
    queued: AtomicU64,
    dropped_detect: AtomicU64,
    evicted_detect: AtomicU64,
    counted_enforced: AtomicU64,
    dropped_enforced: AtomicU64,
}

pub struct EventQueue {
    capacity: usize,
    queue: Mutex<VecDeque<WafEvent>>,
    counters: Counters,
}

impl EventQueue {
    pub fn new(capacity: usize) -> Option<Self> {
        (capacity > 0).then(|| Self {
            capacity,
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
            counters: Counters::default(),
        })
    }

    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn offer(&self, event: WafEvent) -> Admission {
        self.counters.offered.fetch_add(1, Ordering::Relaxed);
        let droppable = event.verdict.droppable();
        let admission = {
            let mut queue =
                self.queue.lock().unwrap_or_else(|p| p.into_inner());
            if queue.len() < self.capacity {
                queue.push_back(event);
                Admission::Queued
            } else if droppable {
                Admission::Dropped
            } else if let Some(victim) =
                queue.iter().position(|queued| queued.verdict.droppable())
            {
                queue.remove(victim);
                queue.push_back(event);
                Admission::EvictedADetect
            } else {
                Admission::Counted
            }
        };
        match admission {
            Admission::Queued => {
                self.counters.queued.fetch_add(1, Ordering::Relaxed);
            },
            Admission::Dropped => {
                self.counters.dropped_detect.fetch_add(1, Ordering::Relaxed);
            },
            Admission::EvictedADetect => {
                self.counters.evicted_detect.fetch_add(1, Ordering::Relaxed);
                self.counters.queued.fetch_add(1, Ordering::Relaxed);
            },
            Admission::Counted => {
                self.counters
                    .counted_enforced
                    .fetch_add(1, Ordering::Relaxed);
            },
        };
        admission
    }

    pub fn drain(&self, limit: usize) -> Vec<WafEvent> {
        let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        let count = limit.min(queue.len());
        queue.drain(..count).collect()
    }

    pub fn len(&self) -> usize {
        self.queue.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn offered(&self) -> u64 {
        self.counters.offered.load(Ordering::Relaxed)
    }
    pub fn queued(&self) -> u64 {
        self.counters.queued.load(Ordering::Relaxed)
    }
    pub fn dropped_detect(&self) -> u64 {
        self.counters.dropped_detect.load(Ordering::Relaxed)
    }
    pub fn evicted_detect(&self) -> u64 {
        self.counters.evicted_detect.load(Ordering::Relaxed)
    }
    pub fn counted_enforced(&self) -> u64 {
        self.counters.counted_enforced.load(Ordering::Relaxed)
    }
    pub fn dropped_enforced(&self) -> u64 {
        self.counters.dropped_enforced.load(Ordering::Relaxed)
    }
}

static GLOBAL: OnceLock<Arc<EventQueue>> = OnceLock::new();

pub fn install(queue: Arc<EventQueue>) -> Result<(), Arc<EventQueue>> {
    GLOBAL.set(queue.clone()).map_err(|_| queue)
}

pub fn global() -> Option<Arc<EventQueue>> {
    GLOBAL.get().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_is_missing_before_install_and_rejects_replacement() {
        assert!(global().is_none());
        let first = Arc::new(EventQueue::new(1).expect("positive capacity"));
        assert!(install(first.clone()).is_ok());
        assert!(Arc::ptr_eq(&global().expect("installed queue"), &first));

        let replacement =
            Arc::new(EventQueue::new(2).expect("positive capacity"));
        let rejected = install(replacement.clone())
            .expect_err("replacement must be rejected");
        assert!(Arc::ptr_eq(&rejected, &replacement));
        assert!(Arc::ptr_eq(
            &global().expect("original queue remains"),
            &first
        ));
    }
}
