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

/// Native history has no request payload. Every field is structured metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeKind {
    Detected,
    Created,
    Released,
    Expired,
}
impl NativeKind {
    pub const fn action(self) -> &'static str {
        match self {
            Self::Detected => "native.abuse.detected",
            Self::Created => "native.ban.created",
            Self::Released => "native.ban.released",
            Self::Expired => "native.ban.expired",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NativeActor {
    pub id: Option<String>,
    pub username: String,
}
impl Default for NativeActor {
    fn default() -> Self {
        Self {
            id: None,
            username: "system".into(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NativeLifecycle {
    pub version: u8,
    pub kind: NativeKind,
    pub id: String,
    pub epoch: String,
    pub profile: String,
    pub domain: String,
    pub client_ip: String,
    pub scenario: String,
    pub mode: String,
    pub created_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub observed_at_ms: u64,
    pub actor: NativeActor,
    pub reason: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notification {
    Waf(WafEvent),
    Native(NativeLifecycle),
}
impl Notification {
    fn droppable(&self) -> bool {
        matches!(self, Self::Waf(e) if e.verdict.droppable())
    }
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct NativeBan {
    pub id: String,
    pub epoch: String,
    pub profile: String,
    pub domain: String,
    pub client_ip: String,
    pub scenario: String,
    pub mode: &'static str,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub remaining_ms: u64,
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct NativeBanPage {
    pub epoch: String,
    pub items: Vec<NativeBan>,
    pub next_cursor: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Queued,
    Degraded,
    NotApplicable,
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct NativeRelease {
    pub outcome: &'static str,
    pub audit: AuditStatus,
}
/// Runtime bridge; neither the event transport nor control plane owns detectors.
pub trait NativeAbuse: Send + Sync {
    fn epoch(&self) -> String;
    fn list(
        &self,
        profile: Option<&str>,
        domain: Option<&str>,
        after: u64,
        limit: usize,
    ) -> NativeBanPage;
    fn release(
        &self,
        profile: &str,
        domain: &str,
        ip: &str,
        id: &str,
        actor: NativeActor,
    ) -> NativeRelease;
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
    dropped_lifecycle: AtomicU64,
    dropped_native_detection: AtomicU64,
    queued_lifecycle: AtomicU64,
    write_failures: AtomicU64,
    lifecycle_write_failures: AtomicU64,
}

pub struct EventQueue {
    capacity: usize,
    queue: Mutex<VecDeque<Notification>>,
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
        self.offer_notification(Notification::Waf(event))
    }
    pub fn offer_native(&self, event: NativeLifecycle) -> Admission {
        self.offer_notification(Notification::Native(event))
    }
    pub fn offer_notification(&self, event: Notification) -> Admission {
        self.counters.offered.fetch_add(1, Ordering::Relaxed);
        let native = matches!(event, Notification::Native(_));
        let detection = matches!(&event, Notification::Native(e) if e.kind == NativeKind::Detected);
        let droppable = event.droppable();
        let admission = {
            let mut queue =
                self.queue.lock().unwrap_or_else(|p| p.into_inner());
            if queue.len() < self.capacity {
                queue.push_back(event);
                Admission::Queued
            } else if droppable {
                Admission::Dropped
            } else if let Some(victim) =
                queue.iter().position(Notification::droppable)
            {
                queue.remove(victim);
                queue.push_back(event);
                Admission::EvictedADetect
            } else {
                Admission::Counted
            }
        };
        if native {
            if matches!(
                admission,
                Admission::Queued | Admission::EvictedADetect
            ) {
                self.counters
                    .queued_lifecycle
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                self.counters
                    .dropped_lifecycle
                    .fetch_add(1, Ordering::Relaxed);
                if detection {
                    self.counters
                        .dropped_native_detection
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
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
                if !native {
                    self.counters
                        .counted_enforced
                        .fetch_add(1, Ordering::Relaxed);
                }
            },
        };
        admission
    }

    pub fn drain(&self, limit: usize) -> Vec<WafEvent> {
        let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        let mut events = Vec::new();
        let mut i = 0;
        while i < queue.len() && events.len() < limit {
            if matches!(queue[i], Notification::Waf(_)) {
                if let Some(Notification::Waf(e)) = queue.remove(i) {
                    events.push(e);
                }
            } else {
                i += 1;
            }
        }
        events
    }
    pub fn drain_notifications(&self, limit: usize) -> Vec<Notification> {
        let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        let count = limit.min(queue.len());
        queue.drain(..count).collect()
    }
    pub fn dropped_lifecycle(&self) -> u64 {
        self.counters.dropped_lifecycle.load(Ordering::Relaxed)
    }
    pub fn dropped_native_detection(&self) -> u64 {
        self.counters
            .dropped_native_detection
            .load(Ordering::Relaxed)
    }
    pub fn queued_lifecycle(&self) -> u64 {
        self.counters.queued_lifecycle.load(Ordering::Relaxed)
    }

    pub fn record_write_failure(&self, includes_native: bool) {
        self.counters.write_failures.fetch_add(1, Ordering::Relaxed);
        if includes_native {
            self.counters
                .lifecycle_write_failures
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn write_failures(&self) -> u64 {
        self.counters.write_failures.load(Ordering::Relaxed)
    }
    pub fn lifecycle_write_failures(&self) -> u64 {
        self.counters
            .lifecycle_write_failures
            .load(Ordering::Relaxed)
    }
    pub fn pending_lifecycle(&self) -> usize {
        self.queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|n| matches!(n, Notification::Native(_)))
            .count()
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
