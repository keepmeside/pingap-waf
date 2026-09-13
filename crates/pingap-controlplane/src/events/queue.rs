// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The bounded queue between a request and the store.
//!
//! A WAF finding is produced on the request path and consumed by a writer that batches it
//! into the store. The two run at very different speeds — detection is microseconds and a
//! batched insert is milliseconds — so something has to absorb the difference, and whatever
//! it is has to decide what to do when it is full.
//!
//! That decision is the whole content of this module. An undifferentiated drop-on-full queue
//! discards whatever arrives when it is full, and the queue fills precisely during a
//! volumetric attack, when findings spike and are most worth keeping. So the naive policy
//! loses the security record exactly when it matters, which is also the failure this codebase
//! treats as worst: a silent loss of the evidence that something happened.
//!
//! The policy here is that **a finding which stopped or altered a request is never
//! discarded.** A `detect` is droppable and is dropped; a `block` or `redact` displaces a
//! queued `detect` to get in, and when the queue is full of nothing but those, the overflow is
//! counted rather than stored individually. Counted is coarser than stored, but it is a
//! number an operator can see move, and a discarded record is neither.
//!
//! Nothing here blocks. Every method takes a lock, does bounded work, and returns; a slow
//! store cannot stall a request through this queue, and a full one cannot either.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

/// What the WAF decided, for the purposes of the drop policy.
///
/// Separate from what the `waf_events` table stores, which is a single `blocked` flag. A
/// redaction altered the response and is worth as much as a block here; the table cannot yet
/// tell them apart, and mapping both onto one column loses that on the way in. Widening the
/// column is a migration, and until then the distinction lives in the queue, which is the
/// only place it changes a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The request was refused.
    Block,
    /// The response was rewritten to suppress a leak.
    Redact,
    /// Observed and scored, not enforced.
    Detect,
}

impl Verdict {
    /// Whether losing this record is acceptable.
    ///
    /// The one predicate the whole policy rests on, so it is named rather than inlined: a
    /// `block` and a `redact` both mean the gateway did something, and an audit trail that
    /// cannot say what it did is not one.
    pub const fn droppable(self) -> bool {
        matches!(self, Self::Detect)
    }
}

/// One WAF finding, in the shape the `waf_events` table stores it.
///
/// No `id`: the store assigns it, so two producers cannot collide on a key. `rule_id`,
/// `category` and `severity` are optional because a finding can come from an operator's custom
/// rule or from an aggregate score with no single rule behind it, and inventing a placeholder
/// would put a number in the log that means nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WafEvent {
    /// Which node produced this. Peers share a store, so an event with no node on it cannot
    /// be attributed after the fact.
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
    /// Unix seconds, supplied by the caller. Taken as an argument rather than read from the
    /// clock here so a test can pin it, which is the same reason the store's methods take one.
    pub created_at: i64,
}

impl WafEvent {
    /// The `blocked` column's value.
    ///
    /// A redaction is recorded as not-blocked, which is a loss — see [`Verdict`]. It is
    /// recorded here rather than at the write site so there is one place that knows.
    pub const fn blocked_flag(&self) -> bool {
        matches!(self.verdict, Verdict::Block)
    }
}

/// What the queue did with an offered event.
///
/// Returned rather than swallowed because the caller is the only one who can log it, and
/// because a policy this deliberate should be observable at the point it fires rather than
/// only in aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// There was room.
    Queued,
    /// There was no room, so a queued `detect` was discarded to make some. The offered event
    /// is in the queue.
    EvictedADetect,
    /// The queue was full of events that may not be discarded, so this one is counted instead
    /// of stored. Not a drop, and not stored either — the distinction matters and is why this
    /// is its own variant.
    Counted,
    /// Discarded. Only ever returned for a [`Verdict::Detect`].
    Dropped,
}

/// What the queue has done over its lifetime.
///
/// Every counter is relaxed: they are observability, not synchronisation, and a reader seeing
/// a slightly stale value learns nothing false. The one that matters is `dropped_enforced`,
/// which no code path increments — see [`EventQueue::dropped_enforced`].
#[derive(Debug, Default)]
pub struct Counters {
    offered: AtomicU64,
    queued: AtomicU64,
    dropped_detect: AtomicU64,
    evicted_detect: AtomicU64,
    counted_enforced: AtomicU64,
    dropped_enforced: AtomicU64,
}

impl Counters {
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// A lock that cannot poison the process.
///
/// A panic while the lock is held would otherwise make every subsequent request fail on a
/// queue that is fine. Taking the inner value out of a poisoned lock is safe here because
/// nothing in this module holds an invariant across a yield point: the `VecDeque` is either
/// consistent or it is not, and a panic between two statements leaves it consistent.
fn lock(
    queue: &Mutex<VecDeque<WafEvent>>,
) -> MutexGuard<'_, VecDeque<WafEvent>> {
    queue
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The bounded queue.
///
/// Fixed capacity, set at construction and never grown: a queue that grows under load is a
/// memory leak with a delay, and the point of a bound is that the process's worst case is
/// known.
pub struct EventQueue {
    capacity: usize,
    queue: Mutex<VecDeque<WafEvent>>,
    counters: Counters,
}

impl EventQueue {
    /// A queue holding at most `capacity` events.
    ///
    /// `capacity` of zero is refused rather than accepted, because a zero-capacity queue
    /// would discard or count every event including blocks, and the invariant this module
    /// exists to hold would be false from construction. A caller that wants no queue should
    /// not build one.
    pub fn new(capacity: usize) -> Option<Self> {
        (capacity > 0).then(|| Self {
            capacity,
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
            counters: Counters::default(),
        })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Offer an event. Never blocks, never fails, never grows the queue past capacity.
    pub fn offer(&self, event: WafEvent) -> Admission {
        Counters::bump(&self.counters.offered);
        let droppable = event.verdict.droppable();
        let admission = {
            let mut queue = lock(&self.queue);
            if queue.len() < self.capacity {
                queue.push_back(event);
                Admission::Queued
            } else if droppable {
                Admission::Dropped
            } else if let Some(victim) =
                queue.iter().position(|queued| queued.verdict.droppable())
            {
                // The oldest droppable event, not the newest: a finding that has been waiting
                // longest is the one closest to being written, but it is also the stalest,
                // and keeping the queue's contents as recent as possible is worth more during
                // the attack that filled it.
                queue.remove(victim);
                queue.push_back(event);
                Admission::EvictedADetect
            } else {
                Admission::Counted
            }
        };
        match admission {
            Admission::Queued => Counters::bump(&self.counters.queued),
            Admission::Dropped => Counters::bump(&self.counters.dropped_detect),
            Admission::EvictedADetect => {
                Counters::bump(&self.counters.evicted_detect);
                Counters::bump(&self.counters.queued);
            },
            Admission::Counted => {
                Counters::bump(&self.counters.counted_enforced)
            },
        }
        admission
    }

    /// Take up to `limit` events for writing, oldest first.
    ///
    /// Removed from the queue rather than peeked: the writer is the only consumer, and a
    /// batch that failed to write is the writer's to retry or account for, not the queue's to
    /// hold. Holding it would mean a slow store silently shrinks the space available to
    /// requests, which is backpressure by another name.
    pub fn drain(&self, limit: usize) -> Vec<WafEvent> {
        let mut queue = lock(&self.queue);
        let count = limit.min(queue.len());
        queue.drain(..count).collect()
    }

    pub fn len(&self) -> usize {
        lock(&self.queue).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Events offered.
    pub fn offered(&self) -> u64 {
        self.counters.offered.load(Ordering::Relaxed)
    }

    /// Events admitted to the queue, including ones that displaced a `detect`.
    pub fn queued(&self) -> u64 {
        self.counters.queued.load(Ordering::Relaxed)
    }

    /// `detect` findings discarded because the queue was full.
    pub fn dropped_detect(&self) -> u64 {
        self.counters.dropped_detect.load(Ordering::Relaxed)
    }

    /// `detect` findings discarded to make room for one that could not be.
    ///
    /// Reported separately from [`Self::dropped_detect`] because they answer different
    /// questions: this one is the cost of the priority policy, and a rise in it means blocks
    /// are arriving faster than the writer drains them.
    pub fn evicted_detect(&self) -> u64 {
        self.counters.evicted_detect.load(Ordering::Relaxed)
    }

    /// Enforced findings counted rather than stored individually.
    ///
    /// The degradation path. Non-zero means the writer cannot keep up with blocks, which is a
    /// capacity problem worth an alert, and the number says how much detail was lost.
    pub fn counted_enforced(&self) -> u64 {
        self.counters.counted_enforced.load(Ordering::Relaxed)
    }

    /// Enforced findings discarded outright. **No code path increments this.**
    ///
    /// It exists so the invariant is instrumented rather than assumed. `offer` has three
    /// outcomes for an enforced event — queued, admitted by eviction, or counted — and none
    /// of them loses it, so this is zero by construction today. The reason to expose a
    /// counter that cannot move is that the next person to add a drop path adds it here, and
    /// the test that drives this queue past capacity and asserts zero is already written: it
    /// fails at the moment the invariant stops holding rather than at the moment someone
    /// remembers to ask.
    pub fn dropped_enforced(&self) -> u64 {
        self.counters.dropped_enforced.load(Ordering::Relaxed)
    }
}
