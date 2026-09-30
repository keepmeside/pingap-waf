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

//! Draining the queue into the store.
//!
//! The queue decides what survives a burst; this decides how it reaches the store. The two
//! are separate so neither has to know about the other's problem: the queue has no idea a
//! database exists, which is what lets it promise never to block, and this module has no
//! opinion about which findings matter, which is what lets the queue own that policy.
//!
//! The one thing this module adds is a rule the queue cannot express: **a failed write does
//! not lose the batch.** The findings are already out of the queue, so a store error has to
//! put them back or they are gone — and gone silently, which is the exact failure the queue's
//! priority policy exists to prevent. They go back through `offer`, not by splicing the front,
//! because the queue is bounded and a restore that ignored the bound would make the bound
//! meaningless at the moment the store is struggling.

use crate::repository::ControlPlaneStore;
use pingap_events::{Admission, EventQueue};
use std::sync::Arc;
use tracing::warn;

/// How many findings one transaction carries.
///
/// Bounded because the batch is a single transaction and a transaction holds the process's
/// only writer for its whole duration — the same writer the config projection, the audit log
/// and the alert evaluator are waiting on. Large enough that a burst is absorbed in a few
/// round trips rather than hundreds.
pub const DEFAULT_BATCH: usize = 256;

/// The queue, the store, and the batch size that connects them.
pub struct EventWriter {
    queue: Arc<EventQueue>,
    store: Arc<dyn ControlPlaneStore>,
    batch: usize,
}

impl EventWriter {
    pub fn new(
        queue: Arc<EventQueue>,
        store: Arc<dyn ControlPlaneStore>,
    ) -> Self {
        Self {
            queue,
            store,
            batch: DEFAULT_BATCH,
        }
    }

    /// A different batch size. `0` is refused for the same reason a zero-capacity queue is:
    /// it would drain nothing forever and look like a writer that had nothing to do.
    pub fn with_batch(mut self, batch: usize) -> Option<Self> {
        (batch > 0).then(|| {
            self.batch = batch;
            self
        })
    }

    /// Drain one batch and write it. Returns how many findings were stored.
    ///
    /// One round rather than "until empty", so a caller driving this on a timer cannot be
    /// starved by a producer that outpaces the store: it writes a bounded amount, returns,
    /// and the next tick writes the next bounded amount.
    pub async fn flush(&self) -> crate::repository::Result<usize> {
        let batch = self.queue.drain(self.batch);
        if batch.is_empty() {
            return Ok(0);
        }
        let count = batch.len();
        if let Err(error) = self.store.record_waf_events(&batch).await {
            let mut restored = 0usize;
            for event in batch {
                if !matches!(
                    self.queue.offer(event),
                    Admission::Dropped | Admission::Counted
                ) {
                    restored += 1;
                }
            }
            // Both numbers matter and neither is derivable from the other: how many came
            // back says whether the failure cost anything, and the queue's own counters say
            // what it cost. A warning rather than an error because the findings are not lost
            // yet — the next flush retries them — and the store being briefly unreachable is
            // a state this system is required to survive.
            warn!(
                target: "controlplane::events",
                batch = count,
                restored,
                lost = count - restored,
                error = %error,
                "a WAF event batch did not write and was put back"
            );
            return Err(error);
        }
        Ok(count)
    }
}
