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
use crate::repository::NewActivity;
use pingap_events::{Admission, EventQueue, Notification};
use std::collections::VecDeque;
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
        let mut pending: VecDeque<_> =
            self.queue.drain_notifications(self.batch).into();
        let count = pending.len();
        while let Some(first) = pending.front() {
            let (result, acknowledged) = match first {
                Notification::Waf(_) => {
                    let events: Vec<_> = pending
                        .iter()
                        .take_while(|n| matches!(n, Notification::Waf(_)))
                        .filter_map(|n| {
                            if let Notification::Waf(e) = n {
                                Some(e.clone())
                            } else {
                                None
                            }
                        })
                        .collect();
                    (
                        self.store.record_waf_events(&events).await.map(|_| ()),
                        events.len(),
                    )
                },
                Notification::Native(event) => {
                    let result = async {
                        // The authenticated actor snapshot survives account removal. Keep
                        // the original identity in detail, and only use an extant FK.
                        let actor_id = match event.actor.id.as_deref() {
                            Some(id) => self
                                .store
                                .find_user_by_id(id)
                                .await?
                                .map(|user| user.id),
                            None => None,
                        };
                        let entry = NewActivity {
                            actor_id,
                            actor_username: event.actor.username.clone(),
                            action: event.kind.action().into(),
                            target: event.id.clone(),
                            config_version: None,
                            ip: None,
                            user_agent: None,
                            detail: Some(
                                serde_json::to_string(event)
                                    .expect("typed lifecycle serializes"),
                            ),
                        };
                        self.store
                            .record_activity(
                                entry,
                                (event.observed_at_ms / 1000) as i64,
                            )
                            .await
                            .map(|_| ())
                    }
                    .await;
                    (result, 1)
                },
            };
            if let Err(error) = result {
                self.queue.record_write_failure(
                    pending
                        .iter()
                        .any(|e| matches!(e, Notification::Native(_))),
                );
                let unacknowledged = pending.len();
                let mut restored = 0;
                for event in pending {
                    if !matches!(
                        self.queue.offer_notification(event),
                        Admission::Dropped | Admission::Counted
                    ) {
                        restored += 1;
                    }
                }
                warn!(target:"controlplane::events", batch=count, unacknowledged, restored, lost=unacknowledged-restored, error=%error,
                    "event write failed; unacknowledged notifications returned to bounded queue");
                return Err(error);
            }
            pending.drain(..acknowledged);
        }
        Ok(count)
    }
}
