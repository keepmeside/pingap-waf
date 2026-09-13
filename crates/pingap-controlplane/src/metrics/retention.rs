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

//! Bounding the tables that only grow.
//!
//! Two of them are prunable and two are not, and the split is not an oversight.
//! `activity_log` and `alert_history` are append-only by decision: the store trait exposes no
//! update and no delete for either, and a test asserts that by reading the trait's own source,
//! because a trigger cannot be relied on here. An audit trail that can be shortened through
//! the same handle that writes it is not an audit trail.
//!
//! So unbounded growth in those two is the accepted cost of that decision, and the reclaim
//! path is `VACUUM INTO` at backup time rather than a sweep. `waf_events` and
//! `performance_metrics` carry no such obligation — one is telemetry and the other is a
//! derived rollup that can be recomputed from the first — and leaving either to grow without
//! limit would eventually make the store the reason the gateway's admin surface stops
//! answering.
//!
//! [`Retention::DEFAULT_WAF_EVENTS`] and its sibling are defaults with no configuration
//! surface behind them yet. There is no config key for a retention window in pingap's model,
//! and inventing one belongs beside the thing that reads it rather than here.

use crate::repository::{ControlPlaneStore, Result};

/// How long each prunable table keeps its rows, in seconds.
///
/// Two fields and not a map, so a table added later is a compile error here rather than a
/// table nobody thought to prune.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    pub waf_events: i64,
    pub performance_metrics: i64,
}

impl Retention {
    /// Seven days of findings.
    ///
    /// Enough to answer "what happened during the incident" and to tune a rule against real
    /// traffic, which is what an operator actually reads this table for. Beyond that the
    /// rollups are the thing to look at, and they are kept far longer.
    pub const DEFAULT_WAF_EVENTS: i64 = 7 * 24 * 3600;

    /// Ninety days of rollups.
    ///
    /// A rollup is small and is the only record left once the findings it summarised are
    /// gone, so it outlives them by a wide margin.
    pub const DEFAULT_PERFORMANCE_METRICS: i64 = 90 * 24 * 3600;
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            waf_events: Self::DEFAULT_WAF_EVENTS,
            performance_metrics: Self::DEFAULT_PERFORMANCE_METRICS,
        }
    }
}

impl Retention {
    /// The cut-off for each table, given the current time.
    ///
    /// Computed here rather than at each call site so the two cannot disagree about whether
    /// the window is inclusive, and so the two degenerate cases have one meaning each. A
    /// negative window is treated as zero — keep nothing — rather than as "keep everything",
    /// which is what subtracting it would produce. And the result is clamped at zero, because
    /// a window longer than the clock's own value would otherwise give a negative cutoff:
    /// `saturating_sub` saturates at `i64::MIN` and not at zero, and a negative timestamp is
    /// not a meaningful bound on a row.
    pub fn cutoffs(&self, now: i64) -> Cutoffs {
        Cutoffs {
            waf_events: now.saturating_sub(self.waf_events.max(0)).max(0),
            performance_metrics: now
                .saturating_sub(self.performance_metrics.max(0))
                .max(0),
        }
    }
}

/// The timestamps before which each table's rows are removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cutoffs {
    pub waf_events: i64,
    pub performance_metrics: i64,
}

/// What one sweep removed.
///
/// Returned rather than logged here, because whether a large number is worth logging is the
/// caller's call — a sweep that removes a million rows on first run after an upgrade is
/// expected, and the same number every hour is not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pruned {
    pub waf_events: u64,
    pub performance_metrics: u64,
}

impl Pruned {
    pub fn total(&self) -> u64 {
        self.waf_events.saturating_add(self.performance_metrics)
    }
}

/// One sweep of both prunable tables.
///
/// Two deletes and no transaction around them: they are independent tables, and holding the
/// process's single writer across both for no reason would delay the config projection and
/// the audit log, which are waiting on the same handle. A sweep interrupted between them
/// leaves one table pruned and the other not, which the next sweep finishes.
pub async fn sweep(
    store: &dyn ControlPlaneStore,
    retention: &Retention,
    now: i64,
) -> Result<Pruned> {
    let cutoffs = retention.cutoffs(now);
    let waf_events = store.prune_waf_events(cutoffs.waf_events).await?;
    let performance_metrics = store
        .prune_performance_metrics(cutoffs.performance_metrics)
        .await?;
    Ok(Pruned {
        waf_events,
        performance_metrics,
    })
}
