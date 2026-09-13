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

//! Retention, and the boundary it does not cross.
//!
//! Two tables are prunable and two are append-only, and the interesting assertion here is
//! about the second pair: that nothing on the store trait can shorten them. That is checked in
//! `repository.rs`'s own source-reading test, which now names `prune_activity` and
//! `prune_alert_history` alongside the deletes it already refused — because bounded growth is a
//! real requirement and the obvious way to meet it is a window on the audit trail.

use pingap_controlplane::ControlPlaneStore;
use pingap_controlplane::events::{Verdict, WafEvent};
use pingap_controlplane::metrics::{Retention, sweep};
use pingap_controlplane::repository::WafEventFilter;
use pingap_controlplane::store::TursoStore;
use std::sync::Arc;
use tempfile::TempDir;

async fn migrated() -> (Arc<TursoStore>, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = TursoStore::open(
        dir.path().join("cp.db").to_str().expect("utf-8 path"),
    )
    .await
    .expect("the store opens");
    store.migrate().await.expect("migrations apply");
    (Arc::new(store), dir)
}

fn finding(at: i64) -> WafEvent {
    WafEvent {
        node: "node-a".to_string(),
        domain: "site.test".to_string(),
        profile: "waf:strict".to_string(),
        rule_id: Some(942100),
        category: Some("sql_injection".to_string()),
        severity: Some("critical".to_string()),
        score: 5,
        verdict: Verdict::Block,
        client_ip: Some("203.0.113.7".to_string()),
        method: Some("GET".to_string()),
        uri: Some("/".to_string()),
        created_at: at,
    }
}

#[tokio::test]
async fn a_sweep_removes_what_fell_out_of_the_window() {
    let (store, _dir) = migrated().await;
    let now = 10_000;
    // One inside the window, one exactly on the cutoff, one outside.
    let window = 1_000;
    store
        .record_waf_events(&[
            finding(now),
            finding(now - window),
            finding(now - window - 1),
        ])
        .await
        .expect("the findings write");

    let pruned = sweep(
        store.as_ref(),
        &Retention {
            waf_events: window,
            performance_metrics: window,
        },
        now,
    )
    .await
    .expect("the sweep runs");
    assert_eq!(pruned.waf_events, 1, "the wrong number of rows went");

    let left = store
        .read_waf_events(WafEventFilter::default())
        .await
        .expect("readable");
    assert_eq!(left.len(), 2);
    // Strictly older, so a row exactly at the cutoff stays. That is what makes a sweep
    // idempotent: running it twice at the same `now` removes nothing the second time.
    assert!(
        left.iter().all(|row| row.created_at >= now - window),
        "a row inside the window was removed: {left:?}"
    );

    let again = sweep(
        store.as_ref(),
        &Retention {
            waf_events: window,
            performance_metrics: window,
        },
        now,
    )
    .await
    .expect("the sweep runs");
    assert_eq!(
        again.total(),
        0,
        "a second sweep at the same instant removed more"
    );
}

#[tokio::test]
async fn a_window_of_zero_keeps_nothing() {
    let (store, _dir) = migrated().await;
    store
        .record_waf_events(&[finding(1), finding(2)])
        .await
        .expect("writes");
    let pruned = sweep(
        store.as_ref(),
        &Retention {
            waf_events: 0,
            performance_metrics: 0,
        },
        1_000,
    )
    .await
    .expect("the sweep runs");
    assert_eq!(pruned.waf_events, 2);
    assert!(
        store
            .read_waf_events(WafEventFilter::default())
            .await
            .expect("readable")
            .is_empty()
    );
}

/// The cutoffs saturate rather than wrap.
///
/// `now - window` on a small `now` and a large window is negative, and a negative cutoff
/// passed to `created_at < ?1` deletes nothing at all — the opposite of what a window longer
/// than the clock's own value should mean. Checked here rather than against the store, because
/// it is arithmetic and the store cannot tell the difference.
#[test]
fn cutoffs_saturate_rather_than_go_negative() {
    let retention = Retention {
        waf_events: 1_000,
        performance_metrics: 1_000,
    };
    assert_eq!(retention.cutoffs(10).waf_events, 0);
    assert_eq!(retention.cutoffs(10_000).waf_events, 9_000);
    // A negative window is treated as zero rather than as "keep everything", which is what
    // subtracting it would produce.
    let negative = Retention {
        waf_events: -5,
        performance_metrics: -5,
    };
    assert_eq!(negative.cutoffs(100).waf_events, 100);
}

#[test]
fn the_defaults_outlive_each_other_in_the_right_order() {
    let defaults = Retention::default();
    assert!(
        defaults.performance_metrics > defaults.waf_events,
        "rollups must outlive the findings they summarise, or pruning findings leaves a \
         summary of nothing: {defaults:?}"
    );
    assert!(defaults.waf_events > 0 && defaults.performance_metrics > 0);
}

/// The metrics prune names a real column.
///
/// Nothing writes `performance_metrics` yet — the rollup worker is not built — so this cannot
/// check what is removed. It checks the statement runs against a real migrated table, which is
/// what catches a column that was renamed or never existed: a typo there is a sweep that fails
/// on every run, in a background task nobody reads.
#[tokio::test]
async fn pruning_metrics_runs_against_the_real_table() {
    let (store, _dir) = migrated().await;
    assert_eq!(
        store.prune_performance_metrics(1_000).await.expect("runs"),
        0
    );
}
