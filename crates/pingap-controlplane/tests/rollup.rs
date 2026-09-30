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

//! The rollup, as arithmetic and then as rows.
//!
//! The aggregation is a pure function over a slice, so the interesting assertions are about
//! what it decides to emit and what it decides not to. An absent row has to mean "nothing
//! fired" and not "not measured", or a dashboard showing a quiet minute is indistinguishable
//! from one showing a gap.

use pingap_controlplane::ControlPlaneStore;
use pingap_controlplane::metrics::{DEFAULT_BUCKET_SECS, bucket_start, rollup};
use pingap_controlplane::repository::{
    NewPerformanceMetric, TimeRange, WafEventRecord,
};
use pingap_controlplane::store::TursoStore;
use std::sync::Arc;
use tempfile::TempDir;

fn record(
    rule_id: Option<u32>,
    category: Option<&str>,
    blocked: bool,
    at: i64,
) -> WafEventRecord {
    WafEventRecord {
        id: String::new(),
        node: "node-a".to_string(),
        domain: "site.test".to_string(),
        profile: "waf:strict".to_string(),
        rule_id,
        category: category.map(str::to_string),
        severity: Some("critical".to_string()),
        score: 5,
        blocked,
        client_ip: None,
        method: None,
        uri: None,
        created_at: at,
    }
}

/// The rows for one metric name, keyed by bucket.
fn series(rows: &[NewPerformanceMetric], name: &str) -> Vec<(i64, f64)> {
    rows.iter()
        .filter(|row| row.metric == name)
        .map(|row| (row.bucket_start, row.value))
        .collect()
}

#[test]
fn a_bucket_start_is_floor_aligned_to_the_epoch() {
    assert_eq!(bucket_start(0, 60), 0);
    assert_eq!(bucket_start(59, 60), 0);
    assert_eq!(bucket_start(60, 60), 60);
    assert_eq!(bucket_start(61, 60), 60);
    // Flooring rather than truncating division: a negative timestamp truncates toward zero
    // and lands in the bucket *after* the one it belongs in. Nothing writes one, and the
    // arithmetic should not depend on that.
    assert_eq!(bucket_start(-1, 60), -60);
    assert_eq!(bucket_start(-61, 60), -120);
    // A non-positive width would divide by zero; every timestamp is its own bucket instead.
    assert_eq!(bucket_start(123, 0), 123);
}

#[test]
fn findings_are_grouped_by_bucket_and_counted_by_what_they_were() {
    let events = vec![
        record(Some(942100), Some("sql_injection"), true, 1_000),
        record(Some(942100), Some("sql_injection"), false, 1_010),
        record(Some(941110), Some("xss"), true, 1_020),
        // A later bucket.
        record(
            Some(942100),
            Some("sql_injection"),
            true,
            1_000 + DEFAULT_BUCKET_SECS,
        ),
    ];
    let rows = rollup(&events, DEFAULT_BUCKET_SECS, "node-a");

    let first = bucket_start(1_000, DEFAULT_BUCKET_SECS);
    let second = first + DEFAULT_BUCKET_SECS;

    // 1020 is exactly on a bucket edge, so it opens the next bucket rather than joining the
    // one 1000 and 1010 are in. Asserted with the values spelled out per bucket below,
    // because getting this wrong is the difference between a rollup test that checks the
    // aggregation and one that checks my arithmetic.
    assert_eq!(
        series(&rows, "waf.findings"),
        vec![(first, 2.0), (second, 2.0)]
    );
    assert_eq!(
        series(&rows, "waf.blocks"),
        vec![(first, 1.0), (second, 2.0)]
    );
    assert_eq!(
        series(&rows, "waf.rule.942100"),
        vec![(first, 2.0), (second, 1.0)]
    );
    assert_eq!(series(&rows, "waf.rule.941110"), vec![(second, 1.0)]);
    assert_eq!(
        series(&rows, "waf.category.sql_injection"),
        vec![(first, 2.0), (second, 1.0)]
    );
    assert_eq!(series(&rows, "waf.category.xss"), vec![(second, 1.0)]);

    // Every row carries the node, because peers share a store and a total that silently
    // mixes two nodes is a number nobody can act on.
    assert!(rows.iter().all(|row| row.node == "node-a"));
    assert!(
        rows.iter()
            .all(|row| row.bucket_secs == DEFAULT_BUCKET_SECS)
    );
}

/// A rule that did not fire gets no row.
///
/// Sparse by construction, and it is what makes a per-rule breakdown affordable at one-minute
/// buckets: cardinality tracks activity rather than the size of the ruleset. The corollary is
/// the one worth stating, because it is the thing a reader of the output has to know — an
/// absent row means nothing fired, not that the bucket was not measured.
#[test]
fn a_rule_that_did_not_fire_has_no_row() {
    let rows = rollup(
        &[record(Some(942100), Some("sql_injection"), true, 1_000)],
        DEFAULT_BUCKET_SECS,
        "node-a",
    );
    assert!(series(&rows, "waf.rule.942100").len() == 1);
    assert!(
        rows.iter().all(|row| row.metric != "waf.rule.941110"),
        "a rule that never fired still produced a row: {:?}",
        rows.iter().map(|r| &r.metric).collect::<Vec<_>>()
    );
    // The totals are always present, so a bucket is distinguishable from a gap.
    assert_eq!(series(&rows, "waf.findings").len(), 1);
    assert_eq!(series(&rows, "waf.blocks").len(), 1);
}

/// A finding with no single rule behind it still counts.
///
/// An aggregate score or an operator's rule that did not declare a category produces a finding
/// with nothing to attribute it to. Counting it in the totals and in neither derived family is
/// the honest answer; inventing an ID would put a number in a metric name that means nothing.
#[test]
fn an_unattributed_finding_counts_in_the_totals_only() {
    let rows = rollup(
        &[record(None, None, true, 1_000)],
        DEFAULT_BUCKET_SECS,
        "node-a",
    );
    assert_eq!(series(&rows, "waf.findings"), vec![(960, 1.0)]);
    assert_eq!(series(&rows, "waf.blocks"), vec![(960, 1.0)]);
    assert_eq!(
        rows.iter()
            .filter(|row| row.metric.starts_with("waf.rule."))
            .count(),
        0
    );
    assert_eq!(
        rows.iter()
            .filter(|row| row.metric.starts_with("waf.category."))
            .count(),
        0
    );
}

#[test]
fn nothing_to_roll_up_produces_nothing() {
    assert!(rollup(&[], DEFAULT_BUCKET_SECS, "node-a").is_empty());
    // A non-positive width falls back to the default rather than dividing by zero, which is
    // the case that would otherwise panic in a background job nobody is watching.
    let rows = rollup(&[record(None, None, false, 1_000)], 0, "node-a");
    assert_eq!(
        rows.first().expect("a row").bucket_secs,
        DEFAULT_BUCKET_SECS
    );
}

// ---- and then as rows -----------------------------------------------------------

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

fn row(metric: &str, value: f64, bucket_start: i64) -> NewPerformanceMetric {
    NewPerformanceMetric {
        node: "node-a".to_string(),
        metric: metric.to_string(),
        value,
        bucket_start,
        bucket_secs: DEFAULT_BUCKET_SECS,
    }
}

#[tokio::test]
async fn a_rollup_round_trips_oldest_bucket_first() {
    let (store, _dir) = migrated().await;
    store
        .record_performance_metrics(&[
            row("waf.findings", 3.0, 1_200),
            row("waf.blocks", 2.0, 1_200),
            row("waf.findings", 1.0, 1_140),
        ])
        .await
        .expect("the batch writes");

    let rows = store
        .read_performance_metrics(None, TimeRange::default())
        .await
        .expect("readable");
    assert_eq!(rows.len(), 3);
    // A series, so oldest first — unlike every other read here, which is newest first. A
    // caller drawing a chart wants the order it happened in rather than having to reverse it.
    assert_eq!(
        rows.iter().map(|r| r.bucket_start).collect::<Vec<_>>(),
        vec![1_140, 1_200, 1_200]
    );
    let first = &rows[0];
    assert_eq!(first.metric, "waf.findings");
    assert_eq!(first.value, 1.0);
    assert_eq!(first.node, "node-a");
    assert_eq!(first.bucket_secs, DEFAULT_BUCKET_SECS);
    assert!(!first.id.is_empty(), "the store assigns a primary key");

    // Narrowing to one name, which is how a chart asks for one series.
    let blocks = store
        .read_performance_metrics(Some("waf.blocks"), TimeRange::default())
        .await
        .expect("readable");
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].value, 2.0);
}

/// A whole number stored in a `REAL` column comes back as an integer.
///
/// SQLite does not coerce, so a count of exactly 3 is `Integer(3)` and a mean of 3.5 is
/// `Real(3.5)`. Rejecting the first would make the common case — a count — unreadable, and
/// the failure would look like missing data rather than a decoder that is too strict.
#[tokio::test]
async fn a_whole_number_in_a_real_column_still_reads() {
    let (store, _dir) = migrated().await;
    store
        .record_performance_metrics(&[row("waf.findings", 7.0, 1_000)])
        .await
        .expect("writes");
    let rows = store
        .read_performance_metrics(None, TimeRange::default())
        .await
        .expect("readable");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].value, 7.0,
        "a whole count did not survive the round trip"
    );
}

#[tokio::test]
async fn an_empty_rollup_writes_nothing() {
    let (store, _dir) = migrated().await;
    store
        .record_performance_metrics(&[])
        .await
        .expect("nothing to write is not an error");
    assert!(
        store
            .read_performance_metrics(None, TimeRange::default())
            .await
            .expect("readable")
            .is_empty()
    );
}

#[tokio::test]
async fn non_finite_rollup_values_are_rejected_before_writing() {
    let (store, _dir) = migrated().await;
    let error = store
        .record_performance_metrics(&[row("waf.findings", f64::NAN, 1_000)])
        .await
        .expect_err("NaN is not a metric value");
    assert!(error.to_string().contains("finite"), "{error}");
    assert!(
        store
            .read_performance_metrics(None, TimeRange::default())
            .await
            .expect("readable")
            .is_empty()
    );
}

#[tokio::test]
async fn non_finite_rollup_values_are_rejected_without_partial_batches() {
    let (store, _dir) = migrated().await;
    let error = store
        .record_performance_metrics(&[
            row("waf.findings", 1.0, 1_000),
            row("waf.blocks", f64::INFINITY, 1_000),
        ])
        .await
        .expect_err("infinite values are not metrics");
    assert!(error.to_string().contains("finite"), "{error}");
    assert!(
        store
            .read_performance_metrics(None, TimeRange::default())
            .await
            .expect("readable")
            .is_empty()
    );
}

/// The end of the pipeline: findings in, a rollup written, and a series read back.
///
/// Not a test of either half, which have their own — this is the seam, where a metric name
/// spelled differently on the way in and the way out would show up as an empty chart rather
/// than as a failure.
#[tokio::test]
async fn findings_rolled_up_and_read_back_are_the_same_series() {
    let (store, _dir) = migrated().await;
    let events = [
        record(Some(942100), Some("sql_injection"), true, 5_000),
        record(Some(942100), Some("sql_injection"), true, 5_010),
        record(Some(941110), Some("xss"), false, 5_020),
    ];
    // The findings go in through the write path and come back out as records, so the rollup
    // runs on what the store holds rather than on what the test constructed.
    let findings = events
        .iter()
        .map(|event| pingap_controlplane::events::WafEvent {
            node: event.node.clone(),
            domain: event.domain.clone(),
            profile: event.profile.clone(),
            rule_id: event.rule_id,
            category: event.category.clone(),
            severity: event.severity.clone(),
            score: event.score,
            verdict: if event.blocked {
                pingap_controlplane::events::Verdict::Block
            } else {
                pingap_controlplane::events::Verdict::Detect
            },
            client_ip: event.client_ip.clone(),
            method: event.method.clone(),
            uri: event.uri.clone(),
            created_at: event.created_at,
        })
        .collect::<Vec<_>>();
    store
        .record_waf_events(&findings)
        .await
        .expect("findings write");

    let stored = store
        .read_waf_events(Default::default())
        .await
        .expect("readable");
    let rolled = rollup(&stored, DEFAULT_BUCKET_SECS, "node-a");
    assert!(!rolled.is_empty(), "three findings produced no rollup");
    store
        .record_performance_metrics(&rolled)
        .await
        .expect("writes");

    let blocks = store
        .read_performance_metrics(Some("waf.blocks"), TimeRange::default())
        .await
        .expect("readable");
    assert_eq!(blocks.len(), 1, "{blocks:?}");
    assert_eq!(blocks[0].value, 2.0, "two of the three were enforced");

    let findings_row = store
        .read_performance_metrics(Some("waf.findings"), TimeRange::default())
        .await
        .expect("readable");
    assert_eq!(findings_row[0].value, 3.0);
}
