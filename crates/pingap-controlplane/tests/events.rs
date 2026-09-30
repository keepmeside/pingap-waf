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

//! The queue's drop policy, under the load it exists for.
//!
//! The property under test is not "the queue works" but "a finding that stopped or altered a
//! request is never discarded, however full the queue is". That is the invariant an
//! undifferentiated drop-on-full queue violates, and it fails in the exact conditions that
//! make the record worth keeping: the queue fills during a volumetric attack, when enforced
//! findings spike.
//!
//! Everything here is single-threaded on purpose. The policy is a decision about ordering and
//! capacity, and a test that needed concurrency to make its point would be testing the lock
//! rather than the policy.

use pingap_controlplane::events::{Admission, EventQueue, Verdict, WafEvent};

fn event(verdict: Verdict, at: i64) -> WafEvent {
    WafEvent {
        node: "node-a".to_string(),
        domain: "site.test".to_string(),
        profile: "waf:strict".to_string(),
        rule_id: Some(942100),
        category: Some("sql_injection".to_string()),
        severity: Some("critical".to_string()),
        score: 5,
        verdict,
        client_ip: Some("203.0.113.7".to_string()),
        method: Some("GET".to_string()),
        uri: Some("/".to_string()),
        created_at: at,
    }
}

#[test]
fn a_queue_of_zero_capacity_is_refused() {
    // Not a degenerate case to tolerate: a zero-capacity queue discards or counts every
    // event including blocks, so the invariant this module exists to hold would be false
    // from construction. A caller that wants no queue should not build one.
    assert!(EventQueue::new(0).is_none());
    assert!(EventQueue::new(1).is_some());
}

#[test]
fn a_detect_finding_that_does_not_fit_is_dropped() {
    let queue = EventQueue::new(3).expect("a capacity of three is valid");
    for index in 0..3 {
        assert_eq!(
            queue.offer(event(Verdict::Detect, index)),
            Admission::Queued
        );
    }
    assert_eq!(queue.len(), 3);

    for index in 3..7 {
        assert_eq!(
            queue.offer(event(Verdict::Detect, index)),
            Admission::Dropped,
            "a full queue admitted a detect finding"
        );
    }
    assert_eq!(queue.len(), 3, "the queue grew past its capacity");
    assert_eq!(queue.dropped_detect(), 4);
    assert_eq!(queue.dropped_enforced(), 0);
}

/// The policy, in the case it exists for: blocks arriving into a queue full of detects.
#[test]
fn a_block_displaces_a_queued_detect_rather_than_being_lost() {
    let queue = EventQueue::new(2).expect("valid");
    assert_eq!(queue.offer(event(Verdict::Detect, 1)), Admission::Queued);
    assert_eq!(queue.offer(event(Verdict::Detect, 2)), Admission::Queued);

    assert_eq!(
        queue.offer(event(Verdict::Block, 3)),
        Admission::EvictedADetect,
        "a block was turned away by a queue of droppable findings"
    );

    let drained = queue.drain(10);
    assert_eq!(drained.len(), 2);
    // Oldest first, and the evicted one is the oldest detect rather than the newest: the
    // queue keeps the most recent findings it can, which is what an operator triaging an
    // attack in progress needs.
    assert_eq!(drained[0].created_at, 2);
    assert_eq!(drained[0].verdict, Verdict::Detect);
    assert_eq!(drained[1].created_at, 3);
    assert_eq!(drained[1].verdict, Verdict::Block);
    assert_eq!(queue.evicted_detect(), 1);
    assert_eq!(queue.dropped_detect(), 0, "an eviction is not a drop");
    assert_eq!(queue.dropped_enforced(), 0);
}

#[test]
fn a_redaction_is_protected_the_same_way_a_block_is() {
    // A redaction altered the response: a leak was suppressed. Losing that record is losing
    // the evidence that the gateway did something, which is the same loss as a dropped block.
    let queue = EventQueue::new(1).expect("valid");
    assert_eq!(queue.offer(event(Verdict::Detect, 1)), Admission::Queued);
    assert_eq!(
        queue.offer(event(Verdict::Redact, 2)),
        Admission::EvictedADetect
    );
    assert_eq!(queue.drain(10)[0].verdict, Verdict::Redact);
    assert_eq!(queue.dropped_enforced(), 0);
}

/// The degradation path, and the assertion that it is not a drop.
#[test]
fn a_queue_full_of_blocks_counts_the_overflow_instead_of_discarding_it() {
    let queue = EventQueue::new(2).expect("valid");
    assert_eq!(queue.offer(event(Verdict::Block, 1)), Admission::Queued);
    assert_eq!(queue.offer(event(Verdict::Block, 2)), Admission::Queued);

    // Nothing droppable left, so there is nothing to displace. The event is counted: coarser
    // than a stored row, but a number an operator can see move, where a discarded record is
    // invisible by definition.
    for index in 3..8 {
        assert_eq!(
            queue.offer(event(Verdict::Block, index)),
            Admission::Counted,
            "an enforced finding was silently turned away"
        );
    }
    assert_eq!(queue.counted_enforced(), 5);
    assert_eq!(queue.dropped_enforced(), 0);
    assert_eq!(queue.len(), 2, "the queue grew past its capacity");
}

/// Conservation, which is the invariant stated positively.
///
/// Every enforced finding offered is either in the queue or counted. Asserted by draining and
/// comparing against the offered total, because a counter that only ever rises proves nothing
/// on its own — it has to add up against what actually came out.
#[test]
fn every_enforced_finding_offered_is_either_queued_or_counted() {
    let queue = EventQueue::new(4).expect("valid");
    // Ten droppable findings, then five enforced ones into a queue of four.
    for index in 0..10 {
        queue.offer(event(Verdict::Detect, index));
    }
    // Five enforced findings into a queue that by now holds nothing droppable.
    let blocks_offered: u64 = 5;
    for index in 100..105 {
        queue.offer(event(Verdict::Block, index));
    }

    let drained = queue.drain(usize::MAX);
    let blocks_queued = drained
        .iter()
        .filter(|event| event.verdict == Verdict::Block)
        .count() as u64;
    assert_eq!(
        blocks_queued + queue.counted_enforced(),
        blocks_offered,
        "enforced findings went missing: {} queued, {} counted, {} offered",
        blocks_queued,
        queue.counted_enforced(),
        blocks_offered
    );
    assert_eq!(queue.dropped_enforced(), 0);
    // And the droppable ones absorbed the pressure, which is what the priority is for.
    assert_eq!(queue.dropped_detect(), 6);
    assert_eq!(queue.evicted_detect(), 4);
    assert_eq!(blocks_queued, 4, "the queue should be all blocks by now");
}

#[test]
fn draining_frees_capacity_and_takes_oldest_first() {
    let queue = EventQueue::new(3).expect("valid");
    for index in 0..3 {
        queue.offer(event(Verdict::Detect, index));
    }
    assert_eq!(queue.offer(event(Verdict::Detect, 9)), Admission::Dropped);

    // A partial drain, which is what a batch writer does: take a bounded chunk, write it,
    // come back. The queue must be usable again immediately, not only once fully emptied.
    let batch = queue.drain(2);
    assert_eq!(batch.len(), 2);
    assert_eq!(
        batch
            .iter()
            .map(|event| event.created_at)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert_eq!(queue.len(), 1);

    assert_eq!(
        queue.offer(event(Verdict::Detect, 10)),
        Admission::Queued,
        "a drained queue did not accept new events"
    );
    assert_eq!(queue.len(), 2);

    // A drain larger than the queue takes what is there and no more.
    assert_eq!(queue.drain(100).len(), 2);
    assert!(queue.is_empty());
    assert!(queue.drain(100).is_empty());
}

#[test]
fn the_blocked_flag_collapses_a_redaction_and_that_is_recorded() {
    // The `waf_events` table has one `blocked` column, so a redaction is stored as not
    // blocked. That is a real loss of fidelity and it is asserted here rather than left
    // implicit, so widening the column is a decision someone makes on purpose.
    assert!(event(Verdict::Block, 1).blocked_flag());
    assert!(!event(Verdict::Redact, 1).blocked_flag());
    assert!(!event(Verdict::Detect, 1).blocked_flag());
    // The queue's own policy does not share the collapse.
    assert!(!Verdict::Redact.droppable());
    assert!(Verdict::Detect.droppable());
}

#[test]
fn the_counters_account_for_everything_offered() {
    let queue = EventQueue::new(2).expect("valid");
    queue.offer(event(Verdict::Detect, 1)); // queued
    queue.offer(event(Verdict::Detect, 2)); // queued
    queue.offer(event(Verdict::Detect, 3)); // dropped
    queue.offer(event(Verdict::Block, 4)); // evicts a detect, queued
    queue.offer(event(Verdict::Block, 5)); // evicts a detect, queued
    queue.offer(event(Verdict::Block, 6)); // counted

    assert_eq!(queue.offered(), 6);
    // `queued` counts admissions, so an event that displaced another is counted once, here,
    // and the displaced one is counted under `evicted_detect` — not twice.
    assert_eq!(queue.queued(), 4);
    assert_eq!(queue.dropped_detect(), 1);
    assert_eq!(queue.evicted_detect(), 2);
    assert_eq!(queue.counted_enforced(), 1);
    assert_eq!(queue.dropped_enforced(), 0);
}

// ---- the write path -------------------------------------------------------------
//
// Above this line the queue is tested alone, with no store, because its policy is a decision
// about ordering and capacity and needs nothing else. Below it the batch writer is tested
// against a real store, because what it adds is the part that can only go wrong against one:
// thirteen positional parameters in and thirteen positional reads out.

use pingap_controlplane::ControlPlaneStore;
use pingap_controlplane::events::EventWriter;
use pingap_controlplane::repository::{StoreError, TimeRange, WafEventFilter};
use pingap_controlplane::store::TursoStore;
use std::sync::Arc;

async fn migrated() -> (Arc<dyn ControlPlaneStore>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store =
        TursoStore::open(dir.path().join("cp.db").to_str().expect("utf-8"))
            .await
            .expect("the store opens");
    store.migrate().await.expect("migrations apply");
    (Arc::new(store) as Arc<dyn ControlPlaneStore>, dir)
}

/// Every column lands in its own field.
///
/// The write is thirteen positional parameters and the read is thirteen positional decodes,
/// so a transposition is a value in the wrong field rather than an error — a severity where
/// the rule ID goes still parses, if the types happen to line up. Asserting the round trip
/// field by field, including the nulls, is the only thing that catches it.
#[tokio::test]
async fn a_batch_round_trips_with_every_column_in_its_place() {
    let (store, _dir) = migrated().await;
    let full = WafEvent {
        node: "node-a".to_string(),
        domain: "site.test".to_string(),
        profile: "waf:strict".to_string(),
        rule_id: Some(942100),
        category: Some("sql_injection".to_string()),
        severity: Some("critical".to_string()),
        score: 15,
        verdict: Verdict::Block,
        client_ip: Some("203.0.113.7".to_string()),
        method: Some("POST".to_string()),
        uri: Some("/login".to_string()),
        created_at: 1_700_000_000,
    };
    // The sparse shape: a finding with no single rule behind it, from an aggregate score.
    let sparse = WafEvent {
        node: "node-b".to_string(),
        domain: "other.test".to_string(),
        profile: "waf:audit".to_string(),
        rule_id: None,
        category: None,
        severity: None,
        score: 3,
        verdict: Verdict::Detect,
        client_ip: None,
        method: None,
        uri: None,
        created_at: 1_700_000_100,
    };
    store
        .record_waf_events(&[full.clone(), sparse.clone()])
        .await
        .expect("the batch writes");

    let rows = store
        .read_waf_events(WafEventFilter::default())
        .await
        .expect("readable");
    assert_eq!(rows.len(), 2, "{rows:?}");

    let blocked = rows
        .iter()
        .find(|row| row.blocked)
        .expect("the block is stored as blocked");
    assert!(!blocked.id.is_empty(), "the store assigns a primary key");
    assert_eq!(blocked.node, "node-a");
    assert_eq!(blocked.domain, "site.test");
    assert_eq!(blocked.profile, "waf:strict");
    assert_eq!(blocked.rule_id, Some(942100));
    assert_eq!(blocked.category.as_deref(), Some("sql_injection"));
    assert_eq!(blocked.severity.as_deref(), Some("critical"));
    assert_eq!(blocked.score, 15);
    assert_eq!(blocked.client_ip.as_deref(), Some("203.0.113.7"));
    assert_eq!(blocked.method.as_deref(), Some("POST"));
    assert_eq!(blocked.uri.as_deref(), Some("/login"));
    assert_eq!(blocked.created_at, 1_700_000_000);

    let detected = rows
        .iter()
        .find(|row| !row.blocked)
        .expect("the detect finding is stored");
    assert_eq!(detected.node, "node-b");
    assert_eq!(
        detected.rule_id, None,
        "an absent rule ID became a placeholder"
    );
    assert_eq!(detected.category, None);
    assert_eq!(detected.severity, None);
    assert_eq!(detected.score, 3);
    assert_eq!(detected.client_ip, None);

    // Newest first, so a caller paging backwards through an incident reads it in the order
    // it happened.
    assert_eq!(rows[0].created_at, 1_700_000_100);
}

#[tokio::test]
async fn an_empty_batch_is_a_no_op() {
    let (store, _dir) = migrated().await;
    store
        .record_waf_events(&[])
        .await
        .expect("nothing to write is not an error");
    assert!(
        store
            .read_waf_events(WafEventFilter::default())
            .await
            .expect("readable")
            .is_empty()
    );
}

#[tokio::test]
async fn a_range_excludes_what_falls_outside_it() {
    let (store, _dir) = migrated().await;
    let mut events = Vec::new();
    for at in [1_000, 2_000, 3_000] {
        events.push(event(Verdict::Detect, at));
    }
    store.record_waf_events(&events).await.expect("writes");

    let window = TimeRange {
        since: Some(1_500),
        until: Some(2_500),
        limit: None,
    };
    let rows = store
        .read_waf_events(WafEventFilter {
            range: window,
            ..Default::default()
        })
        .await
        .expect("readable");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].created_at, 2_000);
}

/// A failed write puts the batch back rather than losing it.
///
/// The findings are already out of the queue by the time the store is asked, so this is the
/// only place the loss can happen — and a silent loss of security records is the failure the
/// queue's whole priority policy exists to prevent. An unmigrated store stands in for a store
/// that will not accept the write; what matters is that the batch is back in the queue and is
/// the same batch.
#[tokio::test]
async fn a_failed_write_puts_the_batch_back() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = TursoStore::open(
        dir.path().join("unmigrated.db").to_str().expect("utf-8"),
    )
    .await
    .expect("the store opens");
    let queue = Arc::new(EventQueue::new(8).expect("valid"));
    assert_eq!(queue.offer(event(Verdict::Block, 1)), Admission::Queued);
    assert_eq!(queue.offer(event(Verdict::Detect, 2)), Admission::Queued);

    let writer = EventWriter::new(Arc::clone(&queue), Arc::new(store));
    let error = writer
        .flush()
        .await
        .expect_err("a store with no waf_events table cannot take the batch");
    assert!(matches!(error, StoreError::Backend { .. }), "{error:?}");

    assert_eq!(queue.len(), 2, "the batch was lost rather than put back");
    let drained = queue.drain(10);
    assert_eq!(drained[0].created_at, 1);
    assert_eq!(drained[0].verdict, Verdict::Block);
    assert_eq!(drained[1].created_at, 2);
}

#[tokio::test]
async fn flush_writes_one_batch_and_leaves_the_rest() {
    let (store, _dir) = migrated().await;
    let queue = Arc::new(EventQueue::new(16).expect("valid"));
    for index in 0..5 {
        queue.offer(event(Verdict::Detect, index));
    }

    let writer = EventWriter::new(Arc::clone(&queue), Arc::clone(&store))
        .with_batch(2)
        .expect("a batch of two is valid");
    assert_eq!(writer.flush().await.expect("writes"), 2);
    assert_eq!(queue.len(), 3, "one round drains one batch, not the queue");
    assert_eq!(writer.flush().await.expect("writes"), 2);
    assert_eq!(writer.flush().await.expect("writes"), 1);
    assert_eq!(writer.flush().await.expect("writes"), 0);

    assert!(
        EventWriter::new(Arc::clone(&queue), Arc::clone(&store))
            .with_batch(0)
            .is_none(),
        "a zero batch would drain nothing forever and look idle"
    );
}

/// Filtering narrows, and an absent filter is not a filter that matches nothing.
///
/// The query is one statement shape with `? IS NULL OR column = ?` per optional filter rather
/// than a `WHERE` built up per call, so what is asserted here is that the sentinels behave: a
/// field left `None` must widen and not narrow.
#[tokio::test]
async fn a_filter_narrows_by_the_fields_it_names() {
    let (store, _dir) = migrated().await;
    let mut sqli = event(Verdict::Block, 1_000);
    sqli.domain = "api.test".to_string();
    sqli.rule_id = Some(942100);
    sqli.category = Some("sql_injection".to_string());
    let mut xss = event(Verdict::Detect, 2_000);
    xss.domain = "www.test".to_string();
    xss.rule_id = Some(941110);
    xss.category = Some("xss".to_string());
    xss.verdict = Verdict::Detect;
    store
        .record_waf_events(&[sqli, xss])
        .await
        .expect("both write");

    async fn read(
        store: &Arc<dyn ControlPlaneStore>,
        filter: WafEventFilter,
    ) -> Vec<String> {
        store
            .read_waf_events(filter)
            .await
            .expect("readable")
            .iter()
            .map(|row| row.domain.clone())
            .collect()
    }

    let all = read(&store, WafEventFilter::default()).await;
    assert_eq!(all.len(), 2, "an empty filter narrowed: {all:?}");

    assert_eq!(
        read(
            &store,
            WafEventFilter {
                domain: Some("api.test".to_string()),
                ..Default::default()
            }
        )
        .await,
        vec!["api.test".to_string()]
    );
    assert_eq!(
        read(
            &store,
            WafEventFilter {
                rule_id: Some(941110),
                ..Default::default()
            }
        )
        .await,
        vec!["www.test".to_string()]
    );
    assert_eq!(
        read(
            &store,
            WafEventFilter {
                category: Some("sql_injection".to_string()),
                ..Default::default()
            }
        )
        .await,
        vec!["api.test".to_string()]
    );
    assert_eq!(
        read(
            &store,
            WafEventFilter {
                blocked: Some(true),
                ..Default::default()
            }
        )
        .await,
        vec!["api.test".to_string()]
    );

    // Two filters at once, and the pair that matches nothing. A query that AND-ed wrongly
    // would return one of the two rows here instead of none.
    assert_eq!(
        read(
            &store,
            WafEventFilter {
                domain: Some("api.test".to_string()),
                rule_id: Some(941110),
                ..Default::default()
            }
        )
        .await
        .len(),
        0
    );
    assert_eq!(
        read(
            &store,
            WafEventFilter {
                domain: Some("api.test".to_string()),
                blocked: Some(true),
                ..Default::default()
            }
        )
        .await
        .len(),
        1
    );
}
