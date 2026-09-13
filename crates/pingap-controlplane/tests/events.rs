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
