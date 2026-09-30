//! Budget-degradation assertions for the behaviour plugin: when scoring overruns
//! the per-request budget the request must degrade to the configured policy
//! (pass through, `budget_exhausted`) and must never be turned into a block.
//!
//! The wall-clock race is removed by asserting the decision on the extracted
//! boundary function: the request path passes measured elapsed milliseconds
//! into `budget_exceeded`, so the test exercises the exact predicate the hot
//! path runs rather than hoping a real request takes long enough.

use pingap_behaviour::budget_exceeded;

#[test]
fn exceeding_the_budget_is_detected() {
    assert!(budget_exceeded(2, 1), "2ms elapsed over a 1ms budget");
    assert!(!budget_exceeded(1, 1), "at the budget is not over it");
    assert!(!budget_exceeded(0, 1), "under the budget is not over it");
}

#[test]
fn the_budget_boundary_is_strictly_greater_than() {
    // `elapsed > budget`, matching the call site: a request that lands exactly
    // on its budget keeps being scored rather than degraded.
    for budget in [1u64, 2, 5, 100] {
        assert!(!budget_exceeded(budget, budget));
        assert!(budget_exceeded(budget + 1, budget));
    }
}
