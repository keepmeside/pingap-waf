use pingap_challenge::escalation::Escalator;
use pingap_challenge::loopdetect::LoopDetector;
use std::time::{Duration, Instant};

#[test]
fn an_idle_escalated_entry_decays_back_to_the_floor() {
    // Asserted with an injected clock, not a sleeping test: drive a client to
    // tier 1, then read its state from an instant past the decay window.
    let escalator = Escalator::new(8);
    let ladder = [2, 4, 8];
    let decay = Duration::from_secs(300);
    for _ in 0..4 {
        escalator.failure("a.test", "203.0.113.1", &ladder, decay);
    }
    let escalated = escalator.get("a.test", "203.0.113.1", decay);
    assert_eq!(escalated.level, 1, "four failures land on tier 1");

    // Inside the decay window the tier holds.
    let soon = escalator.get_at(
        "a.test",
        "203.0.113.1",
        decay,
        Instant::now() + Duration::from_secs(60),
    );
    assert_eq!(soon.level, 1, "within the window the tier is unchanged");

    // Past it, the entry decays to the floor — level and failures reset.
    let idle = escalator.get_at(
        "a.test",
        "203.0.113.1",
        decay,
        Instant::now() + Duration::from_secs(301),
    );
    assert_eq!(idle.level, 0, "an idle entry decays back");
    assert_eq!(idle.failures, 0);
}

#[test]
fn failures_raise_a_tier_and_success_lowers_it_without_cross_domain_leakage() {
    let escalator = Escalator::new(8);
    let ladder = [2, 4, 8];
    assert_eq!(
        escalator
            .failure("a.test", "203.0.113.1", &ladder, Duration::from_secs(60))
            .level,
        0
    );
    assert_eq!(
        escalator
            .failure("a.test", "203.0.113.1", &ladder, Duration::from_secs(60))
            .level,
        0
    );
    assert_eq!(
        escalator
            .failure("a.test", "203.0.113.1", &ladder, Duration::from_secs(60))
            .level,
        0
    );
    assert_eq!(
        escalator
            .failure("a.test", "203.0.113.1", &ladder, Duration::from_secs(60))
            .level,
        1
    );
    assert_eq!(
        escalator
            .get("b.test", "203.0.113.1", Duration::from_secs(60))
            .level,
        0
    );
    assert_eq!(
        escalator
            .success("a.test", "203.0.113.1", Duration::from_secs(60))
            .level,
        0
    );
}

#[test]
fn loop_detection_stays_bounded_and_fails_closed_at_capacity() {
    let detector = LoopDetector::with_capacity(3, 1);
    assert_eq!(detector.issued("a.test", "one", "pow"), 1);
    assert!(detector.looping(detector.issued("b.test", "two", "pow")));
}
