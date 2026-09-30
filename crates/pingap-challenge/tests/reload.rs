use pingap_challenge::escalation::Escalator;
use std::time::Duration;

#[test]
fn changing_ladder_configuration_does_not_reset_process_global_failures() {
    let escalator = Escalator::new(16);
    assert_eq!(
        escalator
            .failure("a.test", "203.0.113.1", &[2, 4], Duration::from_secs(60))
            .failures,
        1
    );
    let state = escalator.failure(
        "a.test",
        "203.0.113.1",
        &[3, 6],
        Duration::from_secs(60),
    );
    assert_eq!(state.failures, 2);
    assert_eq!(
        state.level, 0,
        "the new ladder is applied to existing state"
    );
}
