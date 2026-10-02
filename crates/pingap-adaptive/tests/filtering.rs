use pingap_adaptive::{AdaptiveConfig, AdaptiveLearner, SampleDisposition};

#[test]
fn denied_challenged_and_bot_samples_do_not_train_the_baseline() {
    let config = AdaptiveConfig {
        max_samples_per_hour: 8,
        ..Default::default()
    };
    let mut learner = AdaptiveLearner::new(config);
    for disposition in [
        SampleDisposition::Denied,
        SampleDisposition::Challenged,
        SampleDisposition::Bot,
    ] {
        for _ in 0..100 {
            learner.record(0, 10_000.0, 1.0, disposition);
        }
    }
    assert_eq!(learner.samples, 0);
    assert_eq!(learner.profiles[0].len(), 0);
}

/// The disposition filter is what makes the baseline mean something: the
/// samples that train it are the requests the gateway itself judged normal,
/// so an attack burst must not dilute the baseline it is measured against.
/// The same burst recorded as honest traffic is a flash crowd — the baseline
/// should absorb it, or every genuine spike would be tightened like an
/// attack. Two learners, identical until the burst, one per disposition.
#[test]
fn a_burst_of_honest_traffic_is_absorbed_while_a_burst_of_attack_traffic_tightens()
 {
    let config = AdaptiveConfig {
        max_samples_per_hour: 4,
        min_days_to_calibrate: 1,
        min_confidence: 0.01,
        ..Default::default()
    };
    let mut absorbed = AdaptiveLearner::new(config.clone());
    let mut attacked = AdaptiveLearner::new(config);
    for _ in 0..24 {
        absorbed.record(0, 10.0, 0.0, SampleDisposition::Normal);
        attacked.record(0, 10.0, 0.0, SampleDisposition::Normal);
    }
    assert!(
        absorbed.calibrated && attacked.calibrated,
        "the honest phase should calibrate both learners identically"
    );

    // Eight samples at ten times the baseline rate. To the learner that
    // accepts them they are the new normal; to the one that refuses them
    // they are an ongoing deviation from an untouched baseline.
    for _ in 0..8 {
        absorbed.record(0, 100.0, 0.0, SampleDisposition::Normal);
        attacked.record(0, 100.0, 1.0, SampleDisposition::Bot);
    }

    let honest = absorbed.decision(0, 100.0);
    assert_eq!(
        honest.reason, "ratio_normal",
        "a rate the baseline absorbed is not a deviation"
    );
    assert_eq!(honest.rate_limit_factor, 1.0);
    let attack = attacked.decision(0, 100.0);
    assert_eq!(
        attack.reason, "ratio_major",
        "ten times an untouched baseline is a major deviation"
    );
    assert!(
        attack.rate_limit_factor < honest.rate_limit_factor,
        "the attack burst tightened less than the honest one"
    );
    // The refused samples never trained: the baseline the attack is measured
    // against is still the honest one, and only the accepting learner's
    // sample count moved.
    assert_eq!(attacked.samples, 24);
    assert_eq!(absorbed.samples, 32);
}
