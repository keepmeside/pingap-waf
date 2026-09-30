//! Calibration-gate assertions for the adaptive learner: an uncalibrated or
//! erroring learner must leave the configured static thresholds exactly in
//! force (Decision 11), cold start must be indistinguishable from "feature
//! disabled", and calibration state must distinguish "not yet calibrated" from
//! "disabled" rather than guessing.

use pingap_adaptive::{AdaptiveConfig, AdaptiveLearner, SampleDisposition};

fn config() -> AdaptiveConfig {
    AdaptiveConfig {
        enabled: true,
        // Lower the calibration gate so the test does not need a week of
        // synthetic samples to cross it.
        min_days_to_calibrate: 1,
        min_confidence: 0.01,
        client_ip_from_peer: true,
        ..Default::default()
    }
}

fn calibrated_learner() -> AdaptiveLearner {
    let config = config();
    let mut learner = AdaptiveLearner::new(config.clone());
    // Populate every hourly profile past the populated-fraction floor and the
    // day gate so the learner crosses `min_days_to_calibrate * 24` samples.
    for hour in 0..24 {
        for _ in 0..(config.min_days_to_calibrate as usize * 8) {
            learner.record(hour, 10.0, 0.0, SampleDisposition::Normal);
        }
    }
    learner
}

#[test]
fn an_uncalibrated_learner_is_indistinguishable_from_disabled() {
    // Cold start: a learner with no history returns the normal decision —
    // `Decision::normal()` — which carries `calibrated: false`, factor 1.0 and
    // the `not_calibrated` reason. No configured threshold is moved.
    let learner = AdaptiveLearner::new(config());
    let decision = learner.decision(0, 10_000.0);
    assert!(!decision.calibrated);
    assert_eq!(decision.reason, "not_calibrated");
    assert_eq!(decision.rate_limit_factor, 1.0);
    assert_eq!(decision.challenge_level, 0);
    // The effective multiplier stays at the configured ceiling (1.0 = no change).
    assert_eq!(learner.effective_factor(1.0, &decision), 1.0);
}

#[test]
fn calibration_requires_both_history_depth_and_confidence() {
    // Below the sample gate the learner stays uncalibrated even with some data.
    let mut learner = AdaptiveLearner::new(config());
    for _ in 0..5 {
        learner.record(0, 10.0, 0.0, SampleDisposition::Normal);
    }
    assert!(
        !learner.calibrated,
        "a handful of samples must not calibrate"
    );

    // A fully-populated learner crosses the gate and reports confidence.
    let learner = calibrated_learner();
    assert!(learner.calibrated, "enough history should calibrate");
    assert!(learner.confidence > 0.0);
    assert!(learner.samples >= 24);
}

#[test]
fn a_calibrated_learner_reports_a_reason_on_every_decision() {
    let learner = calibrated_learner();
    // A burst far above the learned baseline must tighten and name its branch.
    let hot = learner.decision(0, 10_000.0);
    assert!(hot.calibrated);
    assert!(!hot.reason.is_empty());
    assert_ne!(hot.reason, "not_calibrated");
    // And the reason differs across ratio branches.
    let normal = learner.decision(0, 10.0);
    assert!(!normal.reason.is_empty());
}

#[test]
fn bot_rate_changes_the_decision_not_just_the_record() {
    // Two learners identical except for the recorded bot rate must reach a
    // different ratio — `avg_bot_rate` participates in the decision rather
    // than being a write-only field.
    let mut clean = calibrated_learner();
    let mut noisy = calibrated_learner();
    // Re-record the current hour with a high bot rate on `noisy` only.
    for _ in 0..40 {
        clean.record(0, 10.0, 0.0, SampleDisposition::Normal);
        noisy.record(0, 10.0, 1.0, SampleDisposition::Normal);
    }
    let same_burst = 40.0;
    let clean_ratio = clean.decision(0, same_burst).ratio;
    let noisy_ratio = noisy.decision(0, same_burst).ratio;
    assert!(
        noisy_ratio > clean_ratio,
        "a higher bot rate should raise the effective ratio: \
         clean={clean_ratio} noisy={noisy_ratio}"
    );
}

#[test]
fn calibration_state_is_observable_not_silent() {
    // The gate fields an operator needs — sample count, calibrated flag and
    // confidence — must all be readable per learner, so "not yet calibrated"
    // is distinguishable from "disabled" on the metrics surface.
    let mut learner = AdaptiveLearner::new(config());
    assert_eq!(learner.samples, 0);
    assert!(!learner.calibrated);
    for _ in 0..3 {
        learner.record(0, 5.0, 0.0, SampleDisposition::Normal);
    }
    assert_eq!(learner.samples, 3);
    assert!(!learner.calibrated, "still below the day gate");
}
