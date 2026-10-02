use pingap_adaptive::{AdaptiveConfig, AdaptiveLearner, SampleDisposition};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[test]
fn restored_aggregate_starts_uncalibrated_and_stale_data_is_discarded() {
    let config = AdaptiveConfig {
        max_baseline_age_days: 1,
        ..Default::default()
    };
    let mut learner = AdaptiveLearner::new(config.clone());
    for _ in 0..10 {
        learner.record(0, 1.0, 0.0, SampleDisposition::Normal);
    }
    let mut baseline = learner.baseline();
    baseline.learned_at_secs = UNIX_EPOCH
        .elapsed()
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(3 * 86_400);
    assert!(!learner.restore(baseline, SystemTime::now()));
    assert_eq!(learner.discarded_baselines, 1);
    let baseline = learner.baseline();
    assert!(
        learner.restore(baseline, SystemTime::now() + Duration::from_secs(1))
    );
    assert!(!learner.calibrated);
}

#[test]
fn a_restored_baseline_keeps_its_own_learned_time() {
    // Stamping the restore time as the learned time would refresh a baseline's
    // freshness on every restart, so one cycling through restarts would never
    // age out and the max-age check would only ever fire for a process that
    // stayed up. The restored learner must keep the time it learned at.
    let mut learner = AdaptiveLearner::new(AdaptiveConfig::default());
    for _ in 0..10 {
        learner.record(0, 1.0, 0.0, SampleDisposition::Normal);
    }
    let mut baseline = learner.baseline();
    let learned_at = UNIX_EPOCH
        .elapsed()
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(86_400);
    baseline.learned_at_secs = learned_at;
    let later = SystemTime::now() + Duration::from_secs(3600);
    assert!(learner.restore(baseline, later));
    assert_eq!(
        learner.baseline().learned_at_secs,
        learned_at,
        "restore must not refresh the baseline's age"
    );
}
