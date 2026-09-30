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
