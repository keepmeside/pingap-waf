use pingap_adaptive::{AdaptiveConfig, AdaptiveLearner, SampleDisposition};

#[test]
fn hourly_ring_buffers_remain_fixed() {
    let config = AdaptiveConfig {
        max_samples_per_hour: 8,
        ..Default::default()
    };
    let mut learner = AdaptiveLearner::new(config);
    for index in 0..1_000_000 {
        learner.record(0, index as f64, 0.0, SampleDisposition::Normal);
    }
    assert_eq!(learner.profiles[0].samples.len(), 8);
}
