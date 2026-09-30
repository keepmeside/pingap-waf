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
