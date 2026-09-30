use pingap_adaptive::decision;
use pingap_adaptive::{AdaptiveConfig, AdaptiveLearner, SampleDisposition};

#[test]
fn cold_start_is_disabled_and_tightening_never_raises_the_limit() {
    let config = AdaptiveConfig {
        enabled: true,
        client_ip_from_peer: true,
        min_days_to_calibrate: 1,
        min_confidence: 0.01,
        ..Default::default()
    };
    config.validate().expect("valid config");
    let learner = AdaptiveLearner::new(config.clone());
    assert!(!learner.decision(0, 10.0).calibrated);
    let factor = decision::clamp_factor(100.0, 0.1, 0.1, false);
    assert!(factor <= 1.0);
    let _ = SampleDisposition::Denied;
}

#[test]
fn min_factor_at_or_above_one_is_rejected() {
    let config = AdaptiveConfig {
        enabled: true,
        client_ip_from_peer: true,
        min_factor: 1.0,
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn non_finite_adaptive_values_are_rejected() {
    let config = AdaptiveConfig {
        enabled: true,
        client_ip_from_peer: true,
        min_factor: f64::NAN,
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn each_ratio_branch_has_a_reason_and_bot_rate_changes_the_ratio() {
    let config = AdaptiveConfig::default();
    let normal = decision::decide(&config, 10.0, 20.0, 0.0);
    assert_eq!(normal.reason, "ratio_minor");
    let extreme = decision::decide(&config, 10.0, 250.0, 0.0);
    assert_eq!(extreme.reason, "ratio_extreme");
    let bot_adjusted = decision::decide(&config, 10.0, 20.0, 1.0);
    assert!(bot_adjusted.ratio > normal.ratio);
}
