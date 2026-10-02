// The one deliberate guard-across-await in this file: the HOSTS_LOCK guard
// on the counter test below must span the driven requests, because the set
// it protects is process-global and tests in this binary run on separate
// threads — releasing it mid-test would let another test rewrite the set
// under a driven request. The mock sessions are always ready, so the awaits
// never actually suspend.
#![allow(clippy::await_holding_lock)]

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

/// Every branch of the ladder, walked once, each asserting the reason an
/// operator reads in the counters, the factor the branch applies, and the
/// challenge level it carries. The clamp is where a branch touches the
/// operator's configured limit, and the property that must hold at every
/// branch is that it never raises it: a tightening that could originate an
/// increase would let a noisy baseline loosen the very limit it was
/// calibrated to tighten.
#[test]
fn every_tightening_branch_names_itself_and_never_raises_the_limit() {
    let config = AdaptiveConfig::default();
    // expected 10, bot_rate 0 → adjusted 10, so ratio = current / 10.
    let ladder = [
        (10.0, "ratio_normal", 1.0, 0u8),
        (20.0, "ratio_minor", 0.9, 0),
        (30.0, "ratio_moderate", 0.75, 1),
        (50.0, "ratio_significant", 0.5, 1),
        (100.0, "ratio_major", 0.25, 2),
        (200.0, "ratio_extreme", 0.1, 2),
    ];
    for (current, reason, factor, level) in ladder {
        let decision = decision::decide(&config, 10.0, current, 0.0);
        assert_eq!(decision.reason, reason, "at {current} rps");
        assert_eq!(decision.rate_limit_factor, factor, "at {current} rps");
        assert_eq!(decision.challenge_level, level, "at {current} rps");
        // `clamp_factor` returns the factor the configured limit is multiplied
        // by, so "never raises" is "never above 1.0" — a tightening that could
        // originate a factor above neutral would let a noisy baseline loosen
        // the very limit it was calibrated to tighten.
        let effective = decision::clamp_factor(
            100.0,
            decision.rate_limit_factor,
            config.min_factor,
            config.allow_loosening,
        );
        assert!(
            effective <= 1.0,
            "{reason} raised the limit: factor {effective}"
        );
    }

    // The one branch that may raise the limit is loosening, and only when the
    // operator opted in: the same low ratio clamps back to a factor of 1.0
    // when loosening is off. Loosening cannot be an accident of the ladder.
    let loose = AdaptiveConfig {
        allow_loosening: true,
        ..Default::default()
    };
    let loosened = decision::decide(&loose, 10.0, 2.0, 0.0);
    assert_eq!(loosened.reason, "ratio_low_loosening");
    assert_eq!(loosened.rate_limit_factor, 2.0);
    assert!(decision::clamp_factor(100.0, 2.0, 0.1, true) > 1.0);
    assert!(decision::clamp_factor(100.0, 2.0, 0.1, false) <= 1.0);
}

/// Serialises the registered-host rewrite below: the registered set is
/// process-global, so a test rewriting it while another classifies would
/// classify against the other test's set. This is the only test in this
/// binary that touches the set, but the lock keeps that true by construction
/// if another is added.
static HOSTS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The tuning that makes the counter test below deterministic: calibration
/// after exactly 24 samples (one day at one sample per request), a confidence
/// floor a single populated hour can reach, and a `ratio_minor` band wide
/// enough that the burst's live rate lands in it whether the mock requests
/// span one wall-clock second or two.
fn counter_conf() -> pingap_config::PluginConf {
    toml::from_str(
        r#"category = "adaptive"
           enabled = true
           client_ip_from_peer = true
           max_samples_per_hour = 64
           min_days_to_calibrate = 1
           min_confidence = 0.1
           ratio_minor = 0.5
           ratio_moderate = 10.0
           ratio_significant = 11.0
           ratio_major = 12.0
           ratio_extreme = 13.0
           factor_minor = 0.5
           allow_loosening = false
           max_baseline_age_days = 30
        "#,
    )
    .expect("config parses")
}

#[tokio::test]
async fn a_modulating_decision_counts_under_its_fixed_reason() {
    let _guard = HOSTS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    pingap_domainstate::set_registered_hosts(["a.test"]);

    let plugin = pingap_adaptive::plugin::Adaptive::try_from(&counter_conf())
        .expect("builds");
    // Twenty-four requests calibrate the learner at exactly the 24th sample.
    // Every request's live rate rises above the hour's running average (each
    // request sees a window count one higher than the last), so from the first
    // calibrated request on, every decision lands in the `ratio_minor` band
    // with a rate factor off neutral — a modulation. Before calibration the
    // decisions are `not_calibrated` and must not count at all.
    let session_for = |host: &str| {
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        async move {
            let io = tokio_test::io::Builder::new()
                .read(request.as_bytes())
                .build();
            let mut session = pingora::proxy::Session::new_h1(Box::new(io));
            session.read_request().await.expect("mock request reads");
            session
        }
    };
    let mut last = pingap_core::Ctx::default();
    for _ in 0..24 {
        use pingap_core::Plugin;
        let mut session = session_for("a.test").await;
        let mut ctx = pingap_core::Ctx::default();
        plugin
            .handle_request(
                pingap_core::PluginStep::Request,
                &mut session,
                &mut ctx,
            )
            .await
            .expect("handle_request is total");
        last = ctx;
    }
    // The dial is on by default: the calibrated factor reaches the limiter
    // on the very request that counted as a modulation. The off path — the
    // same decision with `modulate_rate_limit = false` reaching no limiter
    // and counting as nothing — is asserted in `tests/modulates.rs`.
    assert!(
        last.extensions
            .get::<pingap_core::AdaptiveRateMultiplier>()
            .is_some(),
        "the default-on dial must carry the factor to the limiter"
    );

    let rows = pingap_adaptive::domain_state_snapshot();
    let state = rows.get("a.test").expect("the driven domain has a learner");
    assert!(
        state.calibrated,
        "24 samples should calibrate, got {state:?}"
    );
    // The gate is published with the reading: the sample count against the
    // one it requires, the confidence against its floor, and the enabled
    // flag that separates "not yet calibrated" from "disabled". The
    // disabled reading is asserted in `tests/modulates.rs`.
    assert_eq!(
        state.samples_required, 24,
        "min_days_to_calibrate 1 requires 24 samples: {state:?}"
    );
    assert_eq!(state.min_confidence, 0.1, "{state:?}");
    assert!(state.enabled, "the feature is on: {state:?}");
    assert!(
        state.samples >= state.samples_required
            && state.confidence >= state.min_confidence,
        "calibrated must mean the published gate is met: {state:?}"
    );
    assert_eq!(
        state.modulated.get("ratio_minor"),
        Some(&1),
        "exactly the one calibrated, dial-moving decision counts, got {:?}",
        state.modulated
    );
    assert_eq!(
        state.modulated.values().sum::<u64>(),
        1,
        "no other reason may count: {:?}",
        state.modulated
    );

    // Leave the set empty for any test that runs after this one.
    pingap_domainstate::set_registered_hosts::<[&str; 0], &str>([]);
}
