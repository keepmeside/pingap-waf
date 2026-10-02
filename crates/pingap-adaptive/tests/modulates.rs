//! The rate-limit dial is explicit in config: `modulate_rate_limit` decides
//! whether the learned factor reaches the configured limiter at all, and the
//! published per-domain state must distinguish a learner still earning its
//! calibration from a feature the operator switched off. Both are properties
//! of the process-global registry, so both are asserted through the plugin
//! surface.

// The one deliberate guard-across-await in this file: the HOSTS_LOCK guards
// below must span the driven requests, because the set they protect is
// process-global and tests in this binary run on separate threads —
// releasing one mid-test would let the other test rewrite the set or race
// the enabled flag under a driven request. The mock sessions are always
// ready, so the awaits never actually suspend.
#![allow(clippy::await_holding_lock)]

use pingap_adaptive::plugin::Adaptive;
use pingap_config::PluginConf;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use std::sync::Mutex;
use tokio_test::io::Builder;

/// Serialises the registered-host rewrites and the plugin constructions:
/// both are process-global, so a test rewriting the host set or flipping the
/// constructed-plugin state while the other asserts would race it.
static HOSTS_LOCK: Mutex<()> = Mutex::new(());

/// The tuning that makes both tests deterministic, identical in both so
/// whichever construction freezes the global registry first, the frozen
/// config is the same: calibration at exactly 24 samples, a confidence floor
/// one populated hour reaches, and a wide `ratio_minor` band with a factor
/// off neutral — so the dial-off leg suppresses a real movement, not a
/// neutral one. The rate-limit dial itself is off.
fn dial_off_conf() -> PluginConf {
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
           modulate_rate_limit = false
        "#,
    )
    .expect("config parses")
}

fn disabled_conf() -> PluginConf {
    toml::from_str(
        r#"category = "adaptive"
           enabled = false
        "#,
    )
    .expect("config parses")
}

fn plugin(conf: &PluginConf) -> Adaptive {
    Adaptive::try_from(conf).expect("builds")
}

async fn drive(plugin: &Adaptive, host: &str) -> Ctx {
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
    let io = Builder::new().read(request.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(io));
    session.read_request().await.expect("mock request reads");
    let mut ctx = Ctx::default();
    let result = plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total");
    assert!(
        matches!(result, RequestPluginResult::Continue),
        "an adaptive decision must never refuse a request"
    );
    ctx
}

/// With the dial off, the learned factor never reaches the limiter: a
/// calibrated `ratio_minor` decision — a factor off neutral on the very band
/// the tuning pins — leaves no multiplier in the request context and counts
/// as no modulation, while the learning itself runs to calibration and the
/// snapshot still carries the decision. The published row along the way
/// reads as "not yet calibrated", with the gate it is judged against beside
/// it rather than as a silent false.
#[tokio::test]
async fn an_unopted_limiter_never_receives_the_learned_factor() {
    let _guard = HOSTS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    pingap_domainstate::set_registered_hosts(["scope.test"]);
    let adaptive = plugin(&dial_off_conf());

    // One sample in: the row must read "not yet calibrated", with the sample
    // gate and the confidence floor published beside the reading.
    drive(&adaptive, "scope.test").await;
    let young = pingap_adaptive::domain_state_snapshot()
        .get("scope.test")
        .cloned()
        .expect("the driven domain has a learner");
    assert!(young.enabled, "the feature is on: {young:?}");
    assert!(!young.calibrated, "one sample cannot calibrate: {young:?}");
    assert_eq!(young.samples, 1, "one request, one sample: {young:?}");
    assert_eq!(
        young.samples_required, 24,
        "the sample gate is min_days x 24: {young:?}"
    );
    assert_eq!(
        young.min_confidence, 0.1,
        "the floor is published: {young:?}"
    );
    assert!(
        young.confidence < young.min_confidence,
        "an unpopulated hour is under the floor: {young:?}"
    );

    // To calibration: the decision on the 24th request is `ratio_minor` with
    // a 0.5 factor — a real movement — and the dial being off is what keeps
    // it from reaching the limiter.
    let mut last = Ctx::default();
    for _ in 0..23 {
        last = drive(&adaptive, "scope.test").await;
    }
    assert_eq!(
        last.get_variable("adaptive_reason"),
        Some("ratio_minor"),
        "the 24th decision is a tightening, not a neutral one"
    );
    assert!(
        last.extensions
            .get::<pingap_core::AdaptiveRateMultiplier>()
            .is_none(),
        "the dial is off: the factor must not reach the limiter"
    );
    assert!(
        last.extensions
            .get::<pingap_adaptive::AdaptiveSnapshot>()
            .is_some(),
        "the decision itself is still published for the challenge dial"
    );

    let row = pingap_adaptive::domain_state_snapshot()
        .get("scope.test")
        .cloned()
        .expect("the driven domain has a learner");
    assert!(row.calibrated, "24 samples calibrate: {row:?}");
    assert_eq!(row.samples, 24, "no sample was lost: {row:?}");
    assert!(
        row.modulated.is_empty(),
        "a suppressed factor is not a modulation: {row:?}"
    );

    pingap_domainstate::set_registered_hosts::<[&str; 0], &str>([]);
}

/// A config apply that disables the plugin does not erase what was learned —
/// the registry and its history survive — so the published row must say the
/// feature is off rather than letting a learner from the enabled period read
/// as a live one. The disabled instance itself modulates nothing.
#[tokio::test]
async fn a_disabled_apply_publishes_its_rows_as_off() {
    let _guard = HOSTS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    pingap_domainstate::set_registered_hosts(["off.test"]);
    let adaptive = plugin(&dial_off_conf());
    for _ in 0..24 {
        drive(&adaptive, "off.test").await;
    }
    let calibrated = pingap_adaptive::domain_state_snapshot()
        .get("off.test")
        .cloned()
        .expect("the driven domain has a learner");
    assert!(
        calibrated.enabled && calibrated.calibrated,
        "{calibrated:?}"
    );

    // The apply: a new instance built from a disabled config.
    let disabled = plugin(&disabled_conf());
    let ctx = drive(&disabled, "off.test").await;
    assert!(
        ctx.extensions
            .get::<pingap_core::AdaptiveRateMultiplier>()
            .is_none()
            && ctx
                .extensions
                .get::<pingap_adaptive::AdaptiveSnapshot>()
                .is_none(),
        "a disabled instance modulates and publishes nothing"
    );
    assert_eq!(
        ctx.get_variable("adaptive_reason"),
        None,
        "a disabled instance states no reason"
    );

    let row = pingap_adaptive::domain_state_snapshot()
        .get("off.test")
        .cloned()
        .expect("the learner survives the switch-off");
    assert!(
        !row.enabled,
        "the row must say the feature is off, not read as a live learner: {row:?}"
    );
    assert!(row.calibrated, "the history is intact: {row:?}");
    assert_eq!(
        row.samples, 24,
        "the disabled instance recorded nothing: {row:?}"
    );

    pingap_domainstate::set_registered_hosts::<[&str; 0], &str>([]);
}
