use pingap_behaviour::Behaviour;
use pingap_behaviour::score::{self, Classification};
use pingap_behaviour::{
    BehaviourConfig, Observation, Profile, SignalWeights, Thresholds,
};
use pingap_config::PluginConf;
use std::time::{Duration, Instant};

fn profile() -> Profile {
    let start = Instant::now();
    let mut profile = Profile::new(64, 16, 4, Duration::from_secs(900));
    for index in 0..12 {
        profile.record(Observation {
            at: start + Duration::from_millis(index * 700),
            uri: format!("/page/{}", index % 4),
            user_agent: if index % 2 == 0 {
                "browser".into()
            } else {
                "browser2".into()
            },
            status: 200,
            denied: false,
            challenged: false,
            bot: false,
        });
    }
    profile
}

#[test]
fn signals_need_a_minimum_sample_count_and_score_reports_contributors() {
    let empty = Profile::new(64, 16, 4, Duration::from_secs(900));
    let score = score::score(
        &empty,
        SignalWeights::default(),
        Thresholds::default(),
        6,
    );
    assert_eq!(score.contributing_signals, 0);
    let score = score::score(
        &profile(),
        SignalWeights::default(),
        Thresholds::default(),
        6,
    );
    assert!(score.contributing_signals > 0);
}

#[test]
fn a_zero_weight_signal_is_disabled_and_does_not_count_as_contributing() {
    // Weight 0 is the disabled state — the only way to turn a signal off. It
    // must not appear in `contributing_signals`, or a score would claim more
    // evidence than it actually used.
    let weights = SignalWeights {
        // Move UA's weight onto timing so the sum still validates to 100.
        timing_regularity: 35,
        user_agent_consistency: 0,
        ..SignalWeights::default()
    };
    let with_ua = score::score(
        &profile(),
        SignalWeights::default(),
        Thresholds::default(),
        6,
    );
    let without_ua =
        score::score(&profile(), weights, Thresholds::default(), 6);
    assert_eq!(
        without_ua.contributing_signals,
        with_ua.contributing_signals - 1,
        "the disabled signal still counted as contributing"
    );
}

#[test]
fn high_noise_signals_wait_for_their_own_sample_floor() {
    let start = Instant::now();
    let mut profile = Profile::new(64, 64, 16, Duration::from_secs(900));
    for index in 0..6 {
        profile.record(Observation {
            at: start + Duration::from_millis(index * 100),
            uri: format!("/{index}"),
            user_agent: "browser".into(),
            status: 500,
            denied: false,
            challenged: false,
            bot: false,
        });
    }
    assert!(
        pingap_behaviour::signals::user_agent_consistency(&profile, 5)
            .is_some()
    );
    assert!(
        pingap_behaviour::signals::timing_regularity(&profile, 10).is_none()
    );
    assert!(pingap_behaviour::signals::url_entropy(&profile, 20).is_none());
    assert!(
        pingap_behaviour::signals::request_diversity(&profile, 20).is_none()
    );
    assert!(pingap_behaviour::signals::request_speed(&profile, 10).is_none());
    assert!(pingap_behaviour::signals::error_pattern(&profile, 20).is_none());
}

#[test]
fn a_score_from_one_signal_is_not_classified_like_a_score_from_six() {
    // A low-traffic client whose single populated signal reads machine-like is
    // a verdict from noise. With only one contributing signal the score holds
    // at `Suspicious`; with all six it classifies on the weighted value.
    let start = Instant::now();
    let mut sparse = Profile::new(64, 64, 16, Duration::from_secs(900));
    for index in 0..6 {
        sparse.record(Observation {
            at: start + Duration::from_millis(index * 100),
            uri: format!("/{index}"),
            user_agent: "browser".into(),
            status: 500,
            denied: false,
            challenged: false,
            bot: false,
        });
    }
    let one = score::score(
        &sparse,
        SignalWeights::default(),
        Thresholds::default(),
        6,
    );
    assert_eq!(one.contributing_signals, 1, "only UA clears the floor");
    assert_eq!(
        one.classification,
        Classification::Suspicious,
        "a one-signal score must not classify confidently"
    );
}

#[test]
fn weights_are_required_to_sum_to_one_hundred() {
    let config = BehaviourConfig {
        enabled: true,
        client_ip_from_peer: true,
        weights: SignalWeights {
            timing_regularity: 19,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn a_score_alone_is_never_a_terminal_decision() {
    let score = score::score(
        &profile(),
        SignalWeights {
            timing_regularity: 0,
            url_entropy: 0,
            request_diversity: 0,
            request_speed: 0,
            error_pattern: 0,
            user_agent_consistency: 100,
        },
        Thresholds::default(),
        6,
    );
    assert!(matches!(
        score.classification,
        Classification::Human
            | Classification::Suspicious
            | Classification::Bot
            | Classification::DdosShaped
    ));
}

#[test]
fn disabled_behaviour_does_not_require_an_identity_anchor() {
    let conf: PluginConf = "enabled = false".parse().expect("config");
    Behaviour::try_from(&conf).expect("disabled detector is a no-op");
}
