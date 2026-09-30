use pingap_behaviour::score::{self, Classification};
use pingap_behaviour::{Observation, Profile, SignalWeights, Thresholds};
use std::time::{Duration, Instant};

fn observation(at: Instant, status: u16) -> Observation {
    Observation {
        at,
        uri: "/health".into(),
        user_agent: "browser".into(),
        status,
        denied: false,
        challenged: false,
        bot: false,
    }
}

#[test]
fn terminated_requests_do_not_fabricate_error_observations() {
    let start = Instant::now();
    let empty = Profile::new(32, 8, 4, Duration::from_secs(900));
    let empty_score = score::score(
        &empty,
        SignalWeights::default(),
        Thresholds::default(),
        6,
    );
    assert_eq!(empty_score.observation_count, 0);
    assert_eq!(empty_score.contributing_signals, 0);

    let mut allowed = Profile::new(32, 8, 4, Duration::from_secs(900));
    for offset in 0..20 {
        allowed.record(observation(
            start + Duration::from_millis(offset * 100),
            500,
        ));
    }
    let allowed_score = score::score(
        &allowed,
        SignalWeights::default(),
        Thresholds::default(),
        6,
    );
    assert_eq!(allowed_score.observation_count, 20);
    assert!(allowed.errors > 0);
    assert!(matches!(
        allowed_score.classification,
        Classification::Human
            | Classification::Suspicious
            | Classification::Bot
            | Classification::DdosShaped
    ));

    let mut clean = Profile::new(32, 8, 4, Duration::from_secs(900));
    for offset in 0..20 {
        clean.record(observation(
            start + Duration::from_millis(offset * 100),
            200,
        ));
    }
    let clean_score = score::score(
        &clean,
        SignalWeights::default(),
        Thresholds::default(),
        6,
    );
    assert!(allowed_score.value < clean_score.value);
}
