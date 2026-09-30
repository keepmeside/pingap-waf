use crate::config::{SignalWeights, Thresholds};
use crate::profile::Profile;
use crate::signals;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    Human,
    Suspicious,
    Bot,
    DdosShaped,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Score {
    pub value: u8,
    pub classification: Classification,
    pub contributing_signals: u8,
    pub observation_count: u64,
}

pub fn score(
    profile: &Profile,
    weights: SignalWeights,
    thresholds: Thresholds,
    min_samples: usize,
) -> Score {
    let values = [
        signals::timing_regularity(profile, min_samples.max(10)),
        signals::url_entropy(profile, min_samples.max(20)),
        signals::request_diversity(profile, min_samples.max(20)),
        signals::request_speed(profile, min_samples.max(10)),
        signals::error_pattern(profile, min_samples.max(20)),
        signals::user_agent_consistency(profile, min_samples.max(5)),
    ];
    let weights = weights.values();
    let mut weighted = 0.0;
    let mut total = 0u16;
    let mut count = 0u8;
    for (value, weight) in values.into_iter().zip(weights) {
        // A weight of 0 is the disabled state: the signal neither moves the
        // score nor counts toward `contributing_signals`, so a disabled signal
        // does not inflate how many signals the score claims it heard from.
        if weight == 0 {
            continue;
        }
        if let Some(value) = value {
            weighted += value * f64::from(weight);
            total += u16::from(weight);
            count = count.saturating_add(1);
        }
    }
    let value = if total == 0 {
        0
    } else {
        (weighted / f64::from(total)).round().clamp(0.0, 100.0) as u8
    };
    // A score is only as confident as the evidence behind it. Fewer than two
    // contributing signals is a verdict from noise — a low-traffic client whose
    // one populated signal happens to read machine-like must not be flagged as
    // confidently as a client scored on six. Hold it at `Suspicious` rather
    // than trusting the weighted value either way.
    let classification = if count < 2 {
        Classification::Suspicious
    } else if value >= thresholds.human {
        Classification::Human
    } else if value >= thresholds.suspicious {
        Classification::Suspicious
    } else if value >= thresholds.bot {
        Classification::Bot
    } else {
        Classification::DdosShaped
    };
    Score {
        value,
        classification,
        contributing_signals: count,
        observation_count: profile.observed,
    }
}
