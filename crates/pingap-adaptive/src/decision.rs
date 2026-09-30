use crate::config::AdaptiveConfig;

#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub ratio: f64,
    pub challenge_level: u8,
    pub rate_limit_factor: f64,
    pub reason: String,
    pub calibrated: bool,
}
impl Decision {
    pub fn normal() -> Self {
        Self {
            ratio: 1.0,
            challenge_level: 0,
            rate_limit_factor: 1.0,
            reason: "not_calibrated".into(),
            calibrated: false,
        }
    }
}

pub fn decide(
    config: &AdaptiveConfig,
    expected: f64,
    current: f64,
    bot_rate: f64,
) -> Decision {
    if expected <= 0.0 {
        return Decision::normal();
    }
    let adjusted =
        (expected * (1.0 - bot_rate.clamp(0.0, 1.0) * 0.5)).max(0.001);
    let ratio = current.max(0.0) / adjusted;
    let (level, factor, reason) = if ratio >= config.ratio_extreme {
        (2, config.factor_extreme, "ratio_extreme")
    } else if ratio >= config.ratio_major {
        (2, config.factor_major, "ratio_major")
    } else if ratio >= config.ratio_significant {
        (1, config.factor_significant, "ratio_significant")
    } else if ratio >= config.ratio_moderate {
        (1, config.factor_moderate, "ratio_moderate")
    } else if ratio >= config.ratio_minor {
        (0, config.factor_minor, "ratio_minor")
    } else if ratio < 0.3 && config.allow_loosening {
        (0, 2.0, "ratio_low_loosening")
    } else {
        (0, 1.0, "ratio_normal")
    };
    Decision {
        ratio,
        challenge_level: level,
        rate_limit_factor: factor,
        reason: reason.into(),
        calibrated: true,
    }
}

pub fn clamp_factor(
    configured: f64,
    factor: f64,
    min_factor: f64,
    allow_loosening: bool,
) -> f64 {
    let lower = configured * min_factor.clamp(0.01, 1.0);
    let upper = if allow_loosening {
        configured * factor.max(1.0)
    } else {
        configured
    };
    (configured * factor).clamp(lower, upper)
        / configured.max(f64::MIN_POSITIVE)
}
