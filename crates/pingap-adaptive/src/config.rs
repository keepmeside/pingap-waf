use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct AdaptiveConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_samples")]
    pub max_samples_per_hour: usize,
    #[serde(default = "default_min_days")]
    pub min_days_to_calibrate: u32,
    #[serde(default = "default_confidence")]
    pub min_confidence: f64,
    #[serde(default = "default_ratio_minor")]
    pub ratio_minor: f64,
    #[serde(default = "default_ratio_moderate")]
    pub ratio_moderate: f64,
    #[serde(default = "default_ratio_significant")]
    pub ratio_significant: f64,
    #[serde(default = "default_ratio_major")]
    pub ratio_major: f64,
    #[serde(default = "default_ratio_extreme")]
    pub ratio_extreme: f64,
    #[serde(default = "default_factor_minor")]
    pub factor_minor: f64,
    #[serde(default = "default_factor_moderate")]
    pub factor_moderate: f64,
    #[serde(default = "default_factor_significant")]
    pub factor_significant: f64,
    #[serde(default = "default_factor_major")]
    pub factor_major: f64,
    #[serde(default = "default_factor_extreme")]
    pub factor_extreme: f64,
    #[serde(default = "default_min_factor")]
    pub min_factor: f64,
    #[serde(default)]
    pub allow_loosening: bool,
    #[serde(default = "default_persist")]
    pub persist: bool,
    #[serde(default = "default_age_days")]
    pub max_baseline_age_days: u64,
    #[serde(default = "default_window", with = "humantime_serde")]
    pub sample_window: Duration,
    #[serde(default)]
    pub client_ip_from_peer: bool,
}

const fn default_max_samples() -> usize {
    240
}
const fn default_min_days() -> u32 {
    7
}
const fn default_confidence() -> f64 {
    0.6
}
const fn default_ratio_minor() -> f64 {
    2.0
}
const fn default_ratio_moderate() -> f64 {
    3.0
}
const fn default_ratio_significant() -> f64 {
    5.0
}
const fn default_ratio_major() -> f64 {
    10.0
}
const fn default_ratio_extreme() -> f64 {
    20.0
}
const fn default_factor_minor() -> f64 {
    0.9
}
const fn default_factor_moderate() -> f64 {
    0.75
}
const fn default_factor_significant() -> f64 {
    0.5
}
const fn default_factor_major() -> f64 {
    0.25
}
const fn default_factor_extreme() -> f64 {
    0.1
}
const fn default_min_factor() -> f64 {
    0.1
}
const fn default_persist() -> bool {
    true
}
const fn default_age_days() -> u64 {
    14
}
const fn default_window() -> Duration {
    Duration::from_secs(3600)
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_samples_per_hour: default_max_samples(),
            min_days_to_calibrate: default_min_days(),
            min_confidence: default_confidence(),
            ratio_minor: default_ratio_minor(),
            ratio_moderate: default_ratio_moderate(),
            ratio_significant: default_ratio_significant(),
            ratio_major: default_ratio_major(),
            ratio_extreme: default_ratio_extreme(),
            factor_minor: default_factor_minor(),
            factor_moderate: default_factor_moderate(),
            factor_significant: default_factor_significant(),
            factor_major: default_factor_major(),
            factor_extreme: default_factor_extreme(),
            min_factor: default_min_factor(),
            allow_loosening: false,
            persist: default_persist(),
            max_baseline_age_days: default_age_days(),
            sample_window: default_window(),
            client_ip_from_peer: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, snafu::Snafu)]
pub enum ConfigError {
    #[snafu(display("adaptive: `{key}` must be greater than zero"))]
    Zero { key: &'static str },
    #[snafu(display(
        "adaptive: `min_factor` is {value}; it must be below 1.0"
    ))]
    MinFactor { value: String },
    #[snafu(display("adaptive: ratio thresholds must be strictly ascending"))]
    RatioOrder,
    #[snafu(display("adaptive: `{key}` must be finite"))]
    NonFinite { key: &'static str },
    #[snafu(display("adaptive: identity gate refused construction: {reason}"))]
    Identity { reason: String },
}

impl AdaptiveConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.max_samples_per_hour == 0 {
            return Err(ConfigError::Zero {
                key: "max_samples_per_hour",
            });
        }
        if self.min_days_to_calibrate == 0 {
            return Err(ConfigError::Zero {
                key: "min_days_to_calibrate",
            });
        }
        let finite = [
            ("min_confidence", self.min_confidence),
            ("ratio_minor", self.ratio_minor),
            ("ratio_moderate", self.ratio_moderate),
            ("ratio_significant", self.ratio_significant),
            ("ratio_major", self.ratio_major),
            ("ratio_extreme", self.ratio_extreme),
            ("factor_minor", self.factor_minor),
            ("factor_moderate", self.factor_moderate),
            ("factor_significant", self.factor_significant),
            ("factor_major", self.factor_major),
            ("factor_extreme", self.factor_extreme),
            ("min_factor", self.min_factor),
        ];
        if let Some((key, _)) =
            finite.into_iter().find(|(_, value)| !value.is_finite())
        {
            return Err(ConfigError::NonFinite { key });
        }
        if !(0.0..=1.0).contains(&self.min_confidence)
            || self.min_confidence == 0.0
        {
            return Err(ConfigError::Zero {
                key: "min_confidence",
            });
        }
        if !(self.ratio_minor < self.ratio_moderate
            && self.ratio_moderate < self.ratio_significant
            && self.ratio_significant < self.ratio_major
            && self.ratio_major < self.ratio_extreme)
        {
            return Err(ConfigError::RatioOrder);
        }
        if self.min_factor >= 1.0 || self.min_factor <= 0.0 {
            return Err(ConfigError::MinFactor {
                value: self.min_factor.to_string(),
            });
        }
        if self.max_baseline_age_days == 0 {
            return Err(ConfigError::Zero {
                key: "max_baseline_age_days",
            });
        }
        if self.sample_window.is_zero() {
            return Err(ConfigError::Zero {
                key: "sample_window",
            });
        }
        pingap_domainstate::ClientIdentity::new(self.client_ip_from_peer)
            .map(|_| ())
            .map_err(|reason| ConfigError::Identity {
                reason: reason.to_string(),
            })
    }
}
