use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct BehaviourConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_window", with = "humantime_serde")]
    pub window: Duration,
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,
    #[serde(default = "default_max_urls")]
    pub max_url_keys: usize,
    #[serde(default = "default_max_ua")]
    pub max_user_agents: usize,
    #[serde(default = "default_max_samples")]
    pub max_interval_samples: usize,
    #[serde(default = "default_min_samples")]
    pub min_samples: usize,
    #[serde(default = "default_budget_ms")]
    pub budget_ms: u64,
    #[serde(default)]
    pub weights: SignalWeights,
    #[serde(default)]
    pub thresholds: Thresholds,
    #[serde(default)]
    pub client_ip_from_peer: bool,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct SignalWeights {
    #[serde(default = "weight_timing")]
    pub timing_regularity: u8,
    #[serde(default = "weight_entropy")]
    pub url_entropy: u8,
    #[serde(default = "weight_diversity")]
    pub request_diversity: u8,
    #[serde(default = "weight_speed")]
    pub request_speed: u8,
    #[serde(default = "weight_errors")]
    pub error_pattern: u8,
    #[serde(default = "weight_ua")]
    pub user_agent_consistency: u8,
}

impl Default for SignalWeights {
    fn default() -> Self {
        Self {
            timing_regularity: 25,
            url_entropy: 20,
            request_diversity: 20,
            request_speed: 15,
            error_pattern: 10,
            user_agent_consistency: 10,
        }
    }
}

impl SignalWeights {
    pub fn total(self) -> u16 {
        u16::from(self.timing_regularity)
            + u16::from(self.url_entropy)
            + u16::from(self.request_diversity)
            + u16::from(self.request_speed)
            + u16::from(self.error_pattern)
            + u16::from(self.user_agent_consistency)
    }
    pub fn values(self) -> [u8; 6] {
        [
            self.timing_regularity,
            self.url_entropy,
            self.request_diversity,
            self.request_speed,
            self.error_pattern,
            self.user_agent_consistency,
        ]
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Thresholds {
    #[serde(default = "default_human")]
    pub human: u8,
    #[serde(default = "default_suspicious")]
    pub suspicious: u8,
    #[serde(default = "default_bot")]
    pub bot: u8,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            human: default_human(),
            suspicious: default_suspicious(),
            bot: default_bot(),
        }
    }
}
const fn default_window() -> Duration {
    Duration::from_secs(300)
}
const fn default_max_clients() -> usize {
    5000
}
const fn default_max_urls() -> usize {
    64
}
const fn default_max_ua() -> usize {
    8
}
const fn default_max_samples() -> usize {
    32
}
const fn default_min_samples() -> usize {
    6
}
const fn default_budget_ms() -> u64 {
    2
}
const fn weight_timing() -> u8 {
    25
}
const fn weight_entropy() -> u8 {
    20
}
const fn weight_diversity() -> u8 {
    20
}
const fn weight_speed() -> u8 {
    15
}
const fn weight_errors() -> u8 {
    10
}
const fn weight_ua() -> u8 {
    10
}
const fn default_human() -> u8 {
    55
}
const fn default_suspicious() -> u8 {
    40
}
const fn default_bot() -> u8 {
    20
}

impl Default for BehaviourConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window: default_window(),
            max_clients: default_max_clients(),
            max_url_keys: default_max_urls(),
            max_user_agents: default_max_ua(),
            max_interval_samples: default_max_samples(),
            min_samples: default_min_samples(),
            budget_ms: default_budget_ms(),
            weights: SignalWeights::default(),
            thresholds: Thresholds::default(),
            client_ip_from_peer: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, snafu::Snafu)]
pub enum ConfigError {
    #[snafu(display("behaviour: `{key}` must be greater than zero"))]
    Zero { key: &'static str },
    #[snafu(display(
        "behaviour: `weights` sum to {total}; expected exactly 100"
    ))]
    WeightSum { total: u16 },
    #[snafu(display(
        "behaviour: thresholds must descend human >= suspicious >= bot"
    ))]
    ThresholdOrder,
    #[snafu(display(
        "behaviour: identity gate refused construction: {reason}"
    ))]
    Identity { reason: String },
}

impl BehaviourConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.window.is_zero() {
            return Err(ConfigError::Zero { key: "window" });
        }
        if self.max_clients == 0 {
            return Err(ConfigError::Zero { key: "max_clients" });
        }
        if self.max_url_keys == 0 {
            return Err(ConfigError::Zero {
                key: "max_url_keys",
            });
        }
        if self.max_user_agents == 0 {
            return Err(ConfigError::Zero {
                key: "max_user_agents",
            });
        }
        if self.max_interval_samples == 0 {
            return Err(ConfigError::Zero {
                key: "max_interval_samples",
            });
        }
        if self.min_samples == 0 {
            return Err(ConfigError::Zero { key: "min_samples" });
        }
        if self.budget_ms == 0 {
            return Err(ConfigError::Zero { key: "budget_ms" });
        }
        let total = self.weights.total();
        if total != 100 {
            return Err(ConfigError::WeightSum { total });
        }
        if !(self.thresholds.human >= self.thresholds.suspicious
            && self.thresholds.suspicious >= self.thresholds.bot)
        {
            return Err(ConfigError::ThresholdOrder);
        }
        pingap_domainstate::ClientIdentity::new(self.client_ip_from_peer)
            .map(|_| ())
            .map_err(|reason| ConfigError::Identity {
                reason: reason.to_string(),
            })
    }
}
