use serde::Deserialize;
use std::time::Duration;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    #[default]
    Pow,
    Silent,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct ChallengeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub secret: String,
    #[serde(default = "default_prefix")]
    pub prefix: String,
    #[serde(default)]
    pub kind: ChallengeKind,
    #[serde(default = "default_difficulty")]
    pub difficulty: u8,
    #[serde(default = "default_token_ttl", with = "humantime_serde")]
    pub token_ttl: Duration,
    #[serde(default = "default_pass_ttl", with = "humantime_serde")]
    pub pass_ttl: Duration,
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_max_domains")]
    pub max_domains: usize,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default)]
    pub client_ip_from_peer: bool,
    #[serde(default = "default_ladder")]
    pub ladder: Vec<u8>,
    #[serde(default)]
    pub exempt: Vec<String>,
    #[serde(default = "default_loop_threshold")]
    pub loop_threshold: u32,
    #[serde(default = "default_decay", with = "humantime_serde")]
    pub decay: Duration,
    #[serde(default)]
    pub bypass_on_loop: LoopBypass,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum LoopBypass {
    #[default]
    Refuse,
    Allow,
}

fn default_prefix() -> String {
    "/.pingap/challenge/".to_string()
}
const fn default_difficulty() -> u8 {
    4
}
fn default_token_ttl() -> Duration {
    Duration::from_secs(300)
}
fn default_pass_ttl() -> Duration {
    Duration::from_secs(3600)
}
const fn default_max_entries() -> usize {
    4096
}
const fn default_max_domains() -> usize {
    256
}
const fn default_max_attempts() -> u32 {
    8
}
const fn default_loop_threshold() -> u32 {
    3
}
fn default_decay() -> Duration {
    Duration::from_secs(900)
}
fn default_ladder() -> Vec<u8> {
    vec![2, 4, 8]
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            secret: String::new(),
            prefix: default_prefix(),
            kind: ChallengeKind::default(),
            difficulty: default_difficulty(),
            token_ttl: default_token_ttl(),
            pass_ttl: default_pass_ttl(),
            max_entries: default_max_entries(),
            max_domains: default_max_domains(),
            max_attempts: default_max_attempts(),
            client_ip_from_peer: false,
            ladder: default_ladder(),
            exempt: Vec::new(),
            loop_threshold: default_loop_threshold(),
            decay: default_decay(),
            bypass_on_loop: LoopBypass::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, snafu::Snafu)]
pub enum ConfigError {
    #[snafu(display("challenge: `secret` is required when `enabled = true`"))]
    MissingSecret,
    #[snafu(display("challenge: `difficulty` is {value}; expected 1..=10"))]
    Difficulty { value: u8 },
    #[snafu(display(
        "challenge: `prefix` must start with `/` and contain no control characters"
    ))]
    BadPrefix,
    #[snafu(display("challenge: `{key}` must be greater than zero"))]
    Zero { key: &'static str },
    #[snafu(display(
        "challenge: `client_ip_from_peer` or `basic.trusted_proxies` is required for identity-bound state: {reason}"
    ))]
    Identity { reason: String },
    #[snafu(display(
        "challenge: exempt entry `{value}` is not an IP address or CIDR range"
    ))]
    BadExempt { value: String },
    #[snafu(display(
        "challenge: `ladder` must be non-decreasing — each threshold applies to a \
         higher tier than the last, so a descending run like {values} would let \
         more failures produce a *lower* challenge level"
    ))]
    LadderOrder { values: String },
}

impl ChallengeConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.secret.is_empty() {
            return Err(ConfigError::MissingSecret);
        }
        if !(1..=10).contains(&self.difficulty) {
            return Err(ConfigError::Difficulty {
                value: self.difficulty,
            });
        }
        if self.prefix == "/"
            || !self.prefix.starts_with('/')
            || !self.prefix.ends_with('/')
            || self.prefix.contains("//")
            || self.prefix.bytes().any(|b| b.is_ascii_control())
        {
            return Err(ConfigError::BadPrefix);
        }
        if self.token_ttl.is_zero() {
            return Err(ConfigError::Zero { key: "token_ttl" });
        }
        if self.pass_ttl.is_zero() {
            return Err(ConfigError::Zero { key: "pass_ttl" });
        }
        if self.max_entries == 0 {
            return Err(ConfigError::Zero { key: "max_entries" });
        }
        if self.max_domains == 0 {
            return Err(ConfigError::Zero { key: "max_domains" });
        }
        if self.max_attempts == 0 {
            return Err(ConfigError::Zero {
                key: "max_attempts",
            });
        }
        if self.loop_threshold == 0 {
            return Err(ConfigError::Zero {
                key: "loop_threshold",
            });
        }
        if self.decay.is_zero() {
            return Err(ConfigError::Zero { key: "decay" });
        }
        // The ladder maps consecutive-failure thresholds onto escalating tiers,
        // so it must be non-decreasing: a descending run silently inverts
        // severity (more failures would earn a lower challenge level).
        if self.ladder.windows(2).any(|pair| pair[0] > pair[1]) {
            return Err(ConfigError::LadderOrder {
                values: format!("{:?}", self.ladder),
            });
        }
        let rules = pingap_util::IpRules::new(&self.exempt);
        if rules.len() != self.exempt.len() {
            let value = self
                .exempt
                .iter()
                .find(|entry| {
                    pingap_util::IpRules::new(std::slice::from_ref(*entry))
                        .is_empty()
                })
                .cloned()
                .unwrap_or_default();
            return Err(ConfigError::BadExempt { value });
        }
        pingap_domainstate::ClientIdentity::new(self.client_ip_from_peer)
            .map(|_| ())
            .map_err(|e| ConfigError::Identity {
                reason: e.to_string(),
            })
    }
}
