//! A bounded, self-contained challenge response tier.

pub mod config;
pub mod cookie;
pub mod escalation;
pub mod exempt;
pub mod loopdetect;
pub mod marker;
pub mod page;
pub mod plugin;
pub mod pow;
pub mod redirect;
pub mod silent;
pub mod token;

pub use config::{ChallengeConfig, ChallengeKind, ConfigError};
pub use plugin::Challenge;
pub use token::{ChallengeRecord, TokenStore};
