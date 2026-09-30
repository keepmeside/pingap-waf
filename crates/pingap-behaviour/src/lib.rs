pub mod config;
pub mod plugin;
pub mod profile;
pub mod score;
pub mod signals;
pub mod store;

pub use config::{BehaviourConfig, ConfigError, SignalWeights, Thresholds};
pub use plugin::{Behaviour, BehaviourSnapshot, budget_exceeded};
pub use profile::{Observation, Profile};
pub use score::{Classification, Score};
pub use store::BehaviourStore;
