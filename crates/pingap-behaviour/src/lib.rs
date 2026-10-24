pub mod config;
pub mod plugin;
pub mod profile;
pub mod score;
pub mod signals;
pub mod store;

pub use config::{BehaviourConfig, ConfigError, SignalWeights, Thresholds};
pub use plugin::{
    Behaviour, BehaviourCounters, BehaviourSnapshot, BehaviourSnapshots,
    budget_exceeded, counters_snapshot, tracked_snapshot,
};
pub use profile::{Observation, Profile};
pub use score::{Classification, Score};
pub use store::BehaviourStore;

pub mod decisions;
pub mod scenario;

/// Reconcile process state only after a successful runtime provider replacement.
pub fn activate_profiles(
    configs: &std::collections::HashMap<String, pingap_config::PluginConf>,
) {
    activate_profiles_with_retained(configs, &[]);
}

pub fn activate_profiles_with_retained(
    configs: &std::collections::HashMap<String, pingap_config::PluginConf>,
    retained_namespaces: &[String],
) {
    let profiles = configs
        .values()
        .filter_map(|conf| {
            if conf.get("category").and_then(|v| v.as_str())
                != Some("behaviour")
            {
                return None;
            }
            let cfg: BehaviourConfig =
                toml::Value::Table(conf.clone()).try_into().ok()?;
            if !cfg.enabled || !cfg.abuse.enabled || cfg.validate().is_err() {
                return None;
            }
            decisions::ScenarioProfile::new(
                cfg.abuse_namespace.as_deref()?,
                cfg.abuse,
                cfg.max_clients,
                cfg.max_interval_samples,
                cfg.max_url_keys,
            )
            .ok()
        })
        .collect();
    decisions::registry()
        .activate_with_retained(profiles, retained_namespaces);
}

/// Routing and abuse admission share the new registered set after a successful
/// location swap. Removed domains cannot be re-admitted by an older request.
pub fn set_abuse_hosts(hosts: pingap_domainstate::HostPolicy) {
    decisions::registry().retain_hosts(hosts);
}
