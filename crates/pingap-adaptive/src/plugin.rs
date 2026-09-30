use crate::config::AdaptiveConfig;
use crate::learner::{AdaptiveLearner, SampleDisposition};
use async_trait::async_trait;
use ctor::ctor;
use pingap_config::PluginConf;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult, get_host};
use pingap_plugin::{Error, get_plugin_factory, get_step_conf_in};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const CATEGORY: &str = "adaptive";
pub struct Adaptive {
    step: PluginStep,
    registry: Arc<AdaptiveRegistry>,
    hash: String,
}

#[derive(Debug)]
struct AdaptiveRegistry {
    config: AdaptiveConfig,
    profiles: Mutex<HashMap<String, AdaptiveLearner>>,
    max_domains: usize,
}

static GLOBAL_REGISTRY: OnceLock<Arc<AdaptiveRegistry>> = OnceLock::new();

fn registry_for(config: AdaptiveConfig) -> Arc<AdaptiveRegistry> {
    if !config.enabled {
        return Arc::new(AdaptiveRegistry {
            config,
            profiles: Mutex::new(HashMap::new()),
            max_domains: 256,
        });
    }
    GLOBAL_REGISTRY
        .get_or_init(|| {
            Arc::new(AdaptiveRegistry {
                config,
                profiles: Mutex::new(HashMap::new()),
                max_domains: 256,
            })
        })
        .clone()
}

pub(crate) fn calibrate_global() -> bool {
    let Some(registry) = GLOBAL_REGISTRY.get() else {
        return false;
    };
    let mut profiles = registry
        .profiles
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for learner in profiles.values_mut() {
        learner.recalibrate();
    }
    true
}

#[derive(Debug, Clone)]
pub struct AdaptiveSnapshot {
    pub decision: crate::Decision,
}

impl TryFrom<&PluginConf> for Adaptive {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self, Self::Error> {
        let config: AdaptiveConfig = toml::Value::Table(value.clone())
            .try_into()
            .map_err(|e| Error::Invalid {
                category: CATEGORY.into(),
                message: e.to_string(),
            })?;
        config.validate().map_err(|e| Error::Invalid {
            category: CATEGORY.into(),
            message: e.to_string(),
        })?;
        Ok(Self {
            step: get_step_conf_in(
                value,
                CATEGORY,
                PluginStep::Request,
                &[PluginStep::Request],
            )?,
            registry: registry_for(config),
            hash: pingap_plugin::get_hash_key(value),
        })
    }
}

#[async_trait]
impl Plugin for Adaptive {
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash)
    }
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        let enabled = self.registry.config.enabled;
        if step != self.step || !enabled {
            return Ok(RequestPluginResult::Continue);
        }
        let domain = get_host(session.req_header())
            .unwrap_or(ctx.upstream.location.as_ref())
            .to_ascii_lowercase();
        let mut profiles = self
            .registry
            .profiles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !profiles.contains_key(&domain)
            && profiles.len() >= self.registry.max_domains
        {
            ctx.add_variable("adaptive_reason", "domain_capacity");
            return Ok(RequestPluginResult::Continue);
        }
        let learner = profiles.entry(domain).or_insert_with(|| {
            AdaptiveLearner::new(self.registry.config.clone())
        });
        // The domain's live rate comes from the learner's own windowed counter.
        // Nothing else writes `adaptive_current_rps`, so reading it here produced
        // a constant 1.0 and the baseline learned a flat line.
        let now = SystemTime::now();
        let current = learner.observe(now);
        let hour =
            (now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
                / 3600
                % 24) as usize;
        let disposition = match ctx.get_variable("waf_action") {
            Some("block") => SampleDisposition::Denied,
            Some("challenge") => SampleDisposition::Challenged,
            _ if matches!(
                ctx.get_variable("behaviour_profile"),
                Some("bot" | "ddos")
            ) =>
            {
                SampleDisposition::Bot
            },
            _ => SampleDisposition::Normal,
        };
        let bot_rate =
            matches!(disposition, SampleDisposition::Bot) as u8 as f64;
        learner.record(hour, current, bot_rate, disposition);
        let decision = learner.decision(hour, current);
        ctx.extensions.insert(AdaptiveSnapshot {
            decision: decision.clone(),
        });
        ctx.extensions.insert(pingap_core::AdaptiveRateMultiplier(
            learner.effective_factor(1.0, &decision),
        ));
        ctx.add_variable("adaptive_reason", &decision.reason);
        ctx.add_variable("adaptive_ratio", &decision.ratio.to_string());
        Ok(RequestPluginResult::Continue)
    }
}

#[ctor(unsafe)]
fn register() {
    get_plugin_factory()
        .register(CATEGORY, |params| Ok(Arc::new(Adaptive::try_from(params)?)));
}

#[cfg(test)]
mod tests {
    #[test]
    fn category_is_registered_with_the_factory() {
        assert!(
            pingap_plugin::get_plugin_factory()
                .supported_plugins()
                .contains(&"adaptive".to_string())
        );
    }
}
