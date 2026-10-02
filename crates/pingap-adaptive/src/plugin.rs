use crate::config::AdaptiveConfig;
use crate::learner::{AdaptiveLearner, Baseline, SampleDisposition};
use async_trait::async_trait;
use ctor::ctor;
use pingap_config::PluginConf;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult, get_host};
use pingap_plugin::{Error, get_plugin_factory, get_step_conf_in};
use pingora::proxy::Session;
use serde::Serialize;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Per-domain modulation counters, keyed by the classified domain label and
    /// the decision's fixed reason string. Only ever locked while the profiles
    /// lock is already held — the request path and the snapshot below take the
    /// two in that order, never the reverse.
    modulated: Mutex<BTreeMap<String, BTreeMap<String, u64>>>,
    max_domains: usize,
}

static GLOBAL_REGISTRY: OnceLock<Arc<AdaptiveRegistry>> = OnceLock::new();

/// Whether the adaptive feature is currently on: the state of the latest
/// constructed plugin's config, not the frozen first-enabled config the
/// global registry keeps. The global registry outlives a config apply that
/// sets `enabled = false` — its learners and their history survive the
/// switch-off — so the published state needs this flag to say "the feature
/// is off" rather than letting a row from the enabled period read as a live
/// learner.
static FEATURE_ENABLED: AtomicBool = AtomicBool::new(false);

fn registry_for(config: AdaptiveConfig) -> Arc<AdaptiveRegistry> {
    FEATURE_ENABLED.store(config.enabled, Ordering::Relaxed);
    if !config.enabled {
        return Arc::new(AdaptiveRegistry {
            config,
            profiles: Mutex::new(HashMap::new()),
            modulated: Mutex::new(BTreeMap::new()),
            max_domains: 256,
        });
    }
    GLOBAL_REGISTRY
        .get_or_init(|| {
            Arc::new(AdaptiveRegistry {
                config,
                profiles: Mutex::new(HashMap::new()),
                modulated: Mutex::new(BTreeMap::new()),
                max_domains: 256,
            })
        })
        .clone()
}

impl AdaptiveRegistry {
    /// Count one modulated decision: a learner that was calibrated and whose
    /// decision actually moved a dial — a challenge level above zero, or a rate
    /// factor off neutral. The reason is the fixed string `decision.rs` emits,
    /// never a value read from a request.
    fn count_modulated(&self, domain: &str, reason: &str) {
        let mut rows = self
            .modulated
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *rows
            .entry(domain.to_string())
            .or_default()
            .entry(reason.to_string())
            .or_default() += 1;
    }
}

/// Every learner's baseline, keyed by the classified domain label it learned
/// under, for the persistence task's write-back. Deterministically ordered so
/// two consecutive sweeps write the same sequence. Empty when no adaptive
/// plugin is configured, which is the honest reading: nothing was learned.
pub fn baselines() -> BTreeMap<String, Baseline> {
    let Some(registry) = GLOBAL_REGISTRY.get() else {
        return BTreeMap::new();
    };
    let profiles = registry
        .profiles
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    profiles
        .iter()
        .map(|(domain, learner)| (domain.clone(), learner.baseline()))
        .collect()
}

/// What happened to a baseline offered back to the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// The baseline was accepted; the learner resumes from it uncalibrated and
    /// re-earns calibration from live samples.
    Restored,
    /// The baseline was rejected — wrong shape or past its maximum age. The
    /// learner remains in place with the discard counted on it, so a stale
    /// store row is visible in the published state rather than silent.
    Discarded,
    /// The registry is at domain capacity; nothing was restored.
    Capacity,
    /// No adaptive registry is configured in this process; nothing was
    /// restored and nothing ever will be.
    Disabled,
}

/// Offer a stored baseline back to the registry, creating the domain's learner
/// if it does not exist, within domain capacity. Called by the startup restore
/// sweep before any write-back, so a fresh process resumes from what it
/// previously learned instead of overwriting it with empty learners.
pub fn restore_baseline(
    domain: &str,
    baseline: Baseline,
    now: SystemTime,
) -> RestoreOutcome {
    let Some(registry) = GLOBAL_REGISTRY.get() else {
        return RestoreOutcome::Disabled;
    };
    let mut profiles = registry
        .profiles
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !profiles.contains_key(domain) && profiles.len() >= registry.max_domains
    {
        return RestoreOutcome::Capacity;
    }
    let learner = profiles
        .entry(domain.to_string())
        .or_insert_with(|| AdaptiveLearner::new(registry.config.clone()));
    if learner.restore(baseline, now) {
        RestoreOutcome::Restored
    } else {
        RestoreOutcome::Discarded
    }
}

/// One domain's published adaptive state: the learner's aggregate state plus
/// the fixed-reason modulation counts. Aggregate only, nothing keyed by client
/// identity.
#[derive(Debug, Default, Clone, Serialize)]
pub struct AdaptiveDomainState {
    /// Whether the adaptive feature is currently enabled — the latest
    /// applied config, not the config the learner was built from. `false`
    /// with populated learners beside it is the "disabled" reading; `true`
    /// with `calibrated: false` is "not yet calibrated". The two must never
    /// read as one condition.
    pub enabled: bool,
    pub calibrated: bool,
    pub samples: u64,
    /// The sample count the calibration gate requires —
    /// `min_days_to_calibrate` × 24 — so "not yet calibrated" is diagnosable
    /// as "8 of 168 samples" rather than a silent false.
    pub samples_required: u64,
    pub confidence: f64,
    /// The confidence floor of the same calibration gate.
    pub min_confidence: f64,
    pub discarded_baselines: u64,
    /// Modulation counts keyed by the decision's fixed reason string — the
    /// closed set `decision.rs` emits, never a value read from a request.
    pub modulated: BTreeMap<String, u64>,
}

/// The process-global per-domain adaptive state, for the metrics surface to
/// publish. Empty when no adaptive plugin is configured.
pub fn domain_state_snapshot() -> BTreeMap<String, AdaptiveDomainState> {
    let Some(registry) = GLOBAL_REGISTRY.get() else {
        return BTreeMap::new();
    };
    let profiles = registry
        .profiles
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let modulated = registry
        .modulated
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut rows = BTreeMap::new();
    let enabled = FEATURE_ENABLED.load(Ordering::Relaxed);
    for (domain, learner) in profiles.iter() {
        rows.insert(
            domain.clone(),
            AdaptiveDomainState {
                enabled,
                calibrated: learner.calibrated,
                samples: learner.samples,
                samples_required: u64::from(
                    registry.config.min_days_to_calibrate,
                ) * 24,
                confidence: learner.confidence,
                min_confidence: registry.config.min_confidence,
                discarded_baselines: learner.discarded_baselines,
                modulated: modulated.get(domain).cloned().unwrap_or_default(),
            },
        );
    }
    rows
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
        // Classified, not raw: the label is the registered host's canonical
        // spelling or the one shared overflow label, so the registry's key set
        // is the registered host set plus one overflow entry, whatever `Host`
        // values arrive.
        let domain = pingap_domainstate::label(
            get_host(session.req_header())
                .unwrap_or(ctx.upstream.location.as_ref()),
        );
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
        let learner = profiles.entry(domain.clone()).or_insert_with(|| {
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
        // The rate-limit dial is explicit in config: the learned factor
        // multiplies the ceiling of whatever `limit` plugin handles the
        // request — the limiter keeps its own keying — so an operator who
        // never opted into that modulation keeps the configured ceiling
        // exactly.
        let modulate_rate_limit = self.registry.config.modulate_rate_limit;
        // A modulation is a calibrated decision that actually moved a dial.
        // Counted under the decision's fixed reason string; a
        // `not_calibrated` or neutral `ratio_normal` decision is traffic,
        // not a modulation — and a rate factor off neutral counts as movement
        // only on a limiter the operator pointed the dial at.
        if decision.calibrated
            && (decision.challenge_level > 0
                || (decision.rate_limit_factor != 1.0 && modulate_rate_limit))
        {
            self.registry.count_modulated(&domain, &decision.reason);
        }
        ctx.extensions.insert(AdaptiveSnapshot {
            decision: decision.clone(),
        });
        if modulate_rate_limit {
            ctx.extensions.insert(pingap_core::AdaptiveRateMultiplier(
                learner.effective_factor(1.0, &decision),
            ));
        }
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
