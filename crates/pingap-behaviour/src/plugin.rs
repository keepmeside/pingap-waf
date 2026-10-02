use crate::config::BehaviourConfig;
use crate::profile::{Observation, Profile};
use crate::score::{self, Classification, Score};
use crate::store::BehaviourStore;
use async_trait::async_trait;
use ctor::ctor;
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, Plugin, PluginStep, RequestPluginResult, ResponsePluginResult,
    ensure_client_ip, get_host, get_remote_addr,
};
use pingap_domainstate::ClientIdentity;
use pingap_plugin::{Error, get_plugin_factory, get_step_conf_in};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use serde::Serialize;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

const CATEGORY: &str = "behaviour";
static GLOBAL: OnceLock<Arc<BehaviourStore>> = OnceLock::new();

/// One domain's behaviour counters: fixed-name fields, aggregate only, none
/// keyed by client identity. The names are the values the `behaviour_profile`
/// log variable writes, so the published vocabulary and the log vocabulary are
/// one set.
///
/// The key a row lives under is the *classified* domain label, never a raw
/// `Host` value, so the map's cardinality is the registered host set plus one
/// overflow row.
#[derive(Debug, Default, Clone, Serialize)]
pub struct BehaviourCounters {
    pub human: u64,
    pub suspicious: u64,
    pub bot: u64,
    pub ddos: u64,
    pub insufficient: u64,
}

/// The process-global per-domain counters, for the metrics surface to publish.
/// Empty until the first request is classified, which is the honest reading of
/// a deployment with no behaviour plugin configured: there is nothing to count.
static COUNTERS: OnceLock<Mutex<BTreeMap<String, BehaviourCounters>>> =
    OnceLock::new();

/// Count one classified request under its domain label.
fn count(domain: &str, score: &Score) {
    let mut rows = COUNTERS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let row = rows.entry(domain.to_string()).or_default();
    if score.contributing_signals == 0 {
        row.insufficient += 1;
    } else {
        match score.classification {
            Classification::Human => row.human += 1,
            Classification::Suspicious => row.suspicious += 1,
            Classification::Bot => row.bot += 1,
            Classification::DdosShaped => row.ddos += 1,
        }
    }
}

/// The process-global per-domain behaviour counters, for the metrics surface to
/// publish.
pub fn counters_snapshot() -> BTreeMap<String, BehaviourCounters> {
    let Some(counters) = COUNTERS.get() else {
        return BTreeMap::new();
    };
    counters
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Distinct identities tracked per domain label, from the process-global
/// store — the published observable that makes a false `client_ip_from_peer`
/// assertion detectable: when every request maps to one identity, this gauge
/// pins at 1 while the same label's request counters keep climbing.
pub fn tracked_snapshot() -> BTreeMap<String, u64> {
    let Some(store) = GLOBAL.get() else {
        return BTreeMap::new();
    };
    store.tracked_per_domain(Instant::now())
}

/// Whether the work done so far this request has overrun the per-request
/// scoring budget. Pure so the degrade direction is assertable without a
/// wall-clock race: the caller passes measured elapsed time, never `Instant`.
#[doc(hidden)]
pub fn budget_exceeded(elapsed_ms: u64, budget_ms: u64) -> bool {
    elapsed_ms > budget_ms
}

#[derive(Debug, Clone)]
pub struct BehaviourSnapshot {
    pub score: Score,
    pub classification: Classification,
}

#[derive(Debug, Clone)]
struct PendingObservation {
    domain: String,
    identity: String,
    observation: Observation,
}

pub struct Behaviour {
    step: PluginStep,
    config: BehaviourConfig,
    identity: Option<ClientIdentity>,
    store: Arc<BehaviourStore>,
    hash: String,
}

impl TryFrom<&PluginConf> for Behaviour {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self, Self::Error> {
        let config: BehaviourConfig = toml::Value::Table(value.clone())
            .try_into()
            .map_err(|e| Error::Invalid {
                category: CATEGORY.into(),
                message: e.to_string(),
            })?;
        config.validate().map_err(|e| Error::Invalid {
            category: CATEGORY.into(),
            message: e.to_string(),
        })?;
        let identity = if config.enabled {
            Some(ClientIdentity::new(config.client_ip_from_peer).map_err(
                |e| Error::Invalid {
                    category: CATEGORY.into(),
                    message: e.to_string(),
                },
            )?)
        } else {
            None
        };
        let store = GLOBAL
            .get_or_init(|| {
                Arc::new(BehaviourStore::new(
                    config.max_clients,
                    config.max_url_keys,
                    config.max_user_agents,
                    config.max_samples(),
                    config.window,
                ))
            })
            .clone();
        let step = get_step_conf_in(
            value,
            CATEGORY,
            PluginStep::Request,
            &[PluginStep::Request],
        )?;
        Ok(Self {
            step,
            config,
            identity,
            store,
            hash: pingap_plugin::get_hash_key(value),
        })
    }
}

impl Behaviour {
    fn domain(&self, session: &Session, ctx: &Ctx) -> String {
        // Classified, not raw: the label is the registered host's canonical
        // spelling or the one shared overflow label, so the store's key set and
        // the counters' key set are the registered host set plus one overflow
        // entry, whatever `Host` values arrive.
        pingap_domainstate::label(
            get_host(session.req_header())
                .unwrap_or(ctx.upstream.location.as_ref()),
        )
    }
    fn identity(&self, session: &Session, ctx: &mut Ctx) -> String {
        match self.identity.as_ref().map(ClientIdentity::source) {
            None => get_remote_addr(session)
                .map(|(address, _)| address)
                .unwrap_or_default(),
            Some(pingap_domainstate::IdentitySource::PeerAddress) => {
                get_remote_addr(session)
                    .map(|(address, _)| address)
                    .unwrap_or_default()
            },
            Some(pingap_domainstate::IdentitySource::TrustedProxies) => {
                ensure_client_ip(session, ctx).to_string()
            },
        }
    }
    pub fn store(&self) -> &BehaviourStore {
        &self.store
    }
}

#[async_trait]
impl Plugin for Behaviour {
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash)
    }
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.step || !self.config.enabled {
            return Ok(RequestPluginResult::Continue);
        }
        let started = Instant::now();
        let domain = self.domain(session, ctx);
        let identity = self.identity(session, ctx);
        let profile = self
            .store
            .snapshot(&domain, &identity, started)
            .unwrap_or_else(|| {
                Profile::new(
                    self.config.max_samples(),
                    self.config.max_url_keys,
                    self.config.max_user_agents,
                    self.config.window,
                )
            });
        let score = score::score(
            &profile,
            self.config.weights,
            self.config.thresholds,
            self.config.min_samples,
        );
        if budget_exceeded(
            started.elapsed().as_millis() as u64,
            self.config.budget_ms,
        ) {
            ctx.add_variable("behaviour_status", "budget_exhausted");
            return Ok(RequestPluginResult::Continue);
        }
        // The published per-domain counter for the classification this request
        // settled on — the same fixed name set the `behaviour_profile` log
        // variable writes. Counted before `domain` and `score` move into the
        // request's extensions, and not at all on the budget-exhausted path
        // above, where no classification settled.
        count(&domain, &score);
        let observation = Observation {
            at: Instant::now(),
            uri: session.req_header().uri.path().to_string(),
            user_agent: session
                .get_header(http::header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string(),
            status: ctx
                .upstream
                .status
                .map(|status| status.as_u16())
                .unwrap_or(200),
            denied: false,
            challenged: false,
            bot: false,
        };
        ctx.extensions.insert(PendingObservation {
            domain,
            identity,
            observation,
        });
        if score.contributing_signals > 0 {
            ctx.extensions.insert(BehaviourSnapshot {
                score,
                classification: score.classification,
            });
        }
        ctx.add_variable("behaviour_score", &score.value.to_string());
        let profile_name = if score.contributing_signals == 0 {
            "insufficient"
        } else {
            match score.classification {
                Classification::Human => "human",
                Classification::Suspicious => "suspicious",
                Classification::Bot => "bot",
                Classification::DdosShaped => "ddos",
            }
        };
        ctx.add_variable("behaviour_profile", profile_name);
        ctx.add_variable(
            "behaviour_observations",
            &score.observation_count.to_string(),
        );
        ctx.add_variable(
            "behaviour_contributing_signals",
            &score.contributing_signals.to_string(),
        );
        ctx.add_variable(
            "behaviour_cost_ms",
            &started.elapsed().as_millis().to_string(),
        );
        Ok(RequestPluginResult::Continue)
    }

    async fn handle_response(
        &self,
        _session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        if !self.config.enabled {
            return Ok(ResponsePluginResult::Unchanged);
        }
        let Some(mut pending) = ctx.extensions.remove::<PendingObservation>()
        else {
            return Ok(ResponsePluginResult::Unchanged);
        };
        pending.observation.status = upstream_response.status.as_u16();
        pending.observation.denied =
            matches!(ctx.get_variable("waf_action"), Some("block" | "deny"));
        pending.observation.challenged =
            matches!(ctx.get_variable("challenge_status"), Some("issued"));
        pending.observation.bot = ctx
            .extensions
            .get::<BehaviourSnapshot>()
            .is_some_and(|snapshot| {
                matches!(
                    snapshot.classification,
                    Classification::Bot | Classification::DdosShaped
                )
            });
        let _ = self.store.record(
            &pending.domain,
            &pending.identity,
            pending.observation,
        );
        Ok(ResponsePluginResult::Unchanged)
    }
}

impl BehaviourConfig {
    fn max_samples(&self) -> usize {
        self.max_interval_samples.max(self.min_samples)
    }
}

#[ctor(unsafe)]
fn register() {
    get_plugin_factory().register(CATEGORY, |params| {
        Ok(Arc::new(Behaviour::try_from(params)?))
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn category_is_registered_with_the_factory() {
        assert!(
            pingap_plugin::get_plugin_factory()
                .supported_plugins()
                .contains(&"behaviour".to_string())
        );
    }
}
