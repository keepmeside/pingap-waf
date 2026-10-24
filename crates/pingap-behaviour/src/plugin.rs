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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

const CATEGORY: &str = "behaviour";
static GLOBAL: OnceLock<Arc<BehaviourStore>> = OnceLock::new();
static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

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

#[derive(Debug, Default, Clone)]
pub struct BehaviourSnapshots(BTreeMap<String, BehaviourSnapshot>);

impl BehaviourSnapshots {
    fn insert(&mut self, key: String, snapshot: BehaviourSnapshot) {
        self.0.insert(key, snapshot);
    }

    fn remove(&mut self, key: &str) -> Option<BehaviourSnapshot> {
        self.0.remove(key)
    }

    pub fn strongest(&self) -> Option<&BehaviourSnapshot> {
        self.0.values().max_by_key(|snapshot| {
            let class = match snapshot.classification {
                Classification::Human => 0,
                Classification::Suspicious => 1,
                Classification::Bot => 2,
                Classification::DdosShaped => 3,
            };
            (class, snapshot.score.value)
        })
    }
}

#[derive(Debug, Clone)]
struct PendingObservation {
    domain: String,
    identity: String,
    observation: Observation,
    ticket: Option<crate::decisions::Ticket>,
    record_score: bool,
}

#[derive(Debug, Default, Clone)]
struct PendingObservations(BTreeMap<String, PendingObservation>);

pub struct Behaviour {
    step: PluginStep,
    config: BehaviourConfig,
    identity: Option<ClientIdentity>,
    store: Arc<BehaviourStore>,
    hash: String,
    pending_key: String,
    native_profile: Option<crate::decisions::ScenarioProfile>,
}

impl TryFrom<&PluginConf> for Behaviour {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self, Self::Error> {
        // Explicit false is the supported disable switch. An omitted flag with
        // enabled abuse would otherwise construct an inert required policy.
        if !value.contains_key("enabled")
            && value
                .get("abuse")
                .and_then(|abuse| abuse.get("enabled"))
                .and_then(toml::Value::as_bool)
                == Some(true)
        {
            return Err(Error::Invalid {
                category: CATEGORY.into(),
                message:
                    "top-level enabled must be explicit when abuse is enabled"
                        .into(),
            });
        }
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
            config: config.clone(),
            identity,
            store,
            native_profile: if config.enabled && config.abuse.enabled {
                Some(
                    crate::decisions::ScenarioProfile::new(
                        config.abuse_namespace.as_deref().unwrap_or_default(),
                        config.abuse.clone(),
                        config.max_clients,
                        config.max_interval_samples,
                        config.max_url_keys,
                    )
                    .map_err(|message| Error::Invalid {
                        category: CATEGORY.into(),
                        message,
                    })?,
                )
            } else {
                None
            },
            // Two identically configured Behaviour plugins may run on the same
            // request. Their response observations must have distinct slots.
            pending_key: format!(
                "behaviour:{}",
                NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed)
            ),
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
        let mut ticket = None;
        if let Some(native_profile) = &self.native_profile {
            let expected_generation = ctx
                .extensions
                .get::<pingap_core::PolicyGeneration>()
                .map(|generation| generation.0);
            if native_profile.config.enforcing()
                && (pingap_core::policy_reload_in_progress()
                    || expected_generation.is_some_and(|generation| {
                        generation != pingap_core::policy_generation()
                    }))
            {
                return Ok(RequestPluginResult::Respond(
                    pingap_core::HttpResponse::builder(
                        http::StatusCode::SERVICE_UNAVAILABLE,
                    )
                    .no_store()
                    .body("Abuse policy is reloading")
                    .finish(),
                ));
            }
            match crate::decisions::registry().admit_profile(
                native_profile,
                &domain,
                &identity,
                session.req_header().method.as_str(),
                session.req_header().uri.path(),
                domain != pingap_domainstate::OVERFLOW_LABEL,
            ) {
                crate::decisions::Admission::Blocked(ban) => {
                    crate::decisions::registry().record_block(&ban);
                    ctx.add_variable("native_abuse_action", "block");
                    return Ok(RequestPluginResult::Respond(
                        pingap_core::HttpResponse::builder(
                            http::StatusCode::FORBIDDEN,
                        )
                        .no_store()
                        .body("Temporarily blocked by abuse policy")
                        .finish(),
                    ));
                },
                crate::decisions::Admission::Allowed(admitted) => {
                    ticket = admitted
                },
                crate::decisions::Admission::Saturated => {
                    ctx.add_variable("native_abuse_status", "saturated")
                },
                crate::decisions::Admission::Unavailable => {
                    ctx.add_variable("native_abuse_status", "unavailable");
                    if self.config.abuse.enforcing()
                        && pingap_core::policy_fails_open()
                    {
                        tracing::warn!(profile=%native_profile.namespace,"native abuse policy unavailable; serving unprotected under explicit fail_open");
                    }
                    if self.config.abuse.enforcing()
                        && !pingap_core::policy_fails_open()
                    {
                        return Ok(RequestPluginResult::Respond(
                            pingap_core::HttpResponse::builder(
                                http::StatusCode::SERVICE_UNAVAILABLE,
                            )
                            .no_store()
                            .body("Abuse policy is unavailable")
                            .finish(),
                        ));
                    }
                },
                crate::decisions::Admission::Unregistered => {},
            }
        }
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
        let record_score = !budget_exceeded(
            started.elapsed().as_millis() as u64,
            self.config.budget_ms,
        );
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
        let pending = PendingObservation {
            domain: domain.clone(),
            identity,
            observation,
            ticket,
            record_score,
        };
        if ctx.extensions.get::<PendingObservations>().is_none() {
            ctx.extensions.insert(PendingObservations::default());
        }
        if let Some(rows) = ctx.extensions.get_mut::<PendingObservations>() {
            rows.0.insert(self.pending_key.clone(), pending);
        }
        if !record_score {
            ctx.add_variable("behaviour_status", "budget_exhausted");
            return Ok(RequestPluginResult::Continue);
        }
        count(&domain, &score);
        if score.contributing_signals > 0 {
            let snapshot = BehaviourSnapshot {
                score,
                classification: score.classification,
            };
            if ctx.extensions.get::<BehaviourSnapshots>().is_none() {
                ctx.extensions.insert(BehaviourSnapshots::default());
            }
            if let Some(snapshots) =
                ctx.extensions.get_mut::<BehaviourSnapshots>()
            {
                snapshots.insert(self.pending_key.clone(), snapshot);
            }
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
        let Some(mut pending) = ctx
            .extensions
            .get_mut::<PendingObservations>()
            .and_then(|rows| rows.0.remove(&self.pending_key))
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
            .get_mut::<BehaviourSnapshots>()
            .and_then(|snapshots| snapshots.remove(&self.pending_key))
            .as_ref()
            .is_some_and(|snapshot| {
                matches!(
                    snapshot.classification,
                    Classification::Bot | Classification::DdosShaped
                )
            });
        if let Some(ticket) = &pending.ticket {
            crate::decisions::registry().observe(
                ticket,
                upstream_response.status.as_u16(),
                pending.observation.denied || pending.observation.challenged,
            );
        }
        if pending.record_score {
            let _ = self.store.record(
                &pending.domain,
                &pending.identity,
                pending.observation,
            );
        }
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
    use super::*;

    #[test]
    fn omitted_enabled_rejects_native_abuse_but_explicit_false_disables_it() {
        let mut conf: PluginConf = toml::from_str(
            r#"category = "behaviour"
abuse_namespace = "behaviour:example"
[abuse]
enabled = true
[abuse.scan]
mode = "block"
window = "1m"
threshold = 2
ban_ttl = "1m"
"#,
        )
        .expect("config");
        assert!(Behaviour::try_from(&conf).is_err());
        conf.insert("enabled".into(), toml::Value::Boolean(false));
        assert!(Behaviour::try_from(&conf).is_ok());
    }

    #[test]
    fn identical_plugin_instances_have_distinct_request_slots() {
        let conf: PluginConf =
            toml::from_str("category = \"behaviour\"\nenabled = true\n")
                .expect("config");
        let first = Behaviour::try_from(&conf).expect("first");
        let second = Behaviour::try_from(&conf).expect("second");
        assert_ne!(first.pending_key, second.pending_key);
    }

    #[test]
    fn category_is_registered_with_the_factory() {
        assert!(
            pingap_plugin::get_plugin_factory()
                .supported_plugins()
                .contains(&"behaviour".to_string())
        );
    }
}
