use crate::config::{ChallengeConfig, ChallengeKind, LoopBypass};
use crate::cookie;
use crate::escalation::Escalator;
use crate::exempt::Exemptions;
use crate::loopdetect::LoopDetector;
use crate::page;
use crate::pow;
use crate::redirect::safe_return_path;
use crate::silent;
use crate::token::{self, ChallengeRecord, TokenError, TokenStore};
use async_trait::async_trait;
use bytes::Bytes;
use ctor::ctor;
use http::header;
use pingap_acl::ChallengeMarker;
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult,
    ensure_client_ip, get_host, get_remote_addr,
};
use pingap_domainstate::ClientIdentity;
use pingap_plugin::{Error, get_plugin_factory, get_step_conf_in};
use pingora::proxy::Session;
use serde::Serialize;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;
const CATEGORY: &str = "challenge";
static SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// One domain's challenge counters, in the `Observation` shape: fixed-name fields,
/// aggregate only, none keyed by client identity.
///
/// The key a row lives under is the *classified* domain label, never a raw `Host`
/// value, so the map's cardinality is the registered host set plus one overflow
/// row — a flood of generated `Host` headers grows counts, not keys.
#[derive(Debug, Default, Clone, Serialize)]
pub struct ChallengeCounters {
    pub issued: u64,
    pub solved: u64,
    pub failed: u64,
    pub expired: u64,
    pub bypassed: u64,
    pub saturated: u64,
    pub saturated_domains: u64,
    pub saturated_entries: u64,
    pub stateless_fallback: u64,
    pub exempt_hit: u64,
}

#[derive(Debug)]
struct GlobalState {
    tokens: TokenStore,
    escalator: Escalator,
    loops: LoopDetector,
    counters: Mutex<BTreeMap<String, ChallengeCounters>>,
}

static GLOBAL: OnceLock<Arc<GlobalState>> = OnceLock::new();

impl GlobalState {
    /// Count one event for one domain label.
    ///
    /// One lock per bump, held for a map entry and a field increment — shorter than
    /// the token-store lock the same paths already take, and taken after it, so the
    /// two never nest in opposite orders.
    fn count(&self, domain: &str, bump: impl FnOnce(&mut ChallengeCounters)) {
        let mut rows = self
            .counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        bump(rows.entry(domain.to_string()).or_default());
    }
}

fn global(
    max_domains: usize,
    max_entries: usize,
    loop_threshold: u32,
) -> Arc<GlobalState> {
    GLOBAL
        .get_or_init(|| {
            Arc::new(GlobalState {
                tokens: TokenStore::with_limits(max_domains, max_entries),
                escalator: Escalator::new(max_entries),
                loops: LoopDetector::with_capacity(loop_threshold, max_entries),
                counters: Mutex::new(BTreeMap::new()),
            })
        })
        .clone()
}

/// The process-global per-domain counters, for the metrics surface to publish.
///
/// Empty until the first challenge plugin is constructed, which is the honest
/// reading of a deployment with no challenge configured: there is nothing to count.
/// `expired` is mirrored from the token store because the store is the only place
/// an expiry is observed — a record is dropped the moment it is found stale, so the
/// count lives where the drop happens and is attributed to the domain that owned
/// the record.
pub fn counters_snapshot() -> BTreeMap<String, ChallengeCounters> {
    let Some(state) = GLOBAL.get() else {
        return BTreeMap::new();
    };
    let mut rows = state
        .counters
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    for (domain, expired) in state.tokens.expired_by_domain() {
        rows.entry(domain).or_default().expired += expired;
    }
    rows
}

pub struct Challenge {
    plugin_step: PluginStep,
    config: ChallengeConfig,
    secret: Vec<u8>,
    /// This node's pass-cookie key identifier: the first hex of the secret's
    /// SHA-256, the same value baked into every pass cookie this node signs.
    /// Published as an access-log variable beside `challenge_status` so a
    /// solve loop caused by two nodes sharing traffic with two different
    /// secrets reads as two different `challenge_key_id` values in the two
    /// nodes' logs, rather than as an unexplained solve rate.
    key_id: String,
    identity: Option<ClientIdentity>,
    exemptions: Exemptions,
    state: Arc<GlobalState>,
    hash_value: String,
}

impl TryFrom<&PluginConf> for Challenge {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = pingap_plugin::get_hash_key(value);
        let plugin_step = get_step_conf_in(
            value,
            CATEGORY,
            PluginStep::Request,
            &[PluginStep::Request],
        )?;
        let config: ChallengeConfig = toml::Value::Table(value.clone())
            .try_into()
            .map_err(|e| Error::Invalid {
                category: CATEGORY.into(),
                message: format!("challenge config: {e}"),
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
        let exemptions =
            Exemptions::new(&config.exempt).map_err(|e| Error::Invalid {
                category: CATEGORY.into(),
                message: e,
            })?;
        Ok(Self {
            plugin_step,
            key_id: cookie::key_id(config.secret.as_bytes()),
            secret: config.secret.as_bytes().to_vec(),
            state: global(
                config.max_domains,
                config.max_entries,
                config.loop_threshold,
            ),
            config,
            identity,
            exemptions,
            hash_value,
        })
    }
}

impl Challenge {
    /// Publish one challenge status with this node's key identifier beside it.
    ///
    /// The two travel together because the pair is what a cross-node secret
    /// mismatch reads from: the status says what this node did with the
    /// request, the key id says which secret's authority it did it under.
    fn note(&self, ctx: &mut Ctx, status: &str) {
        ctx.add_variable("challenge_status", status);
        ctx.add_variable("challenge_key_id", &self.key_id);
    }

    /// Record one challenge decision as a log line naming the domain and the
    /// reason, on the solved paths as well as the refused ones. The counters
    /// are the aggregate record; the access-log variables are the per-request
    /// one; this line is the attributable one an operator reads when asking
    /// why a domain is challenging — at the same `debug` level the ACL and
    /// WAF record their own per-request decisions, so turning it on is the
    /// same act for all three.
    fn record(&self, domain: &str, outcome: &str, reason: &str) {
        debug!(
            target: "challenge",
            domain = domain,
            outcome = outcome,
            reason = reason,
            "a challenge decision was recorded"
        );
    }

    pub fn new(config: ChallengeConfig) -> Result<Self> {
        let table =
            toml::Value::try_from(&config).map_err(|e| Error::Invalid {
                category: CATEGORY.into(),
                message: e.to_string(),
            })?;
        let conf = table.as_table().cloned().unwrap_or_default();
        Self::try_from(&conf)
    }

    fn domain(&self, session: &Session, ctx: &Ctx) -> String {
        // Classified, not raw: the label is the registered host's canonical spelling
        // or the one shared overflow label, so a flood of `Host` values cannot mint
        // state keys, and every stateful component below — tokens, escalation, loop
        // detection, the signed cookie — keys the same label for the same request.
        pingap_domainstate::label(
            get_host(session.req_header())
                .unwrap_or(ctx.upstream.location.as_ref()),
        )
    }

    fn identity(&self, session: &Session, ctx: &mut Ctx) -> String {
        match self.identity.as_ref().map(ClientIdentity::source) {
            None => get_remote_addr(session)
                .map(|(addr, _)| addr)
                .unwrap_or_default(),
            Some(pingap_domainstate::IdentitySource::PeerAddress) => {
                get_remote_addr(session)
                    .map(|(addr, _)| addr)
                    .unwrap_or_default()
            },
            Some(pingap_domainstate::IdentitySource::TrustedProxies) => {
                ensure_client_ip(session, ctx).to_string()
            },
        }
    }

    fn target(session: &Session) -> String {
        safe_return_path(&session.req_header().uri.to_string()).to_string()
    }

    fn escalation_for(
        &self,
        domain: &str,
        identity: &str,
    ) -> Option<crate::escalation::EscalationState> {
        if self.exemptions.contains(identity) {
            self.state.count(domain, |row| row.exempt_hit += 1);
            return None;
        }
        Some(self.state.escalator.failure(
            domain,
            identity,
            &self.config.ladder,
            self.config.decay,
        ))
    }

    fn header_value(
        session: &Session,
        name: header::HeaderName,
    ) -> Option<String> {
        session
            .get_header(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    }

    fn response(&self, body: String) -> HttpResponse {
        HttpResponse::builder(http::StatusCode::OK)
            .body(Bytes::from(body))
            .header((
                header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/html; charset=utf-8"),
            ))
            .header((
                header::CACHE_CONTROL,
                http::HeaderValue::from_static("no-store"),
            ))
            .finish()
    }

    fn issue(
        &self,
        marker: &ChallengeMarker,
        domain: &str,
        identity: &str,
        target: String,
    ) -> HttpResponse {
        let kind = if marker.level > 0 && marker.level % 2 == 1 {
            ChallengeKind::Silent
        } else {
            self.config.kind
        };
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let token_id = token::token_id(&self.secret, sequence, &target);
        let salt =
            token::token_id(&self.secret, sequence.wrapping_add(1), domain)
                [..24]
                .to_string();
        let difficulty =
            self.config.difficulty.saturating_add(marker.level).min(10);
        let count = self.state.loops.issued(
            domain,
            identity,
            if kind == ChallengeKind::Pow {
                "pow"
            } else {
                "silent"
            },
        );
        if self.state.loops.looping(count)
            && self.config.bypass_on_loop == LoopBypass::Refuse
        {
            self.state.count(domain, |row| row.bypassed += 1);
            self.record(domain, "bypassed", "loop-detected");
            return HttpResponse::builder(http::StatusCode::FORBIDDEN)
                .body(Bytes::from_static(b"Challenge loop detected"))
                .finish();
        }
        let record = ChallengeRecord {
            domain: domain.to_string(),
            identity: identity.to_string(),
            salt: salt.clone(),
            difficulty,
            target: target.clone(),
            kind: match kind {
                ChallengeKind::Pow => "pow",
                ChallengeKind::Silent => "silent",
            }
            .to_string(),
            attempts: 0,
            expires_at: SystemTime::now() + self.config.token_ttl,
        };
        let token = match self.state.tokens.issue(token_id.clone(), record) {
            Ok(()) => token_id,
            Err(TokenError::FullDomains) => {
                self.state.count(domain, |row| {
                    row.saturated += 1;
                    row.saturated_domains += 1;
                });
                self.record(domain, "saturated", "domain-capacity");
                return HttpResponse::builder(
                    http::StatusCode::SERVICE_UNAVAILABLE,
                )
                .body(Bytes::from_static(
                    b"Challenge state domain capacity reached",
                ))
                .finish();
            },
            Err(TokenError::FullEntries) => {
                self.state.count(domain, |row| {
                    row.saturated += 1;
                    row.saturated_entries += 1;
                    row.stateless_fallback += 1;
                });
                self.record(domain, "saturated", "entry-capacity");
                token::stateless(
                    &self.secret,
                    domain,
                    identity,
                    &target,
                    &salt,
                    difficulty,
                    self.config.token_ttl,
                )
            },
        };
        self.state.count(domain, |row| row.issued += 1);
        // The marker's reason is the originating policy's reason — which rule
        // challenged, or which threshold tripped — and it is what makes this
        // line answer "why was this domain challenging", not only "that it was".
        self.record(domain, "issued", &marker.reason);
        let body = match kind {
            ChallengeKind::Pow => page::pow(
                &token,
                &salt,
                difficulty,
                &format!("{}verify", self.config.prefix),
                &target,
            ),
            ChallengeKind::Silent => page::silent(
                &token,
                &format!("{}verify", self.config.prefix),
                &target,
            ),
        };
        self.response(body)
    }

    fn verify(
        &self,
        session: &Session,
        ctx: &mut Ctx,
        domain: &str,
        identity: &str,
    ) -> HttpResponse {
        let query = session.req_header().uri.query().unwrap_or_default();
        let mut token_value = None;
        let mut nonce = None;
        for pair in query.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            match key {
                "challenge_token" => token_value = Some(value),
                "nonce" => nonce = value.parse::<u64>().ok(),
                _ => {},
            }
        }
        let Some(token_value) = token_value else {
            self.state.count(domain, |row| row.failed += 1);
            self.record(domain, "failed", "missing-token");
            return HttpResponse::bad_request("missing challenge token");
        };
        let stateful = self.state.tokens.get(
            token_value,
            domain,
            identity,
            SystemTime::now(),
        );
        let record = stateful.clone().or_else(|| {
            token::parse_stateless(
                &self.secret,
                token_value,
                domain,
                identity,
                SystemTime::now(),
            )
        });
        let Some(record) = record else {
            self.state.count(domain, |row| row.failed += 1);
            self.record(domain, "failed", "invalid-token");
            return HttpResponse::builder(http::StatusCode::FORBIDDEN)
                .body(Bytes::from_static(b"Invalid or expired challenge"))
                .finish();
        };
        if record.kind == "pow"
            && !pow::solved(
                &record.salt,
                nonce.unwrap_or(u64::MAX),
                record.difficulty,
            )
        {
            if stateful.is_some() {
                let attempts = self
                    .state
                    .tokens
                    .increment_attempts(token_value)
                    .unwrap_or(self.config.max_attempts);
                if attempts >= self.config.max_attempts {
                    self.state.tokens.remove(token_value);
                }
            }
            self.state.count(domain, |row| row.failed += 1);
            self.record(domain, "failed", "proof-failed");
            return HttpResponse::builder(http::StatusCode::FORBIDDEN)
                .body(Bytes::from_static(b"Challenge proof failed"))
                .finish();
        }
        let fingerprint_cookie = Self::header_value(session, header::COOKIE);
        let signed_fingerprint = if record.kind == "silent" {
            let raw = cookie::named_cookie(
                fingerprint_cookie.as_deref(),
                "pingap_challenge_fp",
            )
            .and_then(|value| urlencoding::decode(value).ok())
            .map(|value| value.into_owned());
            let prefix = format!("{token_value}|");
            let Some(raw) = raw.filter(|value| value.starts_with(&prefix))
            else {
                self.state.count(domain, |row| row.failed += 1);
                self.record(domain, "failed", "fingerprint-missing");
                return HttpResponse::builder(http::StatusCode::FORBIDDEN)
                    .body(Bytes::from_static(
                        b"Missing silent challenge fingerprint",
                    ))
                    .finish();
            };
            let fingerprint = raw.strip_prefix(&prefix).unwrap_or_default();
            Some(silent::fingerprint_cookie(
                &self.secret,
                token_value,
                fingerprint,
            ))
        } else {
            None
        };
        if stateful.is_some()
            && self
                .state
                .tokens
                .take(token_value, domain, identity, SystemTime::now())
                .is_none()
        {
            self.state.count(domain, |row| row.failed += 1);
            self.record(domain, "failed", "token-consumed");
            return HttpResponse::builder(http::StatusCode::FORBIDDEN)
                .body(Bytes::from_static(
                    b"Challenge token was already consumed",
                ))
                .finish();
        }
        self.state.loops.solved(domain, identity, &record.kind);
        self.state
            .escalator
            .success(domain, identity, self.config.decay);
        self.state.count(domain, |row| row.solved += 1);
        // The token's kind is the honest reason on this path: the marker that
        // originated the challenge belonged to the earlier request, and what
        // this decision records is which proof the client satisfied.
        self.record(domain, "solved", &record.kind);
        let value = cookie::sign(
            &self.secret,
            domain,
            identity,
            self.config.pass_ttl,
            SystemTime::now(),
        );
        let cookie_header = http::HeaderValue::from_str(&cookie::set_cookie(
            &value,
            self.config.pass_ttl,
        ))
        .ok();
        let location =
            http::HeaderValue::from_str(safe_return_path(&record.target)).ok();
        let mut response =
            HttpResponse::builder(http::StatusCode::SEE_OTHER).no_store();
        if let Some(value) = cookie_header {
            response = response.header((header::SET_COOKIE, value));
        }
        if let Some(value) = signed_fingerprint
            && let Ok(value) = http::HeaderValue::from_str(
                &cookie::set_fingerprint_cookie(&value),
            )
        {
            response = response.header((header::SET_COOKIE, value));
        }
        if let Some(value) = location {
            response = response.header((header::LOCATION, value));
        }
        self.note(ctx, "solved");
        response.finish()
    }
}

#[async_trait]
impl Plugin for Challenge {
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step || !self.config.enabled {
            return Ok(RequestPluginResult::Continue);
        }
        let domain = self.domain(session, ctx);
        let identity = self.identity(session, ctx);
        let path = session.req_header().uri.path();
        if path.starts_with(&self.config.prefix) {
            let response = self.verify(session, ctx, &domain, &identity);
            return Ok(RequestPluginResult::Respond(response));
        }
        if cookie::cookie_value(
            Self::header_value(session, header::COOKIE).as_deref(),
        )
        .and_then(|value| {
            cookie::verify(
                &self.secret,
                value,
                &domain,
                &identity,
                SystemTime::now(),
            )
        })
        .is_some()
        {
            self.note(ctx, "solved");
            self.record(&domain, "solved", "pass-cookie");
            return Ok(RequestPluginResult::Continue);
        }
        let Some(mut marker) = ctx.extensions.get::<ChallengeMarker>().cloned()
        else {
            return Ok(RequestPluginResult::Continue);
        };
        if let Some(snapshot) =
            ctx.extensions.get::<pingap_behaviour::BehaviourSnapshot>()
        {
            marker.level =
                marker.level.saturating_add(match snapshot.classification {
                    pingap_behaviour::Classification::Human => 0,
                    pingap_behaviour::Classification::Suspicious => 1,
                    pingap_behaviour::Classification::Bot => 2,
                    pingap_behaviour::Classification::DdosShaped => 3,
                });
        }
        if let Some(snapshot) =
            ctx.extensions.get::<pingap_adaptive::AdaptiveSnapshot>()
        {
            marker.level = marker
                .level
                .saturating_add(snapshot.decision.challenge_level);
        }
        let Some(escalation) = self.escalation_for(&domain, &identity) else {
            self.note(ctx, "exempt");
            self.record(&domain, "exempt", "exempt");
            return Ok(RequestPluginResult::Continue);
        };
        marker.level = marker.level.max(escalation.level);
        let response =
            self.issue(&marker, &domain, &identity, Self::target(session));
        self.note(ctx, "issued");
        Ok(RequestPluginResult::Respond(response))
    }
}

#[ctor(unsafe)]
fn register() {
    get_plugin_factory().register(CATEGORY, |params| {
        Ok(Arc::new(Challenge::try_from(params)?))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn an_exempt_identity_does_not_create_escalation_state() {
        let config = ChallengeConfig {
            enabled: true,
            secret: "test-secret".into(),
            client_ip_from_peer: true,
            exempt: vec!["203.0.113.1".into()],
            ..Default::default()
        };
        let challenge = Challenge::new(config).expect("valid challenge");
        assert!(challenge.escalation_for("a.test", "203.0.113.1").is_none());
        assert_eq!(
            challenge
                .state
                .escalator
                .get("a.test", "203.0.113.1", Duration::from_secs(60))
                .failures,
            0
        );
    }

    #[test]
    fn category_is_registered_with_the_factory() {
        assert!(
            pingap_plugin::get_plugin_factory()
                .supported_plugins()
                .contains(&"challenge".to_string())
        );
    }
}
