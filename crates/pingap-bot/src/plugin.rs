//! The pingap plugin: config, registration, and the one decision that cannot be made in
//! a pure function.
//!
//! That decision is **where header order comes from**. JA4H's `b` component hashes header
//! names in wire order, and Pingora preserves wire order only for HTTP/1.x: it builds a
//! parallel case map during h1 parsing, reachable through `case_header_iter()` and gated
//! on `has_case()`. For HTTP/2 the case map is `None`, and the only iteration left is
//! `http::HeaderMap`'s, whose own documentation says the order "is arbitrary" and that
//! callers "must not rely on any incidental order".
//!
//! Computing JA4H from that would be the worst kind of bug: the value is *stable within a
//! build*, so it passes "byte-identical across repeated requests" and "different clients
//! differ", while matching no published JA4H for any client. Every library entry misses,
//! python-requests over h2 goes unblocked, and a legitimate client whose arbitrary order
//! happens to collide with a deny entry is refused. Nothing errors.
//!
//! So: **no case map, no fingerprint.** The request is counted as a miss, broken out by
//! protocol so an all-h2 miss population stays distinguishable from an attacker forcing
//! misses, and it is allowed through — fail-open, documented, and measurable.

use crate::analytics::{Analytics, Observation, Verdict};
use crate::ja4h::{RequestHead, ja4h};
use crate::rule::{BotProfile, BotRule, PolicyMode, ValidatedBotRule};
use async_trait::async_trait;
use bytes::Bytes;
use ctor::ctor;
use http::StatusCode;
use pingap_config::PluginConf;
use pingap_core::{Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult};
use pingap_plugin::{
    Error, get_hash_key, get_plugin_factory, get_step_conf_in,
};
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use serde::Deserialize;
use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

const CATEGORY: &str = "bot";
/// The context variable the fingerprint is published under, so an access-log format can
/// pick it up as `{:ja4h}` with no change to `pingap-logger`.
pub const JA4H_VARIABLE: &str = "ja4h";

#[derive(Debug, Default, Deserialize)]
struct BotConf {
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    mode: PolicyMode,
    /// Exempt search-engine crawlers from a broad deny.
    #[serde(default)]
    allow_known_bots: bool,
    /// Prepend the shipped self-declared-client signatures, moved here from the WAF's
    /// detector set. Opt-in: matching a client by the name it chose to send is a weak
    /// signal, so it is offered rather than assumed.
    #[serde(default)]
    use_signatures: bool,
    #[serde(default)]
    rules: Vec<BotRule>,
}

/// Per-request bot state, parked on `Ctx` under its own type.
#[derive(Debug, Default, Clone)]
pub struct BotState {
    pub profile: String,
    /// `None` when no fingerprint could be computed for this request.
    pub ja4h: Option<String>,
    pub denied: bool,
    /// Set even in `detect` mode, which is what makes a staged rollout measurable.
    pub would_deny: bool,
    pub decided_by: Option<usize>,
    pub logged: Vec<usize>,
    pub known_bot: bool,
    /// True when the fingerprint could not be computed, so policy was skipped.
    pub fingerprint_missed: bool,
}

/// The bot plugin.
pub struct Bot {
    plugin_step: PluginStep,
    profile: BotProfile,
    forbidden: HttpResponse,
    /// Aggregate counters.
    ///
    /// Shared across every domain that binds this entry, which the domain policy model
    /// permits for exactly this shape: each observation carries its own domain, so the
    /// counts are *keyed* by domain rather than merged. What must never live here is
    /// anything a verdict depends on — a per-domain threshold would then be advanced by
    /// another domain's traffic.
    ///
    /// A mutex on the request path is a contention point. It is held for a handful of
    /// map increments, which is cheaper than the fingerprint hash that precedes it.
    analytics: Mutex<Analytics>,
    hash_value: String,
}

impl TryFrom<&PluginConf> for Bot {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        // Strict, not `get_step_conf`: a typo in `step` would otherwise produce a bot
        // policy that silently never runs.
        let plugin_step = get_step_conf_in(
            value,
            CATEGORY,
            PluginStep::Request,
            &[PluginStep::Request],
        )?;

        let invalid = |message: String| Error::Invalid {
            category: CATEGORY.to_string(),
            message,
        };

        let conf: BotConf = toml::Value::Table(value.clone())
            .try_into()
            .map_err(|e| invalid(format!("bot config: {e}")))?;

        if conf.rules.is_empty()
            && !conf.allow_known_bots
            && !conf.use_signatures
        {
            return Err(invalid(
                "no `rules`, no `use_signatures` and `allow_known_bots` is false, so \
                 this entry enforces nothing. Remove it, or give it a rule"
                    .to_string(),
            ));
        }

        // Operator rules first, so an explicit `allow` can exempt a client the shipped
        // signatures would deny. The signatures are a floor, not an override.
        let mut specs = conf.rules;
        if conf.use_signatures {
            specs.extend(crate::library::scanner_signatures());
        }
        let mut rules = Vec::with_capacity(specs.len());
        for (index, spec) in specs.into_iter().enumerate() {
            rules.push(
                ValidatedBotRule::new(spec, index)
                    .map_err(|e| invalid(e.to_string()))?,
            );
        }

        let name = conf.profile.unwrap_or_else(|| "default".to_string());
        Ok(Self {
            plugin_step,
            profile: BotProfile::new(
                &name,
                conf.mode,
                conf.allow_known_bots,
                rules,
            ),
            forbidden: HttpResponse {
                status: StatusCode::FORBIDDEN,
                body: Bytes::from_static(b"Forbidden"),
                ..Default::default()
            },
            analytics: Mutex::new(Analytics::default()),
            hash_value,
        })
    }
}

/// Header names in wire order, or `None` when this request has no order to read.
///
/// The single accessor for the order source, so the `has_case()` guard cannot be bypassed
/// by a later caller reaching for `headers.iter()` because it was convenient. Returns
/// borrowed `&str`, skipping any name that is not UTF-8 — a non-UTF-8 header name cannot
/// appear in a published fingerprint, and lossily converting one would invent bytes.
pub fn ordered_header_names(header: &RequestHeader) -> Option<Vec<&str>> {
    if !header.has_case() {
        return None;
    }
    Some(
        header
            .case_header_iter()
            .filter_map(|(name, _)| std::str::from_utf8(name.as_slice()).ok())
            .collect(),
    )
}

/// JA4H's two version digits for a `http::Version`.
///
/// `None` for anything this crate will not fingerprint. HTTP/2 is spelled `20` by the
/// spec and is deliberately absent: the version is the easy part, and emitting a value
/// whose header component is unreliable is the failure this module exists to avoid.
fn version_digits(version: http::Version) -> Option<&'static str> {
    match version {
        http::Version::HTTP_10 => Some("10"),
        http::Version::HTTP_11 => Some("11"),
        _ => None,
    }
}

impl Bot {
    /// Compute the fingerprint, or `None` when this request has no usable header order.
    fn fingerprint(session: &Session) -> Option<String> {
        let header = session.req_header();
        let names = ordered_header_names(header)?;
        let digits = version_digits(header.version)?;
        let value_of = |name: &str| {
            header
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
        };
        let mut head = RequestHead {
            method: header.method.as_str(),
            version_digits: digits,
            header_names: &names,
            cookie: None,
            accept_language: None,
        };
        head.cookie = value_of("cookie");
        head.accept_language = value_of("accept-language");
        Some(ja4h(&head))
    }

    /// A snapshot of the counters, for the admin API to render.
    pub fn analytics(&self) -> Analytics {
        self.analytics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn record(&self, observation: &Observation) {
        self.analytics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record(observation);
    }
}

#[async_trait]
impl Plugin for Bot {
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        let fingerprint = Self::fingerprint(session);
        let user_agent = session
            .get_header(http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let protocol = format!("{:?}", session.req_header().version);
        let domain = pingap_core::get_host(session.req_header())
            .map(str::to_string)
            .unwrap_or_else(|| ctx.upstream.location.to_string());

        // Published before any verdict, so an access log records the fingerprint even for
        // a request the policy allows — which is the population an operator needs in
        // order to build a deny list in the first place.
        if let Some(value) = &fingerprint {
            ctx.add_variable(JA4H_VARIABLE, value);
        }

        let outcome =
            self.profile.evaluate(fingerprint.as_deref(), &user_agent);
        let missed = fingerprint.is_none();

        let verdict = if missed {
            Verdict::Missed
        } else if outcome.known_bot {
            Verdict::KnownBot
        } else if outcome.denied {
            Verdict::Denied
        } else if outcome.would_deny {
            Verdict::WouldDeny
        } else {
            Verdict::Allowed
        };
        self.record(&Observation {
            domain,
            fingerprint: fingerprint.clone(),
            verdict,
            protocol,
        });

        // Recorded whenever there is anything to say. A request that matched nothing on a
        // profile with no findings leaves `Ctx` untouched.
        if missed
            || outcome.would_deny
            || outcome.known_bot
            || !outcome.logged.is_empty()
        {
            let state = ctx.extensions.get_or_insert_default::<BotState>();
            state.profile = self.profile.name().to_string();
            state.ja4h = fingerprint;
            state.denied = outcome.denied;
            state.would_deny = outcome.would_deny;
            state.decided_by = outcome.decided_by;
            state.logged = outcome.logged;
            state.known_bot = outcome.known_bot;
            state.fingerprint_missed = missed;
        }

        if outcome.denied {
            debug!(target: "bot", rule = ?outcome.decided_by, "bot policy refused the request");
            return Ok(RequestPluginResult::Respond(self.forbidden.clone()));
        }
        Ok(RequestPluginResult::Continue)
    }
}

/// Registered with a hand-rolled ctor rather than `register_plugin!`, which has no
/// `#[macro_export]` and is invisible outside `pingap-plugin`.
#[ctor(unsafe)]
fn register() {
    get_plugin_factory()
        .register(CATEGORY, |params| Ok(Arc::new(Bot::try_from(params)?)));
}
