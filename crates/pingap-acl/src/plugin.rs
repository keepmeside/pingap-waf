//! The pingap plugin: config, registration, and evaluation on the request path.
//!
//! Behind the `plugin` feature, because this is the only part of the crate that knows
//! Pingora exists. The rule table and its evaluation stay testable without a proxy.
//!
//! Three decisions here are load-bearing and argued at their use sites:
//! evaluation runs at `PluginStep::Request` so a denial is honoured and a denied
//! request never reaches upstream selection; an access list gates *before* the rule
//! table rather than being a rule in it; and a failure to construct is loud, because a
//! silently-absent ACL serves traffic nobody meant to expose.

use crate::access_list::{AccessList, AccessListConf};
use crate::evaluate::{DefaultAction, RequestFacts, RuleSet};
use crate::rule::{AclRule, ValidatedRule};
use async_trait::async_trait;
use bytes::Bytes;
use ctor::ctor;
use http::{HeaderValue, StatusCode};
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult,
    ensure_client_ip,
};
use pingap_plugin::{
    Error, get_hash_key, get_plugin_factory, get_step_conf_in,
};
use pingora::proxy::Session;
use serde::Deserialize;
use std::borrow::Cow;
use std::sync::Arc;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

const CATEGORY: &str = "acl";

/// The plugin's own config shape.
#[derive(Debug, Default, Deserialize)]
struct AclConf {
    #[serde(default)]
    default_action: DefaultAction,
    #[serde(default)]
    rules: Vec<AclRule>,
    /// An optional named access list gating this domain.
    #[serde(default)]
    access_list: Option<AccessListConf>,
    /// Realm shown in the `WWW-Authenticate` challenge.
    #[serde(default)]
    realm: Option<String>,
}

/// Per-request ACL state, parked on `Ctx` under its own type.
///
/// One struct so a request carries at most one insertion and the logging stage has a
/// single place to look — the same arrangement `pingap-waf` uses for its verdict.
#[derive(Debug, Default, Clone)]
pub struct AclState {
    /// Whether the request was refused by this plugin.
    pub denied: bool,
    /// Position of the rule that decided, when a rule did.
    pub decided_by: Option<usize>,
    /// Positions of `log` rules that matched. Observations, not decisions.
    pub logged: Vec<usize>,
    /// Whether an access list refused the request, as distinct from a rule.
    pub access_list_refused: bool,
}

/// The ACL plugin.
pub struct Acl {
    plugin_step: PluginStep,
    rules: RuleSet,
    access_list: Option<AccessList>,
    forbidden: HttpResponse,
    unauthorized: HttpResponse,
    hash_value: String,
}

impl TryFrom<&PluginConf> for Acl {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        // Strict, not `get_step_conf`: that one falls back to the default on an
        // unparseable value, so a typo in `step` would produce an access control that
        // silently never runs.
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

        let conf: AclConf = toml::Value::Table(value.clone())
            .try_into()
            .map_err(|e| invalid(format!("acl config: {e}")))?;

        let mut rules = Vec::with_capacity(conf.rules.len());
        for (index, spec) in conf.rules.into_iter().enumerate() {
            rules.push(
                ValidatedRule::new(spec, index)
                    .map_err(|e| invalid(e.to_string()))?,
            );
        }
        let rules = RuleSet::new(rules, conf.default_action);

        let access_list = match &conf.access_list {
            Some(list) => Some(
                AccessList::new(CATEGORY, list)
                    .map_err(|e| invalid(e.to_string()))?,
            ),
            None => None,
        };

        // A table with no rules and no access list is not a policy, it is an entry
        // somebody forgot to fill in. Refusing it is the difference between an operator
        // finding out at config load and finding out from an incident — and a
        // `default_action = "deny"` with no rules is the one exception, because that
        // *is* a policy: refuse everything.
        if rules.is_empty()
            && access_list.is_none()
            && conf.default_action == DefaultAction::Allow
        {
            return Err(invalid(
                "no `rules` and no `access_list`, so this entry enforces nothing. \
                 Remove it, or set `default_action = \"deny\"` if refusing \
                 everything is the intent"
                    .to_string(),
            ));
        }

        let realm = conf.realm.unwrap_or_else(|| "Restricted".to_string());
        let challenge =
            HeaderValue::from_str(&format!("Basic realm=\"{realm}\""))
                .map_err(|e| {
                    invalid(format!("`realm` is not a header value: {e}"))
                })?;

        Ok(Self {
            plugin_step,
            rules,
            access_list,
            forbidden: HttpResponse {
                status: StatusCode::FORBIDDEN,
                body: Bytes::from_static(b"Forbidden"),
                ..Default::default()
            },
            unauthorized: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: Some(vec![(
                    http::header::WWW_AUTHENTICATE,
                    challenge,
                )]),
                body: Bytes::from_static(b"Unauthorized"),
                ..Default::default()
            },
            hash_value,
        })
    }
}

impl Acl {
    /// Header name/value pairs, skipping values that are not UTF-8.
    ///
    /// A non-UTF-8 header value cannot be compared against a configured string. It is
    /// dropped rather than lossily converted, because a lossy conversion invents bytes
    /// that were never sent and could manufacture a match.
    fn header_pairs(session: &Session) -> Vec<(&str, &str)> {
        session
            .req_header()
            .headers
            .iter()
            .filter_map(|(name, value)| {
                value.to_str().ok().map(|v| (name.as_str(), v))
            })
            .collect()
    }

    /// The `user:password` pair from a `Basic` `Authorization` header.
    ///
    /// Returns `None` for anything else, including a `Bearer` token — an access list
    /// checks basic-auth users, and treating another scheme's credential as a password
    /// would be a confusing way to fail.
    fn basic_credentials(session: &Session) -> Option<(String, String)> {
        let value = session.get_header(http::header::AUTHORIZATION)?;
        let encoded = value.to_str().ok()?.strip_prefix("Basic ")?;
        let decoded = pingap_util::base64_decode(encoded.trim()).ok()?;
        let text = String::from_utf8(decoded).ok()?;
        let (user, password) = text.split_once(':')?;
        Some((user.to_string(), password.to_string()))
    }
}

#[async_trait]
impl Plugin for Acl {
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Evaluate the access list, then the rule table.
    ///
    /// Runs at `PluginStep::Request`, which is where a `Respond` is honoured and which
    /// is before `upstream_peer` — so a denied request never reaches a backend. At
    /// `EarlyRequest` the dispatch result was historically discarded, which would have
    /// meant answering the client and proxying anyway; that is fixed in this fork, but
    /// `Request` remains the correct hook because ACL needs the matched Location.
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        // Resolved through the gateway's own trusted-proxy logic, so the ACL and the
        // access log cannot disagree about who the client is.
        let client_ip = ensure_client_ip(session, ctx).to_string();

        // The access list gates first, and it is a gate rather than a rule: an `allow`
        // rule in the table cannot let past an address the list refuses. Ordering the
        // other way would make "attach an access list to this domain" mean nothing as
        // soon as any allow rule existed.
        if let Some(list) = &self.access_list {
            let credentials = Self::basic_credentials(session);
            let pair =
                credentials.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
            if !list.admits(&client_ip, pair) {
                debug!(target: "acl", "access list refused the request");
                let state = ctx.extensions.get_or_insert_default::<AclState>();
                state.denied = true;
                state.access_list_refused = true;
                // 401 only when a credential could actually satisfy the list.
                // Challenging for a password that does not exist invites a client to
                // retry forever against an IP-only gate.
                let response = if list.has_users() {
                    self.unauthorized.clone()
                } else {
                    self.forbidden.clone()
                };
                return Ok(RequestPluginResult::Respond(response));
            }
        }

        let headers = Self::header_pairs(session);
        let outcome = self.rules.evaluate(&RequestFacts {
            client_ip: &client_ip,
            method: session.req_header().method.as_str(),
            headers: &headers,
        });

        // Recorded whether or not the request was refused: a `log` rule that matched on
        // an allowed request is the entire point of having a non-terminal action.
        if !outcome.allowed || !outcome.logged.is_empty() {
            let state = ctx.extensions.get_or_insert_default::<AclState>();
            state.denied |= !outcome.allowed;
            state.decided_by = outcome.decided_by;
            state.logged = outcome.logged;
        }

        if outcome.allowed {
            return Ok(RequestPluginResult::Continue);
        }
        debug!(target: "acl", rule = ?outcome.decided_by, "acl refused the request");
        Ok(RequestPluginResult::Respond(self.forbidden.clone()))
    }
}

/// Registered with a hand-rolled ctor rather than `register_plugin!`.
///
/// That macro has no `#[macro_export]`, so it is invisible outside `pingap-plugin` and
/// every one of its call sites is in-crate. `get_plugin_factory` is public, so this
/// needs no vendored change — the same route `pingap-imageoptim` and `pingap-waf` take.
#[ctor(unsafe)]
fn register() {
    get_plugin_factory()
        .register(CATEGORY, |params| Ok(Arc::new(Acl::try_from(params)?)));
}
