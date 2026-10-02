//! The pingap plugin: config, registration, and both evaluation surfaces wired in.
//!
//! Behind the `plugin` feature, because this is the only part of the crate that knows
//! Pingora exists. The engine, the detectors and the inspection state machine stay
//! testable and fuzzable without a proxy.
//!
//! Four decisions here are load-bearing and are argued at their use sites below:
//! the IP filter runs at `Request` rather than `EarlyRequest`; the request body is
//! withheld rather than drained; response-side redaction masks in place rather than
//! rewriting length; and construction fails when an IP-derived control is enabled
//! without a trusted-proxy list.

use crate::config::WafConfig;
use crate::engine::{RequestInput, ResponseInput, RuleEngine};
use crate::inspect::{BodyBuffer, Feed, OverCap, mask};
use crate::ip_filter::{IpFilter, ListMode};
use crate::rule::Hit;
use async_trait::async_trait;
use bytes::Bytes;
use ctor::ctor;
use http::StatusCode;
use pingap_acl::ChallengeMarker;
use pingap_acl::marker::count_write;
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult,
    ResponseBodyPluginResult, ensure_client_ip, new_internal_error,
    trusted_proxies_enabled,
};
use pingap_events::{Verdict as EventVerdict, WafEvent};
use pingap_intel::{FeedMatch, FeedRegistry};
use pingap_plugin::{
    Error, get_hash_key, get_plugin_factory, get_step_conf_in,
};
use pingora::proxy::Session;
use serde::Deserialize;
use std::borrow::Cow;
use std::fmt::Write as _;
use std::sync::Arc;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

const CATEGORY: &str = "waf";

/// Plugin-level keys that are not part of the engine's own config.
#[derive(Debug, Default, Deserialize)]
struct PluginExtras {
    #[serde(default)]
    over_cap: OverCap,
    #[serde(default)]
    ip_list_mode: ListMode,
    #[serde(default)]
    ip_list: Vec<String>,
}

/// Per-request WAF state, parked on `Ctx` under its own type.
///
/// One struct rather than several so a request carries at most one insertion, and so
/// the logging stage has a single place to look. Cloneable because that is what
/// `http::Extensions` requires; nothing clones it on the request path.
#[derive(Debug, Default, Clone)]
pub struct WafState {
    /// Which named profile produced this verdict.
    ///
    /// Two domains needing independently-counted policy get two config entries, so
    /// they are already separate instances. This is what makes the *result*
    /// attributable: a block with no profile on it leaves an operator holding two
    /// candidate policies and no way to tell which one fired.
    pub profile: String,
    /// Hits from every surface, in the order they were found. The full list travels
    /// rather than just the worst one, because an unexplainable block is an
    /// untriageable false positive.
    pub hits: Vec<Hit>,
    /// Total anomaly score across all hits.
    pub score: u32,
    /// The subtotal that was compared against the threshold.
    pub enforcing_score: u32,
    /// Whether the request was rejected by this plugin.
    pub blocked: bool,
    /// Whether the WAF requested the challenge tier instead of a hard block.
    pub challenged: bool,
    /// Whether any inspected body had bytes the engine never saw.
    pub truncated: bool,
    /// Whether evaluation ran out of budget on any surface.
    pub budget_exhausted: bool,
    /// Whether a response body was masked.
    pub redacted: bool,
    /// Feed attribution for an IP refusal, when intelligence contributed it.
    pub intel_feed: Option<String>,
    pub intel_category: Option<String>,
    pub emitted_hits: usize,
    pub domain: String,
    pub client_ip: Option<String>,
    pub method: String,
    pub uri: String,
    terminal_emitted: bool,
}

impl WafState {
    fn absorb(&mut self, hits: &[Hit], score: u32, enforcing: u32) {
        self.hits.extend_from_slice(hits);
        self.score = self.score.saturating_add(score);
        self.enforcing_score = self.enforcing_score.saturating_add(enforcing);
    }
}

fn event_verdict(state: &WafState) -> EventVerdict {
    if state.blocked {
        EventVerdict::Block
    } else if state.redacted {
        EventVerdict::Redact
    } else {
        EventVerdict::Detect
    }
}

fn offer_new_events(ctx: &mut Ctx, terminal: bool) {
    let Some(queue) = pingap_events::global() else {
        return;
    };
    let (events, aggregate) = {
        let Some(state) = ctx.extensions.get_mut::<WafState>() else {
            return;
        };
        let mut events = Vec::new();
        for hit in state.hits[state.emitted_hits..].iter() {
            events.push(WafEvent {
                node: state.domain.clone(),
                domain: state.domain.clone(),
                profile: state.profile.clone(),
                rule_id: Some(hit.rule_id.get()),
                category: Some(hit.category.to_string()),
                severity: Some(hit.severity.to_string()),
                score: hit.score,
                verdict: event_verdict(state),
                client_ip: state.client_ip.clone(),
                method: Some(state.method.clone()),
                uri: Some(state.uri.clone()),
                created_at: pingap_core::now_sec() as i64,
            });
        }
        state.emitted_hits = state.hits.len();
        let aggregate =
            terminal && events.is_empty() && !state.terminal_emitted;
        if aggregate {
            state.terminal_emitted = true;
        }
        (events, aggregate)
    };
    for event in events {
        let _ = queue.offer(event);
    }
    if aggregate && let Some(state) = ctx.extensions.get::<WafState>() {
        let _ = queue.offer(WafEvent {
            node: state.domain.clone(),
            domain: state.domain.clone(),
            profile: state.profile.clone(),
            rule_id: None,
            category: state.intel_category.clone(),
            severity: None,
            score: state.score,
            verdict: event_verdict(state),
            client_ip: state.client_ip.clone(),
            method: Some(state.method.clone()),
            uri: Some(state.uri.clone()),
            created_at: pingap_core::now_sec() as i64,
        });
    }
}

/// Request-body accumulation state. A separate type from the two response buffers so
/// the three cannot be confused for one another in `Ctx`.
#[derive(Debug, Clone)]
struct RequestBody(BodyBuffer);

/// Upstream-side response prefix: what enters the cache.
#[derive(Debug, Clone)]
struct UpstreamBody(BodyBuffer);

/// Serving-side response prefix: what leaves for the client, including on a cache
/// hit, where the upstream hook never runs.
#[derive(Debug, Clone)]
struct DownstreamBody(BodyBuffer);

/// The WAF plugin.
pub struct Waf {
    plugin_step: PluginStep,
    engine: RuleEngine,
    ip_filter: Option<IpFilter>,
    intel: Option<Arc<FeedRegistry>>,
    over_cap: OverCap,
    body_limit: usize,
    response_prefix_limit: usize,
    /// Copied out of the validated config so stamping a verdict does not go through
    /// the `ArcSwap` the engine keeps its ruleset behind.
    profile: String,
    forbidden: HttpResponse,
    hash_value: String,
}

impl TryFrom<&PluginConf> for Waf {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        // Strict, not `get_step_conf`: that one falls back to the default on an
        // unparsable value, which for a WAF means a typo in `step` produces a
        // plugin that silently never runs. Failing loudly is the only acceptable
        // behaviour for a security control.
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

        // The engine's own config and the plugin's extra keys are read from the same
        // table. Deserialising twice rather than flattening keeps each struct's
        // `serde` defaults honest and keeps unknown keys from being silently
        // swallowed into the wrong one.
        let table = toml::Value::Table(value.clone());
        let waf: WafConfig = table
            .clone()
            .try_into()
            .map_err(|e| invalid(format!("waf config: {e}")))?;
        let extras: PluginExtras = table
            .try_into()
            .map_err(|e| invalid(format!("waf config: {e}")))?;

        let validated = waf.validate().map_err(|e| invalid(e.to_string()))?;
        let intel_conf = validated.intel.clone();
        let has_static_deny = !extras.ip_list.is_empty()
            || !intel_conf.manual.is_empty()
            || crate::categories::Category::ALL.iter().any(|category| {
                matches!(
                    validated.request_mode(*category),
                    crate::config::RequestMode::Block
                )
            });
        if !intel_conf.feed.is_empty() && !has_static_deny {
            return Err(invalid(format!(
                "WAF profile `{}` selects threat feeds but declares no static deny source; add `ip_list`, `intel.manual`, or a request category with `mode = \"block\"`",
                validated.profile
            )));
        }
        let engine = RuleEngine::build(
            validated,
            crate::detectors::request_rules(),
            crate::detectors::response_rules(),
        )
        .map_err(|e| invalid(e.to_string()))?;

        let ip_filter = Self::build_ip_filter(&extras).map_err(invalid)?;
        let intel =
            if intel_conf.feed.is_empty() && intel_conf.manual.is_empty() {
                None
            } else {
                let plan = pingap_intel::config::plan([(
                    hash_value.as_str(),
                    &intel_conf,
                )])
                .map_err(|error| invalid(error.to_string()))?;
                let registry = Arc::new(FeedRegistry::new(plan));
                let _ = pingap_intel::install_global_registry(registry.clone());
                Some(registry)
            };

        Ok(Self {
            plugin_step,
            body_limit: engine.config().body_inspect_limit,
            response_prefix_limit: engine.config().response_prefix_limit,
            profile: engine.config().profile.clone(),
            engine,
            ip_filter,
            intel,
            over_cap: extras.over_cap,
            forbidden: HttpResponse {
                status: StatusCode::FORBIDDEN,
                body: Bytes::from_static(b"Forbidden"),
                ..Default::default()
            },
            hash_value,
        })
    }
}

impl Waf {
    /// The request's WAF state, created on first use and stamped with this profile.
    ///
    /// One accessor rather than five `get_or_insert_default` calls, so the profile
    /// cannot be attached on some paths and missing on others — an IP-list refusal and
    /// a body block have to be equally attributable.
    fn state<'a>(&self, ctx: &'a mut Ctx) -> &'a mut WafState {
        let state = ctx.extensions.get_or_insert_default::<WafState>();
        if state.profile.is_empty() {
            state.profile = self.profile.clone();
        }
        state
    }

    fn record_intel(state: &mut WafState, matched: FeedMatch) {
        state.intel_feed = matched.feed;
        state.intel_category = matched.category;
        state.blocked = true;
    }

    /// The threat-intelligence registry this policy matches against, for the
    /// surfaces that need to observe what the policy selected.
    pub fn intel_registry(&self) -> Option<&Arc<FeedRegistry>> {
        self.intel.as_ref()
    }

    /// Build the IP filter, refusing the two configurations that would be worse than
    /// having none.
    fn build_ip_filter(
        extras: &PluginExtras,
    ) -> std::result::Result<Option<IpFilter>, String> {
        if extras.ip_list.is_empty() {
            if extras.ip_list_mode == ListMode::Allow {
                // An empty allow list rejects every request, including the
                // operator's own. Almost certainly a config that was meant to be
                // filled in, so it fails rather than locking the site out.
                return Err(
                    "`ip_list_mode` is \"allow\" but `ip_list` is empty, which \
                     would reject every request"
                        .to_string(),
                );
            }
            return Ok(None);
        }

        // With no trusted-proxy list, forwarded headers are trusted
        // unconditionally, so any client can choose its own apparent IP. Enforcing
        // on that value is not access control — it is access control the client
        // configures. Logging on it is fine, which is why this is checked here
        // rather than globally.
        if !trusted_proxies_enabled() {
            return Err(
                "`ip_list` is set but `basic.trusted_proxies` is not. Without it, \
                 `X-Forwarded-For` is trusted unconditionally and any client can \
                 spoof the address this list is matched against. Set \
                 `basic.trusted_proxies` to your own proxies' addresses, or remove \
                 `ip_list`"
                    .to_string(),
            );
        }

        Ok(Some(IpFilter::new(extras.ip_list_mode, &extras.ip_list)?))
    }

    /// Query parameters as borrowed pairs.
    ///
    /// Parsed per parameter rather than matched as one query string, for two reasons:
    /// a hit can then name the parameter that carried it, and a pattern cannot match
    /// across the `&` joining two independent values, which would be a false positive
    /// assembled out of two innocent parameters. The URI is inspected as a whole as
    /// well, so splitting loses nothing.
    fn query_pairs(query: &str) -> Vec<(&str, &str)> {
        query
            .split('&')
            .filter(|part| !part.is_empty())
            .map(|part| match part.split_once('=') {
                Some((k, v)) => (k, v),
                None => (part, ""),
            })
            .collect()
    }

    /// Header name/value pairs, skipping values that are not UTF-8.
    ///
    /// A non-UTF-8 header value cannot be matched by a text pattern. It is dropped
    /// rather than lossily converted, because a lossy conversion invents bytes that
    /// were never sent and could manufacture a match.
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
}

/// Publish the verdict on `Ctx` so an access-log format can render it.
///
/// `add_variable` is the only channel from `Ctx` to a rendered log line: a `{:name}` tag
/// resolves through `Ctx::append_log_value`, which falls through to the variables map. The
/// structured verdict stays on `ctx.extensions` as [`WafState`] for in-process consumers — this
/// is the string view for logs and not a replacement for it, and nothing downstream re-parses
/// what is written here.
///
/// The names are a contract the moment they ship: an operator writes `{:waf_rules}` into an
/// `access_log` format, and renaming the variable silently empties their field with nothing
/// anywhere to fail. The test asserts on those literals rather than on a shared constant,
/// because a rename that moved a constant and the test together would still pass.
///
/// Cheap when there is nothing to say. `waf_action` is always written, so a log format can
/// distinguish "the WAF ran and found nothing" from "there is no WAF here"; the rest is written
/// only on a finding or a caveat. Detection costs hundreds of microseconds to milliseconds, so
/// a few short allocations beside it are noise — the same pair once per body chunk would not
/// be, which is why the body stages publish only at end of stream.
///
/// Called at every path out of an inspection stage rather than once at the end, because the
/// path that most needs publishing is the early `return` a block takes.
fn emit_verdict(ctx: &mut Ctx) {
    // Built inside a block so the immutable borrow of `ctx.extensions` ends before
    // `add_variable` takes `&mut ctx`.
    let fields: Vec<(&'static str, String)> = {
        let Some(state) = ctx.extensions.get::<WafState>() else {
            return;
        };
        let action = if state.blocked {
            "block"
        } else if state.challenged {
            "challenge"
        } else if state.redacted {
            "redact"
        } else if state.hits.is_empty() {
            "pass"
        } else {
            "detect"
        };
        let mut fields = vec![("waf_action", action.to_string())];
        if !state.hits.is_empty() {
            let mut rules = String::new();
            let mut categories = String::new();
            let mut worst = None;
            for (index, hit) in state.hits.iter().enumerate() {
                if index > 0 {
                    rules.push(',');
                    categories.push(',');
                }
                // `fmt::Write` into a `String` cannot fail; the result is discarded rather
                // than unwrapped because this workspace denies `unwrap` outside tests.
                let _ = write!(rules, "{}", hit.rule_id);
                let _ = write!(categories, "{}", hit.category);
                worst = worst.max(Some(hit.severity));
            }
            fields.push(("waf_profile", state.profile.clone()));
            fields.push(("waf_score", state.score.to_string()));
            fields.push(("waf_hits", state.hits.len().to_string()));
            fields.push(("waf_rules", rules));
            fields.push(("waf_categories", categories));
            if let Some(severity) = worst {
                fields.push(("waf_severity", severity.to_string()));
            }
        }
        if let Some(feed) = &state.intel_feed {
            fields.push(("waf_intel_feed", feed.clone()));
        }
        if let Some(category) = &state.intel_category {
            fields.push(("waf_intel_category", category.clone()));
        }
        // The two caveats an operator needs even on a request that was allowed, because both
        // mean the verdict covers less than it looks like: bytes the engine never saw, and an
        // evaluation that stopped early.
        if state.truncated {
            fields.push(("waf_truncated", "true".to_string()));
        }
        if state.budget_exhausted {
            fields.push(("waf_budget_exhausted", "true".to_string()));
        }
        fields
    };
    for (key, value) in fields {
        ctx.add_variable(key, &value);
    }
}

#[async_trait]
impl Plugin for Waf {
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Headers, URI and query, plus the IP filter.
    ///
    /// Runs at `PluginStep::Request`, never `EarlyRequest`. The early dispatch
    /// discards its result — `find_and_apply_location` ends with `let _ =
    /// self.handle_request_plugin(PluginStep::EarlyRequest, …)` and
    /// `early_request_filter` returns `Ok(())` unconditionally, which Pingora reads as
    /// "continue" — while the `Respond` arm has already written the response to the
    /// wire. A denying plugin there would send 403 to the client *and* proxy the
    /// request to the backend, which is an authorization bypass rather than a
    /// performance question.
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        let method = session.req_header().method.as_str().to_string();
        let uri = session.req_header().uri.to_string();
        let client_ip = ensure_client_ip(session, ctx).to_string();
        let domain = pingap_core::get_host(session.req_header())
            .map(str::to_string)
            .unwrap_or_else(|| ctx.upstream.location.to_string());
        {
            let state = self.state(ctx);
            state.domain = domain;
            state.client_ip = Some(client_ip);
            state.method = method;
            state.uri = uri;
        }

        // Cheapest work first, and it uses the gateway's own resolver so the WAF and
        // the access log can never disagree about who the client is.
        if let Some(filter) = &self.ip_filter {
            let ip = ensure_client_ip(session, ctx).to_string();
            if filter.rejects(&ip) {
                debug!(target: "waf", "client ip refused by list");
                let state = self.state(ctx);
                state.blocked = true;
                emit_verdict(ctx);
                offer_new_events(ctx, true);
                return Ok(RequestPluginResult::Respond(
                    self.forbidden.clone(),
                ));
            }
        }

        if let Some(intel) = &self.intel {
            let ip = ensure_client_ip(session, ctx).parse().ok();
            if let Some(ip) = ip.and_then(|ip| intel.matches(&ip)) {
                let state = self.state(ctx);
                Self::record_intel(state, ip);
                emit_verdict(ctx);
                offer_new_events(ctx, true);
                return Ok(RequestPluginResult::Respond(
                    self.forbidden.clone(),
                ));
            }
        }

        let headers = Self::header_pairs(session);
        let uri = session.req_header().uri.to_string();
        let query = session
            .req_header()
            .uri
            .query()
            .map(Self::query_pairs)
            .unwrap_or_default();
        let input = RequestInput {
            method: session.req_header().method.as_str(),
            uri: &uri,
            headers: &headers,
            query: &query,
            // The body has not arrived yet; `handle_request_body` evaluates it.
            body: None,
            client_ip: None,
            body_truncated: false,
        };
        let evaluation = self.engine.evaluate_request(&input);
        let blocking = evaluation.verdict.is_enforcing();

        let state = self.state(ctx);
        state.absorb(
            evaluation.verdict.hits(),
            evaluation.verdict.score(),
            evaluation.enforcing_score,
        );
        state.budget_exhausted |= evaluation.exhausted.is_some();
        if evaluation.verdict.is_challenge() {
            state.challenged = true;
        } else {
            state.blocked |= blocking;
        }

        if blocking {
            if evaluation.verdict.is_challenge() {
                // Counted beside the write, in the challenge plugin's own
                // classified-label space: the read side cannot observe a
                // challenge entry that never runs, so the write is the side
                // that moves. See `pingap-acl/src/marker.rs` for the argument.
                count_write(&pingap_domainstate::label(
                    pingap_core::get_host(session.req_header())
                        .unwrap_or(ctx.upstream.location.as_ref()),
                ));
                ctx.extensions.insert(ChallengeMarker::new(
                    CATEGORY,
                    "anomaly-threshold".to_string(),
                ));
                emit_verdict(ctx);
                offer_new_events(ctx, true);
                return Ok(RequestPluginResult::Continue);
            }
            emit_verdict(ctx);
            offer_new_events(ctx, true);
            return Ok(RequestPluginResult::Respond(self.forbidden.clone()));
        }
        emit_verdict(ctx);
        offer_new_events(ctx, true);
        Ok(RequestPluginResult::Continue)
    }

    /// Inspect the request body, then release it byte-identical.
    ///
    /// Each chunk is **withheld** — taken out of the stream and buffered — rather than
    /// copied. Nothing reaches the upstream until either the body ends or the
    /// inspection limit is reached, so a rejected request forwards zero bytes and an
    /// allowed one forwards exactly what the client sent.
    ///
    /// The rejected alternative was draining the body inside the request filter.
    /// Pingora mirrors request bytes into a replayable buffer only if that buffer
    /// exists at read time, and `enable_retry_buffering()` runs inside
    /// `proxy_to_upstream` — after `request_filter` has returned. Bytes read there are
    /// dropped, so the upstream gets the original `Content-Length` and no body. It
    /// fails only for *allowed* requests, which is why a test suite that checks
    /// "malicious POST is blocked" passes while every legitimate upload is corrupted.
    fn handle_request_body(
        &self,
        _session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        if self.body_limit == 0 {
            return Ok(());
        }
        let limit = self.body_limit;
        let policy = self.over_cap;
        let buffer = ctx
            .extensions
            .get_or_insert_with(|| RequestBody(BodyBuffer::new(limit, policy)));
        let feed = buffer.0.feed(body.as_deref(), end_of_stream);

        match feed {
            // Already released: this chunk streams on untouched and uninspected.
            Feed::PassThrough => return Ok(()),
            Feed::Hold => {
                // Withhold. `None` means "no bytes for the upstream yet", which is
                // exactly what keeps a not-yet-judged body out of the origin.
                *body = None;
                return Ok(());
            },
            Feed::Reject => {
                *body = None;
                let state = self.state(ctx);
                state.blocked = true;
                emit_verdict(ctx);
                offer_new_events(ctx, true);
                return Err(new_internal_error(
                    413,
                    format!(
                        "waf: request body exceeds the {limit}-byte inspection \
                         limit and `over_cap` is \"reject\""
                    ),
                ));
            },
            Feed::Release => {},
        }

        let inspected = buffer.0.inspected().to_vec();
        let truncated = buffer.0.truncated();
        let release = buffer.0.take();
        let evaluation = self.engine.evaluate_request(&RequestInput {
            method: "",
            uri: "",
            headers: &[],
            query: &[],
            body: Some(&inspected),
            client_ip: None,
            body_truncated: truncated,
        });
        let blocking = evaluation.verdict.is_enforcing();

        let state = self.state(ctx);
        state.absorb(
            evaluation.verdict.hits(),
            evaluation.verdict.score(),
            evaluation.enforcing_score,
        );
        state.truncated |= evaluation.truncated;
        state.budget_exhausted |= evaluation.exhausted.is_some();

        if blocking {
            state.blocked = true;
            // Nothing is released, so the upstream sees none of it.
            *body = None;
            emit_verdict(ctx);
            offer_new_events(ctx, true);
            return Err(new_internal_error(
                403,
                "waf: request body rejected".to_string(),
            ));
        }
        *body = Some(Bytes::from(release));
        // Once, at end of stream: this stage runs per chunk, and publishing on each one
        // would allocate a handful of strings per chunk to overwrite the same values.
        if end_of_stream {
            emit_verdict(ctx);
            offer_new_events(ctx, true);
        }
        Ok(())
    }

    /// Inspect what enters the cache.
    ///
    /// Registered **alongside** `handle_response_body`, not instead of it. This hook
    /// runs under `if !from_cache`, before the cache write that pingora comments as
    /// "cache the original response before any downstream transformation" — so
    /// redacting here is what keeps an unredacted body out of the cache entry, and it
    /// never fires on a cache hit.
    fn handle_upstream_response_body(
        &self,
        _session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<ResponseBodyPluginResult> {
        let result =
            self.scan_response::<UpstreamBody>(ctx, body, end_of_stream);
        if end_of_stream {
            emit_verdict(ctx);
            offer_new_events(ctx, true);
        }
        result
    }

    /// Inspect what leaves for the client.
    ///
    /// The other half of the pair. A body cached while a category was `off` would
    /// otherwise be served unredacted for the rest of its TTL, with no hit and no
    /// event — so the operator's dashboard would show zero response-side findings and
    /// they would conclude the leak was fixed. The double scan on a cache miss is the
    /// price, and it is measured rather than assumed.
    fn handle_response_body(
        &self,
        _session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<ResponseBodyPluginResult> {
        let result =
            self.scan_response::<DownstreamBody>(ctx, body, end_of_stream);
        if end_of_stream {
            emit_verdict(ctx);
            offer_new_events(ctx, true);
        }
        result
    }
}

/// A per-request response-prefix buffer, distinguished by type so the two response
/// hooks cannot share one.
trait PrefixBuffer: Clone + Send + Sync + 'static {
    fn new(limit: usize) -> Self;
    fn buffer(&mut self) -> &mut BodyBuffer;
}

impl PrefixBuffer for UpstreamBody {
    fn new(limit: usize) -> Self {
        // Always `InspectPrefix`: `Reject` has nothing to act on here, because the
        // status line is already downstream by the time a body hook runs.
        Self(BodyBuffer::new(limit, OverCap::InspectPrefix))
    }
    fn buffer(&mut self) -> &mut BodyBuffer {
        &mut self.0
    }
}

impl PrefixBuffer for DownstreamBody {
    fn new(limit: usize) -> Self {
        Self(BodyBuffer::new(limit, OverCap::InspectPrefix))
    }
    fn buffer(&mut self) -> &mut BodyBuffer {
        &mut self.0
    }
}

impl Waf {
    /// Accumulate a bounded response prefix, evaluate it, and mask any hit before the
    /// bytes go anywhere.
    ///
    /// Buffering rather than scanning chunk by chunk, for one reason that matters: a
    /// leak that straddles a chunk boundary is invisible to a per-chunk scan. The cost
    /// is that time-to-first-byte waits for the prefix to fill, bounded by
    /// `response_prefix_limit`, and the operator sets that number.
    fn scan_response<T: PrefixBuffer>(
        &self,
        ctx: &mut Ctx,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<ResponseBodyPluginResult> {
        if self.response_prefix_limit == 0
            || self.engine.response_rule_count() == 0
        {
            return Ok(ResponseBodyPluginResult::Unchanged);
        }
        let limit = self.response_prefix_limit;
        let status = ctx.state.status.map(|s| s.as_u16()).unwrap_or_default();
        let holder = ctx.extensions.get_or_insert_with(|| T::new(limit));
        match holder.buffer().feed(body.as_deref(), end_of_stream) {
            Feed::PassThrough => {
                return Ok(ResponseBodyPluginResult::Unchanged);
            },
            Feed::Hold => {
                *body = None;
                return Ok(ResponseBodyPluginResult::Unchanged);
            },
            // `Reject` is unreachable: `PrefixBuffer::new` always uses
            // `InspectPrefix`. Treated as a release rather than an `unreachable!`,
            // because a panic here would take the gateway down over a refactor.
            Feed::Reject | Feed::Release => {},
        }
        let truncated = holder.buffer().truncated();
        let inspected_len = holder.buffer().inspected().len();
        let mut release = holder.buffer().take();

        let evaluation = self.engine.evaluate_response(&ResponseInput {
            status,
            headers: &[],
            body_chunk: Some(&release[..inspected_len]),
            request_score: 0,
            body_truncated: truncated,
        });
        let redacting = evaluation.verdict.is_enforcing();
        let mut masked = false;
        if redacting {
            for hit in evaluation.verdict.hits() {
                if let crate::rule::MatchedField::ResponseBody { offset, len } =
                    &hit.matched_field
                {
                    masked |= mask(&mut release, *offset, *len);
                }
            }
        }

        let state = self.state(ctx);
        state.absorb(
            evaluation.verdict.hits(),
            evaluation.verdict.score(),
            evaluation.enforcing_score,
        );
        state.truncated |= evaluation.truncated;
        state.budget_exhausted |= evaluation.exhausted.is_some();
        state.redacted |= masked;

        *body = Some(Bytes::from(release));
        Ok(if masked {
            debug!(target: "waf", "response body span masked");
            ResponseBodyPluginResult::PartialReplaced
        } else {
            ResponseBodyPluginResult::Unchanged
        })
    }
}

/// Registered with a hand-rolled ctor rather than `register_plugin!`.
///
/// That macro carries no `#[macro_export]`, so it is invisible outside
/// `pingap-plugin` and every one of its call sites is in-crate. `get_plugin_factory`
/// is public, so an out-of-crate plugin registers through it directly — which is what
/// `pingap-imageoptim` already does. Adding `#[macro_export]` to the vendored macro
/// would have bought the same thing at the cost of a fourth vendored file.
#[ctor(unsafe)]
fn init() {
    get_plugin_factory()
        .register(CATEGORY, |params| Ok(Arc::new(Waf::try_from(params)?)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_core::PluginStep;
    use pingap_logger::Parser;
    use tokio_test::io::Builder;

    /// A profile in blocking mode with a threshold of one, so a single hit is a 403.
    /// The shipped default is `detect`; blocking is what these tests are about.
    const BLOCKING: &str = r#"
category = "waf"
anomaly_threshold = 1
categories = { sql_injection = "block", xss = "block", data_leakage = "redact", web_shell = "redact" }
"#;

    fn plugin(conf: &str) -> Waf {
        Waf::try_from(
            &toml::from_str::<PluginConf>(conf).expect("test config parses"),
        )
        .expect("test config builds")
    }

    async fn session_for(request: &str) -> Session {
        let io = Builder::new().read(request.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(io));
        session.read_request().await.expect("mock request reads");
        session
    }

    #[tokio::test]
    async fn the_category_is_registered_with_the_plugin_factory() {
        // The `#[ctor]` runs at load, so by the time a test body executes the
        // registration has either happened or silently not happened — which is the
        // failure mode that would leave `category = "waf"` unknown at config load.
        assert!(
            get_plugin_factory()
                .supported_plugins()
                .contains(&CATEGORY.to_string()),
            "the waf category did not reach the factory"
        );
    }

    #[tokio::test]
    async fn an_unsupported_step_is_rejected_rather_than_silently_ignored() {
        // `get_step_conf` would fall back to the default here, producing a plugin
        // that never runs. For a security control that is the worst possible
        // outcome, so the strict parser is used and this asserts it.
        let err = match Waf::try_from(
            &toml::from_str::<PluginConf>(
                "category = \"waf\"\nstep = \"upstream_response\"\n",
            )
            .expect("parses"),
        ) {
            Err(e) => e,
            Ok(_) => panic!("an unsupported step must fail"),
        };
        assert!(
            err.to_string().contains("step"),
            "the error must name the key: {err}"
        );
    }

    #[tokio::test]
    async fn a_malicious_query_is_blocked_and_a_benign_one_is_not() {
        let waf = plugin(BLOCKING);
        let mut ctx = Ctx::default();
        let mut session = session_for(
            "GET /s?q=%27+UNION+SELECT+pw+FROM+users+--+ HTTP/1.1\r\n\r\n",
        )
        .await;
        let result = waf
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .expect("evaluation is total");
        let RequestPluginResult::Respond(resp) = result else {
            panic!("a SQL injection in the query string was not blocked");
        };
        assert_eq!(resp.status.as_u16(), 403);
        let state = ctx.extensions.get::<WafState>().expect("state recorded");
        assert!(state.blocked);
        assert!(!state.hits.is_empty(), "a block must name its rules");

        let mut ctx = Ctx::default();
        let mut session =
            session_for("GET /products?page=2&sort=price HTTP/1.1\r\n\r\n")
                .await;
        assert!(
            waf.handle_request(PluginStep::Request, &mut session, &mut ctx)
                .await
                .expect("evaluation is total")
                == RequestPluginResult::Continue,
            "an ordinary request was blocked"
        );
    }

    #[tokio::test]
    async fn challenge_mode_writes_a_marker_and_continues_to_the_next_plugin() {
        let waf = plugin(
            r#"category = "waf"
anomaly_threshold = 1
categories = { sql_injection = "challenge" }
"#,
        );
        let mut ctx = Ctx::default();
        let mut session = session_for(
            "GET /s?q=%27+UNION+SELECT+pw+FROM+users+--+ HTTP/1.1\r\n\r\n",
        )
        .await;
        let result = waf
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .expect("evaluation is total");
        assert!(matches!(result, RequestPluginResult::Continue));
        let marker = ctx
            .extensions
            .get::<ChallengeMarker>()
            .expect("challenge marker");
        assert_eq!(marker.source, "waf");
        assert!(
            ctx.extensions
                .get::<WafState>()
                .is_some_and(|state| state.challenged)
        );
    }

    #[tokio::test]
    async fn challenge_mode_counts_its_marker_write_beside_the_write() {
        // Same argument as the ACL side: the counter must move at the write,
        // because an out-of-order or missing challenge entry never reads the
        // marker. The registered host keeps this test's writes alone in their
        // row — nothing else in this module sends that `Host`.
        pingap_domainstate::set_registered_hosts(["verify.test"]);
        let waf = plugin(
            r#"category = "waf"
anomaly_threshold = 1
categories = { sql_injection = "challenge" }
"#,
        );
        let before = pingap_acl::marker::counters_snapshot()
            .get("verify.test")
            .copied()
            .unwrap_or(0);
        let mut ctx = Ctx::default();
        let mut session = session_for(
            "GET /s?q=%27+UNION+SELECT+pw+FROM+users+--+ HTTP/1.1\r\nHost: verify.test\r\n\r\n",
        )
        .await;
        let result = waf
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .expect("evaluation is total");
        assert!(matches!(result, RequestPluginResult::Continue));
        assert!(
            ctx.extensions.get::<ChallengeMarker>().is_some(),
            "the request was challenged, so the marker was written"
        );
        let after = pingap_acl::marker::counters_snapshot();
        assert_eq!(
            after.get("verify.test"),
            Some(&(before + 1)),
            "the waf marker write is counted under the request's classified \
             label"
        );
    }

    #[tokio::test]
    async fn an_ip_list_without_trusted_proxies_fails_to_construct() {
        // Without a trusted-proxy list, forwarded headers are trusted
        // unconditionally, so the address an IP list is matched against is one the
        // client chose. Enforcing on it is not access control.
        let err = match Waf::try_from(
            &toml::from_str::<PluginConf>(
                "category = \"waf\"\nip_list = [\"10.0.0.0/8\"]\n",
            )
            .expect("parses"),
        ) {
            Err(e) => e,
            Ok(_) => panic!("an IP list without trusted proxies must fail"),
        };
        let msg = err.to_string();
        assert!(msg.contains("trusted_proxies"), "names the key: {msg}");
        assert!(msg.contains("spoof"), "says why it matters: {msg}");
    }

    #[tokio::test]
    async fn an_empty_allow_list_fails_rather_than_locking_the_site_out() {
        let err = match Waf::try_from(
            &toml::from_str::<PluginConf>(
                "category = \"waf\"\nip_list_mode = \"allow\"\n",
            )
            .expect("parses"),
        ) {
            Err(e) => e,
            Ok(_) => panic!("an empty allow list must fail"),
        };
        assert!(
            err.to_string().contains("reject every request"),
            "the error must say what would happen: {err}"
        );
    }

    #[tokio::test]
    async fn feed_only_policy_fails_without_a_static_deny_source() {
        let err = match Waf::try_from(
            &toml::from_str::<PluginConf>(
                r#"category = "waf"

[intel]
[[intel.feed]]
name = "example"
url = "https://example.invalid/list"
"#,
            )
            .expect("parses"),
        ) {
            Err(error) => error,
            Ok(_) => {
                panic!("feed-only policy must fail closed at construction")
            },
        };
        assert!(err.to_string().contains("no static deny source"));
    }

    /// A blocked request publishes its verdict as access-log variables.
    ///
    /// The names are asserted as literals rather than read from a shared constant, because the
    /// literal is what an operator types into an `access_log` format: a rename that moved a
    /// constant and this test together would still pass while their field went empty.
    #[tokio::test]
    async fn a_blocked_request_publishes_its_verdict_for_the_access_log() {
        let waf = plugin(BLOCKING);
        let mut session = session_for(
            "GET /?id=1%27%20OR%201=1-- HTTP/1.1\r\nhost: example.test\r\n\r\n",
        )
        .await;
        let mut ctx = Ctx::default();
        let result = waf
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .expect("the plugin runs");
        assert!(
            matches!(result, RequestPluginResult::Respond(_)),
            "the probe was not blocked, so there is no verdict to publish"
        );

        let variables = ctx
            .features
            .as_ref()
            .and_then(|features| features.variables.as_ref())
            .expect("a blocked request published no log variables");
        assert_eq!(
            variables.get("waf_action").map(String::as_str),
            Some("block")
        );
        let rules = variables
            .get("waf_rules")
            .expect("the rule IDs are not published");
        assert!(!rules.is_empty(), "a block with no rule ID is untriageable");
        assert!(
            rules.split(',').all(|id| !id.is_empty()),
            "a rule ID rendered empty: {rules}"
        );
        assert!(
            variables
                .get("waf_severity")
                .is_some_and(|value| !value.is_empty()),
            "the severity is not published: {variables:?}"
        );
        assert!(
            variables.contains_key("waf_score"),
            "the anomaly score is not published: {variables:?}"
        );
    }

    /// A clean request publishes the action and nothing else.
    ///
    /// `waf_action` alone is what lets a log format distinguish "the WAF ran and found
    /// nothing" from "there is no WAF here", which is the coverage question an operator asks.
    /// The detail fields are absent rather than empty, so a format built around them renders
    /// the same field it always did for a request that never triggered a rule.
    #[tokio::test]
    async fn a_clean_request_publishes_only_the_action() {
        let waf = plugin(BLOCKING);
        let mut session =
            session_for("GET / HTTP/1.1\r\nhost: example.test\r\n\r\n").await;
        let mut ctx = Ctx::default();
        waf.handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .expect("the plugin runs");

        let variables = ctx
            .features
            .as_ref()
            .and_then(|features| features.variables.as_ref())
            .expect("a request the WAF saw published nothing at all");
        assert_eq!(
            variables.get("waf_action").map(String::as_str),
            Some("pass")
        );
        for absent in ["waf_rules", "waf_severity", "waf_score", "waf_hits"] {
            assert!(
                !variables.contains_key(absent),
                "a clean request published {absent}: {variables:?}"
            );
        }
    }

    /// The criterion end to end: a blocked request's rule ID, severity and score appear in a
    /// rendered access-log line.
    ///
    /// Asserted on the bytes the formatter produces and not on the variables map, because the
    /// map is not what a log line reads — `{:name}` resolves through `Ctx::append_log_value`.
    /// That distinction is the whole reason this test exists: until that function fell through
    /// to the variables map, an assertion against the map passed while every field rendered
    /// empty, and the tag parser separately refused any name containing a digit.
    #[tokio::test]
    async fn a_blocked_verdict_renders_into_an_access_log_line() {
        let waf = plugin(BLOCKING);
        let mut session = session_for(
            "GET /?id=1%27%20OR%201=1-- HTTP/1.1\r\nhost: example.test\r\n\r\n",
        )
        .await;
        let mut ctx = Ctx::default();
        waf.handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .expect("the plugin runs");

        let parser: Parser =
            "{:waf_action}|{:waf_rules}|{:waf_severity}|{:waf_score}".into();
        let rendered = parser.format(&session, &ctx);
        let line = String::from_utf8_lossy(&rendered).to_string();
        let fields: Vec<&str> = line.split('|').collect();
        assert_eq!(
            fields.len(),
            4,
            "the format did not render four fields: {line}"
        );
        assert_eq!(fields[0], "block", "{line}");
        assert!(
            !fields[1].is_empty()
                && fields[1]
                    .split(',')
                    .all(|id| id.chars().all(|c| c.is_ascii_digit())),
            "the rule IDs did not render as IDs: {line}"
        );
        assert!(!fields[2].is_empty(), "the severity rendered empty: {line}");
        assert!(
            !fields[3].is_empty()
                && fields[3].chars().all(|c| c.is_ascii_digit()),
            "the anomaly score did not render: {line}"
        );

        // A clean request renders `pass` and empty detail fields, which is what a log format
        // built around these tags has to tolerate.
        let mut session =
            session_for("GET / HTTP/1.1\r\nhost: example.test\r\n\r\n").await;
        let mut ctx = Ctx::default();
        waf.handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .expect("the plugin runs");
        let rendered = parser.format(&session, &ctx);
        assert_eq!("pass|||", String::from_utf8_lossy(&rendered));
    }
}
