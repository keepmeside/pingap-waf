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
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult,
    ResponseBodyPluginResult, ensure_client_ip, new_internal_error,
    trusted_proxies_enabled,
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
    /// Whether any inspected body had bytes the engine never saw.
    pub truncated: bool,
    /// Whether evaluation ran out of budget on any surface.
    pub budget_exhausted: bool,
    /// Whether a response body was masked.
    pub redacted: bool,
}

impl WafState {
    fn absorb(&mut self, hits: &[Hit], score: u32, enforcing: u32) {
        self.hits.extend_from_slice(hits);
        self.score = self.score.saturating_add(score);
        self.enforcing_score = self.enforcing_score.saturating_add(enforcing);
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
        // unparseable value, which for a WAF means a typo in `step` produces a
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
        let engine = RuleEngine::build(
            validated,
            crate::detectors::request_rules(),
            crate::detectors::response_rules(),
        )
        .map_err(|e| invalid(e.to_string()))?;

        let ip_filter = Self::build_ip_filter(&extras).map_err(invalid)?;

        Ok(Self {
            plugin_step,
            body_limit: engine.config().body_inspect_limit,
            response_prefix_limit: engine.config().response_prefix_limit,
            profile: engine.config().profile.clone(),
            engine,
            ip_filter,
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

        // Cheapest work first, and it uses the gateway's own resolver so the WAF and
        // the access log can never disagree about who the client is.
        if let Some(filter) = &self.ip_filter {
            let ip = ensure_client_ip(session, ctx).to_string();
            if filter.rejects(&ip) {
                debug!(target: "waf", "client ip refused by list");
                let state = self.state(ctx);
                state.blocked = true;
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
        state.blocked |= blocking;

        if blocking {
            return Ok(RequestPluginResult::Respond(self.forbidden.clone()));
        }
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
            return Err(new_internal_error(
                403,
                "waf: request body rejected".to_string(),
            ));
        }
        *body = Some(Bytes::from(release));
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
        self.scan_response::<UpstreamBody>(ctx, body, end_of_stream)
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
        self.scan_response::<DownstreamBody>(ctx, body, end_of_stream)
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
}
