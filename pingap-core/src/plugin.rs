// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{Ctx, HttpResponse};
use ahash::AHashMap;
use async_trait::async_trait;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use strum::EnumString;

#[derive(
    PartialEq, Debug, Default, Clone, Copy, EnumString, strum::Display,
)]
#[strum(serialize_all = "snake_case")]
pub enum PluginStep {
    EarlyRequest,
    #[default]
    Request,
    /// The request body, delivered chunk by chunk on the way to the upstream.
    ///
    /// Names the lifecycle position that [`Plugin::handle_request_body`] occupies.
    /// Unlike the request steps, this one does not gate dispatch: the body hook is
    /// offered to every plugin on the location, exactly as the two response-body
    /// hooks already are, because a plugin that inspects a body almost always also
    /// needs the headers and so declares `request` as its step. Declaring
    /// `request_body` is for a plugin that wants *only* the body.
    RequestBody,
    ProxyUpstream,
    UpstreamResponse,
    Response,
}

/// A more expressive return type for `handle_request`.
/// It clearly states the plugin's decision.
pub enum RequestPluginResult {
    /// The plugin did not run or took no action.
    Skipped,
    /// The plugin ran and modified the request; processing should continue.
    Continue,
    /// The plugin has decided to terminate the request and send an immediate response.
    Respond(HttpResponse),
}

/// Represents the action a plugin takes on a response.
#[derive(Debug, PartialEq, Eq)]
pub enum ResponsePluginResult {
    /// The plugin did not change the response.
    Unchanged,
    /// The plugin modified the response (e.g., headers or body).
    Modified,
    // TODO
    // FullyReplaced(HttpResponse),
}

// Represents the action a plugin task on a response
#[derive(Debug, PartialEq, Eq)]
pub enum ResponseBodyPluginResult {
    /// The plugin did not modify the response body.
    Unchanged,
    /// The plugin partially replaced the response body.
    PartialReplaced,
    /// The plugin fully replaced the response body.
    FullyReplaced,
}

// Manually implement the PartialEq trait for RequestPluginResult
impl PartialEq for RequestPluginResult {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            // Two Skipped variants are always equal.
            (RequestPluginResult::Skipped, RequestPluginResult::Skipped) => {
                true
            },

            // Two Continue variants are always equal.
            (RequestPluginResult::Continue, RequestPluginResult::Continue) => {
                true
            },

            // Any other combination is not equal.
            _ => false,
        }
    }
}

/// Core trait that defines the interface all plugins must implement.
///
/// Plugins can handle both requests and responses at different processing steps.
/// The default implementations do nothing and return Ok.
#[async_trait]
pub trait Plugin: Sync + Send {
    /// Returns a unique key that identifies this specific plugin instance.
    ///
    /// # Purpose
    /// - Can be used for caching plugin results
    /// - Helps differentiate between multiple instances of the same plugin type
    /// - Useful for tracking and debugging
    ///
    /// # Default
    /// Returns an empty string by default, which means no specific instance identification.
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed("")
    }

    /// Processes an HTTP request at a specified lifecycle step.
    ///
    /// # Parameters
    /// * `_step` - Current processing step in the request lifecycle (e.g., pre-routing, post-routing)
    /// * `_session` - Mutable reference to the HTTP session containing request data
    /// * `_ctx` - Mutable reference to the request context for storing state
    ///
    /// # Returns
    /// * `Ok(result)` where:
    ///   * `result` - The result of the plugin's action on the request
    ///     - `Skipped`: Plugin did not run or took no action
    ///     - `Continue`: Plugin ran and modified the request; processing should continue
    ///     - `Respond(response)`: Plugin has decided to terminate the request and send an immediate response
    ///   * `response` - Optional HTTP response:
    ///     - `Some(response)`: Terminates request processing and returns this response to client
    ///     - `None`: Allows request to continue to next plugin or upstream
    /// * `Err` - Returns error if plugin processing failed
    #[inline]
    async fn handle_request(
        &self,
        _step: PluginStep,
        _session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        Ok(RequestPluginResult::Skipped)
    }

    /// Processes a chunk of the request body as it streams to the upstream.
    ///
    /// # Why this is a hook rather than a drain in `handle_request`
    /// Reading the body inside a `PluginStep::Request` plugin destroys it. Pingora
    /// mirrors request bytes into a replayable buffer only if that buffer already
    /// exists at read time (`read_body_bytes` copies under
    /// `if let Some(buffer) = self.retry_buffer.as_mut()`), and
    /// `enable_retry_buffering()` runs inside `proxy_to_upstream`, strictly after
    /// `request_filter` has returned. So bytes a request-filter plugin reads are
    /// handed over and dropped, and the upstream receives the original
    /// `Content-Length` with no body. There is no un-read or push-back API on the
    /// downstream session.
    ///
    /// This hook is called per chunk on the real proxy path, so the body is
    /// inspected as it streams and is never consumed out from under the upstream.
    ///
    /// # Parameters
    /// * `_body` - The chunk, mutable so a plugin may rewrite it
    /// * `_end_of_stream` - `true` on the final chunk
    ///
    /// # Returns
    /// * `Ok(())` - Continue proxying
    /// * `Err` - Reject the request. Return `new_internal_error(status, message)`
    ///   so the existing `fail_to_proxy` path renders the response, exactly as the
    ///   413 body-size guard does.
    #[inline]
    fn handle_request_body(
        &self,
        _session: &mut Session,
        _ctx: &mut Ctx,
        _body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
    ) -> pingora::Result<()> {
        Ok(())
    }

    /// Processes an HTTP response at a specified lifecycle step.
    ///
    /// # Parameters
    /// * `_session` - Mutable reference to the HTTP session
    /// * `_ctx` - Mutable reference to the request context
    /// * `_upstream_response` - Mutable reference to the upstream response header
    ///
    /// # Returns
    /// * `Ok(result)` - The result of the plugin's action on the response
    ///   - `Unchanged`: Plugin did not modify the response
    ///   - `Modified`: Plugin modified the response in some way
    /// * `Err` - Returns error if plugin processing failed
    #[inline]
    async fn handle_response(
        &self,
        _session: &mut Session,
        _ctx: &mut Ctx,
        _upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        Ok(ResponsePluginResult::Unchanged)
    }

    /// Processes an HTTP response body at a specified lifecycle step.
    ///
    /// # Parameters
    /// * `_session` - Mutable reference to the HTTP session
    /// * `_ctx` - Mutable reference to the request context
    /// * `_body` - Mutable reference to the response body
    /// * `_end_of_stream` - Boolean flag:
    ///   - `true`: The end of the response body has been reached
    ///   - `false`: The response body is still being received
    ///
    /// # Returns
    /// * `Ok(result)` - The result of the plugin's action on the response body
    ///   - `Unchanged`: Plugin did not modify the response body
    ///   - `PartialReplaced(new_body)`: Plugin replaced a part of the response body
    ///   - `FullyReplaced(new_body)`: Plugin replaced the response body with a new one
    /// * `Err` - Returns error if plugin processing failed
    #[inline]
    fn handle_response_body(
        &self,
        _session: &mut Session,
        _ctx: &mut Ctx,
        _body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
    ) -> pingora::Result<ResponseBodyPluginResult> {
        Ok(ResponseBodyPluginResult::Unchanged)
    }

    /// Processes an upstream response at a specified lifecycle step.
    ///
    /// # Parameters
    /// * `_session` - Mutable reference to the HTTP session
    /// * `_ctx` - Mutable reference to the request context
    /// * `_upstream_response` - Mutable reference to the upstream response header
    ///
    /// # Returns
    /// * `Ok(result)` - The result of the plugin's action on the response
    ///   - `Unchanged`: Plugin did not modify the response
    ///   - `Modified`: Plugin modified the response in some way
    /// * `Err` - Returns error if plugin processing failed
    #[inline]
    fn handle_upstream_response(
        &self,
        _session: &mut Session,
        _ctx: &mut Ctx,
        _upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        Ok(ResponsePluginResult::Unchanged)
    }

    /// Processes an upstream response body at a specified lifecycle step.
    ///
    /// # Parameters
    /// * `_session` - Mutable reference to the HTTP session
    /// * `_ctx` - Mutable reference to the request context
    /// * `_body` - Mutable reference to the upstream response body
    /// * `_end_of_stream` - Boolean flag:
    ///   - `true`: The end of the upstream response body has been reached
    ///   - `false`: The upstream response body is still being received
    ///
    /// # Returns
    /// * `Ok(result)` - The result of the plugin's action on the response body
    ///   - `Unchanged`: Plugin did not modify the response body
    ///   - `PartialReplaced(new_body)`: Plugin replaced a part of the response body
    ///   - `FullyReplaced(new_body)`: Plugin replaced the response body with a new one
    /// * `Err` - Returns error if plugin processing failed
    #[inline]
    fn handle_upstream_response_body(
        &self,
        _session: &mut Session,
        _ctx: &mut Ctx,
        _body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
    ) -> pingora::Result<ResponseBodyPluginResult> {
        Ok(ResponseBodyPluginResult::Unchanged)
    }
}

/// Why a plugin name did not resolve to an instance.
///
/// The distinction is the whole point. `get` returning `None` conflates "no entry with
/// that name is configured" with "an entry exists and failed to construct", and those want
/// opposite handling: the first is a config typo the operator will see as a route that
/// does nothing, the second is a *security control that is not running* while the config
/// says it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginMiss {
    /// Nothing is configured under that name.
    Unknown,
    /// An entry exists, and building it failed.
    Failed {
        /// The `category` from its config, so the caller can decide by category rather
        /// than by parsing a name.
        category: String,
        reason: String,
        enforcement_required: bool,
    },
}

/// Plugin categories whose absence must not be served around.
///
/// A broken `compression` or `cors` should not take a site down; a broken `waf` serving
/// unfiltered traffic while the control plane reports healthy is the failure this whole
/// product exists to prevent. The list lives here, beside the trait that reports the
/// miss, so there is one place that answers "is this plugin load-bearing for security".
pub const SECURITY_ENFORCING_CATEGORIES: &[&str] =
    &["waf", "acl", "bot", "access_list", "challenge"];

/// Desired enforcement survives malformed or unavailable constructors.
/// A valid detect-only/disabled Behaviour remains advisory. Explicit malformed
/// abuse configuration must not turn a requested security control into a bypass.
pub fn security_failure_intent(
    category: &str,
    conf: &serde_json::Value,
) -> bool {
    if category == "limit" {
        return conf.get("enforcement_required").and_then(|v| v.as_bool())
            == Some(true);
    }
    if category != "behaviour" {
        return is_security_enforcing(category);
    }
    if conf.get("enabled").and_then(|v| v.as_bool()) == Some(false) {
        return false;
    }
    let Some(abuse) = conf.get("abuse") else {
        return false;
    };
    // An omitted or malformed top-level flag cannot be treated as a valid
    // detect-only profile: the constructor's default is disabled.
    if conf.get("enabled").and_then(|v| v.as_bool()) != Some(true) {
        return true;
    }
    if !abuse.is_object() {
        return true;
    }
    if abuse.get("enabled").and_then(|v| v.as_bool()) == Some(false) {
        return false;
    }
    if abuse.get("enabled").is_some_and(|v| !v.is_boolean()) {
        return true;
    }
    if abuse.get("enabled").is_none()
        && abuse
            .as_object()
            .is_some_and(|fields| fields.keys().any(|key| key != "enabled"))
    {
        return true;
    }
    if abuse.get("enabled").is_none() {
        return false;
    }
    if conf
        .get("abuse_namespace")
        .and_then(|v| v.as_str())
        .is_none_or(|namespace| namespace.trim().is_empty())
    {
        return true;
    }
    if !valid_advisory_behaviour_base(conf) {
        return true;
    }
    let login_capacity =
        match advisory_capacity(conf, "max_interval_samples", 32) {
            Some(capacity) => capacity,
            None => return true,
        };
    let path_capacity = match advisory_capacity(conf, "max_url_keys", 64) {
        Some(capacity) => capacity,
        None => return true,
    };
    let mut found = false;
    for name in ["failed_login", "scan"] {
        if let Some(scenario) = abuse.get(name) {
            found = true;
            let capacity = if name == "failed_login" {
                login_capacity
            } else {
                path_capacity
            };
            if !valid_detect_scenario(name, scenario, capacity) {
                return true;
            }
        }
    }
    !found
}

/// A detect-only Behaviour is advisory only after the fields required to build a
/// real rule are present and well-shaped. The implementation crate performs the full
/// typed validation; this small boundary check keeps malformed explicit security
/// config fail-closed without introducing a dependency cycle from core to plugins.
fn advisory_capacity(
    conf: &serde_json::Value,
    key: &str,
    default: u64,
) -> Option<u64> {
    let capacity = conf
        .get(key)
        .map_or(Some(default), serde_json::Value::as_u64)?;
    (capacity > 0 && usize::try_from(capacity).is_ok()).then_some(capacity)
}

fn valid_advisory_behaviour_base(conf: &serde_json::Value) -> bool {
    if conf.get("window").is_some() && !positive_duration(conf.get("window")) {
        return false;
    }
    for (key, default) in [
        ("max_clients", 5000),
        ("max_url_keys", 64),
        ("max_user_agents", 8),
        ("max_interval_samples", 32),
        ("min_samples", 6),
        ("budget_ms", 2),
    ] {
        if advisory_capacity(conf, key, default).is_none() {
            return false;
        }
    }
    if conf
        .get("client_ip_from_peer")
        .is_some_and(|v| !v.is_boolean())
    {
        return false;
    }
    if conf.get("client_ip_from_peer").and_then(|v| v.as_bool()) != Some(true)
        && !crate::construction_trusted_proxies_enabled()
    {
        return false;
    }
    if conf
        .get("step")
        .is_some_and(|v| v.as_str() != Some("request"))
    {
        return false;
    }
    let weights = [
        ("timing_regularity", 25),
        ("url_entropy", 20),
        ("request_diversity", 20),
        ("request_speed", 15),
        ("error_pattern", 10),
        ("user_agent_consistency", 10),
    ];
    let Some(total) = advisory_fields(conf.get("weights"), &weights) else {
        return false;
    };
    if total != 100 {
        return false;
    }
    let thresholds = [("human", 55), ("suspicious", 40), ("bot", 20)];
    let Some(values) =
        advisory_field_values(conf.get("thresholds"), &thresholds)
    else {
        return false;
    };
    values[0] >= values[1] && values[1] >= values[2]
}

fn advisory_field_values(
    value: Option<&serde_json::Value>,
    defaults: &[(&str, u8)],
) -> Option<Vec<u8>> {
    let fields = match value {
        None => None,
        Some(value) => Some(value.as_object()?),
    };
    defaults
        .iter()
        .map(|(key, default)| {
            fields
                .and_then(|fields| fields.get(*key))
                .map_or(Some(*default), |v| u8::try_from(v.as_u64()?).ok())
        })
        .collect()
}

fn advisory_fields(
    value: Option<&serde_json::Value>,
    defaults: &[(&str, u8)],
) -> Option<u16> {
    Some(
        advisory_field_values(value, defaults)?
            .into_iter()
            .map(u16::from)
            .sum(),
    )
}

fn positive_duration(value: Option<&serde_json::Value>) -> bool {
    value
        .and_then(serde_json::Value::as_str)
        .and_then(|raw| humantime::parse_duration(raw).ok())
        .is_some_and(|duration| !duration.is_zero())
}

fn valid_detect_scenario(
    name: &str,
    value: &serde_json::Value,
    capacity: u64,
) -> bool {
    let Some(rule) = value.as_object() else {
        return false;
    };
    if rule.get("mode").and_then(|v| v.as_str()) != Some("detect")
        || rule
            .get("threshold")
            .and_then(|v| v.as_u64())
            .is_none_or(|n| n == 0 || n > capacity)
        || !positive_duration(rule.get("window"))
        || !positive_duration(rule.get("ban_ttl"))
    {
        return false;
    }
    if name != "failed_login" {
        return true;
    }
    let Some(path) = rule.get("path").and_then(|v| v.as_str()) else {
        return false;
    };
    let Some(method) = rule.get("method").and_then(|v| v.as_str()) else {
        return false;
    };
    let Some(statuses) = rule.get("statuses").and_then(|v| v.as_array()) else {
        return false;
    };
    path.starts_with('/')
        && !path.contains('?')
        && !path.contains('#')
        && method.parse::<http::Method>().is_ok()
        && !statuses.is_empty()
        && statuses.iter().all(|status| {
            status
                .as_u64()
                .is_some_and(|code| (400..=599).contains(&code))
        })
}

/// Optional per-request multiplier supplied by the adaptive learner.
///
/// Keeping the value in request extensions lets the limiter retain its existing
/// keying while adaptive policy only modulates the configured ceiling.
#[derive(Debug, Clone, Copy)]
pub struct AdaptiveRateMultiplier(pub f64);

/// Whether a failed plugin of this category must fail the request rather than be skipped.
pub fn is_security_enforcing(category: &str) -> bool {
    SECURITY_ENFORCING_CATEGORIES.contains(&category)
}

/// What to do when a Location lists a security-enforcing plugin that is not running.
///
/// `false` — the default — means the request is refused. An operator who would rather
/// serve unprotected traffic than serve none can say so, and the choice is visible in
/// config and logged at startup rather than being an inherited default nobody chose.
static POLICY_FAILS_OPEN: AtomicBool = AtomicBool::new(false);

/// Set from `basic.on_policy_unavailable`. Safe to call on every reload.
///
/// Anything other than the two known values is treated as `fail_closed`, and the caller
/// logs it: a typo must not silently pick the permissive branch.
pub fn set_policy_unavailable_mode(mode: &Option<String>) {
    let open = matches!(mode.as_deref(), Some("fail_open"));
    POLICY_FAILS_OPEN.store(open, Ordering::Relaxed);
}

/// Whether an unavailable security policy serves the request anyway.
pub fn policy_fails_open() -> bool {
    POLICY_FAILS_OPEN.load(Ordering::Relaxed)
}

/// Plugin provider trait
pub trait PluginProvider: Send + Sync {
    /// Get a plugin by name
    ///
    /// # Arguments
    /// * `name` - The name of the plugin to get
    ///
    /// # Returns
    /// * `Option<Arc<dyn Plugin>>` - The plugin if found, None otherwise
    fn get(&self, name: &str) -> Option<Arc<dyn Plugin>>;

    /// Resolve one request against a coherent instance/failure snapshot.
    /// Providers that publish both maps must override this method atomically.
    fn resolve(
        &self,
        name: &str,
    ) -> std::result::Result<Arc<dyn Plugin>, PluginMiss> {
        self.get(name).ok_or_else(|| self.miss(name))
    }

    /// Why `name` did not resolve.
    ///
    /// Only meaningful after [`Self::get`] has returned `None`. Defaults to
    /// [`PluginMiss::Unknown`] so a provider that does not track construction failures —
    /// a test double, say — keeps compiling and keeps today's behaviour.
    fn miss(&self, _name: &str) -> PluginMiss {
        PluginMiss::Unknown
    }
}

pub type Plugins = AHashMap<String, Arc<dyn Plugin>>;

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_plugin_step() {
        let step = "early_request".parse::<PluginStep>().unwrap();
        assert_eq!(step, PluginStep::EarlyRequest);
        assert_eq!(step.to_string(), "early_request");

        let step = "request".parse::<PluginStep>().unwrap();
        assert_eq!(step, PluginStep::Request);
        assert_eq!(step.to_string(), "request");

        let step = "request_body".parse::<PluginStep>().unwrap();
        assert_eq!(step, PluginStep::RequestBody);
        assert_eq!(step.to_string(), "request_body");

        let step = "proxy_upstream".parse::<PluginStep>().unwrap();
        assert_eq!(step, PluginStep::ProxyUpstream);
        assert_eq!(step.to_string(), "proxy_upstream");

        let step = "response".parse::<PluginStep>().unwrap();
        assert_eq!(step, PluginStep::Response);
        assert_eq!(step.to_string(), "response");
    }

    #[test]
    fn test_request_plugin_result() {
        let skip1 = RequestPluginResult::Skipped;
        let skip2 = RequestPluginResult::Skipped;
        assert_eq!(true, skip1 == skip2);

        let continue1 = RequestPluginResult::Continue;
        let continue2 = RequestPluginResult::Continue;
        assert_eq!(true, continue1 == continue2);

        let respond1 = RequestPluginResult::Respond(HttpResponse::no_content());
        let respond2 = RequestPluginResult::Respond(HttpResponse::no_content());
        assert_eq!(false, respond1 == respond2);
    }
}

#[cfg(test)]
mod security_failure_intent_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn security_failure_intent_preserves_explicit_protection_without_widening_legacy()
     {
        assert!(!security_failure_intent(
            "behaviour",
            &json!({"enabled":true})
        ));
        for mode in ["block", "unknown"] {
            assert!(security_failure_intent(
                "behaviour",
                &json!({"enabled":true,"abuse":{"enabled":true,"scan":{"mode":mode}}})
            ));
        }
        assert!(!security_failure_intent(
            "behaviour",
            &json!({"enabled":true,"client_ip_from_peer":true,"abuse_namespace":"behaviour:detect","abuse":{"enabled":true,"scan":{"mode":"detect","window":"30s","threshold":3,"ban_ttl":"2m"}}})
        ));
        crate::with_construction_trusted_proxies(&None, || {
            assert!(security_failure_intent(
                "behaviour",
                &json!({"enabled":true,"abuse_namespace":"behaviour:detect","abuse":{"enabled":true,"scan":{"mode":"detect","window":"30s","threshold":3,"ban_ttl":"2m"}}})
            ));
        });
        assert!(security_failure_intent(
            "behaviour",
            &json!({"enabled":true,"abuse":{"enabled":true,"scan":{"mode":"detect","window":"30s","threshold":0,"ban_ttl":"2m"}}})
        ));
        for bad_window in ["bogus", "0s"] {
            assert!(security_failure_intent(
                "behaviour",
                &json!({"enabled":true,"client_ip_from_peer":true,"abuse_namespace":"behaviour:detect","abuse":{"enabled":true,"scan":{"mode":"detect","window":bad_window,"threshold":3,"ban_ttl":"2m"}}})
            ));
        }
        assert!(security_failure_intent(
            "behaviour",
            &json!({"enabled":true,"client_ip_from_peer":true,"abuse_namespace":"behaviour:detect","max_url_keys":2,"abuse":{"enabled":true,"scan":{"mode":"detect","window":"30s","threshold":3,"ban_ttl":"2m"}}})
        ));
        for invalid_base in [
            json!({"window":"0s"}),
            json!({"budget_ms":0}),
            json!({"weights":{"request_speed":14}}),
            json!({"thresholds":{"human":10}}),
            json!({"step":"response"}),
        ] {
            let mut profile = json!({"enabled":true,"client_ip_from_peer":true,"abuse_namespace":"behaviour:detect","abuse":{"enabled":true,"scan":{"mode":"detect","window":"30s","threshold":3,"ban_ttl":"2m"}}});
            profile.as_object_mut().expect("profile").extend(
                invalid_base.as_object().expect("invalid base").clone(),
            );
            assert!(security_failure_intent("behaviour", &profile));
        }
        assert!(security_failure_intent(
            "behaviour",
            &json!({"abuse_namespace":"behaviour:detect","abuse":{"enabled":true,"scan":{"mode":"detect","window":"30s","threshold":3,"ban_ttl":"2m"}}})
        ));
        assert!(!security_failure_intent(
            "behaviour",
            &json!({"enabled":true,"abuse":{"enabled":false,"scan":{"mode":"block"}}})
        ));
        assert!(!security_failure_intent(
            "behaviour",
            &json!({"enabled":false,"abuse":{"enabled":true,"scan":{"mode":"block"}}})
        ));
        assert!(security_failure_intent(
            "behaviour",
            &json!({"enabled":true,"abuse":{"enabled":true}})
        ));
        assert!(!security_failure_intent("limit", &json!({})));
        assert!(security_failure_intent(
            "limit",
            &json!({"enforcement_required":true})
        ));
        assert!(security_failure_intent("waf", &json!({})));
    }
}
