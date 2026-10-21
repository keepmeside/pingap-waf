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

//! What the config-shaped routes actually do.
//!
//! The enumeration test next door asks who may reach a route. This one asks what a write
//! *is*: every one of them regenerates the whole config from stored intent and hands it to
//! the `Applier`, so the assertions here are on the version row and the audit row a write
//! produced — not on a response body, which a handler that wrote config directly would fill
//! in just as convincingly.

use bytes::Bytes;
use http::{Method, StatusCode};
use pingap_admin_api::{ApiRequest, ApiResponse, AppState, Caller, dispatch};
use pingap_controlplane::projection::{
    Applier, ConfigSink, DataPlane, Intent, PluginCheck, Validator,
    plugin_config_key,
};
use pingap_controlplane::{
    AuthLevel, ControlPlaneStore, Role, TotpGuard, TursoStore,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A throwaway AES key in the shape `pingap-util` expects.
///
/// Real rather than absent: second-factor enrolment seals the secret with it, and a fixture
/// that passed `None` would make every enrolment test a test of the missing-key refusal.
const TOTP_KEY: &str = "PLpKJqvfkjTcYTDpauJf+2JnEayP+bm+0Oe60Jk=";

/// What a reload of the last committed config would bring up.
///
/// Post-commit verification asks the data plane which plugins it holds; with no gateway here,
/// this answers from what was committed. That is enough for these tests, whose subject is the
/// write path — a real provider read-back is asserted in the binary, and the request-level
/// outcome in `tests/gateway_projection.rs`.
#[derive(Default)]
struct Reloaded {
    running: Mutex<BTreeMap<String, String>>,
}

struct ReloadingSink {
    reloaded: Arc<Reloaded>,
    path: std::path::PathBuf,
}

#[async_trait::async_trait]
impl ConfigSink for ReloadingSink {
    async fn commit(&self, canonical_toml: &str) -> Result<(), String> {
        let config =
            pingap_config::PingapConfig::new(canonical_toml.as_bytes(), true)
                .map_err(|e| e.to_string())?;
        std::fs::write(&self.path, canonical_toml)
            .map_err(|e| e.to_string())?;
        let mut running = self.reloaded.running.lock().expect("lock");
        running.clear();
        for (name, conf) in &config.plugins {
            running.insert(name.clone(), plugin_config_key(conf));
        }
        Ok(())
    }
}

impl DataPlane for Reloaded {
    fn running_config_key(&self, name: &str) -> Option<String> {
        self.running.lock().expect("lock").get(name).cloned()
    }
}

struct Api {
    state: AppState,
    store: Arc<dyn ControlPlaneStore>,
    admin: Caller,
    _dir: tempfile::TempDir,
}

async fn api() -> Api {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = TursoStore::open(
        dir.path().join("cp.db").to_str().expect("utf-8 path"),
    )
    .await
    .expect("the store opens");
    store.migrate().await.expect("migrations apply");
    let store: Arc<dyn ControlPlaneStore> = Arc::new(store);
    let user = store
        .create_user(
            pingap_controlplane::NewUser {
                username: "admin".to_string(),
                email: "admin@example.test".to_string(),
                password_hash: "$argon2id$v=19$m=19456,t=2,p=1$salt$hash"
                    .to_string(),
                role: Role::Admin,
            },
            1_000,
        )
        .await
        .expect("the admin is created");
    let reloaded = Arc::new(Reloaded::default());
    let applier = Applier::new(
        store.clone(),
        // Accepts everything: the validation gate has its own tests in
        // `pingap-controlplane`, and pointing this at a real gateway binary would make
        // every route test depend on a build.
        Validator::new("/bin/true"),
        Arc::new(RateCheck),
        Arc::new(ReloadingSink {
            reloaded: reloaded.clone(),
            path: dir.path().join("gateway.toml"),
        }),
        reloaded,
        Duration::from_millis(0),
    );
    Api {
        admin: Caller {
            session_id: "s1".to_string(),
            user_id: user.id,
            username: user.username,
            role: Role::Admin,
            auth_level: AuthLevel::TwoFactor,
        },
        state: AppState::new(
            store.clone(),
            Arc::new(applier),
            Arc::new(TotpGuard::default()),
            Some(TOTP_KEY.to_string()),
        ),
        store,
        _dir: dir,
    }
}

#[allow(dead_code)]
async fn send_query(
    api: &Api,
    method: Method,
    path: &str,
    query: &str,
) -> ApiResponse {
    dispatch(
        &api.state,
        &ApiRequest {
            method,
            path: path.to_string(),
            query: query.to_string(),
            body: Bytes::new(),
            caller: Some(api.admin.clone()),
        },
    )
    .await
}

async fn send(
    api: &Api,
    method: Method,
    path: &str,
    body: &str,
) -> ApiResponse {
    dispatch(
        &api.state,
        &ApiRequest {
            method,
            path: path.to_string(),
            query: String::new(),
            body: Bytes::copy_from_slice(body.as_bytes()),
            caller: Some(api.admin.clone()),
        },
    )
    .await
}

/// Every field, because `projection::Domain` has no defaults: a field it did not name is a
/// field the contract does not describe, and serde refusing the body is how that stays true.
const DOMAIN: &str = r#"{
    "hostnames": ["site.test"],
    "path": null,
    "listener": "http",
    "upstream": "app",
    "priority": null,
    "notes": null,
    "client_max_body_size": null,
    "grpc_web": false,
    "reverse_proxy_headers": null,
    "max_processing": null,
    "max_retries": null,
    "policies": []
}"#;

const UPSTREAM: &str = r#"{
    "backends": [{"addr": "127.0.0.1:8080", "weight": null}],
    "lb_algorithm": null,
    "health_check": null,
    "discovery": null,
    "tls_sni": null,
    "verify_cert": null
}"#;

const LISTENER: &str = r#"{
    "addr": "127.0.0.1:6199",
    "http2": null,
    "tls": null,
    "access_log": null,
    "server_timing": null
}"#;

struct RateCheck;
impl PluginCheck for RateCheck {
    fn check(
        &self,
        _name: &str,
        conf: &pingap_config::PluginConf,
        _config: &pingap_config::PingapConfig,
    ) -> Result<(), String> {
        if conf.get("category").and_then(|v| v.as_str()) == Some("limit") {
            pingap_plugin::get_plugin_factory()
                .create(conf)
                .map(|_| ())
                .map_err(|e| e.to_string())
        } else {
            Ok(())
        }
    }
}
#[tokio::test]
async fn website_rate_binding_roundtrips_and_marks_only_bound_profiles_required()
 {
    let api = api().await;
    for (path, body) in [
        ("/upstreams/app", UPSTREAM),
        ("/listeners/http", LISTENER),
        (
            "/policies/limit:edge",
            r#"{"category":"limit","type":"rate","tag":"ip","max":10,"interval":"10s","weight":50,"remark":"retained","config":{"custom":"keep"}}"#,
        ),
    ] {
        assert_eq!(
            send(&api, Method::PUT, path, body).await.status,
            StatusCode::OK
        );
    }
    let version = api
        .store
        .latest_applied_config_version()
        .await
        .expect("read")
        .expect("version");
    let intent: Intent =
        serde_json::from_str(&version.intent_json).expect("intent");
    assert!(
        !pingap_controlplane::projection::generate(&intent)
            .expect("generate")
            .config
            .plugins["limit:edge"]
            .contains_key("enforcement_required")
    );
    let mut domain: serde_json::Value =
        serde_json::from_str(DOMAIN).expect("domain");
    domain["policies"] = serde_json::json!([{"limit":"edge"}]);
    let response =
        send(&api, Method::PUT, "/domains/site", &domain.to_string()).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let version = api
        .store
        .latest_applied_config_version()
        .await
        .expect("read")
        .expect("version");
    let intent: Intent =
        serde_json::from_str(&version.intent_json).expect("intent");
    let projected =
        pingap_controlplane::projection::generate(&intent).expect("generate");
    assert_eq!(
        projected.config.plugins["limit:edge"]["enforcement_required"]
            .as_bool(),
        Some(true)
    );
    assert_eq!(
        projected.config.locations["site"]
            .plugins
            .as_ref()
            .expect("plugins"),
        &vec!["limit:edge".to_string()]
    );
    assert!(
        !intent.policies["limit:edge"].contains_key("enforcement_required")
    );
    assert_eq!(
        intent.policies["limit:edge"]["remark"].as_str(),
        Some("retained")
    );
    assert_eq!(
        intent.policies["limit:edge"]["config"]["custom"].as_str(),
        Some("keep")
    );
    domain["policies"] = serde_json::json!([]);
    assert_eq!(
        send(&api, Method::PUT, "/domains/site", &domain.to_string())
            .await
            .status,
        StatusCode::OK
    );
    let version = api
        .store
        .latest_applied_config_version()
        .await
        .expect("read")
        .expect("version");
    let intent: Intent =
        serde_json::from_str(&version.intent_json).expect("intent");
    assert!(intent.policies.contains_key("limit:edge"));
    assert!(
        !pingap_controlplane::projection::generate(&intent)
            .expect("generate")
            .config
            .plugins["limit:edge"]
            .contains_key("enforcement_required")
    );
}
#[tokio::test]
async fn missing_mismatched_and_unbuildable_limit_profiles_are_not_applied() {
    let api = api().await;
    for (path, body) in
        [("/upstreams/app", UPSTREAM), ("/listeners/http", LISTENER)]
    {
        assert_eq!(
            send(&api, Method::PUT, path, body).await.status,
            StatusCode::OK
        );
    }
    let mut domain: serde_json::Value =
        serde_json::from_str(DOMAIN).expect("domain");
    domain["policies"] = serde_json::json!([{"limit":"missing"}]);
    assert_eq!(
        send(&api, Method::PUT, "/domains/site", &domain.to_string())
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send(
            &api,
            Method::PUT,
            "/policies/limit:bad",
            r#"{"category":"waf"}"#
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    for body in [
        r#"{"category":"limit","interval":"wrong"}"#,
        r#"{"category":"limit","step":"response"}"#,
        r#"{"category":"limit","enforcement_required":true}"#,
    ] {
        assert!(
            !send(&api, Method::PUT, "/policies/limit:bad", body)
                .await
                .status
                .is_success()
        );
    }
}
#[test]
fn every_existing_wire_binding_shape_stays_compatible() {
    for category in [
        "waf",
        "acl",
        "bot",
        "challenge",
        "behaviour",
        "adaptive",
        "limit",
    ] {
        let value = serde_json::json!({category:"profile"});
        let binding: pingap_controlplane::projection::PolicyBinding =
            serde_json::from_value(value.clone()).expect("supported binding");
        assert_eq!(serde_json::to_value(binding).expect("wire"), value);
    }
    assert!(serde_json::from_value::<pingap_controlplane::projection::PolicyBinding>(serde_json::json!({"unknown":"profile"})).is_err());
}
