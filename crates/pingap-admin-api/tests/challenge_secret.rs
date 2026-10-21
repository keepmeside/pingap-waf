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
        Arc::new(ChallengeCheck),
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
struct ChallengeCheck;
impl PluginCheck for ChallengeCheck {
    fn check(
        &self,
        _name: &str,
        conf: &pingap_config::PluginConf,
        _config: &pingap_config::PingapConfig,
    ) -> Result<(), String> {
        if conf.get("category").and_then(|v| v.as_str()) == Some("challenge") {
            pingap_challenge::Challenge::try_from(conf)
                .map(|_| ())
                .map_err(|e| e.to_string())
        } else {
            Ok(())
        }
    }
}
#[tokio::test]
async fn inspection_redacts_literal_and_metadata_roundtrip_preserves_canonical_source()
 {
    let api = api().await;
    let body = r#"{"category":"challenge","enabled":true,"client_ip_from_peer":true,"secret":"sentinel-private-legacy","remark":"retained"}"#;
    assert_eq!(
        send(&api, Method::PUT, "/policies/challenge:edge", body)
            .await
            .status,
        StatusCode::OK
    );
    let get = send(&api, Method::GET, "/policies/challenge:edge", "").await;
    assert_eq!(get.status, StatusCode::OK);
    assert!(
        !String::from_utf8_lossy(&get.body).contains("sentinel-private-legacy")
    );
    let mut view: serde_json::Value =
        serde_json::from_slice(&get.body).expect("test fixture succeeds");
    assert_eq!(view["secret_configured"], true);
    assert_eq!(view["secret_source"]["kind"], "literal");
    view["difficulty"] = serde_json::json!(3);
    let response = send(
        &api,
        Method::PUT,
        "/policies/challenge:edge",
        &serde_json::json!({"config":view}).to_string(),
    )
    .await;
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
        .expect("test fixture succeeds")
        .expect("test fixture succeeds");
    let intent: Intent = serde_json::from_str(&version.intent_json)
        .expect("test fixture succeeds");
    let conf = &intent.policies["challenge:edge"];
    assert_eq!(conf["secret"].as_str(), Some("sentinel-private-legacy"));
    assert_eq!(conf["remark"].as_str(), Some("retained"));
    assert!(!conf.contains_key("secret_source"));
    assert!(!conf.contains_key("secret_configured"));
    let list = send(&api, Method::GET, "/policies", "").await;
    assert!(
        !String::from_utf8_lossy(&list.body)
            .contains("sentinel-private-legacy")
    );
}
#[tokio::test]
async fn file_replacement_validates_before_committing_and_preserves_unknown_fields()
 {
    let api = api().await;
    let root = std::path::Path::new("/run/secrets/pingap/challenge");
    std::fs::create_dir_all(root).expect("test fixture succeeds");
    let reference = format!("api-test-{}", std::process::id());
    let path = root.join(&reference);
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .expect("test fixture succeeds");
    std::fs::write(&path, b"sentinel-file-material")
        .expect("test fixture succeeds");
    let original = r#"{"category":"challenge","enabled":true,"client_ip_from_peer":true,"secret":"legacy-private"}"#;
    assert_eq!(
        send(&api, Method::PUT, "/policies/challenge:edge", original)
            .await
            .status,
        StatusCode::OK
    );
    let replace = serde_json::json!({"config":{"category":"challenge","enabled":true,"client_ip_from_peer":true,"secret_file":reference,"remark":"retain-me"}});
    let response = send(
        &api,
        Method::PUT,
        "/policies/challenge:edge",
        &replace.to_string(),
    )
    .await;
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
        .expect("test fixture succeeds")
        .expect("test fixture succeeds");
    let intent: Intent = serde_json::from_str(&version.intent_json)
        .expect("test fixture succeeds");
    assert!(!intent.policies["challenge:edge"].contains_key("secret"));
    assert_eq!(
        intent.policies["challenge:edge"]["secret_file"].as_str(),
        Some(reference.as_str())
    );
    let preserve = serde_json::json!({"config":{"category":"challenge","enabled":true,"client_ip_from_peer":true,"difficulty":3,"remark":"retain-me","secret_configured":true,"secret_source":{"kind":"file","reference":"stale-client-reference"}}});
    assert_eq!(
        send(
            &api,
            Method::PUT,
            "/policies/challenge:edge",
            &preserve.to_string()
        )
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
    let preserved: Intent =
        serde_json::from_str(&version.intent_json).expect("intent");
    assert_eq!(
        preserved.policies["challenge:edge"]["secret_file"].as_str(),
        Some(reference.as_str())
    );
    assert!(
        !preserved.policies["challenge:edge"].contains_key("secret_source")
    );
    for input in [
        serde_json::json!({"category":"challenge","enabled":true,"client_ip_from_peer":true,"secret_file":"missing-test-reference"}),
        serde_json::json!({"category":"challenge","enabled":true,"client_ip_from_peer":true,"secret":"private-marker","secret_file":reference}),
    ] {
        let response = send(
            &api,
            Method::PUT,
            "/policies/challenge:edge",
            &input.to_string(),
        )
        .await;
        assert!(!response.status.is_success());
        assert!(
            !String::from_utf8_lossy(&response.body).contains("private-marker")
        );
        assert_eq!(
            api.store
                .latest_applied_config_version()
                .await
                .expect("test fixture succeeds")
                .expect("test fixture succeeds")
                .id,
            version.id
        );
    }
    for bad in [
        serde_json::json!({"category":"challenge","enabled":true,"client_ip_from_peer":true,"secret":"private-marker","token_ttl":"private-marker"}),
        serde_json::json!({"category":"challenge","enabled":true,"client_ip_from_peer":true,"secret_file":reference,"token_ttl":"0s"}),
        serde_json::json!({"category":"challenge","enabled":true,"client_ip_from_peer":true,"secret":"private-marker","step":1}),
    ] {
        let response = send(
            &api,
            Method::PUT,
            "/policies/challenge:edge",
            &bad.to_string(),
        )
        .await;
        assert!(!response.status.is_success());
        assert!(
            !String::from_utf8_lossy(&response.body).contains("private-marker")
        );
        assert_eq!(
            api.store
                .latest_applied_config_version()
                .await
                .expect("read")
                .expect("version")
                .id,
            version.id
        );
    }
    let get = send(&api, Method::GET, "/policies/challenge:edge", "").await;
    assert!(
        !String::from_utf8_lossy(&get.body).contains("sentinel-file-material")
    );
    std::fs::remove_file(path).expect("test fixture succeeds");
}
