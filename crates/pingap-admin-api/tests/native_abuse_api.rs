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
    Applier, ConfigSink, DataPlane, NoPluginCheck, Validator, plugin_config_key,
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
        Arc::new(NoPluginCheck),
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

use pingap_behaviour::decisions::{Admission, Registry, ScenarioProfile};
use pingap_controlplane::events::{EventQueue, EventWriter};
use pingap_domainstate::{Limits, ManualClock};
fn native(
    clock: ManualClock,
    queue: Arc<EventQueue>,
) -> Arc<Registry<ManualClock>> {
    let config = toml::from_str(
        r#"enabled=true
[scan]
mode="block"
window="10s"
threshold=2
ban_ttl="1s"
"#,
    )
    .expect("test fixture succeeds");
    let r = Arc::new(
        Registry::with_clock(Limits::default(), clock).with_event_queue(queue),
    );
    r.activate(vec![
        ScenarioProfile::new("behaviour:a", config, 128, 8, 8)
            .expect("test fixture succeeds"),
    ]);
    r
}
fn ban(r: &Registry<ManualClock>) -> String {
    for path in ["/a", "/b"] {
        let Admission::Allowed(Some(t)) =
            r.admit("behaviour:a", "a.test", "::1", "GET", path, true)
        else {
            panic!("admission")
        };
        r.observe(&t, 404, false);
    }
    r.active_decisions(0, 100)[0].id.clone()
}
const OWNER: &str =
    r#"{"profile":"behaviour:a","domain":"a.test","client_ip":"::1"}"#;
#[tokio::test]
async fn routes_guard_list_release_and_preserve_exact_decision_ownership() {
    let mut api = api().await;
    let queue = Arc::new(EventQueue::new(32).expect("test fixture succeeds"));
    let runtime = native(ManualClock::at(0), queue.clone());
    let id = ban(&runtime);
    api.state = api.state.with_native_abuse(runtime.clone());
    let page = send(&api, Method::GET, "/abuse/bans", "").await;
    assert_eq!(page.status, StatusCode::OK);
    let page: serde_json::Value =
        serde_json::from_slice(&page.body).expect("test fixture succeeds");
    assert_eq!(page["items"][0]["id"], id);
    assert_eq!(page["items"][0]["mode"], "block");
    let empty =
        send_query(&api, Method::GET, "/abuse/bans", "domain=b.test").await;
    assert!(
        serde_json::from_slice::<serde_json::Value>(&empty.body)
            .expect("test fixture succeeds")["items"]
            .as_array()
            .expect("test fixture succeeds")
            .is_empty()
    );
    assert_eq!(
        send_query(&api, Method::GET, "/abuse/bans", "cursor=bad")
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send(&api, Method::DELETE, "/abuse/bans/bad", OWNER)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let path = format!("/abuse/bans/{id}");
    let unauth = dispatch(
        &api.state,
        &ApiRequest {
            method: Method::GET,
            path: "/abuse/bans".into(),
            query: String::new(),
            body: Bytes::new(),
            caller: None,
        },
    )
    .await;
    assert_eq!(unauth.status, StatusCode::UNAUTHORIZED);
    api.admin.role = Role::Viewer;
    assert_eq!(
        send(&api, Method::GET, "/abuse/bans", "").await.status,
        StatusCode::OK
    );
    assert_eq!(
        send(&api, Method::DELETE, &path, OWNER).await.status,
        StatusCode::FORBIDDEN
    );
    api.admin.role = Role::Admin;
    api.admin.auth_level = AuthLevel::PasswordOnly;
    assert_eq!(
        send(&api, Method::DELETE, &path, OWNER).await.status,
        StatusCode::FORBIDDEN
    );
    api.admin.auth_level = AuthLevel::TwoFactor;
    let wrong = OWNER.replace("a.test", "b.test");
    assert!(
        String::from_utf8_lossy(
            &send(&api, Method::DELETE, &path, &wrong).await.body
        )
        .contains("already_absent")
    );
    assert_eq!(runtime.active_decisions(0, 100).len(), 1);
    let released = send(&api, Method::DELETE, &path, OWNER).await;
    assert_eq!(released.status, StatusCode::OK);
    let result: serde_json::Value =
        serde_json::from_slice(&released.body).expect("test fixture succeeds");
    assert_eq!(result["outcome"], "released");
    assert_eq!(result["audit"], "queued");
    assert!(
        String::from_utf8_lossy(
            &send(&api, Method::DELETE, &path, OWNER).await.body
        )
        .contains("already_absent")
    );
    EventWriter::new(queue, api.store.clone())
        .flush()
        .await
        .expect("test fixture succeeds");
    let history = send(&api, Method::GET, "/activity", "").await;
    let rows: serde_json::Value =
        serde_json::from_slice(&history.body).expect("test fixture succeeds");
    let released = rows
        .as_array()
        .expect("test fixture succeeds")
        .iter()
        .find(|r| r["action"] == "native.ban.released")
        .expect("test fixture succeeds");
    assert_eq!(released["actor_username"], "admin");
    assert_eq!(released["target"], id);
    assert!(
        released["detail"]
            .as_str()
            .expect("test fixture succeeds")
            .contains("operator_release")
    );
}
#[tokio::test]
async fn stale_release_after_expiry_and_reban_does_not_clear_new_evidence() {
    let mut api = api().await;
    let clock = ManualClock::at(0);
    let queue = Arc::new(EventQueue::new(32).expect("test fixture succeeds"));
    let runtime = native(clock.clone(), queue.clone());
    let old = ban(&runtime);
    clock.advance(Duration::from_secs(2));
    let new = ban(&runtime);
    assert_ne!(old, new);
    api.state = api.state.with_native_abuse(runtime.clone());
    let response =
        send(&api, Method::DELETE, &format!("/abuse/bans/{old}"), OWNER).await;
    assert!(String::from_utf8_lossy(&response.body).contains("already_absent"));
    assert_eq!(runtime.active_decisions(0, 100)[0].id, new);
    let events = queue.drain_notifications(32);
    assert_eq!(
        events.len(),
        3,
        "created,expired,created; no fabricated release"
    );
}

#[tokio::test]
async fn release_reports_degraded_delivery_without_losing_runtime_transition() {
    let mut api = api().await;
    let queue = Arc::new(EventQueue::new(1).expect("test fixture succeeds"));
    let runtime = native(ManualClock::at(0), queue.clone());
    let id = ban(&runtime);
    api.state = api.state.with_native_abuse(runtime.clone());
    api.admin.role = Role::Operator;
    let result =
        send(&api, Method::DELETE, &format!("/abuse/bans/{id}"), OWNER).await;
    assert_eq!(result.status, StatusCode::OK);
    let result: serde_json::Value =
        serde_json::from_slice(&result.body).expect("test fixture succeeds");
    assert_eq!(result["outcome"], "released");
    assert_eq!(result["audit"], "degraded");
    assert!(runtime.active_decisions(0, 100).is_empty());
    assert_eq!(queue.dropped_lifecycle(), 1);
}

#[tokio::test]
async fn filtered_pagination_and_runtime_epoch_never_mix_decisions() {
    let mut api = api().await;
    let runtime = native(
        ManualClock::at(0),
        Arc::new(EventQueue::new(256).expect("test fixture succeeds")),
    );
    for index in 1..=105 {
        for path in ["/one", "/two"] {
            let Admission::Allowed(Some(ticket)) = runtime.admit(
                "behaviour:a",
                "a.test",
                &format!("192.0.2.{index}"),
                "GET",
                path,
                true,
            ) else {
                panic!("bounded fixture admission")
            };
            runtime.observe(&ticket, 404, false);
        }
    }
    api.state = api.state.with_native_abuse(runtime);
    let first = send_query(
        &api,
        Method::GET,
        "/abuse/bans",
        "profile=behaviour%3Aa&domain=a.test",
    )
    .await;
    let first: serde_json::Value =
        serde_json::from_slice(&first.body).expect("test fixture succeeds");
    assert_eq!(
        first["items"]
            .as_array()
            .expect("test fixture succeeds")
            .len(),
        100
    );
    let cursor = first["next_cursor"]
        .as_str()
        .expect("test fixture succeeds");
    let next = send_query(
        &api,
        Method::GET,
        "/abuse/bans",
        &format!("domain=a.test&cursor={cursor}"),
    )
    .await;
    let next: serde_json::Value =
        serde_json::from_slice(&next.body).expect("test fixture succeeds");
    assert_eq!(
        next["items"]
            .as_array()
            .expect("test fixture succeeds")
            .len(),
        5
    );
    let ids: std::collections::HashSet<_> = first["items"]
        .as_array()
        .expect("test fixture succeeds")
        .iter()
        .chain(next["items"].as_array().expect("test fixture succeeds"))
        .map(|e| e["id"].as_str().expect("test fixture succeeds"))
        .collect();
    assert_eq!(ids.len(), 105);
    assert_eq!(
        send_query(
            &api,
            Method::GET,
            "/abuse/bans",
            "cursor=previous-epoch:100"
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
}
