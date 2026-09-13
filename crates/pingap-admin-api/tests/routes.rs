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
    Applier, ConfigSink, DataPlane, Intent, NoPluginCheck, Validator,
    plugin_config_key,
};
use pingap_controlplane::repository::TimeRange;
use pingap_controlplane::{
    AuthLevel, ConfigStatus, ControlPlaneStore, Role, TursoStore,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
}

#[async_trait::async_trait]
impl ConfigSink for ReloadingSink {
    async fn commit(&self, canonical_toml: &str) -> Result<(), String> {
        let config =
            pingap_config::PingapConfig::new(canonical_toml.as_bytes(), true)
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
        state: AppState::new(store.clone(), Arc::new(applier)),
        store,
        _dir: dir,
    }
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

/// The write path, end to end: three edits, three versions, three audit rows.
///
/// The version rows are the assertion. A handler that wrote config directly would answer 200
/// to every one of these requests and leave `config_versions` empty — which is exactly the
/// failure the criterion "no new config route writes config outside projection" names.
#[tokio::test]
async fn each_write_produces_a_config_version_and_one_audit_row() {
    let api = api().await;

    for (path, body) in [
        ("/upstreams/app", UPSTREAM),
        ("/listeners/http", LISTENER),
        ("/domains/site", DOMAIN),
    ] {
        let response = send(&api, Method::PUT, path, body).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "PUT {path} answered {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        );
    }

    // Read back through the API, from stored intent rather than from config.
    let domains = send(&api, Method::GET, "/domains", "").await;
    assert_eq!(domains.status, StatusCode::OK);
    let body = String::from_utf8_lossy(&domains.body).to_string();
    assert!(
        body.contains("site.test"),
        "the domain did not persist: {body}"
    );

    // One version per write, and every one of them confirmed enforcing.
    let versions = api
        .store
        .list_config_versions(None)
        .await
        .expect("versions are listable");
    assert_eq!(versions.len(), 3, "one version per write");
    assert_eq!(
        versions
            .iter()
            .filter(|v| v.status == ConfigStatus::Applied)
            .count(),
        1,
        "exactly one version should still be the applied one"
    );

    // One activity row per mutation, each naming the version it produced.
    let log = api
        .store
        .read_activity(TimeRange::default())
        .await
        .expect("the log is readable");
    assert_eq!(log.len(), 3, "one audit row per mutation: {log:?}");
    for row in &log {
        assert!(
            row.config_version.is_some(),
            "a config mutation was logged without the version it produced: {row:?}"
        );
        assert_eq!(row.actor_username, "admin");
    }
}

/// A domain naming an upstream nothing defines is refused, and nothing is written.
///
/// The projection refuses it rather than dropping the reference, because pingap resolves a
/// Location's upstream by name and a Location with none proxies nowhere. What this test adds
/// is that the refusal reaches the caller as a 400 they can fix — not a 500, and not a 200
/// with a version row recording a config that was never valid.
#[tokio::test]
async fn a_domain_naming_an_undefined_upstream_is_refused_and_writes_nothing() {
    let api = api().await;
    let response = send(&api, Method::PUT, "/domains/orphan", DOMAIN).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "a dangling upstream was accepted: {}",
        String::from_utf8_lossy(&response.body)
    );
    assert!(
        String::from_utf8_lossy(&response.body).contains("app"),
        "the refusal did not name the missing upstream: {}",
        String::from_utf8_lossy(&response.body)
    );
    assert!(
        api.store
            .list_config_versions(None)
            .await
            .expect("listable")
            .is_empty(),
        "a refused projection still recorded a version"
    );
}

/// Deleting something that is not there is a 404, not a version.
///
/// The projection is total, so a delete that matched nothing would still regenerate, commit
/// and record a version and an audit row claiming a removal — an audit trail that says
/// something happened when nothing did.
#[tokio::test]
async fn deleting_an_absent_resource_is_404_and_writes_no_version() {
    let api = api().await;
    let response =
        send(&api, Method::DELETE, "/upstreams/never-existed", "").await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert!(
        api.store
            .list_config_versions(None)
            .await
            .expect("listable")
            .is_empty(),
        "a delete that matched nothing recorded a version"
    );
    assert!(
        api.store
            .read_activity(TimeRange::default())
            .await
            .expect("readable")
            .is_empty(),
        "a delete that matched nothing wrote an audit row"
    );
}

/// A profile name without a category is refused before it can reach the projection.
///
/// `generate` would happily emit a plugin entry keyed `strict`, which no policy binding can
/// name — so the domain that meant to use it would project with an empty plugin list and
/// serve unfiltered traffic while the control plane showed a profile attached.
#[tokio::test]
async fn a_policy_name_without_a_category_is_refused() {
    let api = api().await;
    let response = send(
        &api,
        Method::PUT,
        "/policies/strict",
        r#"{"category":"waf"}"#,
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let body = String::from_utf8_lossy(&response.body).to_string();
    assert!(
        body.contains("category:profile"),
        "the refusal did not say what a profile name looks like: {body}"
    );
}

/// The uploaded shape. The key is a sentinel rather than key material: nothing here parses
/// it, and what the assertions need is a string that must appear in no response.
const UPLOADED_CERTIFICATE: &str = r#"{
    "domains": ["site.test"],
    "tls_cert": "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----",
    "tls_key": "-----BEGIN PRIVATE KEY-----\nDO-NOT-ECHO\n-----END PRIVATE KEY-----",
    "is_default": null,
    "is_ca": null,
    "acme": null,
    "dns_challenge": null,
    "dns_provider": null,
    "dns_service_url": null,
    "buffer_days": null,
    "remark": "uploaded"
}"#;

/// The same certificate, edited, with no key in the body — what a UI can send, because the
/// read route that populated its form never returned one.
const EDITED_CERTIFICATE: &str = r#"{
    "domains": ["site.test", "www.site.test"],
    "tls_cert": "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----",
    "tls_key": null,
    "is_default": null,
    "is_ca": null,
    "acme": null,
    "dns_challenge": null,
    "dns_provider": null,
    "dns_service_url": null,
    "buffer_days": null,
    "remark": "rotated"
}"#;

/// `body` with one key added that no contract names.
fn with_unknown_key(body: &str) -> String {
    let inner = body.trim().trim_end_matches('}').trim_end();
    format!("{inner}, \"a_key_no_contract_names\": 1}}")
}

/// A key the DTO does not name is refused, not ignored.
///
/// `serde_json` drops unknown fields by default, so without `deny_unknown_fields` a typo'd
/// `client_max_body_limit` answers 200, records a version and an audit row, and changes
/// nothing. The operator's own evidence says the write succeeded. Every config-shaped body
/// is checked, because the attribute lives on the intent types and a new one could be added
/// without it.
#[tokio::test]
async fn a_body_carrying_a_key_the_contract_does_not_name_is_refused() {
    let api = api().await;
    for (path, body) in [
        ("/domains/site", DOMAIN),
        ("/upstreams/app", UPSTREAM),
        ("/listeners/http", LISTENER),
        ("/ssl/edge", UPLOADED_CERTIFICATE),
    ] {
        let response =
            send(&api, Method::PUT, path, &with_unknown_key(body)).await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "PUT {path} accepted an unknown key: {}",
            String::from_utf8_lossy(&response.body)
        );
        assert!(
            String::from_utf8_lossy(&response.body)
                .contains("a_key_no_contract_names"),
            "the refusal did not name the key it rejected: {}",
            String::from_utf8_lossy(&response.body)
        );
    }
    assert!(
        api.store
            .list_config_versions(None)
            .await
            .expect("listable")
            .is_empty(),
        "a refused body still recorded a version"
    );
}

/// A certificate write goes through the projection like any other, and the private key is
/// not in any response.
///
/// The redaction is asserted on both read routes and on the write's own response, because a
/// key leaked by the `PUT` that accepted it would never reach a `GET`. What is checked is the
/// sentinel string and not the field name: a response carrying `tls_key` with the value
/// stripped is still a response whose shape invites a UI to bind to it.
#[tokio::test]
async fn a_certificate_write_is_projected_and_never_echoes_the_key() {
    let api = api().await;
    let written =
        send(&api, Method::PUT, "/ssl/edge", UPLOADED_CERTIFICATE).await;
    assert_eq!(
        written.status,
        StatusCode::OK,
        "PUT /ssl/edge answered {}: {}",
        written.status,
        String::from_utf8_lossy(&written.body)
    );

    for response in [
        written,
        send(&api, Method::GET, "/ssl", "").await,
        send(&api, Method::GET, "/ssl/edge", "").await,
    ] {
        let body = String::from_utf8_lossy(&response.body).to_string();
        assert!(
            !body.contains("DO-NOT-ECHO"),
            "a response carried the private key: {body}"
        );
        assert!(
            !body.contains("\"tls_key\""),
            "a response named the key field at all: {body}"
        );
    }

    // The public half stays readable, and the fact of a key travels instead of its value.
    let body = String::from_utf8_lossy(
        &send(&api, Method::GET, "/ssl/edge", "").await.body,
    )
    .to_string();
    assert!(body.contains("\"has_tls_key\":true"), "{body}");
    assert!(body.contains("CHAIN"), "the chain was redacted too: {body}");
    assert!(body.contains("uploaded"), "{body}");

    // And the write is a version with an audit row, not a direct edit.
    let versions = api
        .store
        .list_config_versions(None)
        .await
        .expect("listable");
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].status, ConfigStatus::Applied);
    let log = api
        .store
        .read_activity(TimeRange::default())
        .await
        .expect("readable");
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].action, "certificate.create:edge");
    assert!(log[0].config_version.is_some());
}

/// An edit that omits the key keeps the stored one.
///
/// The read route never returns it, so a `PUT` that replaced the whole entry would demand a
/// secret the server just refused to hand back — changing a remark would mean re-uploading
/// the key. Omitting it means "keep", and that is safe rather than merely convenient: the
/// projection refuses a chain with no key, so had the key been dropped this write would have
/// been a 409 and not a 200. The status is the proof, and the stored intent is checked so
/// the proof does not rest on one error message.
#[tokio::test]
async fn editing_a_certificate_without_resending_its_key_keeps_the_stored_one()
{
    let api = api().await;
    assert_eq!(
        send(&api, Method::PUT, "/ssl/edge", UPLOADED_CERTIFICATE)
            .await
            .status,
        StatusCode::OK
    );
    let edited = send(&api, Method::PUT, "/ssl/edge", EDITED_CERTIFICATE).await;
    assert_eq!(
        edited.status,
        StatusCode::OK,
        "an edit that omitted the key was refused: {}",
        String::from_utf8_lossy(&edited.body)
    );

    let version = api
        .store
        .latest_applied_config_version()
        .await
        .expect("readable")
        .expect("the edit applied");
    let intent: Intent =
        serde_json::from_str(&version.intent_json).expect("intent parses");
    let stored = &intent.certificates["edge"];
    assert!(
        stored
            .tls_key
            .as_deref()
            .is_some_and(|key| key.contains("DO-NOT-ECHO")),
        "the stored key was not carried forward: {:?}",
        stored.tls_key
    );
    assert_eq!(stored.remark.as_deref(), Some("rotated"));
    assert_eq!(stored.domains.len(), 2, "the rest of the body was applied");
}

/// The category table is published from the engine, not restated beside it.
///
/// The point of the assertion is `modes`. A response-side category cannot block — the body
/// hook's result type has no `Respond` variant — so a UI offering `block` for `data_leakage`
/// offers a write the projection refuses, or one it accepts and treats as `redact`, leaving an
/// operator believing a leak is suppressed when it is only rewritten. Recomputing the expected
/// set from `pingap-waf`'s own enums rather than writing the three strings here is what keeps
/// this from becoming a second list that can disagree with the first.
#[tokio::test]
async fn the_waf_category_list_carries_lineage_and_the_modes_that_category_accepts()
 {
    let api = api().await;
    let response = send(&api, Method::GET, "/waf/categories", "").await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let body: Vec<serde_json::Value> =
        serde_json::from_slice(&response.body).expect("json");

    assert_eq!(
        body.len(),
        pingap_waf::categories::Category::ALL.len(),
        "a category was not published"
    );

    let request_modes: Vec<&str> = pingap_waf::config::RequestMode::ALL
        .iter()
        .map(|mode| mode.key())
        .collect();
    let response_modes: Vec<&str> = pingap_waf::config::ResponseMode::ALL
        .iter()
        .map(|mode| mode.key())
        .collect();

    for category in pingap_waf::categories::Category::ALL {
        let published = body
            .iter()
            .find(|entry| entry["key"] == category.key())
            .unwrap_or_else(|| {
                panic!("`{}` was not published", category.key())
            });

        assert_eq!(published["crs_group"], category.crs_group());
        assert_eq!(published["crs_file"], category.crs_file());
        assert_eq!(published["response_side"], category.is_response_side());
        let (low, high) = category.id_range();
        assert_eq!(
            published["id_range"],
            serde_json::json!([low, high]),
            "{}",
            category.key()
        );

        let modes: Vec<&str> = published["modes"]
            .as_array()
            .expect("modes is a list")
            .iter()
            .map(|mode| mode.as_str().expect("a mode is a string"))
            .collect();
        let expected = if category.is_response_side() {
            &response_modes
        } else {
            &request_modes
        };
        assert_eq!(
            modes,
            *expected,
            "`{}` was published with the wrong mode set",
            category.key()
        );
    }

    // The consequence, stated once against the published bytes rather than left to the loop:
    // a response-side category offers `redact` and never `block`.
    let leakage = body
        .iter()
        .find(|entry| entry["key"] == "data_leakage")
        .expect("data_leakage is published");
    assert_eq!(leakage["response_side"], true);
    let modes = leakage["modes"].to_string();
    assert!(modes.contains("redact"), "{modes}");
    assert!(!modes.contains("block"), "{modes}");
}
/// A certificate that has nothing to serve and nothing to obtain one is refused at the API
/// boundary, with the projection's reason, and writes nothing.
#[tokio::test]
async fn a_certificate_with_no_key_material_and_no_issuer_is_refused() {
    let api = api().await;
    let response = send(
        &api,
        Method::PUT,
        "/ssl/empty",
        r#"{"domains": [], "tls_cert": null, "tls_key": null, "is_default": null,
            "is_ca": null, "acme": null, "dns_challenge": null,
            "dns_provider": null, "dns_service_url": null, "buffer_days": null,
            "remark": null}"#,
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(
        String::from_utf8_lossy(&response.body)
            .contains("no PEM pair and no ACME issuer"),
        "the projection's reason did not reach the caller: {}",
        String::from_utf8_lossy(&response.body)
    );
    assert!(
        api.store
            .list_config_versions(None)
            .await
            .expect("listable")
            .is_empty(),
        "a refused certificate still recorded a version"
    );
}
