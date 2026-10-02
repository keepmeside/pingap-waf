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
use pingap_controlplane::events::{Verdict, WafEvent};
use pingap_controlplane::projection::{
    Applier, ConfigSink, DataPlane, Intent, NoPluginCheck, Validator,
    plugin_config_key,
};
use pingap_controlplane::repository::{NewPerformanceMetric, TimeRange};
use pingap_controlplane::{
    AuthLevel, ConfigStatus, ControlPlaneStore, Role, TotpGuard, TursoStore,
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

fn finding(domain: &str, verdict: Verdict, at: i64, rule: u32) -> WafEvent {
    WafEvent {
        node: "node-a".to_string(),
        domain: domain.to_string(),
        profile: "waf:strict".to_string(),
        rule_id: Some(rule),
        category: Some("sql_injection".to_string()),
        severity: Some("critical".to_string()),
        score: 5,
        verdict,
        client_ip: Some("203.0.113.7".to_string()),
        method: Some("GET".to_string()),
        uri: Some("/".to_string()),
        created_at: at,
    }
}

/// The findings route filters, pages by time, and treats a bad parameter as no parameter.
///
/// The last part is the behaviour worth pinning. These are filters, so an unparsable `since`
/// is ignored rather than refused — answering a malformed bookmark with a 400 would break it
/// the moment a parameter's shape changed. An *empty* one is ignored too, because a UI that
/// clears a text input sends `?domain=` and treating that as a domain named "" would return
/// nothing and look like the data had gone.
#[tokio::test]
async fn the_findings_route_filters_and_pages_by_time() {
    let api = api().await;
    api.store
        .record_waf_events(&[
            finding("api.test", Verdict::Block, 3_000, 942100),
            finding("www.test", Verdict::Detect, 2_000, 941110),
            finding("api.test", Verdict::Detect, 1_000, 942100),
        ])
        .await
        .expect("the findings write");

    async fn domains(api: &Api, query: &str) -> Vec<String> {
        let response =
            send_query(api, Method::GET, "/logs/waf-events", query).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{query} answered {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        );
        let rows: Vec<serde_json::Value> =
            serde_json::from_slice(&response.body).expect("json");
        rows.iter()
            .map(|row| row["domain"].as_str().expect("a domain").to_string())
            .collect()
    }

    // Newest first, and unfiltered means everything.
    assert_eq!(
        domains(&api, "").await,
        vec!["api.test", "www.test", "api.test"]
    );
    assert_eq!(
        domains(&api, "domain=api.test").await,
        vec!["api.test", "api.test"]
    );
    assert_eq!(domains(&api, "blocked=true").await, vec!["api.test"]);
    assert_eq!(domains(&api, "rule_id=941110").await, vec!["www.test"]);

    // Paging is a time bound, not an offset: the second page starts below the oldest row of
    // the first.
    assert_eq!(
        domains(&api, "until=2500").await,
        vec!["www.test", "api.test"]
    );
    assert_eq!(
        domains(&api, "since=1500&until=2500").await,
        vec!["www.test"]
    );
    assert_eq!(domains(&api, "limit=1").await, vec!["api.test"]);

    // Ignored rather than refused, and empty rather than absent means the same thing.
    assert_eq!(
        domains(&api, "since=not-a-number").await.len(),
        3,
        "an unparsable filter was refused or treated as a value"
    );
    assert_eq!(
        domains(&api, "domain=").await.len(),
        3,
        "an emptied filter input matched nothing"
    );
    assert_eq!(
        domains(&api, "blocked=perhaps").await.len(),
        3,
        "an unrecognised flag silently meant `false`"
    );
}

fn metric(name: &str, value: f64, at: i64) -> NewPerformanceMetric {
    NewPerformanceMetric {
        node: "node-a".to_string(),
        metric: name.to_string(),
        value,
        bucket_start: at,
        bucket_secs: 60,
    }
}

#[tokio::test]
async fn performance_reads_stored_rollups_in_time_order() {
    let mut api = api().await;
    api.admin.role = Role::Viewer;
    api.admin.auth_level = AuthLevel::PasswordOnly;
    api.store
        .record_performance_metrics(&[
            metric("waf.findings", 8.0, 180),
            metric("waf.blocks", 2.0, 120),
            metric("waf.findings", 4.0, 60),
        ])
        .await
        .expect("rollups write");
    for (query, expected) in [
        ("", vec![60, 120, 180]),
        ("metric=waf.findings", vec![60, 180]),
        ("since=120&until=180", vec![120, 180]),
        ("limit=1", vec![60]),
        ("metric=", vec![60, 120, 180]),
        ("metric=%27%20OR%201%3D1%20--", vec![]),
    ] {
        let response =
            send_query(&api, Method::GET, "/performance", query).await;
        assert_eq!(response.status, StatusCode::OK, "{query}: {response:?}");
        let rows: Vec<serde_json::Value> =
            serde_json::from_slice(&response.body).expect("json");
        assert_eq!(
            rows.iter()
                .map(|row| row["bucket_start"].as_i64().expect("timestamp"))
                .collect::<Vec<_>>(),
            expected,
            "{query}"
        );
        for row in &rows {
            assert_eq!(row["node"], "node-a");
            assert_eq!(row["bucket_secs"], 60);
        }
        if query == "metric=waf.findings" {
            assert_eq!(rows[0]["value"], 4.0);
            assert_eq!(rows[1]["value"], 8.0);
        }
    }
}

#[tokio::test]
async fn metric_reads_reject_invalid_or_unbounded_windows() {
    let api = api().await;
    for path in ["/performance", "/dashboard"] {
        for query in [
            "since=x",
            "until=x",
            "since=20&until=10",
            "limit=0",
            "limit=1001",
            "limit=-1",
        ] {
            let response = send_query(&api, Method::GET, path, query).await;
            assert_eq!(
                response.status,
                StatusCode::BAD_REQUEST,
                "{path}?{query}: {response:?}"
            );
        }
    }
}

#[tokio::test]
async fn dashboard_reads_rollups_not_raw_findings_and_never_guesses_drift() {
    let api = api().await;
    api.store
        .record_waf_events(&[finding("site.test", Verdict::Block, 120, 942100)])
        .await
        .expect("finding writes");
    let response = send_query(&api, Method::GET, "/dashboard", "").await;
    assert_eq!(response.status, StatusCode::OK, "{response:?}");
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("json");
    assert_eq!(body["metrics"], serde_json::json!([]));
    assert_eq!(body["drift"]["status"], "unavailable");

    api.store
        .record_performance_metrics(&[metric("waf.blocks", 7.0, 120)])
        .await
        .expect("rollup writes");
    let response =
        send_query(&api, Method::GET, "/dashboard", "since=120&until=120")
            .await;
    assert_eq!(response.status, StatusCode::OK, "{response:?}");
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("json");
    assert_eq!(body["metrics"].as_array().expect("metrics").len(), 1);
    assert_eq!(body["metrics"][0]["value"], 7.0);
    assert!(
        api.store
            .read_activity(TimeRange::default())
            .await
            .expect("audit")
            .is_empty()
    );
}

#[tokio::test]
async fn detection_publishes_the_provider_and_names_the_missing_one() {
    // The API this crate serves never builds a provider of its own — the
    // binary injects it — so the provider here is a stand-in asserting the
    // route is a passthrough, not a second aggregation of anything.
    let provided = serde_json::json!({
        "challenge": {"site.test": {"issued": 1, "verified": 1, "expired": 0}},
    });
    let mut wired = api().await;
    wired.state = wired
        .state
        .with_detection_metrics(Arc::new(move || provided.clone()));
    let response =
        send_query(&wired, Method::GET, "/metrics/detection", "").await;
    assert_eq!(response.status, StatusCode::OK, "{response:?}");
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("json");
    assert_eq!(body["challenge"]["site.test"]["issued"], 1);

    // The same route on the same store with no provider wired in.
    let api = api().await;
    let response =
        send_query(&api, Method::GET, "/metrics/detection", "").await;
    assert_eq!(
        response.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{response:?}"
    );
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("json");
    let reason = body["error"].as_str().expect("reason").to_string();
    assert!(reason.contains("detection metrics provider"), "{reason}");
}

struct ConfigFile(std::path::PathBuf);

#[async_trait::async_trait]
impl pingap_controlplane::projection::ConfigSource for ConfigFile {
    async fn current(&self) -> Result<pingap_config::PingapConfig, String> {
        let contents = std::fs::read(&self.0).map_err(|e| e.to_string())?;
        pingap_config::PingapConfig::new(&contents, true)
            .map_err(|e| e.to_string())
    }
}

#[tokio::test]
async fn dashboard_checks_stored_config_without_exposing_or_correcting_it() {
    let mut api = api().await;
    let path = api._dir.path().join("gateway.toml");
    api.state = api
        .state
        .with_config_source(Arc::new(ConfigFile(path.clone())));

    let response = send(&api, Method::GET, "/dashboard", "").await;
    assert_eq!(response.status, StatusCode::OK, "{response:?}");
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("json");
    assert_eq!(body["drift"]["status"], "no_baseline");

    assert_eq!(
        send(&api, Method::PUT, "/upstreams/app", UPSTREAM)
            .await
            .status,
        StatusCode::OK
    );
    let applied = api
        .store
        .latest_applied_config_version()
        .await
        .expect("read")
        .expect("version");
    api.admin.role = Role::Viewer;
    api.admin.auth_level = AuthLevel::PasswordOnly;
    let response = send(&api, Method::GET, "/dashboard", "").await;
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("json");
    assert_eq!(body["drift"]["status"], "in_sync");
    assert_eq!(body["drift"]["version_id"], applied.id);

    let original = std::fs::read_to_string(&path).expect("committed config");
    let edited = format!(
        "{original}\n[plugins.manual]\ncategory = 'basic_auth'\nauthorization = 'DO-NOT-EXPOSE'\n"
    );
    std::fs::write(&path, &edited).expect("out-of-band edit");
    let response = send(&api, Method::GET, "/dashboard", "").await;
    assert_eq!(response.status, StatusCode::OK, "{response:?}");
    assert!(!String::from_utf8_lossy(&response.body).contains("DO-NOT-EXPOSE"));
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("json");
    assert_eq!(body["drift"]["status"], "detected");
    assert_eq!(body["drift"]["version_id"], applied.id);
    assert_eq!(body["drift"]["expected_hash"], applied.hash);
    assert_ne!(body["drift"]["actual_hash"], applied.hash);
    assert_eq!(body["drift"]["differing"], serde_json::json!(["plugins"]));
    assert_eq!(std::fs::read_to_string(&path).expect("read back"), edited);

    // Parse diagnostics can include the line carrying a secret. Never return them to viewers.
    std::fs::write(&path, "[plugins.manual]\nsecret = DO-NOT-EXPOSE")
        .expect("bad edit");
    let response = send(&api, Method::GET, "/dashboard", "").await;
    assert_eq!(response.status, StatusCode::OK, "{response:?}");
    assert!(!String::from_utf8_lossy(&response.body).contains("DO-NOT-EXPOSE"));
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("json");
    assert_eq!(body["drift"]["status"], "unavailable");
    assert_eq!(
        api.store
            .list_config_versions(None)
            .await
            .expect("versions")
            .len(),
        1
    );
    assert_eq!(
        api.store
            .read_activity(TimeRange::default())
            .await
            .expect("audit")
            .len(),
        1
    );
}

/// `GET /nodes` without a shared backend reports `Unavailable`, not an empty cluster.
///
/// The fixture wires no `ClusterInventory`, which is the shape a single-node deployment
/// takes — and the honest answer is "there is no inventory to read", not "zero peers",
/// which would read as either a healthy cluster or a reaping bug.
#[tokio::test]
async fn nodes_with_no_shared_backend_is_unavailable_not_empty() {
    let api = api().await;
    let response = send(&api, Method::GET, "/nodes", "").await;
    assert_eq!(
        response.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{response:?}"
    );
}

/// `GET /backup` returns the empty registry when nothing is scheduled and nothing exported.
#[tokio::test]
async fn backup_lists_schedules_and_files_empty() {
    let api = api().await;
    let response = send(&api, Method::GET, "/backup", "").await;
    assert_eq!(response.status, StatusCode::OK, "{response:?}");
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("json");
    assert_eq!(body["schedules"], serde_json::json!([]));
    assert_eq!(body["files"], serde_json::json!([]));
}

/// A schedule is created, listed, and removed — and the audit trail names each write.
#[tokio::test]
async fn a_backup_schedule_round_trips_and_is_audited() {
    let api = api().await;

    let response = send(
        &api,
        Method::POST,
        "/backup/schedules",
        r#"{"name":"nightly","cron":"0 3 * * *","retain":7,"enabled":true}"#,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{response:?}");
    let created: serde_json::Value =
        serde_json::from_slice(&response.body).expect("json");
    let id = created["id"].as_str().expect("an id");
    assert_eq!(created["name"], "nightly");

    // A duplicate name is a conflict — the schedule is keyed by name so an operator can
    // address it.
    let response = send(
        &api,
        Method::POST,
        "/backup/schedules",
        r#"{"name":"nightly","cron":"0 4 * * *","retain":7,"enabled":true}"#,
    )
    .await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{response:?}");

    let body: serde_json::Value = serde_json::from_slice(
        &send(&api, Method::GET, "/backup", "").await.body,
    )
    .expect("json");
    assert_eq!(body["schedules"].as_array().expect("a list").len(), 1);

    let response =
        send(&api, Method::DELETE, &format!("/backup/schedules/{id}"), "")
            .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT, "{response:?}");

    // Deleting it again is a 404, not a quiet second success.
    let response =
        send(&api, Method::DELETE, &format!("/backup/schedules/{id}"), "")
            .await;
    assert_eq!(response.status, StatusCode::NOT_FOUND, "{response:?}");

    let actions: Vec<String> = api
        .store
        .read_activity(TimeRange::default())
        .await
        .expect("audit")
        .into_iter()
        .map(|row| row.action)
        .collect();
    assert!(actions.iter().any(|a| a == "backup.schedule.create"));
    assert!(actions.iter().any(|a| a == "backup.schedule.delete"));
}

/// Export and restore refuse cleanly when the deployment set no backup directory.
///
/// The fixture builds `AppState` without `backup_dir`, which is the shape an operator
/// gets when `backup_dir` is unset — and the answer names the setting rather than writing
/// to a path nobody agreed to.
#[tokio::test]
async fn backup_export_and_restore_are_unavailable_without_a_backup_dir() {
    let api = api().await;

    let response = send(&api, Method::POST, "/backup/export", "").await;
    assert_eq!(
        response.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{response:?}"
    );

    let response = send(
        &api,
        Method::POST,
        "/backup/restore",
        r#"{"path":"/tmp/whatever"}"#,
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{response:?}"
    );
}
