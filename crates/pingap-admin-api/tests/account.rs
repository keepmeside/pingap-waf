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

//! The caller's own account, where the handler and not the role gate decides ownership.
//!
//! Revocation is the interesting case. `Capability::RevokeOwnSession` is held by every role,
//! so the router lets a viewer through and the only thing standing between that and revoking
//! an administrator's session is the handler's own lookup. These tests drive two users
//! against one store, which is the shape that distinguishes those two outcomes — a fixture
//! with one user cannot tell an ownership check from an absent one.

use bytes::Bytes;
use http::{Method, StatusCode};
use pingap_admin_api::{ApiRequest, AppState, Caller, dispatch};
use pingap_controlplane::projection::{
    Applier, ConfigSink, DataPlane, NoPluginCheck, Validator,
};
use pingap_controlplane::repository::TimeRange;
use pingap_controlplane::{
    AuthLevel, ControlPlaneStore, NewSession, NewUser, Role, TursoStore,
};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

/// Neither is consulted: nothing here writes config. They exist because `AppState` holds an
/// `Applier` and an `Applier` is built from them.
struct Unused;

#[async_trait::async_trait]
impl ConfigSink for Unused {
    async fn commit(&self, _canonical_toml: &str) -> Result<(), String> {
        unreachable!("no route under test writes config")
    }
}

impl DataPlane for Unused {
    fn running_config_key(&self, _name: &str) -> Option<String> {
        None
    }
}

struct Api {
    state: AppState,
    store: Arc<dyn ControlPlaneStore>,
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
    let shared = Arc::new(Unused);
    let applier = Applier::new(
        store.clone(),
        Validator::new("/bin/true"),
        Arc::new(NoPluginCheck),
        shared.clone(),
        shared,
        Duration::from_millis(0),
    );
    Api {
        state: AppState::new(store.clone(), Arc::new(applier)),
        store,
        _dir: dir,
    }
}

/// "Now", captured once.
///
/// A pinned constant would be simpler and would be wrong: the handler compares a session's
/// expiry against the real clock, so a fixture timestamp in the past makes every session
/// already expired and every revocation a 404 that looks like a broken ownership check.
static NOW: LazyLock<i64> = LazyLock::new(|| {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_secs() as i64
});

/// A user, and one usable session for them.
///
/// `token_hash` is the session's primary key and must differ per session: the store holds
/// the hash and nothing else, so two sessions with one hash are one row.
async fn user_with_session(
    api: &Api,
    username: &str,
    role: Role,
    token_hash: &str,
) -> (Caller, String) {
    let user = api
        .store
        .create_user(
            NewUser {
                username: username.to_string(),
                email: format!("{username}@example.test"),
                password_hash: "$argon2id$v=19$m=19456,t=2,p=1$salt$hash"
                    .to_string(),
                role,
            },
            *NOW,
        )
        .await
        .expect("the user is created");
    let session = api
        .store
        .create_session(NewSession {
            user_id: &user.id,
            token_hash,
            auth_level: AuthLevel::TwoFactor,
            ip: Some("203.0.113.7"),
            user_agent: Some("test"),
            now: *NOW,
            expires_at: *NOW + 3600,
        })
        .await
        .expect("the session is created");
    let caller = Caller {
        session_id: session.id.clone(),
        user_id: user.id,
        username: user.username,
        role,
        auth_level: AuthLevel::TwoFactor,
    };
    (caller, session.id)
}

async fn send(
    api: &Api,
    caller: &Caller,
    method: Method,
    path: &str,
) -> pingap_admin_api::ApiResponse {
    dispatch(
        &api.state,
        &ApiRequest {
            method,
            path: path.to_string(),
            query: String::new(),
            body: Bytes::new(),
            caller: Some(caller.clone()),
        },
    )
    .await
}

/// The listing a revocation is decided from, as the caller sees it.
async fn own_sessions(api: &Api, caller: &Caller) -> serde_json::Value {
    let response = send(api, caller, Method::GET, "/account/sessions").await;
    assert_eq!(response.status, StatusCode::OK);
    serde_json::from_slice(&response.body).expect("json")
}

#[tokio::test]
async fn a_user_revokes_their_own_session_and_it_stops_being_usable() {
    let api = api().await;
    let (caller, own) =
        user_with_session(&api, "admin", Role::Admin, "token-admin").await;
    // A second session for the same user, so the revocation can be shown to have picked one
    // out of several rather than cleared the lot.
    let other = api
        .store
        .create_session(NewSession {
            user_id: &caller.user_id,
            token_hash: "hash-2",
            auth_level: AuthLevel::TwoFactor,
            ip: Some("203.0.113.9"),
            user_agent: Some("test"),
            now: *NOW,
            expires_at: *NOW + 3600,
        })
        .await
        .expect("the second session is created");

    let response = send(
        &api,
        &caller,
        Method::DELETE,
        &format!("/account/sessions/{own}"),
    )
    .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);

    let sessions = api
        .store
        .list_sessions(&caller.user_id)
        .await
        .expect("listable");
    let revoked = sessions.iter().find(|s| s.id == own).expect("still listed");
    // `>=` and not `==`: the handler stamps the revocation with the clock at request time,
    // so pinning the fixture's second makes this fail whenever the two differ. What matters
    // is that it was revoked, and that the stamp is not from before the session existed.
    assert!(
        revoked.revoked_at.is_some_and(|at| at >= *NOW),
        "the session was not revoked: {revoked:?}"
    );
    assert!(
        sessions
            .iter()
            .any(|s| s.id == other.id && s.is_usable(*NOW)),
        "an unrelated session was cut off too"
    );

    // And the listing the UI reads agrees, which is what makes the revoked device
    // recognisable as revoked rather than merely absent.
    let view = own_sessions(&api, &caller).await;
    let entry = view
        .as_array()
        .expect("an array")
        .iter()
        .find(|s| s["id"] == own)
        .expect("the revoked session is still listed");
    assert_eq!(entry["usable"], false);
    assert_eq!(entry["current"], true);

    let log = api
        .store
        .read_activity(TimeRange::default())
        .await
        .expect("readable");
    assert_eq!(log.len(), 1, "one mutation, one row: {log:?}");
    assert_eq!(log[0].action, "session.revoke");
    assert_eq!(log[0].target, own);
    assert_eq!(log[0].actor_username, "admin");
}

/// The ownership check, which is the whole reason this route is worth a test of its own.
///
/// A viewer holds `RevokeOwnSession`, so the router lets them through; if the handler passed
/// the path straight to `revoke_session`, any user could cut off any session — a denial of
/// service against an administrator from the lowest-privileged role in the system.
#[tokio::test]
async fn revoking_someone_elses_session_is_404_and_leaves_it_usable() {
    let api = api().await;
    let (viewer, _) =
        user_with_session(&api, "watcher", Role::Viewer, "token-watcher").await;
    let (_, admin_session) =
        user_with_session(&api, "root", Role::Admin, "token-root").await;

    let response = send(
        &api,
        &viewer,
        Method::DELETE,
        &format!("/account/sessions/{admin_session}"),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::NOT_FOUND,
        "a viewer revoked another user's session"
    );

    let admins = api
        .store
        .find_user_by_username("root")
        .await
        .expect("readable")
        .expect("the admin exists");
    let sessions = api.store.list_sessions(&admins.id).await.expect("listable");
    assert!(
        sessions.iter().all(|s| s.is_usable(*NOW)),
        "another user's session was touched: {sessions:?}"
    );

    assert!(
        api.store
            .read_activity(TimeRange::default())
            .await
            .expect("readable")
            .is_empty(),
        "a refused revocation wrote an audit row"
    );
}

/// An id that is not a revocable session of the caller's is 404, and a repeat request writes
/// nothing.
///
/// One status for unknown, expired and already-revoked, because they are the same fact from
/// where the caller stands and distinguishing them would confirm which ids exist. The second
/// half is the audit invariant: a row claiming a revocation this call did not perform.
#[tokio::test]
async fn revoking_twice_or_nothing_is_404_and_writes_one_row_at_most() {
    let api = api().await;
    let (caller, own) =
        user_with_session(&api, "admin", Role::Admin, "token-admin").await;

    let missing = send(
        &api,
        &caller,
        Method::DELETE,
        "/account/sessions/not-a-session",
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);

    assert_eq!(
        send(
            &api,
            &caller,
            Method::DELETE,
            &format!("/account/sessions/{own}")
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    let again = send(
        &api,
        &caller,
        Method::DELETE,
        &format!("/account/sessions/{own}"),
    )
    .await;
    assert_eq!(
        again.status,
        StatusCode::NOT_FOUND,
        "a session already revoked was revoked again"
    );

    let log = api
        .store
        .read_activity(TimeRange::default())
        .await
        .expect("readable");
    assert_eq!(
        log.len(),
        1,
        "the second request wrote a row for a revocation it did not perform: {log:?}"
    );
}
