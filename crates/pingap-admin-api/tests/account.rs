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
    AuthLevel, Capability, ControlPlaneStore, NewSession, NewUser, Role,
    TotpGuard, TursoStore, authorize,
};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

/// A throwaway AES key in the shape `pingap-util` expects.
///
/// Real rather than absent: second-factor enrolment seals the secret with it, and a fixture
/// that passed `None` would make every enrolment test a test of the missing-key refusal.
const TOTP_KEY: &str = "PLpKJqvfkjTcYTDpauJf+2JnEayP+bm+0Oe60Jk=";

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
    /// The same guard the routes spend codes against, held so a test can play the part of the
    /// login path — which is in the binary, not in this crate, and shares the guard by `Arc`.
    totp: Arc<TotpGuard>,
    _dir: tempfile::TempDir,
}

async fn api() -> Api {
    api_with_totp_key(Some(TOTP_KEY.to_string())).await
}

/// The same store and routes, with the deployment's second-factor key absent.
///
/// A separate constructor rather than a flag on `api()`: only one test wants it, and a
/// parameter every other caller has to pass `Some(..)` to is a parameter that hides what the
/// fixture is really doing.
async fn api_with_totp_key(totp_key: Option<String>) -> Api {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = TursoStore::open(
        dir.path().join("cp.db").to_str().expect("utf-8 path"),
    )
    .await
    .expect("the store opens");
    store.migrate().await.expect("migrations apply");
    let store: Arc<dyn ControlPlaneStore> = Arc::new(store);
    let totp = Arc::new(TotpGuard::default());
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
        state: AppState::new(
            store.clone(),
            Arc::new(applier),
            totp.clone(),
            totp_key,
        ),
        store,
        totp,
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

/// A request with a JSON body, for the routes that take one.
async fn send_json(
    api: &Api,
    caller: &Caller,
    method: Method,
    path: &str,
    body: &str,
) -> pingap_admin_api::ApiResponse {
    dispatch(
        &api.state,
        &ApiRequest {
            method,
            path: path.to_string(),
            query: String::new(),
            body: Bytes::copy_from_slice(body.as_bytes()),
            caller: Some(caller.clone()),
        },
    )
    .await
}

/// A timestamp in the middle of the current TOTP step.
///
/// Mid-step rather than "now", so a handler whose clock has ticked on by the time the request
/// arrives still accepts the code. The verifier's skew window is one step either side, and a
/// code minted at the very start of a step is outside it once a slow test crosses the boundary
/// — which is a flake that looks like a broken second factor.
fn step_now() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_secs();
    (now / 30) * 30 + 15
}

/// The code a device holding `secret` would show.
fn code_for(secret: &str, username: &str, at: u64) -> String {
    pingap_controlplane::auth::totp_code_for(secret, username, at)
        .expect("the secret is the one setup just returned")
}

async fn second_factor(api: &Api, caller: &Caller) -> serde_json::Value {
    let response = send(api, caller, Method::GET, "/account/2fa").await;
    assert_eq!(response.status, StatusCode::OK);
    serde_json::from_slice(&response.body).expect("json")
}

/// Enrol, confirm, and see the account become one a login challenges.
///
/// The status route is read at each step because `enrolled` and `enabled` being separate is
/// the point of it: a half-finished enrolment must not read as a protected account. And the
/// secret is asserted absent from every response but the one that hands it over, because a
/// status route that echoed it would be a second place to leak a credential that is stored
/// sealed precisely so it cannot be read back.
#[tokio::test]
async fn a_second_factor_is_enrolled_and_then_confirmed_by_a_code() {
    let api = api().await;
    let (caller, _) =
        user_with_session(&api, "admin", Role::Admin, "token-admin").await;

    let before = second_factor(&api, &caller).await;
    assert_eq!(before["enrolled"], false, "{before}");
    assert_eq!(before["enabled"], false, "{before}");

    let setup = send(&api, &caller, Method::POST, "/account/2fa/setup").await;
    assert_eq!(
        setup.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&setup.body)
    );
    let body: serde_json::Value =
        serde_json::from_slice(&setup.body).expect("json");
    let secret = body["secret"].as_str().expect("a secret").to_string();
    assert!(!secret.is_empty());
    assert!(
        body["otpauth_uri"]
            .as_str()
            .is_some_and(|uri| uri.starts_with("otpauth://")),
        "an app cannot scan this: {body}"
    );

    let pending = second_factor(&api, &caller).await;
    assert_eq!(pending["enrolled"], true, "{pending}");
    assert_eq!(
        pending["enabled"], false,
        "an unconfirmed enrolment reads as a protected account: {pending}"
    );
    assert!(
        !pending.to_string().contains(&secret),
        "the status route carried the secret: {pending}"
    );

    let confirmed = send_json(
        &api,
        &caller,
        Method::POST,
        "/account/2fa/enable",
        &format!(
            r#"{{"code":"{}"}}"#,
            code_for(&secret, &caller.username, step_now())
        ),
    )
    .await;
    assert_eq!(
        confirmed.status,
        StatusCode::NO_CONTENT,
        "{}",
        String::from_utf8_lossy(&confirmed.body)
    );

    let enabled = second_factor(&api, &caller).await;
    assert_eq!(enabled["enabled"], true, "{enabled}");

    // The store holds the ciphertext, and only that.
    let (stored, is_enabled) = api
        .store
        .totp_secret_for(&caller.user_id)
        .await
        .expect("readable")
        .expect("a secret is stored");
    assert!(is_enabled);
    assert_ne!(stored, secret, "the secret is stored unsealed");
    assert!(
        !stored.contains(&secret),
        "the stored value carries the secret in the clear"
    );

    let log = api
        .store
        .read_activity(TimeRange::default())
        .await
        .expect("readable");
    let actions: Vec<&str> =
        log.iter().map(|row| row.action.as_str()).collect();
    assert!(actions.contains(&"account.2fa.setup"), "{actions:?}");
    assert!(actions.contains(&"account.2fa.enable"), "{actions:?}");
}

/// Enrolling over a live second factor is refused.
///
/// `setup` replaces the stored secret, so allowing it would let anyone holding a session
/// disarm the second factor without producing a code — which is the whole thing
/// `second_factor_disable` requires one for. The refusal has to name the way out, or an
/// operator reads it as a broken endpoint.
#[tokio::test]
async fn enrolling_over_an_enabled_second_factor_is_refused() {
    let api = api().await;
    let (caller, _) =
        user_with_session(&api, "admin", Role::Admin, "token-admin").await;

    let setup = send(&api, &caller, Method::POST, "/account/2fa/setup").await;
    let secret = serde_json::from_slice::<serde_json::Value>(&setup.body)
        .expect("json")["secret"]
        .as_str()
        .expect("a secret")
        .to_string();
    assert_eq!(
        send_json(
            &api,
            &caller,
            Method::POST,
            "/account/2fa/enable",
            &format!(
                r#"{{"code":"{}"}}"#,
                code_for(&secret, &caller.username, step_now())
            ),
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );

    let again = send(&api, &caller, Method::POST, "/account/2fa/setup").await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    let body = String::from_utf8_lossy(&again.body).to_string();
    assert!(
        body.contains("disable it first"),
        "the refusal did not say how to proceed: {body}"
    );
    // And the live secret survived, so the refusal was not a disable by another name.
    assert_eq!(second_factor(&api, &caller).await["enabled"], true);
}

/// A wrong code and a spent one are the same answer, and neither changes anything.
///
/// Distinguishing them would make the endpoint an oracle: an attacker who has collected codes
/// learns which were genuine. Asserted on both routes that take one, because they share the
/// check and a future edit to either could separate them.
#[tokio::test]
async fn a_wrong_or_replayed_code_neither_confirms_nor_removes() {
    let api = api().await;
    let (caller, _) =
        user_with_session(&api, "admin", Role::Admin, "token-admin").await;

    let setup = send(&api, &caller, Method::POST, "/account/2fa/setup").await;
    let secret = serde_json::from_slice::<serde_json::Value>(&setup.body)
        .expect("json")["secret"]
        .as_str()
        .expect("a secret")
        .to_string();

    let wrong = send_json(
        &api,
        &caller,
        Method::POST,
        "/account/2fa/enable",
        r#"{"code":"000000"}"#,
    )
    .await;
    // `000000` is a possible code, so a wrong answer is not guaranteed by the digits — assert
    // on the outcome rather than assuming the value cannot collide.
    if wrong.status == StatusCode::NO_CONTENT {
        panic!("every code was accepted; the second factor verifies nothing");
    }
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(second_factor(&api, &caller).await["enabled"], false);

    let at = step_now();
    let good = code_for(&secret, &caller.username, at);
    assert_eq!(
        send_json(
            &api,
            &caller,
            Method::POST,
            "/account/2fa/enable",
            &format!(r#"{{"code":"{good}"}}"#)
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    // Same step, same code, already spent.
    let replayed = send_json(
        &api,
        &caller,
        Method::POST,
        "/account/2fa/disable",
        &format!(r#"{{"code":"{good}"}}"#),
    )
    .await;
    assert_eq!(
        replayed.status,
        StatusCode::UNAUTHORIZED,
        "a spent code was accepted again"
    );
    assert_eq!(
        second_factor(&api, &caller).await["enabled"],
        true,
        "the replayed code removed the second factor"
    );

    // A fresh code from the next step does remove it, which is what makes the assertion above
    // about the replay and not about `disable` being broken.
    assert_eq!(
        send_json(
            &api,
            &caller,
            Method::POST,
            "/account/2fa/disable",
            &format!(
                r#"{{"code":"{}"}}"#,
                code_for(&secret, &caller.username, at + 30)
            ),
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    let after = second_factor(&api, &caller).await;
    assert_eq!(
        after["enrolled"], false,
        "disabled left a secret behind: {after}"
    );
    assert_eq!(after["enabled"], false, "{after}");

    let log = api
        .store
        .read_activity(TimeRange::default())
        .await
        .expect("readable");
    let actions: Vec<&str> =
        log.iter().map(|row| row.action.as_str()).collect();
    assert_eq!(
        actions
            .iter()
            .filter(|a| **a == "account.2fa.disable")
            .count(),
        1,
        "a refused removal wrote a row saying it removed something: {actions:?}"
    );
}

/// An administrator clears a second factor no code can be produced for.
///
/// The lockout escape, and the reason `disable` can demand a code. Without this the choice is
/// between a permanent lockout for someone who lost their device and a self-service disable a
/// stolen session could also use. Asserted across two roles, because the point is that the
/// account owner cannot reach it and an administrator can.
#[tokio::test]
async fn an_admin_clears_a_second_factor_the_owner_cannot_produce_a_code_for() {
    let api = api().await;
    let (admin, _) =
        user_with_session(&api, "root", Role::Admin, "token-root").await;
    let (locked, _) =
        user_with_session(&api, "watcher", Role::Viewer, "token-watcher").await;
    let locked_id = locked.user_id.clone();

    let setup = send(&api, &locked, Method::POST, "/account/2fa/setup").await;
    let secret = serde_json::from_slice::<serde_json::Value>(&setup.body)
        .expect("json")["secret"]
        .as_str()
        .expect("a secret")
        .to_string();
    assert_eq!(
        send_json(
            &api,
            &locked,
            Method::POST,
            "/account/2fa/enable",
            &format!(
                r#"{{"code":"{}"}}"#,
                code_for(&secret, &locked.username, step_now())
            ),
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );

    // The owner cannot clear it without the device. `disable` needs a code, and the code this
    // test could mint is the one the device would have — a real lockout has neither.
    let reset_by_owner = send_json(
        &api,
        &locked,
        Method::POST,
        &format!("/users/{locked_id}/2fa/reset"),
        "",
    )
    .await;
    assert_eq!(
        reset_by_owner.status,
        StatusCode::FORBIDDEN,
        "an account reached the administrative reset"
    );
    assert_eq!(second_factor(&api, &locked).await["enabled"], true);

    let reset = send_json(
        &api,
        &admin,
        Method::POST,
        &format!("/users/{locked_id}/2fa/reset"),
        "",
    )
    .await;
    assert_eq!(
        reset.status,
        StatusCode::NO_CONTENT,
        "{}",
        String::from_utf8_lossy(&reset.body)
    );

    let after = second_factor(&api, &locked).await;
    assert_eq!(after["enrolled"], false, "the reset left a secret: {after}");
    assert_eq!(after["enabled"], false, "{after}");
    assert_eq!(
        api.store
            .totp_secret_for(&locked_id)
            .await
            .expect("readable")
            .map(|(secret, _)| secret)
            .unwrap_or_default(),
        "",
        "the reset disabled the secret rather than clearing it"
    );

    let log = api
        .store
        .read_activity(TimeRange::default())
        .await
        .expect("readable");
    let reset_row = log
        .iter()
        .find(|row| row.action == "user.2fa.reset")
        .expect("the reset was audited");
    assert_eq!(reset_row.target, locked_id);
    assert_eq!(
        reset_row.actor_username, "root",
        "the row named the wrong actor"
    );
}

/// Enrolment with no encryption key configured names the missing setting.
///
/// `409` and not `500`: this is a deployment an operator can fix, and a crash-shaped answer
/// hides that. Sealing with a default key is not the alternative, because a literal default is
/// indistinguishable from no encryption once the row is written.
#[tokio::test]
async fn enrolment_without_an_encryption_key_names_the_missing_setting() {
    let api = api_with_totp_key(None).await;
    let (caller, _) =
        user_with_session(&api, "admin", Role::Admin, "token-admin").await;

    let setup = send(&api, &caller, Method::POST, "/account/2fa/setup").await;
    assert_eq!(setup.status, StatusCode::CONFLICT);
    let body = String::from_utf8_lossy(&setup.body).to_string();
    assert!(
        body.contains("encryption key"),
        "the refusal did not say what is missing: {body}"
    );
    assert!(
        api.store
            .totp_secret_for(&caller.user_id)
            .await
            .expect("readable")
            .is_none(),
        "a refused enrolment stored something"
    );
    assert!(
        api.store
            .read_activity(TimeRange::default())
            .await
            .expect("readable")
            .iter()
            .all(|row| row.action != "account.2fa.setup"),
        "a refused enrolment wrote an audit row"
    );
}

/// A code already spent by the login path cannot remove the second factor.
///
/// `complete_totp` in the binary calls `verify_once(&principal.user_id, ..)`, and the guard
/// keys its spent-code set by `(identifier, step)`. If this crate passed the username instead,
/// the two paths would keep separate windows and one code would be good for both inside the
/// same step — a captured login code would disarm the second factor. The guard is shared by
/// `Arc` precisely so there is one window, and this test plays the login side to prove it.
///
/// The last assertion is what stops the first two passing vacuously: the same code under a
/// *different* identifier is accepted, so the refusal above is about the identifier matching
/// and not about the guard rejecting everything it is given twice.
#[tokio::test]
async fn a_code_spent_by_the_login_path_cannot_remove_the_second_factor() {
    let api = api().await;
    let (caller, _) =
        user_with_session(&api, "admin", Role::Admin, "token-admin").await;

    let setup = send(&api, &caller, Method::POST, "/account/2fa/setup").await;
    let secret = serde_json::from_slice::<serde_json::Value>(&setup.body)
        .expect("json")["secret"]
        .as_str()
        .expect("a secret")
        .to_string();
    let confirmed_at = step_now();
    assert_eq!(
        send_json(
            &api,
            &caller,
            Method::POST,
            "/account/2fa/enable",
            &format!(
                r#"{{"code":"{}"}}"#,
                code_for(&secret, &caller.username, confirmed_at)
            ),
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );

    // A later step, so this code is not the one `enable` already spent.
    let at = confirmed_at + 30;
    let code = code_for(&secret, &caller.username, at);

    // The login path, reproduced: spend the code under the user id.
    assert!(
        api.totp
            .verify_once(&caller.user_id, &secret, &code, at)
            .expect("the secret is the one setup returned"),
        "the code the login path was given did not verify"
    );

    let response = send_json(
        &api,
        &caller,
        Method::POST,
        "/account/2fa/disable",
        &format!(r#"{{"code":"{code}"}}"#),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "a code already spent at login removed the second factor"
    );
    assert_eq!(second_factor(&api, &caller).await["enabled"], true);

    assert!(
        api.totp
            .verify_once(&caller.username, &secret, &code, at)
            .expect("checks"),
        "the guard is not keying by identifier, so the refusal above proved nothing"
    );
}

/// A user whose stored credential is a real hash, and two usable sessions for them.
///
/// The other fixtures store a hash-shaped string that `verify_password` refuses to parse,
/// which is the right thing for a route that never checks a password and the wrong thing for
/// one that does: a password test over an unparsable hash would be testing the corrupt-hash
/// path and passing for the wrong reason.
async fn user_with_two_sessions(
    api: &Api,
    password: &str,
) -> (Caller, String, String) {
    let user = api
        .store
        .create_user(
            NewUser {
                username: "rotator".to_string(),
                email: "rotator@example.test".to_string(),
                password_hash: pingap_controlplane::hash_password(password)
                    .expect("the password hashes"),
                role: Role::Admin,
            },
            *NOW,
        )
        .await
        .expect("the user is created");
    let first = api
        .store
        .create_session(NewSession {
            user_id: &user.id,
            token_hash: "rotator-1",
            auth_level: AuthLevel::TwoFactor,
            ip: Some("203.0.113.11"),
            user_agent: Some("the device in hand"),
            now: *NOW,
            expires_at: *NOW + 3600,
        })
        .await
        .expect("the first session is created");
    let second = api
        .store
        .create_session(NewSession {
            user_id: &user.id,
            token_hash: "rotator-2",
            auth_level: AuthLevel::TwoFactor,
            ip: Some("203.0.113.12"),
            user_agent: Some("the laptop that may be stolen"),
            now: *NOW,
            expires_at: *NOW + 3600,
        })
        .await
        .expect("the second session is created");
    let caller = Caller {
        session_id: first.id.clone(),
        user_id: user.id.clone(),
        username: user.username,
        role: Role::Admin,
        auth_level: AuthLevel::TwoFactor,
    };
    (caller, first.id, second.id)
}

#[tokio::test]
async fn changing_the_password_cuts_off_every_other_session() {
    let api = api().await;
    let (caller, own, other) =
        user_with_two_sessions(&api, "old-password").await;

    let response = send_json(
        &api,
        &caller,
        Method::POST,
        "/account/password",
        r#"{"current_password":"old-password","new_password":"new-password"}"#,
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("json");
    assert_eq!(
        body["sessions_revoked"], 1,
        "the response should say how many"
    );

    let stored = api
        .store
        .password_hash_for(&caller.user_id)
        .await
        .expect("readable")
        .expect("present");
    assert!(
        pingap_controlplane::verify_password("new-password", &stored)
            .expect("a real hash verifies"),
        "the new password was not the one stored"
    );
    assert!(
        !pingap_controlplane::verify_password("old-password", &stored)
            .expect("a real hash verifies"),
        "the old password still verifies"
    );

    let now = *NOW;
    let sessions = api
        .store
        .list_sessions(&caller.user_id)
        .await
        .expect("listable");
    assert!(
        sessions.iter().any(|s| s.id == other && !s.is_usable(now)),
        "the other device was left signed in: {sessions:?}"
    );
    assert!(
        sessions.iter().any(|s| s.id == own && s.is_usable(now)),
        "the session that proved the old password was logged out too"
    );

    let log = api
        .store
        .read_activity(TimeRange::default())
        .await
        .expect("readable");
    assert_eq!(
        log.iter()
            .filter(|row| row.action == "account.password")
            .count(),
        1,
        "{log:?}"
    );
}

/// The current password is checked, and a failure changes nothing at all.
///
/// Worth asserting the *absence* of effects and not just the status: a handler that stored the
/// new hash and then checked the old one would answer 401 and still have rotated the
/// credential.
#[tokio::test]
async fn a_wrong_current_password_changes_nothing() {
    let api = api().await;
    let (caller, own, other) =
        user_with_two_sessions(&api, "old-password").await;
    let before = api
        .store
        .password_hash_for(&caller.user_id)
        .await
        .expect("readable")
        .expect("present");

    let response = send_json(
        &api,
        &caller,
        Method::POST,
        "/account/password",
        r#"{"current_password":"not-the-password","new_password":"new-password"}"#,
    )
    .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    let after = api
        .store
        .password_hash_for(&caller.user_id)
        .await
        .expect("readable")
        .expect("present");
    assert_eq!(before, after, "a refused change still wrote a hash");

    let now = *NOW;
    let sessions = api
        .store
        .list_sessions(&caller.user_id)
        .await
        .expect("listable");
    assert!(
        sessions.iter().all(|s| s.is_usable(now)),
        "a refused change revoked sessions: {sessions:?}"
    );
    assert!(
        api.store
            .read_activity(TimeRange::default())
            .await
            .expect("readable")
            .is_empty(),
        "a refused change was recorded as though it happened"
    );
    let _ = (own, other);
}

#[tokio::test]
async fn an_empty_new_password_is_refused_before_the_old_one_is_checked() {
    let api = api().await;
    let (caller, _, _) = user_with_two_sessions(&api, "old-password").await;
    let response = send_json(
        &api,
        &caller,
        Method::POST,
        "/account/password",
        r#"{"current_password":"old-password","new_password":""}"#,
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(
        String::from_utf8_lossy(&response.body).contains("empty"),
        "{}",
        String::from_utf8_lossy(&response.body)
    );
}

/// The same list, computed from the matrix rather than read out of a response.
///
/// Lives beside the test that uses it so the expectation is derived and not typed: a hardcoded
/// list of capability names would pass while the matrix changed underneath it, which is the
/// exact drift the field exists to prevent.
fn allowed(role: Role, level: AuthLevel) -> Vec<String> {
    Capability::ALL
        .into_iter()
        .filter(|capability| authorize(role, level, *capability).is_ok())
        .map(|capability| match serde_json::to_value(capability) {
            Ok(serde_json::Value::String(name)) => name,
            other => panic!("{other:?} is not a capability name"),
        })
        .collect()
}

async fn capabilities(api: &Api, caller: &Caller) -> Vec<String> {
    let response = send(api, caller, Method::GET, "/account").await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("json");
    body["capabilities"]
        .as_array()
        .expect("the profile carries a capability list")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("a capability is a string")
                .to_string()
        })
        .collect()
}

/// The profile publishes what this session may do, so no client has to hold a copy of the
/// matrix.
///
/// Three shapes, because the field's whole value is that it is derived. An admin gets every
/// capability; a viewer gets the reads and the mutations on their own account; and a session
/// that has not completed its second factor gets no mutation at all. That last one is the
/// fail-safe direction — a list that is too short hides a control, a list that is too long
/// shows one that answers 403 — and it is only reachable by asking the same `authorize` the
/// router asks, which is what the handler does.
#[tokio::test]
async fn the_profile_publishes_what_this_session_may_do() {
    let api = api().await;
    let (admin, _) =
        user_with_session(&api, "admin", Role::Admin, "token-admin").await;

    let held = capabilities(&api, &admin).await;
    assert_eq!(held, allowed(Role::Admin, AuthLevel::TwoFactor));
    assert_eq!(
        held.len(),
        Capability::ALL.len(),
        "an admin was not given every capability: {held:?}"
    );

    let (viewer, _) =
        user_with_session(&api, "watcher", Role::Viewer, "token-viewer").await;
    let held = capabilities(&api, &viewer).await;
    assert_eq!(held, allowed(Role::Viewer, AuthLevel::TwoFactor));
    for expected in ["view_config", "view_own_sessions", "change_own_password"]
    {
        assert!(
            held.contains(&expected.to_string()),
            "a viewer was not told it holds {expected}: {held:?}"
        );
    }
    for refused in ["manage_users", "edit_domain", "write_raw_config"] {
        assert!(
            !held.contains(&refused.to_string()),
            "a viewer was told it holds {refused}: {held:?}"
        );
    }

    // The same viewer one step short of a second factor: every mutation drops out and every
    // read stays, which is what tells a UI to prompt rather than to hide the page.
    let unconfirmed = Caller {
        auth_level: AuthLevel::PasswordOnly,
        ..viewer.clone()
    };
    let partial = capabilities(&api, &unconfirmed).await;
    assert_eq!(partial, allowed(Role::Viewer, AuthLevel::PasswordOnly));
    assert!(
        partial.iter().all(|name| name.starts_with("view_")),
        "a session that has not completed its second factor was offered a mutation: \
         {partial:?}"
    );
    assert!(
        !partial.is_empty(),
        "a password-only session was told it can do nothing at all, which would hide the \
         prompt that lets it finish"
    );
}

#[tokio::test]
async fn changing_the_email_returns_the_profile_and_is_audited() {
    let api = api().await;
    let (caller, _) =
        user_with_session(&api, "admin", Role::Admin, "token-admin").await;

    let response = send_json(
        &api,
        &caller,
        Method::PATCH,
        "/account",
        r#"{"email":"  corrected@example.test  "}"#,
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("json");
    // Trimmed, and the response says so — a client that showed the value it sent would
    // disagree with the next read.
    assert_eq!(body["email"], "corrected@example.test", "{body}");
    assert_eq!(
        body["username"], "admin",
        "the identity moved with the address"
    );

    let stored = api
        .store
        .find_user_by_id(&caller.user_id)
        .await
        .expect("readable")
        .expect("present");
    assert_eq!(stored.email, "corrected@example.test");

    let log = api
        .store
        .read_activity(TimeRange::default())
        .await
        .expect("readable");
    assert_eq!(
        log.iter()
            .filter(|row| row.action == "account.profile")
            .count(),
        1,
        "{log:?}"
    );
}

/// The route is keyed on the session, so it cannot reach another account.
///
/// Same property the session revocation asserts, and for the same reason: `EditOwnProfile` is
/// held by every role, so the only thing between a viewer and rewriting an administrator's
/// contact address is the handler taking the id from the caller rather than from the request.
/// A body field or a path segment here would be an account-takeover primitive.
#[tokio::test]
async fn a_profile_edit_reaches_only_the_callers_own_account() {
    let api = api().await;
    let (viewer, _) =
        user_with_session(&api, "watcher", Role::Viewer, "token-viewer").await;
    let (admin, _) =
        user_with_session(&api, "root", Role::Admin, "token-root").await;

    let response = send_json(
        &api,
        &viewer,
        Method::PATCH,
        "/account",
        r#"{"email":"taken-over@example.test"}"#,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);

    assert_eq!(
        api.store
            .find_user_by_id(&admin.user_id)
            .await
            .expect("readable")
            .expect("present")
            .email,
        "root@example.test",
        "another account's address was rewritten"
    );
    assert_eq!(
        api.store
            .find_user_by_id(&viewer.user_id)
            .await
            .expect("readable")
            .expect("present")
            .email,
        "taken-over@example.test"
    );
}

#[tokio::test]
async fn an_email_someone_else_holds_is_refused_and_names_the_address() {
    let api = api().await;
    let (first, _) =
        user_with_session(&api, "one", Role::Viewer, "token-one").await;
    let (second, _) =
        user_with_session(&api, "two", Role::Viewer, "token-two").await;

    let response = send_json(
        &api,
        &second,
        Method::PATCH,
        "/account",
        r#"{"email":"one@example.test"}"#,
    )
    .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    let body = String::from_utf8_lossy(&response.body).to_string();
    assert!(
        body.contains("one@example.test"),
        "the refusal did not name the address that was taken: {body}"
    );
    // And the first account kept its own, so the refusal was not a partial write.
    assert_eq!(
        api.store
            .find_user_by_id(&first.user_id)
            .await
            .expect("readable")
            .expect("present")
            .email,
        "one@example.test"
    );
    assert!(
        api.store
            .read_activity(TimeRange::default())
            .await
            .expect("readable")
            .iter()
            .all(|row| row.action != "account.profile"),
        "a refused edit was recorded as though it happened"
    );
}

#[tokio::test]
async fn an_empty_email_is_refused() {
    let api = api().await;
    let (caller, _) =
        user_with_session(&api, "admin", Role::Admin, "token-admin").await;
    for body in [r#"{"email":""}"#, r#"{"email":"   "}"#] {
        let response =
            send_json(&api, &caller, Method::PATCH, "/account", body).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{body}");
    }
}
