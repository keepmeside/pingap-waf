// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Per-user authentication for the admin plugin.
//!
//! Replaces the shared-credential scheme, which hashed `user:pass:timestamp` on
//! the client and could not say *who* did anything — disqualifying for an audit
//! trail. Sessions live in the control-plane store; the plugin holds a token and
//! asks the store who it belongs to.
//!
//! Kept out of `admin.rs` deliberately. That file is vendored, and every line
//! added to it is merge debt; this one is fork-owned, so the plugin gains one
//! field and one call rather than a login flow.
//!
//! Three shapes here are load-bearing:
//!
//! - **The store may be absent.** The gateway serves from config alone, and an
//!   unreachable store must read as a 503 from the admin API — not a crash, and
//!   not an open door. Every path that cannot reach the store denies.
//! - **The first admin is bootstrapped from `--admin user:pass@addr`.** That is
//!   the one credential an operator already has, so it is what unlocks a fresh
//!   store; once a user exists it is never consulted again. Without this an
//!   operator replacing the old scheme is locked out of the thing that creates
//!   accounts.
//! - **Every request re-reads the session.** Revocation takes effect on the next
//!   request because nothing here caches a verdict.

use pingap_controlplane::{
    AuthLevel, ControlPlaneStore, NewSession, NewUser, Role, StoreError,
    TotpGuard, TursoStore, hash_password, hash_token, new_token,
    verify_password,
};
use pingap_core::HttpResponse;
use pingora::http::RequestHeader;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

const LOG_TARGET: &str = "admin";

/// How long a session lasts. The old scheme's `max_age` defaulted to two days
/// and that expectation is kept.
const SESSION_TTL: Duration = Duration::from_secs(2 * 24 * 3600);

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct TotpRequest {
    pub code: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    /// `"password_only"` when a second factor is still outstanding. The UI
    /// shows the TOTP prompt from this, not from a separate round-trip.
    pub auth_level: AuthLevel,
    pub role: Role,
    pub username: String,
}

/// Who is making an authenticated request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub session_id: String,
    pub user_id: String,
    pub username: String,
    pub role: Role,
    pub auth_level: AuthLevel,
}

/// Why a request was refused, mapped to a status the UI can act on.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// 401: no session, or one that is expired, revoked, or unknown.
    Unauthenticated,
    /// 503: the store cannot be reached, so nothing can be decided.
    StoreUnavailable(String),
    /// 500: the store answered, but not with something usable.
    Backend(String),
}

impl Refusal {
    pub fn into_response(self) -> HttpResponse {
        match self {
            Self::Unauthenticated => HttpResponse {
                status: http::StatusCode::UNAUTHORIZED,
                ..Default::default()
            },
            // Distinct from a 500 on purpose: a missing store is a *state* the
            // operator can act on, and a crash-shaped error hides that.
            Self::StoreUnavailable(reason) => HttpResponse {
                status: http::StatusCode::SERVICE_UNAVAILABLE,
                body: bytes::Bytes::from(format!(
                    "control-plane store unavailable: {reason}"
                )),
                ..Default::default()
            },
            Self::Backend(message) => HttpResponse::unknown_error(message),
        }
    }
}

impl From<StoreError> for Refusal {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::Unavailable { reason } => {
                Self::StoreUnavailable(reason)
            },
            other => Self::Backend(other.to_string()),
        }
    }
}

/// What the admin plugin holds: the configuration to open with, and the opened
/// [`AdminAuth`] once a request has forced it.
///
/// Lazy because the plugin factory is synchronous and opening the store is not.
/// The store is process-global anyway (`TursoStore::shared`), so first-use
/// initialisation costs one request a few milliseconds and nothing else.
pub struct LazyAdminAuth {
    store_path: String,
    bootstrap: Option<(String, String)>,
    totp_key: Option<String>,
    /// Whether to go through `TursoStore::shared`. Production does, so every
    /// writer in the process is the one writer. Tests do not: each opens its
    /// own store in its own temp dir, and the process-global handle would
    /// refuse the second path — correctly — and fail every test but the first.
    shared: bool,
    opened: tokio::sync::OnceCell<AdminAuth>,
}

impl LazyAdminAuth {
    pub fn new(
        store_path: String,
        bootstrap: Option<(String, String)>,
        totp_key: Option<String>,
    ) -> Self {
        Self {
            store_path,
            bootstrap,
            totp_key,
            shared: true,
            opened: tokio::sync::OnceCell::new(),
        }
    }

    /// A store private to this instance. Test-only: in production two admin
    /// plugins with two stores would split the audit trail.
    #[cfg(test)]
    pub fn private(
        store_path: String,
        bootstrap: Option<(String, String)>,
        totp_key: Option<String>,
    ) -> Self {
        Self {
            shared: false,
            ..Self::new(store_path, bootstrap, totp_key)
        }
    }

    pub async fn get(&self) -> &AdminAuth {
        self.opened
            .get_or_init(|| {
                AdminAuth::open(
                    &self.store_path,
                    self.bootstrap.clone(),
                    self.totp_key.clone(),
                    self.shared,
                )
            })
            .await
    }
}

/// The admin plugin's view of authentication.
pub struct AdminAuth {
    store: Arc<dyn ControlPlaneStore>,
    /// The `--admin` credential, kept only to create the first account. Cleared
    /// from memory is not an option — the plugin is rebuilt on every config
    /// reload — so the rule is instead that it is *never consulted* once any
    /// user exists.
    bootstrap: Option<(String, String)>,
    totp_guard: TotpGuard,
    /// The TOTP encryption key, from configuration. Absent means 2FA enrolment
    /// is refused rather than stored in the clear.
    totp_key: Option<String>,
}

impl AdminAuth {
    /// Open the store at `store_path` and wire the bootstrap credential.
    ///
    /// A store that will not open is not an error here: the plugin must still
    /// be constructible so the gateway boots, and every request will then be
    /// refused with 503 until the store is back.
    pub async fn open(
        store_path: &str,
        bootstrap: Option<(String, String)>,
        totp_key: Option<String>,
        shared: bool,
    ) -> Self {
        let opened = if shared {
            TursoStore::shared(store_path).await
        } else {
            TursoStore::open(store_path).await.map(Arc::new)
        };
        let store: Arc<dyn ControlPlaneStore> = match opened {
            Ok(store) => {
                if let Err(e) = store.migrate().await {
                    error!(
                        target: LOG_TARGET,
                        error = %e,
                        path = store_path,
                        "control-plane store migration failed; admin auth will refuse until it succeeds"
                    );
                }
                store
            },
            Err(e) => {
                warn!(
                    target: LOG_TARGET,
                    error = %e,
                    path = store_path,
                    "control-plane store unavailable; the gateway serves from config and the admin API answers 503"
                );
                Arc::new(UnavailableStore {
                    reason: e.to_string(),
                })
            },
        };
        Self {
            store,
            bootstrap,
            totp_guard: TotpGuard::default(),
            totp_key,
        }
    }

    /// Construct over an already-open store. For tests, and for callers that
    /// own the store's lifetime themselves.
    #[cfg(test)]
    pub fn over(
        store: Arc<dyn ControlPlaneStore>,
        bootstrap: Option<(String, String)>,
        totp_key: Option<String>,
    ) -> Self {
        Self {
            store,
            bootstrap,
            totp_guard: TotpGuard::default(),
            totp_key,
        }
    }

    /// The one store handle in this process.
    ///
    /// Exposed so the admin API's route table writes through the same handle the session
    /// lookup reads through. `TursoStore::shared` is one writer per process and refuses a
    /// second path, so a second handle is not merely wasteful — it would not open.
    pub fn store(&self) -> &Arc<dyn ControlPlaneStore> {
        &self.store
    }

    /// Whether the store can be reached right now.
    pub async fn store_available(&self) -> Result<(), Refusal> {
        self.store.health().await.map_err(Refusal::from)
    }

    /// Resolve the bearer token on a request to the session it names.
    ///
    /// Reads the store every time. Caching a verdict would make revocation take
    /// effect at cache expiry rather than on the next request, which is the
    /// success criterion this exists to meet.
    pub async fn authenticate(
        &self,
        req_header: &RequestHeader,
    ) -> Result<Principal, Refusal> {
        let value =
            pingap_core::get_req_header_value(req_header, "Authorization")
                .unwrap_or_default();
        let token = value
            .strip_prefix("Bearer ")
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or(Refusal::Unauthenticated)?;
        let now = pingap_core::now_sec() as i64;
        let session = self
            .store
            .session_by_token(&hash_token(token))
            .await?
            .filter(|s| s.is_usable(now))
            .ok_or(Refusal::Unauthenticated)?;
        // The user row is read on every request too, so deactivating an account
        // cuts off its open sessions without having to enumerate them.
        let user = self
            .store
            .find_user_by_id(&session.user_id)
            .await?
            .filter(|u| u.is_active)
            .ok_or(Refusal::Unauthenticated)?;
        Ok(Principal {
            session_id: session.id,
            user_id: user.id,
            username: user.username,
            role: user.role,
            auth_level: session.auth_level,
        })
    }

    /// Exchange a username and password for a session.
    ///
    /// `Ok(None)` for a wrong username *or* a wrong password, identically: the
    /// two must not be distinguishable or the login form becomes a username
    /// oracle. The password is verified even when the user is unknown, for the
    /// same reason — a fast "no such user" and a slow "wrong password" differ
    /// by a full argon2 evaluation, which is measurable.
    ///
    /// On a store with no users at all, the `--admin` credential creates the
    /// first admin. That is the only time it is consulted.
    pub async fn login(
        &self,
        req: LoginRequest,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Option<LoginResponse>, Refusal> {
        let now = pingap_core::now_sec() as i64;
        self.bootstrap_if_empty(now).await?;

        let user = self.store.find_user_by_username(&req.username).await?;
        let stored = match &user {
            Some(u) => self.store.password_hash_for(&u.id).await?,
            None => None,
        };
        let verified = match stored.as_deref() {
            Some(hash) => verify_password(&req.password, hash)
                .map_err(|e| Refusal::Backend(e.to_string()))?,
            // Burn the same time on an unknown user. The hash is a real argon2id
            // output over a throwaway password, so the parameters — and the
            // cost — match a genuine verification.
            None => {
                let _ = verify_password(&req.password, DECOY_HASH);
                false
            },
        };
        let Some(user) = user.filter(|u| verified && u.is_active) else {
            return Ok(None);
        };

        // Whether a second factor is outstanding is decided from the store, per
        // login. A user who enrolled since their last session gets challenged.
        let has_totp = matches!(
            self.store.totp_secret_for(&user.id).await?,
            Some((_, true))
        );
        let auth_level = if has_totp {
            AuthLevel::PasswordOnly
        } else {
            AuthLevel::TwoFactor
        };

        let token = new_token();
        let hashed = hash_token(&token);
        self.store
            .create_session(NewSession {
                user_id: &user.id,
                token_hash: &hashed,
                auth_level,
                ip,
                user_agent,
                now,
                expires_at: now + SESSION_TTL.as_secs() as i64,
            })
            .await?;
        info!(
            target: LOG_TARGET,
            username = user.username,
            auth_level = ?auth_level,
            "admin login"
        );
        Ok(Some(LoginResponse {
            token,
            auth_level,
            role: user.role,
            username: user.username,
        }))
    }

    /// Complete the second factor for a password-only session.
    ///
    /// `Ok(false)` for a wrong code and for a replayed one, identically. The
    /// session is promoted in the store, so the promotion survives a reload
    /// and is visible to every other request immediately.
    pub async fn complete_totp(
        &self,
        principal: &Principal,
        req: TotpRequest,
    ) -> Result<bool, Refusal> {
        let Some((encrypted, true)) =
            self.store.totp_secret_for(&principal.user_id).await?
        else {
            // Nothing enrolled; there is no factor to complete. Not an error —
            // the session is already at `TwoFactor` in that case.
            return Ok(false);
        };
        let secret = pingap_controlplane::decrypt_totp_secret(
            &encrypted,
            self.totp_key.as_deref(),
        )
        .map_err(|e| Refusal::Backend(e.to_string()))?;
        let accepted = self
            .totp_guard
            .verify_once(
                &principal.user_id,
                &secret,
                req.code.trim(),
                pingap_core::now_sec(),
            )
            .map_err(|e| Refusal::Backend(e.to_string()))?;
        if !accepted {
            return Ok(false);
        }
        self.store
            .complete_second_factor(&principal.session_id)
            .await?;
        Ok(true)
    }

    /// Revoke the calling session. Takes effect on the next request.
    pub async fn logout(&self, principal: &Principal) -> Result<(), Refusal> {
        let now = pingap_core::now_sec() as i64;
        self.store
            .revoke_session(&principal.session_id, now)
            .await?;
        Ok(())
    }

    /// Create the first admin from the bootstrap credential, if the store has
    /// no users at all.
    ///
    /// "No users at all" rather than "no admin": a store with only viewers is
    /// a store somebody has already configured, and silently adding an admin
    /// with a credential from the command line would be a privilege escalation
    /// path for anyone who can edit the service definition.
    async fn bootstrap_if_empty(&self, now: i64) -> Result<(), Refusal> {
        let Some((username, password)) = &self.bootstrap else {
            return Ok(());
        };
        if !self.store.list_users().await?.is_empty() {
            return Ok(());
        }
        let password_hash = hash_password(password)
            .map_err(|e| Refusal::Backend(e.to_string()))?;
        match self
            .store
            .create_user(
                NewUser {
                    username: username.clone(),
                    // No address is known. A placeholder that cannot collide
                    // with a real one and cannot receive mail.
                    email: format!("{username}@bootstrap.invalid"),
                    password_hash,
                    role: Role::Admin,
                },
                now,
            )
            .await
        {
            Ok(user) => {
                info!(
                    target: LOG_TARGET,
                    username = user.username,
                    "bootstrapped the first admin from the --admin credential"
                );
                Ok(())
            },
            // Two logins raced on an empty store; the other one won.
            Err(StoreError::Conflict { .. }) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// A real argon2id hash of a throwaway password, so that verifying against it
/// costs what a genuine verification costs. Generated once with the same
/// parameters `hash_password` uses; the password behind it is not recorded
/// anywhere and does not matter.
const DECOY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$VJv5c7oQGfHlC7K2kWcbAw$JqZz5wgVWXfFK+MTsO4PEzB8qpBPiv79RuijYB2o4CM";

/// The store that stands in when the real one would not open.
///
/// Every method reports [`StoreError::Unavailable`], so the admin API answers
/// 503 uniformly rather than each handler checking a flag. `migrate` and
/// `health` fail the same way, which is what lets a health endpoint report the
/// state honestly.
struct UnavailableStore {
    reason: String,
}

impl UnavailableStore {
    fn refuse<T>(&self) -> pingap_controlplane::repository::Result<T> {
        Err(StoreError::Unavailable {
            reason: self.reason.clone(),
        })
    }
}

#[async_trait::async_trait]
impl ControlPlaneStore for UnavailableStore {
    async fn migrate(&self) -> pingap_controlplane::repository::Result<u32> {
        self.refuse()
    }
    async fn health(&self) -> pingap_controlplane::repository::Result<()> {
        self.refuse()
    }
    async fn create_user(
        &self,
        _: NewUser,
        _: i64,
    ) -> pingap_controlplane::repository::Result<pingap_controlplane::User>
    {
        self.refuse()
    }
    async fn find_user_by_username(
        &self,
        _: &str,
    ) -> pingap_controlplane::repository::Result<
        Option<pingap_controlplane::User>,
    > {
        self.refuse()
    }
    async fn find_user_by_id(
        &self,
        _: &str,
    ) -> pingap_controlplane::repository::Result<
        Option<pingap_controlplane::User>,
    > {
        self.refuse()
    }
    async fn password_hash_for(
        &self,
        _: &str,
    ) -> pingap_controlplane::repository::Result<Option<String>> {
        self.refuse()
    }
    async fn list_users(
        &self,
    ) -> pingap_controlplane::repository::Result<Vec<pingap_controlplane::User>>
    {
        self.refuse()
    }
    async fn set_user_active(
        &self,
        _: &str,
        _: bool,
        _: i64,
    ) -> pingap_controlplane::repository::Result<()> {
        self.refuse()
    }
    async fn set_totp_secret(
        &self,
        _: &str,
        _: &str,
        _: bool,
        _: i64,
    ) -> pingap_controlplane::repository::Result<()> {
        self.refuse()
    }
    async fn totp_secret_for(
        &self,
        _: &str,
    ) -> pingap_controlplane::repository::Result<Option<(String, bool)>> {
        self.refuse()
    }
    async fn create_session(
        &self,
        _: NewSession<'_>,
    ) -> pingap_controlplane::repository::Result<pingap_controlplane::Session>
    {
        self.refuse()
    }
    async fn session_by_token(
        &self,
        _: &str,
    ) -> pingap_controlplane::repository::Result<
        Option<pingap_controlplane::Session>,
    > {
        self.refuse()
    }
    async fn list_sessions(
        &self,
        _: &str,
    ) -> pingap_controlplane::repository::Result<
        Vec<pingap_controlplane::Session>,
    > {
        self.refuse()
    }
    async fn revoke_session(
        &self,
        _: &str,
        _: i64,
    ) -> pingap_controlplane::repository::Result<()> {
        self.refuse()
    }
    async fn complete_second_factor(
        &self,
        _: &str,
    ) -> pingap_controlplane::repository::Result<()> {
        self.refuse()
    }
    async fn record_activity(
        &self,
        _: pingap_controlplane::NewActivity,
        _: i64,
    ) -> pingap_controlplane::repository::Result<pingap_controlplane::Activity>
    {
        self.refuse()
    }
    async fn read_activity(
        &self,
        _: pingap_controlplane::TimeRange,
    ) -> pingap_controlplane::repository::Result<
        Vec<pingap_controlplane::Activity>,
    > {
        self.refuse()
    }
    async fn record_config_version(
        &self,
        _: pingap_controlplane::NewConfigVersion,
        _: i64,
    ) -> pingap_controlplane::repository::Result<
        pingap_controlplane::ConfigVersion,
    > {
        self.refuse()
    }
    async fn set_config_version_status(
        &self,
        _: &str,
        _: pingap_controlplane::ConfigStatus,
        _: Option<&str>,
        _: i64,
    ) -> pingap_controlplane::repository::Result<()> {
        self.refuse()
    }
    async fn config_version(
        &self,
        _: &str,
    ) -> pingap_controlplane::repository::Result<
        Option<pingap_controlplane::ConfigVersion>,
    > {
        self.refuse()
    }
    async fn latest_config_version(
        &self,
    ) -> pingap_controlplane::repository::Result<
        Option<pingap_controlplane::ConfigVersion>,
    > {
        self.refuse()
    }
    async fn latest_applied_config_version(
        &self,
    ) -> pingap_controlplane::repository::Result<
        Option<pingap_controlplane::ConfigVersion>,
    > {
        self.refuse()
    }
    async fn list_config_versions(
        &self,
        _: Option<u32>,
    ) -> pingap_controlplane::repository::Result<
        Vec<pingap_controlplane::ConfigVersion>,
    > {
        self.refuse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    const TOTP_KEY: &str = "PLpKJqvfkjTcYTDpauJf+2JnEayP+bm+0Oe60Jk=";

    /// An `AdminAuth` over a fresh, migrated store in a temp dir, bootstrapped
    /// with `admin:123123`.
    async fn auth() -> (AdminAuth, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cp.db");
        let store = TursoStore::open(path.to_str().unwrap()).await.unwrap();
        store.migrate().await.unwrap();
        let auth = AdminAuth::over(
            Arc::new(store),
            Some(("admin".to_string(), "123123".to_string())),
            Some(TOTP_KEY.to_string()),
        );
        (auth, dir)
    }

    fn login_req(username: &str, password: &str) -> LoginRequest {
        LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    fn bearer(token: &str) -> RequestHeader {
        let mut req =
            RequestHeader::build(http::Method::GET, b"/api/basic", None)
                .unwrap();
        req.insert_header("Authorization", format!("Bearer {token}"))
            .unwrap();
        req
    }

    #[tokio::test]
    async fn the_first_login_bootstraps_an_admin_from_the_cli_credential() {
        // The migration story. An operator replacing the shared credential has
        // exactly one credential — the `--admin` one — and it must open the door
        // to the thing that creates accounts, or they are locked out.
        let (auth, _dir) = auth().await;
        let resp = auth
            .login(login_req("admin", "123123"), None, None)
            .await
            .unwrap()
            .expect("the bootstrap credential logs in on an empty store");
        assert_eq!(resp.role, Role::Admin);
        assert_eq!(
            resp.auth_level,
            AuthLevel::TwoFactor,
            "no second factor is enrolled, so nothing is outstanding"
        );
        let principal = auth.authenticate(&bearer(&resp.token)).await.unwrap();
        assert_eq!(principal.username, "admin");
        assert_eq!(principal.role, Role::Admin);
    }

    #[tokio::test]
    async fn the_bootstrap_credential_is_never_consulted_once_a_user_exists() {
        // Otherwise anyone who can edit the service definition can add an
        // admin, which is a privilege escalation path dressed as convenience.
        let (auth, _dir) = auth().await;
        auth.login(login_req("admin", "123123"), None, None)
            .await
            .unwrap()
            .expect("bootstrap");
        // Deactivate the only user, then present the bootstrap credential.
        let admin = auth
            .store()
            .find_user_by_username("admin")
            .await
            .unwrap()
            .unwrap();
        auth.store()
            .set_user_active(&admin.id, false, 1)
            .await
            .unwrap();
        assert!(
            auth.login(login_req("admin", "123123"), None, None)
                .await
                .unwrap()
                .is_none(),
            "the bootstrap credential re-created or re-enabled an account"
        );
        assert_eq!(auth.store().list_users().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_wrong_password_and_an_unknown_user_are_the_same_answer() {
        let (auth, _dir) = auth().await;
        auth.login(login_req("admin", "123123"), None, None)
            .await
            .unwrap()
            .expect("bootstrap");
        let wrong = auth
            .login(login_req("admin", "wrong"), None, None)
            .await
            .unwrap();
        let unknown = auth
            .login(login_req("nobody", "123123"), None, None)
            .await
            .unwrap();
        assert!(wrong.is_none());
        assert!(unknown.is_none());
    }

    #[tokio::test]
    async fn a_revoked_session_is_refused_on_the_very_next_request() {
        // The named success criterion, at the layer that answers requests.
        let (auth, _dir) = auth().await;
        let resp = auth
            .login(login_req("admin", "123123"), None, None)
            .await
            .unwrap()
            .expect("bootstrap");
        let principal = auth.authenticate(&bearer(&resp.token)).await.unwrap();
        auth.logout(&principal).await.unwrap();
        assert_eq!(
            auth.authenticate(&bearer(&resp.token)).await,
            Err(Refusal::Unauthenticated)
        );
    }

    #[tokio::test]
    async fn a_deactivated_user_loses_their_open_sessions() {
        let (auth, _dir) = auth().await;
        let resp = auth
            .login(login_req("admin", "123123"), None, None)
            .await
            .unwrap()
            .expect("bootstrap");
        let principal = auth.authenticate(&bearer(&resp.token)).await.unwrap();
        auth.store()
            .set_user_active(&principal.user_id, false, 1)
            .await
            .unwrap();
        assert_eq!(
            auth.authenticate(&bearer(&resp.token)).await,
            Err(Refusal::Unauthenticated),
            "deactivation did not cut off an open session"
        );
    }

    #[tokio::test]
    async fn the_raw_token_is_not_a_key_into_the_store() {
        let (auth, _dir) = auth().await;
        let resp = auth
            .login(login_req("admin", "123123"), None, None)
            .await
            .unwrap()
            .expect("bootstrap");
        assert!(
            auth.store()
                .session_by_token(&resp.token)
                .await
                .unwrap()
                .is_none(),
            "the store holds the bearer token itself"
        );
        assert!(
            auth.store()
                .session_by_token(&hash_token(&resp.token))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_missing_or_malformed_bearer_is_unauthenticated() {
        let (auth, _dir) = auth().await;
        for value in ["", "Bearer ", "Bearer", "Basic abc", "notatoken"] {
            let mut req =
                RequestHeader::build(http::Method::GET, b"/api/basic", None)
                    .unwrap();
            if !value.is_empty() {
                req.insert_header("Authorization", value).unwrap();
            }
            assert_eq!(
                auth.authenticate(&req).await,
                Err(Refusal::Unauthenticated),
                "`{value}` was accepted"
            );
        }
    }

    #[tokio::test]
    async fn an_enrolled_second_factor_gates_the_session_until_completed() {
        let (auth, _dir) = auth().await;
        let first = auth
            .login(login_req("admin", "123123"), None, None)
            .await
            .unwrap()
            .expect("bootstrap");
        let principal = auth.authenticate(&bearer(&first.token)).await.unwrap();

        // Enrol.
        let (secret, _) = pingap_controlplane::enrol_totp("admin").unwrap();
        let encrypted =
            pingap_controlplane::encrypt_totp_secret(&secret, Some(TOTP_KEY))
                .unwrap();
        auth.store()
            .set_totp_secret(&principal.user_id, &encrypted, true, 1)
            .await
            .unwrap();

        // The next login is password-only until the code arrives.
        let second = auth
            .login(login_req("admin", "123123"), None, None)
            .await
            .unwrap()
            .expect("login");
        assert_eq!(second.auth_level, AuthLevel::PasswordOnly);
        let principal =
            auth.authenticate(&bearer(&second.token)).await.unwrap();
        assert_eq!(principal.auth_level, AuthLevel::PasswordOnly);

        assert!(
            !auth
                .complete_totp(
                    &principal,
                    TotpRequest {
                        code: "000000".to_string()
                    }
                )
                .await
                .unwrap(),
            "a wrong code completed the factor"
        );
        // The code an authenticator would show right now.
        let code = pingap_controlplane::auth::totp_code_for(
            &secret,
            &principal.user_id,
            pingap_core::now_sec(),
        )
        .unwrap();
        assert!(
            auth.complete_totp(&principal, TotpRequest { code })
                .await
                .unwrap()
        );
        let promoted = auth.authenticate(&bearer(&second.token)).await.unwrap();
        assert_eq!(promoted.auth_level, AuthLevel::TwoFactor);
        // And the earlier session, which never completed a factor, is where
        // it was: promotion is per session.
        let earlier = auth.authenticate(&bearer(&first.token)).await.unwrap();
        assert_eq!(
            earlier.auth_level,
            AuthLevel::TwoFactor,
            "the first session predates enrolment and was already complete"
        );
    }

    #[tokio::test]
    async fn an_unavailable_store_refuses_with_503_rather_than_denying_or_allowing()
     {
        // The load-bearing boundary: the gateway serves, and the admin API says
        // *why* it cannot. A 401 here would send an operator to reset a
        // password; a 200 would be an open door.
        let auth = AdminAuth::open(
            "/nonexistent-directory-for-a-test/cp.db",
            Some(("admin".to_string(), "123123".to_string())),
            None,
            false,
        )
        .await;
        assert!(matches!(
            auth.store_available().await,
            Err(Refusal::StoreUnavailable(_))
        ));
        assert!(matches!(
            auth.login(login_req("admin", "123123"), None, None).await,
            Err(Refusal::StoreUnavailable(_))
        ));
        assert!(matches!(
            auth.authenticate(&bearer("anything")).await,
            Err(Refusal::StoreUnavailable(_))
        ));
        assert_eq!(
            Refusal::StoreUnavailable("x".into())
                .into_response()
                .status
                .as_u16(),
            503
        );
    }
}
