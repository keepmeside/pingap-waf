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

//! The caller's own account.
//!
//! Everything here is scoped to the caller by the handler, not by the role gate. That is the
//! distinction `Capability::ViewOwnSessions` and `Capability::RevokeOwnSession` encode: every
//! role has both, so the router lets a viewer through, and it is this module's job to make
//! sure what comes back — and what is acted on — is theirs. A handler here that took a user id
//! from the path or the body would turn a capability every role holds into a way to read any
//! account, or to cut off any session.

use super::{audit, caller, now_sec};
use crate::{ApiError, ApiRequest, ApiResponse, AppState, Result};
use pingap_controlplane::{AuthLevel, Capability, Role, authorize};
use serde::{Deserialize, Serialize};

/// The caller, as they are entitled to see themselves.
///
/// No password hash and no TOTP secret: the store keeps both reachable only through methods
/// whose names say so, and this DTO is built field by field rather than by serialising the
/// stored `User`, so a column added later cannot arrive in a response by default.
#[derive(Debug, Serialize)]
struct Profile {
    username: String,
    email: String,
    role: Role,
    auth_level: AuthLevel,
    is_active: bool,
    created_at: i64,
    /// What this session may do right now, from the server's own matrix.
    ///
    /// Derived rather than mirrored. A UI that hardcodes the matrix keeps a second copy that
    /// drifts, and the drift arrives as a control that always answers 403 — which is worse
    /// than no control, because it looks like a bug in the server.
    ///
    /// Filtered by `authorize` and not by role alone, so a session that has not completed its
    /// second factor is told the read capabilities it actually has. The list can therefore be
    /// too short, which hides a control the caller could use once they confirm; it can never
    /// be too long, which would show one that cannot be used at all.
    capabilities: Vec<Capability>,
}

pub async fn profile(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let caller = caller(request)?;
    let user = state
        .store
        .find_user_by_id(&caller.user_id)
        .await?
        .ok_or(crate::ApiError::Unauthenticated)?;
    ApiResponse::json(&Profile {
        username: user.username,
        email: user.email,
        role: user.role,
        // From the session, not the user row: the role is what this account *is*, the auth
        // level is what this session has *done*, and a UI that needs to prompt for a second
        // factor is asking about the session.
        auth_level: caller.auth_level,
        is_active: user.is_active,
        created_at: user.created_at,
        capabilities: Capability::ALL
            .into_iter()
            .filter(|capability| {
                authorize(caller.role, caller.auth_level, *capability).is_ok()
            })
            .collect(),
    })
}

/// One of the caller's sessions.
///
/// No token, hashed or otherwise. The store only ever holds the hash, and even that has no
/// business leaving it: a listing exists so an operator can recognise a device and cut it
/// off, which needs the address, the agent and the times — not the credential.
#[derive(Debug, Serialize)]
struct SessionView {
    id: String,
    auth_level: AuthLevel,
    ip: Option<String>,
    user_agent: Option<String>,
    created_at: i64,
    expires_at: i64,
    revoked_at: Option<i64>,
    /// Whether this session would be accepted right now. Derived here rather than left to
    /// the client to work out from two timestamps and a null.
    usable: bool,
    /// Which entry is the caller's current one, so a UI can avoid offering to revoke the
    /// session the operator is using without warning them.
    current: bool,
}

pub async fn own_sessions(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let caller = caller(request)?;
    let now = now_sec();
    // Keyed by the session's user id, never by anything the request carries: this route is
    // reachable by every role, and taking the id from a query parameter is how a capability
    // meant for "my laptop" becomes a way to enumerate an admin's sessions.
    let sessions = state.store.list_sessions(&caller.user_id).await?;
    let view: Vec<SessionView> = sessions
        .into_iter()
        .map(|session| SessionView {
            usable: session.is_usable(now),
            current: session.id == caller.session_id,
            id: session.id,
            auth_level: session.auth_level,
            ip: session.ip,
            user_agent: session.user_agent,
            created_at: session.created_at,
            expires_at: session.expires_at,
            revoked_at: session.revoked_at,
        })
        .collect();
    ApiResponse::json(&view)
}

/// Cut off one of the caller's own sessions.
///
/// Ownership is established by looking the id up in the caller's own listing rather than by
/// reading the session and comparing its `user_id`. `revoke_session` takes no user id, so a
/// handler that passed the path straight to it would let any user revoke any session — a
/// denial of service against an administrator, from a route every role can reach.
///
/// Someone else's session, an unknown id, and one already revoked or expired all answer 404.
/// One status for all three because they are the same fact from where the caller stands: not
/// a session of yours that can be revoked. Distinguishing them would confirm which ids
/// exist. It also means a repeat request writes no audit row — an entry claiming a revocation
/// that this call did not perform.
pub async fn revoke_session(
    state: &AppState,
    request: &ApiRequest,
    params: &[String],
) -> Result<ApiResponse> {
    let caller = caller(request)?;
    let id = params.first().ok_or_else(|| ApiError::BadRequest {
        reason: "no session id in the path".to_string(),
    })?;
    let now = now_sec();
    let own = state.store.list_sessions(&caller.user_id).await?;
    let revoked = own
        .iter()
        .any(|session| session.id == *id && session.is_usable(now));
    if !revoked {
        return Err(ApiError::NotFound {
            kind: "session".to_string(),
            id: id.clone(),
        });
    }
    state.store.revoke_session(id, now).await?;
    audit(state, caller, "session.revoke", id, now).await?;
    Ok(ApiResponse::no_content())
}

/// What the caller's second factor looks like from outside.
///
/// Two booleans and no secret. `enrolled` and `enabled` are separate because enrolment is a
/// two-step handshake — a secret is stored pending, then a code confirms it — and a UI that
/// could not tell the two apart would show a half-finished enrolment as a protected account.
#[derive(Debug, Serialize)]
struct SecondFactorStatus {
    /// A secret is stored. It may not be confirmed yet.
    enrolled: bool,
    /// The secret is confirmed, so a login is challenged.
    enabled: bool,
}

/// The secret, returned exactly once.
///
/// Nothing else can produce it: the store holds the ciphertext, and `second_factor_status`
/// deliberately reports only that one exists. Losing this response means re-enrolling, which
/// is the intended cost rather than a recoverable one.
#[derive(Debug, Serialize)]
struct SecondFactorSetup {
    /// Base32, for an app that takes the secret directly.
    secret: String,
    /// The same secret as an `otpauth://` URI, for one that scans.
    otpauth_uri: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecondFactorCode {
    code: String,
}

pub async fn second_factor_status(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let caller = caller(request)?;
    let stored = state.store.totp_secret_for(&caller.user_id).await?;
    // An empty secret is absence, not a third state: clearing writes "" rather than deleting
    // the row, and reading that as enrolled would show a protection that cannot be satisfied.
    let enrolled = stored
        .as_ref()
        .is_some_and(|(secret, _)| !secret.is_empty());
    let enabled = stored.is_some_and(|(_, enabled)| enabled) && enrolled;
    ApiResponse::json(&SecondFactorStatus { enrolled, enabled })
}

/// Begin enrolment: generate a secret, store it unconfirmed, and hand it over once.
///
/// Refuses an account whose second factor is already enabled. Overwriting a live secret would
/// disarm it without a code — the exact thing `second_factor_disable` requires one for — so
/// the caller has to disable first and prove they can still produce a code.
pub async fn second_factor_setup(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let caller = caller(request)?;
    if let Some((secret, enabled)) =
        state.store.totp_secret_for(&caller.user_id).await?
        && enabled
        && !secret.is_empty()
    {
        return Err(ApiError::Conflict {
            reason: "a second factor is already enabled; disable it first, which needs a \
                     code from the device that has it"
                .to_string(),
        });
    }
    let (secret, otpauth_uri) =
        pingap_controlplane::enrol_totp(&caller.username).map_err(|e| {
            ApiError::Internal {
                reason: format!("no second factor could be generated: {e}"),
            }
        })?;
    // Sealed before it is stored, and the failure is a 409 naming the missing setting rather
    // than a 500: sealing with a default key would be storing the secret in plaintext with
    // extra steps, and the store could not tell the difference later.
    let encrypted = state.seal_totp_secret(&secret)?;
    let now = now_sec();
    state
        .store
        .set_totp_secret(&caller.user_id, &encrypted, false, now)
        .await?;
    audit(state, caller, "account.2fa.setup", &caller.user_id, now).await?;
    ApiResponse::json(&SecondFactorSetup {
        secret,
        otpauth_uri,
    })
}

/// Confirm a pending enrolment with a code from the device that just scanned it.
///
/// The stored ciphertext is kept rather than re-sealed: the secret has not changed, only
/// whether a login is challenged by it, and re-encrypting would produce a different ciphertext
/// for the same secret with nothing gained.
pub async fn second_factor_enable(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let caller = caller(request)?;
    let body: SecondFactorCode = request.json()?;
    let (encrypted, _) = second_factor_secret(state, caller).await?;
    confirm_code(state, caller, &encrypted, &body.code).await?;
    let now = now_sec();
    state
        .store
        .set_totp_secret(&caller.user_id, &encrypted, true, now)
        .await?;
    audit(state, caller, "account.2fa.enable", &caller.user_id, now).await?;
    Ok(ApiResponse::no_content())
}

/// Remove the caller's second factor, which takes a code from the device that has it.
///
/// The reference product's equivalent takes none, and that is a posture this fork does not
/// copy: a stolen session could then silently disarm the second factor, leaving the password
/// as the only thing between the attacker and the account. Requiring a code makes that
/// useless, and the lockout it creates for someone who genuinely lost their device is what
/// `POST /users/:id/2fa/reset` exists to end — an administrator clears the secret, and the
/// account can be enrolled again.
///
/// Clears rather than disables. Leaving a disabled secret in place would keep key material
/// that nothing can use, and "disable then re-enable without a code" would be a second way
/// around the check above.
pub async fn second_factor_disable(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let caller = caller(request)?;
    let body: SecondFactorCode = request.json()?;
    let (encrypted, enabled) = second_factor_secret(state, caller).await?;
    if !enabled {
        return Err(ApiError::Conflict {
            reason: "no second factor is enabled on this account".to_string(),
        });
    }
    confirm_code(state, caller, &encrypted, &body.code).await?;
    let now = now_sec();
    state
        .store
        .set_totp_secret(&caller.user_id, "", false, now)
        .await?;
    audit(state, caller, "account.2fa.disable", &caller.user_id, now).await?;
    Ok(ApiResponse::no_content())
}

/// The caller's stored secret, or a refusal that says what is missing.
async fn second_factor_secret(
    state: &AppState,
    caller: &crate::Caller,
) -> Result<(String, bool)> {
    let (encrypted, enabled) = state
        .store
        .totp_secret_for(&caller.user_id)
        .await?
        .filter(|(secret, _)| !secret.is_empty())
        .ok_or_else(|| ApiError::Conflict {
            reason: "no second factor is enrolled; call setup first"
                .to_string(),
        })?;
    Ok((encrypted, enabled))
}

/// Spend a code against a stored secret.
///
/// `401` for a wrong code and for a replayed one, and the guard deliberately does not
/// distinguish them: telling a caller that a captured code was genuine but already used turns
/// the endpoint into an oracle for codes an attacker has collected.
async fn confirm_code(
    state: &AppState,
    caller: &crate::Caller,
    encrypted: &str,
    code: &str,
) -> Result<()> {
    let secret = state.open_totp_secret(encrypted)?;
    let now = now_sec();
    let accepted = state
        .totp()
        .verify_once(
            // The user id, and it has to be the same value the login path passes. The guard
            // keys its spent-code set by `(identifier, step)`, so a second spelling of the
            // same account is a second set — and a code that completed a login would still be
            // good for a disable inside the same step. The identifier is not an input to the
            // code itself, only to the replay window, which is why the mismatch is invisible
            // to every test that mints its own code.
            &caller.user_id,
            &secret,
            code,
            u64::try_from(now).unwrap_or_default(),
        )
        .map_err(|e| ApiError::Internal {
            reason: format!("the second factor could not be checked: {e}"),
        })?;
    if accepted {
        return Ok(());
    }
    // Not counted against the login rate limiter: this route is already behind a session, and
    // the limiter exists to slow credential guessing from outside.
    Err(ApiError::Unauthenticated)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangePassword {
    current_password: String,
    new_password: String,
}

/// Change the caller's password, and cut off every other session.
///
/// Revoking the other sessions is not a convenience. A password change is what someone does
/// when they suspect the credential has leaked, and a change that left every other device
/// signed in would have addressed nothing — the sessions were minted from the credential being
/// replaced. The caller's own session survives, because logging out the request that just
/// proved the old password would make the route unusable from a UI.
///
/// The current password is required even from a session that has completed its second factor.
/// A second factor proves possession of a device, not knowledge of the credential, and the
/// whole value of rotating a password is that the person doing it can demonstrate they hold
/// the one being replaced.
pub async fn change_password(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let caller = caller(request)?;
    let body: ChangePassword = request.json()?;
    if body.new_password.is_empty() {
        return Err(ApiError::BadRequest {
            reason: "the new password is empty".to_string(),
        });
    }
    let stored = state
        .store
        .password_hash_for(&caller.user_id)
        .await?
        // No hash means no account to change the password of. The router authenticated this
        // session against the store a moment ago, so reaching here is a row that vanished
        // under the request rather than a credential failure.
        .ok_or(ApiError::Unauthenticated)?;
    // A wrong password is `Ok(false)` and answers 401. A hash the store cannot parse is
    // `Err` and answers 500, and the two stay distinct: the first is the caller's mistake and
    // the second is our corruption, and collapsing them would tell an operator to retry a
    // password against a row that can never verify.
    let accepted =
        pingap_controlplane::verify_password(&body.current_password, &stored)
            .map_err(|e| ApiError::Internal {
            reason: format!("the stored credential could not be checked: {e}"),
        })?;
    if !accepted {
        return Err(ApiError::Unauthenticated);
    }

    let hashed = pingap_controlplane::hash_password(&body.new_password)
        .map_err(|e| ApiError::Internal {
            reason: format!("the new password could not be stored: {e}"),
        })?;
    let now = now_sec();
    state
        .store
        .set_password_hash(&caller.user_id, &hashed, now)
        .await?;

    let others: Vec<String> = state
        .store
        .list_sessions(&caller.user_id)
        .await?
        .into_iter()
        .filter(|session| {
            session.id != caller.session_id && session.is_usable(now)
        })
        .map(|session| session.id)
        .collect();
    for id in &others {
        state.store.revoke_session(id, now).await?;
    }

    audit(state, caller, "account.password", &caller.user_id, now).await?;
    // The count travels back because "your other devices were signed out" is a fact the
    // caller cannot derive, and a UI that cannot say it will be blamed for the logouts.
    ApiResponse::json(&serde_json::json!({
        "sessions_revoked": others.len(),
    }))
}
