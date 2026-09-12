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
//! distinction `Capability::ViewOwnSessions` encodes: every role has it, so the router lets a
//! viewer through, and it is this module's job to make sure what comes back is theirs. A
//! handler here that took a user id from the path or the body would turn a capability every
//! role holds into a way to read any account.

use super::{caller, now_sec};
use crate::{ApiRequest, ApiResponse, AppState, Result};
use pingap_controlplane::{AuthLevel, Role};
use serde::Serialize;

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
