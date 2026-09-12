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

//! Users. Reading is `ViewUsers`, changing anything is `ManageUsers`.

use super::{caller, now_sec};
use crate::{ApiError, ApiRequest, ApiResponse, AppState, Result};
use pingap_controlplane::{NewActivity, NewUser, Role, hash_password};
use serde::{Deserialize, Serialize};

/// A user as any reader sees them. Built field by field, so the password hash cannot reach a
/// response by being a field of the row.
#[derive(Debug, Serialize)]
struct UserView {
    id: String,
    username: String,
    email: String,
    role: Role,
    is_active: bool,
    created_at: i64,
}

impl From<pingap_controlplane::User> for UserView {
    fn from(user: pingap_controlplane::User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            is_active: user.is_active,
            created_at: user.created_at,
        }
    }
}

pub async fn list(
    state: &AppState,
    _request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let users = state.store.list_users().await?;
    let view: Vec<UserView> = users.into_iter().map(UserView::from).collect();
    ApiResponse::json(&view)
}

/// `deny_unknown_fields` on every request DTO in this crate.
///
/// Serde ignores an unknown key by default, which on an admin API means a typo'd or
/// misremembered field is accepted and does nothing — the caller sees 201 and believes they
/// set something. Rejecting is the only answer that cannot mislead. It is also why
/// `role` being absent here is a 400 and not a silent default.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateUser {
    username: String,
    email: String,
    password: String,
    role: Role,
}

pub async fn create(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let actor = caller(request)?;
    let body: CreateUser = request.json()?;
    if body.username.trim().is_empty() || body.password.is_empty() {
        return Err(ApiError::BadRequest {
            reason: "username and password are required".to_string(),
        });
    }
    // Hashed here, never stored or logged in the clear, and the plaintext is dropped with
    // the DTO at the end of this function.
    let password_hash =
        hash_password(&body.password).map_err(|e| ApiError::Internal {
            reason: e.to_string(),
        })?;
    let now = now_sec();
    let user = state
        .store
        .create_user(
            NewUser {
                username: body.username.trim().to_string(),
                email: body.email.trim().to_string(),
                password_hash,
                role: body.role,
            },
            now,
        )
        .await?;
    audit(state, actor, "user.create", &user.id, now).await?;
    ApiResponse::json(&UserView::from(user))
}

/// Only activation, for now.
///
/// Role reassignment has no store method — `ControlPlaneStore` exposes `set_user_active` and
/// nothing that writes `role` — so offering a `role` field here would mean either adding it
/// to the repository trait and its driver, or accepting a field and ignoring it. The second
/// is the failure this codebase refuses repeatedly, so the field is absent and
/// `deny_unknown_fields` turns an attempt to set it into a 400 that says so.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateUser {
    is_active: bool,
}

pub async fn update(
    state: &AppState,
    request: &ApiRequest,
    params: &[String],
) -> Result<ApiResponse> {
    let actor = caller(request)?;
    let id = params.first().ok_or_else(|| ApiError::BadRequest {
        reason: "no user id in the path".to_string(),
    })?;
    let body: UpdateUser = request.json()?;
    let now = now_sec();
    // `set_user_active` reports a miss rather than silently matching nothing: Turso's
    // `changes()` is partial, so the store checks existence itself, and a 404 here is that
    // check surfacing rather than this handler guessing.
    state.store.set_user_active(id, body.is_active, now).await?;
    audit(
        state,
        actor,
        if body.is_active {
            "user.activate"
        } else {
            "user.deactivate"
        },
        id,
        now,
    )
    .await?;
    ApiResponse::json(&UserView::from(
        state.store.find_user_by_id(id).await?.ok_or_else(|| {
            ApiError::NotFound {
                kind: "user".to_string(),
                id: id.clone(),
            }
        })?,
    ))
}

/// One activity row per mutation, naming who did what to which target.
///
/// Written by the handler rather than by the router, because only the handler knows the
/// target it actually touched. The criterion is one row per mutation, so a handler that
/// mutates twice writes twice — and one that returns an error before mutating writes none.
async fn audit(
    state: &AppState,
    actor: &crate::Caller,
    action: &str,
    target: &str,
    now: i64,
) -> Result<()> {
    state
        .store
        .record_activity(
            NewActivity {
                actor_id: Some(actor.user_id.clone()),
                actor_username: actor.username.clone(),
                action: action.to_string(),
                target: target.to_string(),
                config_version: None,
                ip: None,
                user_agent: None,
                detail: None,
            },
            now,
        )
        .await?;
    Ok(())
}
