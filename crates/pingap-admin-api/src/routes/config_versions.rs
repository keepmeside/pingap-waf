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

//! Config versions, and rollback.
//!
//! The write path here is the projection's, not this crate's: rollback regenerates from the
//! target version's stored intent and runs the whole apply — validate, commit, verify — so a
//! restored config is confirmed enforcing exactly like any other. A handler that wrote config
//! itself would break determinism, drift detection and rollback at once, which is why
//! `AppState` holds an `Applier` and no `ConfigManager`.

use super::{caller, intent_resource::apply_error, now_sec};
use crate::{ApiError, ApiRequest, ApiResponse, AppState, Result};
use pingap_controlplane::ConfigStatus;
use pingap_controlplane::projection::Actor;
use serde::Serialize;

/// A version, without its intent.
///
/// `intent_json` is deliberately omitted: it is the whole stored configuration, it can carry
/// TLS key references and access-list credentials, and a listing is for choosing a version
/// rather than reading one.
#[derive(Debug, Serialize)]
struct VersionView {
    id: String,
    hash: String,
    status: ConfigStatus,
    actor_username: String,
    error: Option<String>,
    created_at: i64,
    settled_at: Option<i64>,
}

pub async fn list(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let limit = request.param("limit").and_then(|v| v.parse().ok());
    let versions = state.store.list_config_versions(limit).await?;
    let view: Vec<VersionView> = versions
        .into_iter()
        .map(|v| VersionView {
            id: v.id,
            hash: v.hash,
            status: v.status,
            actor_username: v.actor_username,
            error: v.error,
            created_at: v.created_at,
            settled_at: v.settled_at,
        })
        .collect();
    ApiResponse::json(&view)
}

/// What a rollback produced.
///
/// The new version's id, not the target's: a rollback records its own row, because "the
/// config the gateway is running" and "the intent an operator chose" are different facts and
/// reusing the target's row would lose the second one.
#[derive(Debug, Serialize)]
struct RollbackResult {
    version: VersionView,
    /// Set when the restored config itself failed verification and an earlier one was put
    /// back — a rollback that did not hold.
    rolled_back_to: Option<String>,
}

pub async fn rollback(
    state: &AppState,
    request: &ApiRequest,
    params: &[String],
) -> Result<ApiResponse> {
    let actor = caller(request)?;
    let target = params.first().ok_or_else(|| ApiError::BadRequest {
        reason: "no version id in the path".to_string(),
    })?;
    let outcome = state
        .applier
        .rollback(
            target,
            &Actor {
                id: Some(actor.user_id.clone()),
                username: actor.username.clone(),
            },
            now_sec(),
        )
        .await
        .map_err(apply_error)?;
    // The activity row is written by the applier, inside the apply, so it names the version
    // it produced. Writing a second one here would double-count the mutation.
    let version = outcome.version;
    ApiResponse::json(&RollbackResult {
        version: VersionView {
            id: version.id,
            hash: version.hash,
            status: version.status,
            actor_username: version.actor_username,
            error: version.error,
            created_at: version.created_at,
            settled_at: version.settled_at,
        },
        rolled_back_to: outcome.rolled_back_to,
    })
}
