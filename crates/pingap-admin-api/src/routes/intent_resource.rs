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

//! Config-shaped resources: read from stored intent, write through the projection.
//!
//! Every entry in `Intent` is a `BTreeMap<String, T>`, and every one of them wants the same
//! four operations. Written once here rather than four times: the interesting part is not
//! the CRUD, it is that a write **regenerates the whole config** — it loads the intent the
//! gateway is running, changes one key, and hands the complete result to the `Applier`.
//! Nothing here writes config, and nothing here patches it.
//!
//! There is no "current intent" table. The intent a version was generated from is stored on
//! that version, so the base for an edit is the newest version that was confirmed
//! *enforcing*. Basing an edit on the newest row instead would re-apply a config that
//! failed verification; basing it on nothing would silently drop everything an operator
//! had configured.

use super::{caller, now_sec};
use crate::{ApiError, ApiRequest, ApiResponse, AppState, Result};
use pingap_controlplane::ConfigStatus;
use pingap_controlplane::projection::{Actor, ApplyError, Intent};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;

/// The intent a new edit starts from.
pub(crate) async fn base_intent(state: &AppState) -> Result<Intent> {
    // A version nobody has settled means the previous apply is still in its reload window,
    // or the process died inside one. Either way there is no safe base: the newest applied
    // intent would silently drop that edit, and the pending one would build on a config
    // nothing has confirmed. The scheduled sweep settles it within the minute.
    if let Some(newest) = state.store.latest_config_version().await?
        && newest.status == ConfigStatus::Pending
    {
        return Err(ApiError::Conflict {
            reason: format!(
                "config version `{}` has not been confirmed enforcing yet; \
                 retry once it settles",
                newest.id
            ),
        });
    }
    match state.store.latest_applied_config_version().await? {
        Some(version) => {
            serde_json::from_str(&version.intent_json).map_err(|e| {
                ApiError::Internal {
                    reason: format!(
                        "stored intent for version `{}` is unreadable: {e}",
                        version.id
                    ),
                }
            })
        },
        // Nothing has ever been applied. The first write is the first version.
        None => Ok(Intent::default()),
    }
}

/// What a write produced.
///
/// The version and its status travel back with the resource, because "the API accepted my
/// edit" and "the gateway is enforcing it" are different facts and this is the only place a
/// caller can learn the second one.
#[derive(Debug, Serialize)]
struct ApplyResult {
    version_id: String,
    hash: String,
    status: ConfigStatus,
    /// Why the version failed, when it did.
    error: Option<String>,
    /// Set when the write was committed, failed verification, and an earlier version was
    /// restored.
    rolled_back_to: Option<String>,
}

/// The applier's failures, mapped to statuses a UI can act on.
///
/// A refused target is the caller's mistake and a 409; an unreadable stored intent is ours
/// and a 500. Collapsing them would tell an operator to retry a request that can never
/// succeed.
pub(crate) fn apply_error(error: ApplyError) -> ApiError {
    match error {
        ApplyError::Store { source } => ApiError::from(source),
        ApplyError::Commit { reason } => ApiError::Conflict { reason },
        ApplyError::Projection { source } => ApiError::BadRequest {
            reason: source.to_string(),
        },
        ApplyError::NothingToRollBackTo => ApiError::Conflict {
            reason: "no version has ever been confirmed applied".to_string(),
        },
        other => ApiError::Internal {
            reason: other.to_string(),
        },
    }
}

/// Run the whole apply for `intent` and report what happened.
///
/// `200` only when the version reached `applied` — that is, when the data plane was read
/// back and found to be enforcing it. Anything else is `409` with the reason, because a 200
/// on a version that failed verification is precisely the "believed-applied" report this
/// projection exists to make impossible.
async fn apply(
    state: &AppState,
    request: &ApiRequest,
    intent: &Intent,
    action: String,
) -> Result<ApiResponse> {
    let actor = caller(request)?;
    let outcome = state
        .applier
        .apply(
            intent,
            &Actor {
                id: Some(actor.user_id.clone()),
                username: actor.username.clone(),
            },
            &action,
            now_sec(),
        )
        .await
        .map_err(apply_error)?;
    let applied = outcome.version.status == ConfigStatus::Applied;
    let mut response = ApiResponse::json(&ApplyResult {
        version_id: outcome.version.id,
        hash: outcome.version.hash,
        status: outcome.version.status,
        error: outcome.version.error,
        rolled_back_to: outcome.rolled_back_to,
    })?;
    if !applied {
        response.status = http::StatusCode::CONFLICT;
    }
    Ok(response)
}

/// Every entry of one category, by name.
pub(crate) async fn list<T: Serialize>(
    state: &AppState,
    pick: fn(&Intent) -> &BTreeMap<String, T>,
) -> Result<ApiResponse> {
    let intent = base_intent(state).await?;
    ApiResponse::json(pick(&intent))
}

/// One entry, or a 404 naming what was looked for.
pub(crate) async fn get<T: Serialize>(
    state: &AppState,
    kind: &str,
    name: &str,
    pick: fn(&Intent) -> &BTreeMap<String, T>,
) -> Result<ApiResponse> {
    let intent = base_intent(state).await?;
    let value = pick(&intent).get(name).ok_or_else(|| ApiError::NotFound {
        kind: kind.to_string(),
        id: name.to_string(),
    })?;
    ApiResponse::json(value)
}

/// Create or replace one entry, then regenerate and apply the whole config.
///
/// Replace rather than merge, and that is the same decision the projection makes one level
/// up: a partial update needs a rule for every absent field, and "absent means unchanged"
/// makes it impossible to clear one. `PUT` with the complete entry has neither problem.
pub(crate) async fn upsert<T: Serialize + DeserializeOwned>(
    state: &AppState,
    request: &ApiRequest,
    kind: &str,
    name: &str,
    pick: fn(&mut Intent) -> &mut BTreeMap<String, T>,
) -> Result<ApiResponse> {
    let value: T = request.json()?;
    let mut intent = base_intent(state).await?;
    let existed = pick(&mut intent).insert(name.to_string(), value).is_some();
    apply(
        state,
        request,
        &intent,
        format!(
            "{kind}.{}:{name}",
            if existed { "update" } else { "create" }
        ),
    )
    .await
}

/// Remove one entry, then regenerate and apply.
///
/// A name that is not there is a 404 rather than a silent success: the projection is total,
/// so a delete that matched nothing would still write a version and an audit row saying
/// something was removed.
pub(crate) async fn remove<T: Serialize>(
    state: &AppState,
    request: &ApiRequest,
    kind: &str,
    name: &str,
    pick: fn(&mut Intent) -> &mut BTreeMap<String, T>,
) -> Result<ApiResponse> {
    let mut intent = base_intent(state).await?;
    if pick(&mut intent).remove(name).is_none() {
        return Err(ApiError::NotFound {
            kind: kind.to_string(),
            id: name.to_string(),
        });
    }
    apply(state, request, &intent, format!("{kind}.delete:{name}")).await
}
