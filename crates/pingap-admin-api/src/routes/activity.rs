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

//! The audit trail, read-only.

use crate::{ApiRequest, ApiResponse, AppState, Result};
use pingap_controlplane::repository::TimeRange;

/// `since`, `until` and `limit`, all optional.
///
/// An unparseable value is ignored rather than refused, and that is the one place in this
/// crate where that is right: the range is a *filter*, and answering a malformed `since` with
/// 400 would break an operator's bookmarked URL when the shape of the parameter changed.
/// Compare the request DTOs, where an unknown field means the caller believes they set
/// something they did not.
pub async fn list(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let range = TimeRange {
        since: request.param("since").and_then(|v| v.parse().ok()),
        until: request.param("until").and_then(|v| v.parse().ok()),
        limit: request.param("limit").and_then(|v| v.parse().ok()),
    };
    let rows = state.store.read_activity(range).await?;
    ApiResponse::json(&rows)
}
