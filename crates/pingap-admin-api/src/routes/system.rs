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

//! Liveness, for an unauthenticated caller.

use crate::{ApiRequest, ApiResponse, AppState, Result};
use serde::Serialize;

/// What `/health` says, and deliberately all it says.
///
/// No version, no build, no store path, no error text. This is the one route reachable
/// without a session, so anything in it is public: a version string tells an unauthenticated
/// scanner which CVEs to try, and a store error message names a filesystem path.
///
/// `store` is a two-value state rather than a reason, because a load balancer needs to know
/// whether this node can accept admin traffic and nothing more. The reason an operator needs
/// is on the authenticated route.
#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
    store: &'static str,
}

pub async fn health(
    state: &AppState,
    _request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    // The gateway is required to serve with the control-plane store down, so an unreachable
    // store is not an unhealthy gateway. `status` answers for the process; `store` answers
    // for the admin surface, and a caller that conflates them would take a serving node out
    // of rotation over a database file.
    let store = match state.store.health().await {
        Ok(()) => "available",
        Err(_) => "unavailable",
    };
    ApiResponse::json(&Health {
        status: "ok",
        store,
    })
}
