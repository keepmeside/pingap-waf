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

//! Listeners: a socket, its TLS settings, its protocol toggles.
//!
//! Separate from domains because it is shared by them: several domains sit on one listener,
//! and the projection derives each listener's Location list from the domains rather than
//! having an operator maintain it twice. So there is nothing here to set membership with —
//! bind a domain to a listener and the membership follows.

use super::{intent_resource, name};
use crate::{ApiRequest, ApiResponse, AppState, Result};

pub async fn list(
    state: &AppState,
    _request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    intent_resource::list(state, |intent| &intent.listeners).await
}

pub async fn get(
    state: &AppState,
    _request: &ApiRequest,
    params: &[String],
) -> Result<ApiResponse> {
    intent_resource::get(state, "listener", name(params)?, |intent| {
        &intent.listeners
    })
    .await
}

pub async fn put(
    state: &AppState,
    request: &ApiRequest,
    params: &[String],
) -> Result<ApiResponse> {
    intent_resource::upsert(
        state,
        request,
        "listener",
        name(params)?,
        |intent| &mut intent.listeners,
    )
    .await
}

pub async fn delete(
    state: &AppState,
    request: &ApiRequest,
    params: &[String],
) -> Result<ApiResponse> {
    intent_resource::remove(
        state,
        request,
        "listener",
        name(params)?,
        |intent| &mut intent.listeners,
    )
    .await
}
