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

//! Upstreams: backends, load balancing, health checks.
//!
//! `weight` is a field of each backend rather than part of its address string. pingap reads
//! `"10.0.0.1:8080 5"` — address and weight space-separated — and letting an operator type
//! that would let them type `"10.0.0.1:8080 five"`, which projects into a config the
//! discovery layer silently reads as weight 1. The projection formats it; the API does not
//! accept it pre-formatted.

use super::{intent_resource, name};
use crate::{ApiRequest, ApiResponse, AppState, Result};

pub async fn list(
    state: &AppState,
    _request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    intent_resource::list(state, |intent| &intent.upstreams).await
}

pub async fn get(
    state: &AppState,
    _request: &ApiRequest,
    params: &[String],
) -> Result<ApiResponse> {
    intent_resource::get(state, "upstream", name(params)?, |intent| {
        &intent.upstreams
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
        "upstream",
        name(params)?,
        |intent| &mut intent.upstreams,
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
        "upstream",
        name(params)?,
        |intent| &mut intent.upstreams,
    )
    .await
}
