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

//! Policy profiles: WAF, ACL and bot, under one route because they are one map.
//!
//! A profile is named `category:profile` — `waf:strict`, `acl:edge` — and that naming is the
//! isolation mechanism, not a convention. A plugin instance is process-global and keyed by
//! its config-entry name, so two domains that must count independently have to bind two
//! *different* profiles. One route over the whole map keeps that visible; a `/waf/profiles`
//! route would suggest the category owns a namespace it does not.
//!
//! The body is the plugin's own config table, uninterpreted here: each plugin validates its
//! own parameters, and the projection's gate asks the real `PluginFactory` whether the table
//! constructs before anything is committed. A profile whose regex is quadratic, whose
//! paranoia is out of range, or whose category this build does not have is refused there —
//! with the reason — rather than accepted and silently absent at reload.

use super::{intent_resource, name};
use crate::{ApiError, ApiRequest, ApiResponse, AppState, Result};

/// Profiles are keyed `category:profile`, and both halves must be there.
///
/// Checked here rather than left to the projection: `generate` would accept `strict` as a
/// key and emit a plugin entry no policy binding can name, so the domain that was supposed
/// to use it would project with an empty plugin list — a Location serving unfiltered traffic
/// while the control plane reported a profile attached.
fn profile_name(params: &[String]) -> Result<&str> {
    let name = name(params)?;
    let Some((category, profile)) = name.split_once(':') else {
        return Err(ApiError::BadRequest {
            reason: format!(
                "`{name}` is not a profile name: it must be `category:profile`, \
                 for example `waf:strict`"
            ),
        });
    };
    if category.is_empty() || profile.is_empty() {
        return Err(ApiError::BadRequest {
            reason: format!("`{name}` has an empty category or profile"),
        });
    }
    Ok(name)
}

pub async fn list(
    state: &AppState,
    _request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    intent_resource::list(state, |intent| &intent.policies).await
}

pub async fn get(
    state: &AppState,
    _request: &ApiRequest,
    params: &[String],
) -> Result<ApiResponse> {
    intent_resource::get(state, "policy", profile_name(params)?, |intent| {
        &intent.policies
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
        "policy",
        profile_name(params)?,
        |intent| &mut intent.policies,
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
        "policy",
        profile_name(params)?,
        |intent| &mut intent.policies,
    )
    .await
}
