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

//! Domains: the composite resource operators actually think in.
//!
//! A domain is a hostname, where its traffic goes, and what policy applies to it. pingap has
//! no such object — it has a Server, a Location and an Upstream — and this does not add one
//! to the data plane. The domain is intent; `docs/domain-model.md` is the field-by-field
//! contract, and `projection::generate` is what turns it into config.
//!
//! Every field of the request body is a field of `projection::Domain`, so a key the contract
//! does not name is refused by deserialisation rather than accepted and dropped. The body is
//! the whole domain: `PUT` replaces, because "absent means unchanged" makes a field
//! impossible to clear.

use super::{intent_resource, name};
use crate::{ApiRequest, ApiResponse, AppState, Result};

pub async fn list(
    state: &AppState,
    _request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    intent_resource::list(state, |intent| &intent.domains).await
}

pub async fn get(
    state: &AppState,
    _request: &ApiRequest,
    params: &[String],
) -> Result<ApiResponse> {
    intent_resource::get(state, "domain", name(params)?, |intent| {
        &intent.domains
    })
    .await
}

pub async fn put(
    state: &AppState,
    request: &ApiRequest,
    params: &[String],
) -> Result<ApiResponse> {
    intent_resource::upsert(state, request, "domain", name(params)?, |intent| {
        &mut intent.domains
    })
    .await
}

pub async fn delete(
    state: &AppState,
    request: &ApiRequest,
    params: &[String],
) -> Result<ApiResponse> {
    intent_resource::remove(state, request, "domain", name(params)?, |intent| {
        &mut intent.domains
    })
    .await
}
