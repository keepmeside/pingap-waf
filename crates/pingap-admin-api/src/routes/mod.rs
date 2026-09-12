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

//! The handlers.
//!
//! One module per resource, and each one is only reached after `router::dispatch` has
//! decided access — so a handler never re-checks the role, and never has to. What a handler
//! does check is *ownership*: `Capability::ViewOwnSessions` says a viewer may list sessions,
//! and it is the handler that makes sure the ones listed are their own.

pub mod account;
pub mod activity;
pub mod config_versions;
pub mod domains;
pub(crate) mod intent_resource;
pub mod listeners;
pub mod policies;
pub mod system;
pub mod upstreams;
pub mod users;

use crate::{ApiError, Caller, Result};

/// The first captured path segment, which for every resource route is its name.
pub(crate) fn name(params: &[String]) -> Result<&str> {
    params
        .first()
        .map(String::as_str)
        .ok_or_else(|| ApiError::BadRequest {
            reason: "no name in the path".to_string(),
        })
}

/// The caller, for a route the router already required one on.
///
/// A handler reaching for `request.caller.expect(..)` would panic on a route someone later
/// marked `Public`; this turns that into a 401 the caller can act on.
pub(crate) fn caller(request: &crate::ApiRequest) -> Result<&Caller> {
    request.caller.as_ref().ok_or(ApiError::Unauthenticated)
}

/// Wall-clock seconds, for the timestamps the store records.
///
/// The store takes `now` as an argument everywhere rather than reading the clock itself,
/// which is what lets its own tests pin time. The API is the caller that supplies the real
/// one.
pub(crate) fn now_sec() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}
