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

//! WAF findings, read back.
//!
//! Every parameter is a filter and an unparsable one is ignored rather than refused, for the
//! reason the audit trail gives: these are filters, and answering a malformed `since` with a
//! 400 breaks an operator's bookmarked URL the moment a parameter's shape changes. A request
//! body is different — there, an unknown field means the caller believes they set something
//! they did not.
//!
//! Paging is `until` set to the oldest `created_at` already on screen, not an offset. The
//! table only grows, so an offset shifts under a concurrent insert and the caller sees one
//! finding twice and misses another.

use crate::{ApiRequest, ApiResponse, AppState, Result};
use pingap_controlplane::repository::{TimeRange, WafEventFilter};

/// A filter parameter that is absent, empty, or unparsable — all three mean "not filtering".
///
/// Empty counts as absent because a UI that clears a text input sends `?domain=` rather than
/// omitting the parameter, and treating that as a domain named "" would return nothing and
/// look like the data had gone.
fn optional(request: &ApiRequest, name: &str) -> Option<String> {
    request.param(name).filter(|value| !value.is_empty())
}

fn parsed<T: std::str::FromStr>(request: &ApiRequest, name: &str) -> Option<T> {
    optional(request, name).and_then(|value| value.parse().ok())
}

/// A tri-state flag. Anything unrecognised is absent rather than false, because `?blocked=x`
/// silently meaning "show me the detections" is worse than showing everything.
fn flag(request: &ApiRequest, name: &str) -> Option<bool> {
    match optional(request, name)?.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

pub async fn waf_events(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let filter = WafEventFilter {
        range: TimeRange {
            since: parsed(request, "since"),
            until: parsed(request, "until"),
            limit: parsed(request, "limit"),
        },
        domain: optional(request, "domain"),
        rule_id: parsed(request, "rule_id"),
        category: optional(request, "category"),
        blocked: flag(request, "blocked"),
    };
    let rows = state.store.read_waf_events(filter).await?;
    ApiResponse::json(&rows)
}
