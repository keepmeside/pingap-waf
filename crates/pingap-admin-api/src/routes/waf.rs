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

//! What the WAF in *this* build can enforce, as a read.
//!
//! Not an intent resource: the category table is compiled in, so there is nothing to store
//! and nothing to project. What a profile actually sets — per-category mode, paranoia,
//! anomaly threshold, custom rules — is that profile's config table, written through
//! `/policies/waf:<profile>` like any other, and which domain uses it is that domain's
//! `policies` list. This route is the vocabulary those two need in order to be filled in
//! correctly.
//!
//! The load-bearing field is `modes`. A response-side category cannot block: the body hook's
//! result type has no `Respond` variant and the status line is already downstream by the time
//! it runs, so `redact` is the strongest thing it can do. That is why the engine has two mode
//! types rather than one, and a UI that offers `block` for `data_leakage` is offering a write
//! the projection will refuse — or worse, one it accepts and silently treats as `redact`,
//! leaving an operator believing a leak is suppressed when it is only rewritten. So the set is
//! read off `RequestMode::ALL` and `ResponseMode::ALL` and never spelled out here.
//!
//! `crs_group` and `crs_file` are a **lineage mapping, not a compatibility claim**. Nothing
//! here promises an arbitrary CRS `.conf` loads; the labels exist so an operator who knows CRS
//! recognises what a category covers. `docs/waf-category-mapping.md` is the published form of
//! the same table.

use crate::{ApiRequest, ApiResponse, AppState, Result};
use pingap_waf::categories::Category;
use pingap_waf::config::{RequestMode, ResponseMode};
use serde::Serialize;

/// One rule category and what may be done with it.
#[derive(Debug, Serialize)]
struct CategoryView {
    /// The key a profile's `categories` table uses, and the config spelling.
    key: &'static str,
    /// The CRS group this category's rules descend from.
    crs_group: u16,
    /// The upstream CRS rule file the lineage traces to.
    crs_file: &'static str,
    /// Evaluates on the way out rather than the way in, and so cannot deny.
    response_side: bool,
    /// Native rule IDs for this category. Derived from the CRS group so an ID is
    /// self-describing — `942_017` is visibly a SQLi rule — and the ranges cannot overlap
    /// because the groups are distinct, which the engine's own tests assert.
    id_range: [u32; 2],
    /// Every mode this category accepts, in increasing strictness.
    modes: Vec<&'static str>,
}

pub async fn categories(
    _state: &AppState,
    _request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let view: Vec<CategoryView> = Category::ALL
        .iter()
        .map(|category| {
            let (low, high) = category.id_range();
            CategoryView {
                key: category.key(),
                crs_group: category.crs_group(),
                crs_file: category.crs_file(),
                response_side: category.is_response_side(),
                id_range: [low, high],
                modes: if category.is_response_side() {
                    ResponseMode::ALL.iter().map(|mode| mode.key()).collect()
                } else {
                    RequestMode::ALL.iter().map(|mode| mode.key()).collect()
                },
            }
        })
        .collect();
    ApiResponse::json(&view)
}
