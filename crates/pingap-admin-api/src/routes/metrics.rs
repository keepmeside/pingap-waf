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

//! Stored rollups, not a second aggregation of raw findings on each dashboard poll.

use crate::{ApiError, ApiRequest, ApiResponse, AppState, Result};
use pingap_controlplane::projection::{Drift, DriftDetector};
use pingap_controlplane::repository::{PerformanceMetricRecord, TimeRange};
use serde_json::{Value, json};

fn number<T: std::str::FromStr>(
    request: &ApiRequest,
    key: &str,
) -> Result<Option<T>> {
    request
        .param(key)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse().map_err(|_| ApiError::BadRequest {
                reason: format!("invalid {key}"),
            })
        })
        .transpose()
}

async fn read(
    state: &AppState,
    request: &ApiRequest,
) -> Result<Vec<PerformanceMetricRecord>> {
    let range = TimeRange {
        since: number(request, "since")?,
        until: number(request, "until")?,
        limit: Some(number(request, "limit")?.unwrap_or(100)),
    };
    if matches!((range.since, range.until), (Some(since), Some(until)) if since > until)
    {
        return Err(ApiError::BadRequest {
            reason: "since must not exceed until".to_string(),
        });
    }
    if !matches!(range.limit, Some(1..=1000)) {
        return Err(ApiError::BadRequest {
            reason: "limit must be between 1 and 1000".to_string(),
        });
    }
    let metric = request.param("metric").filter(|value| !value.is_empty());
    Ok(state
        .store
        .read_performance_metrics(metric.as_deref(), range)
        .await?)
}

pub async fn performance(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    ApiResponse::json(&read(state, request).await?)
}

pub async fn dashboard(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let metrics = read(state, request).await?;
    ApiResponse::json(&json!({"metrics": metrics, "drift": drift(state).await}))
}

/// The detection stack's published snapshots, assembled by the provider the
/// binary injected. The provider owns the vocabulary — this crate never names
/// a counter — so the handler is one access decision and one call.
pub async fn detection(
    state: &AppState,
    _request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let Some(source) = &state.detection_metrics else {
        // No provider wired in means the detection stack is not part of this
        // deployment. `Unavailable` rather than an empty object: `{}` would
        // read as "nothing detected", which is a different and false claim.
        return Err(ApiError::Unavailable {
            reason: "the detection metrics provider is not wired into this \
                     deployment, so there is nothing to publish"
                .to_string(),
        });
    };
    ApiResponse::json(&source())
}

async fn drift(state: &AppState) -> Value {
    let Some(source) = &state.config_source else {
        return json!({"status": "unavailable"});
    };
    // No notifier: reading a dashboard must not fire alerts or correct a manual edit.
    match DriftDetector::new(state.store.clone(), source.clone(), None)
        .check()
        .await
    {
        Ok(Drift::NoBaseline) => json!({"status": "no_baseline"}),
        Ok(Drift::None { version_id }) => {
            json!({"status": "in_sync", "version_id": version_id})
        },
        Ok(Drift::Detected {
            version_id,
            expected_hash,
            actual_hash,
            differing,
        }) => json!({
            "status": "detected", "version_id": version_id,
            "expected_hash": expected_hash, "actual_hash": actual_hash, "differing": differing,
        }),
        // Parser errors can carry raw config, including secrets. Unknown is not clean.
        Err(_) => json!({"status": "unavailable"}),
    }
}
