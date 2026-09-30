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

//! The node inventory: the operator-facing half of clustering.
//!
//! Reads come from [`ClusterInventory`], which is backed by the config `Storage` — etcd in
//! a real deployment, a file in a single-node one. The heartbeat lives on `Storage`, not on
//! the control-plane store, because it is keyed state shared between peers rather than a row
//! in the audit database. A node keeps serving traffic with etcd down, so a missed heartbeat
//! is a cluster-degraded signal, not a process failure — the inventory reports it as
//! offline, it does not take the node out of rotation.

use super::now_sec;
use crate::{ApiError, ApiRequest, ApiResponse, AppState, Result};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct NodeView {
    node_id: String,
    version: String,
    config_version: Option<String>,
    config_hash: Option<String>,
    last_seen: i64,
    /// `healthy` | `stale` | `drifted` | `offline` — derived from `last_seen` against the
    /// liveness threshold and from whether the applied config matches the newest committed
    /// one. The two are different conditions: stale is convergence lag, drifted is tampering
    /// or a partial write, and collapsing them is how "still on the old version" reads as
    /// "compromised".
    status: &'static str,
    cpu_millis: Option<u64>,
    memory_bytes: Option<u64>,
}

fn status_key(
    status: pingap_controlplane::cluster::NodeStatus,
) -> &'static str {
    use pingap_controlplane::cluster::NodeStatus::*;
    match status {
        Healthy => "healthy",
        Offline => "offline",
        Stale => "stale",
        Drifted => "drifted",
    }
}

/// `GET /nodes` — every peer the inventory knows, newest-offline-last ordering by node id.
///
/// The expected version and hash are the newest *applied* config: a peer still on an older
/// committed version reads `stale`, one whose on-disk hash diverged reads `drifted`. The
/// comparison is against what was confirmed enforcing, not what was last written — a
/// committed-but-unverified version is not a thing a peer is expected to be running.
pub async fn list(
    state: &AppState,
    _request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let Some(cluster) = &state.cluster else {
        // No shared backend means no peers to inventory. `Unavailable` rather than an empty
        // list: a deployment on a single node should not present "zero peers" as a healthy
        // cluster state, and an operator told "no nodes" would read it as a reaping bug.
        return Err(ApiError::Unavailable {
            reason:
                "no shared config backend is configured, so there is no peer \
                     inventory to read"
                    .to_string(),
        });
    };

    // The newest applied version is what "in sync" is measured against. `None` — nothing
    // has ever been committed — means every live peer is healthy by definition, and
    // `read` treats a `None` expectation as "no expected value to diverge from".
    let applied = state.store.latest_applied_config_version().await?;
    let expected_version = applied.as_ref().map(|v| v.id.as_str());
    let expected_hash = applied.as_ref().map(|v| v.hash.as_str());

    let inventory = cluster
        .read(now_sec(), expected_version, expected_hash)
        .await
        .map_err(|reason| ApiError::Unavailable { reason })?;

    let view: Vec<NodeView> = inventory
        .into_iter()
        .map(|item| NodeView {
            node_id: item.heartbeat.node_id,
            version: item.heartbeat.version,
            config_version: item.heartbeat.config_version,
            config_hash: item.heartbeat.config_hash,
            last_seen: item.heartbeat.last_seen,
            status: status_key(item.status),
            cpu_millis: item.heartbeat.resource_usage.cpu_millis,
            memory_bytes: item.heartbeat.resource_usage.memory_bytes,
        })
        .collect();
    ApiResponse::json(&view)
}
