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

//! Backup: list schedules and bundles, run an export, stage a restore.
//!
//! The bundle format and its integrity model live in `pingap-controlplane::backup`; this
//! module is the API surface over it. Two decisions worth stating:
//!
//! - **Export uses the canonical projection, not the on-disk config.** A backup of drifted
//!   config silently preserves the drift; a backup of *intent* regenerates the same bytes
//!   the data plane is supposed to be enforcing, so what is saved is what should be live.
//! - **Restore is staged, never in-place.** `restore_bundle` validates checksums and copies
//!   to a staging dir but does not swap live state — the live-swap boundary is a separate,
//!   deliberate step, and a destructive one.

use super::{audit, caller, now_sec};
use crate::{ApiError, ApiRequest, ApiResponse, AppState, Result};
use pingap_controlplane::backup::{
    export_bundle, restore_bundle, sha256_file, validate_bundle,
};
use pingap_controlplane::{NewBackupFile, NewBackupSchedule};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Where export writes and restore reads. A missing directory is an operator-facing error
/// naming the setting, not a 500 that reads like a crash.
fn backup_dir(state: &AppState) -> Result<PathBuf> {
    state.backup_dir.clone().ok_or_else(|| ApiError::Unavailable {
        reason: "no backup directory is configured; set `backup_dir` on the admin plugin \
                 to enable export and restore"
            .to_string(),
    })
}

#[derive(Debug, Serialize)]
struct BackupView {
    schedules: Vec<pingap_controlplane::BackupScheduleRecord>,
    files: Vec<pingap_controlplane::BackupFileRecord>,
}

/// `GET /backup` — the schedule registry and the bundle inventory together.
///
/// Returned as one value rather than two reads because a dashboard shows them side by side,
/// and two calls could disagree about a schedule that was deleted between them.
pub async fn list(
    state: &AppState,
    _request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let schedules = state.store.list_backup_schedules().await?;
    let files = state.store.list_backup_files().await?;
    ApiResponse::json(&BackupView { schedules, files })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewSchedule {
    name: String,
    cron: String,
    retain: i64,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// `POST /backup/schedules` — register a recurring export.
///
/// A schedule is intent, not a running job: the scheduler that honours it is the
/// control-plane's, and creating the row is what makes it run. A duplicate `name` is a
/// conflict — the schedule is keyed by name so an operator can address it.
pub async fn create_schedule(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let actor = caller(request)?;
    let body: NewSchedule = request.json()?;
    if body.name.trim().is_empty() || body.cron.trim().is_empty() {
        return Err(ApiError::BadRequest {
            reason: "schedule name and cron expression are required"
                .to_string(),
        });
    }
    if body.retain < 1 {
        return Err(ApiError::BadRequest {
            reason: "retain must keep at least one bundle".to_string(),
        });
    }
    let schedule = state
        .store
        .create_backup_schedule(
            NewBackupSchedule {
                name: body.name.trim().to_string(),
                cron: body.cron.trim().to_string(),
                retain: body.retain,
                enabled: body.enabled,
            },
            now_sec(),
        )
        .await?;
    audit(
        state,
        actor,
        "backup.schedule.create",
        &schedule.id,
        now_sec(),
    )
    .await?;
    ApiResponse::json(&schedule)
}

/// `DELETE /backup/schedules/:id` — stop a recurring export.
pub async fn delete_schedule(
    state: &AppState,
    request: &ApiRequest,
    params: &[String],
) -> Result<ApiResponse> {
    let actor = caller(request)?;
    let id = super::name(params)?;
    state.store.delete_backup_schedule(id).await?;
    audit(state, actor, "backup.schedule.delete", id, now_sec()).await?;
    Ok(ApiResponse::no_content())
}

/// `POST /backup/export` — write a bundle now.
///
/// Exports the canonical config plus a snapshot of the store file. The snapshot is a plain
/// file copy of `TursoStore::path()`: conservative in that it reads the live file rather
/// than `VACUUM INTO`, which is documented in `export_bundle` — the consistent-snapshot
/// guarantee requires the serialised writer, and the pause it imposes is the documented
/// trade-off, not a hidden one.
pub async fn export(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let actor = caller(request)?;
    let dir = backup_dir(state)?;

    // The canonical form of the *running* config: what should be enforced, not whatever
    // is on disk. `config_source` is the same handle drift detection reads, so the two
    // cannot disagree about what "current" means.
    let source = state.config_source.as_ref().ok_or_else(|| {
        ApiError::Unavailable {
            reason: "no config source is wired, so there is no canonical config to export"
                .to_string(),
        }
    })?;
    let current = source
        .current()
        .await
        .map_err(|reason| ApiError::Unavailable { reason })?;
    let canonical = pingap_controlplane::projection::canonical_toml(&current)
        .map_err(|e| ApiError::Internal {
        reason: format!("could not serialise the canonical config: {e}"),
    })?;

    let now = now_sec();
    let store_path = store_file(state)?;
    let bundle_root = dir.join(format!("backup-{now}"));

    // The manifest is the integrity contract: it records which config version the bundle
    // was cut from, and the checksums the restore re-verifies before staging anything.
    let exported = export_bundle(
        &bundle_root,
        &canonical,
        &store_path,
        env!("CARGO_PKG_VERSION"),
        pingap_controlplane::schema::LATEST_VERSION,
        applied_version_id(state).await,
        now,
    )
    .await
    .map_err(|e| ApiError::Internal {
        reason: format!("the export could not be written: {e}"),
    })?;

    // Record the bundle so the listing and the retention sweep agree on what exists. The
    // checksum is the manifest's own, recomputed over the file the export just wrote.
    let sha = sha256_file(&exported.root.join("manifest.json"))
        .await
        .map_err(|e| ApiError::Internal {
            reason: format!(
                "the bundle was written but could not be hashed: {e}"
            ),
        })?;
    let size_bytes = bundle_size(&exported.root).await;
    let file = state
        .store
        .record_backup_file(
            NewBackupFile {
                schedule_id: None,
                path: bundle_root.to_string_lossy().to_string(),
                size_bytes,
                sha256: sha,
            },
            now,
        )
        .await?;
    audit(state, actor, "backup.export", &file.id, now).await?;
    ApiResponse::json(&file)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreRequest {
    /// The bundle root to restore from — a path the operator names. Required, and named
    /// rather than defaulted, because restoring the wrong bundle is a destructive choice.
    path: String,
}

/// `POST /backup/restore` — validate and stage a bundle.
///
/// Staged, not applied: the manifest is verified, checksums re-checked, and the payload
/// copied to a staging directory, but no live state is touched. The caller is told where
/// the staged files are so the apply step is a separate, deliberate and destructive
/// decision — and so a bundle that fails validation never reaches the live paths.
pub async fn restore(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let actor = caller(request)?;
    let dir = backup_dir(state)?;
    let body: RestoreRequest = request.json()?;
    let root = PathBuf::from(body.path.trim());
    if root.as_os_str().is_empty() {
        return Err(ApiError::BadRequest {
            reason: "a bundle `path` to restore from is required".to_string(),
        });
    }

    // Verify before staging: a corrupt or tampered bundle is refused at the checksum, not
    // after it has already been copied somewhere it could be mistaken for live state.
    validate_bundle(&root)
        .await
        .map_err(|e| ApiError::BadRequest {
            reason: format!("the bundle failed validation: {e}"),
        })?;

    let staging = dir.join(format!("restore-{}", now_sec()));
    let result = restore_bundle(&root, &staging).await.map_err(|e| {
        ApiError::Internal {
            reason: format!("the bundle could not be staged: {e}"),
        }
    })?;
    audit(state, actor, "backup.restore", &body.path, now_sec()).await?;
    ApiResponse::json(&serde_json::json!({
        "staged": true,
        "staged_config": result.staged_config.to_string_lossy(),
        "staged_store": result.staged_store.to_string_lossy(),
        "format_version": result.manifest.format_version,
    }))
}

/// The store's backing file, for the snapshot the export copies.
fn store_file(state: &AppState) -> Result<PathBuf> {
    // `None` is an in-memory store — there is no file to copy, so an export over it is
    // refused rather than producing a bundle with no store in it.
    state.store_file.clone().ok_or_else(|| ApiError::Unavailable {
        reason: "the control-plane store is in-memory; there is no file to snapshot"
            .to_string(),
    })
}

/// The newest applied config version, for the manifest — so a restore can be checked
/// against the schema boundary it was written under.
async fn applied_version_id(state: &AppState) -> Option<String> {
    state
        .store
        .latest_applied_config_version()
        .await
        .ok()
        .flatten()
        .map(|v| v.id)
}

/// Sum the bundle's files for the inventory row. A directory the export half-wrote shows a
/// smaller number than it should, which is fine — the manifest checksums are the integrity
/// check; this is bookkeeping.
async fn bundle_size(root: &std::path::Path) -> i64 {
    let mut total = 0i64;
    let mut entries = match tokio::fs::read_dir(root).await {
        Ok(entries) => entries,
        Err(_) => return 0,
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        if let Ok(meta) = entry.metadata().await {
            total += meta.len() as i64;
        }
    }
    total
}
