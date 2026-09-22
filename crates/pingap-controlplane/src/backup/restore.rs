use crate::backup::{BackupError, BundleManifest, Result, validate_bundle};
use std::path::{Path, PathBuf};
use tokio::fs;

#[derive(Debug, Clone)]
pub struct RestoreResult {
    pub manifest: BundleManifest,
    pub staged_config: PathBuf,
    pub staged_store: PathBuf,
}

/// Validate and stage a bundle without modifying live state.
pub async fn restore_bundle(
    root: impl AsRef<Path>,
    staging: impl AsRef<Path>,
) -> Result<RestoreResult> {
    let root = root.as_ref();
    let manifest = validate_bundle(root).await?;
    let staging = staging.as_ref();
    fs::create_dir_all(staging)
        .await
        .map_err(|source| BackupError::Io { source })?;
    let staged_config = staging.join("config.toml");
    let staged_store = staging.join("store.sqlite");
    fs::copy(root.join("config.toml"), &staged_config)
        .await
        .map_err(|source| BackupError::Io { source })?;
    fs::copy(root.join("store.sqlite"), &staged_store)
        .await
        .map_err(|source| BackupError::Io { source })?;
    Ok(RestoreResult {
        manifest,
        staged_config,
        staged_store,
    })
}
