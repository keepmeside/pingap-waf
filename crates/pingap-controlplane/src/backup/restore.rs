use crate::backup::validate::validate_bundle_for_restore;
use crate::backup::{BackupError, BundleManifest, Result, validate_bundle};
use pingap_util::{aes_decrypt, base64_decode};
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

/// Validate and stage an encrypted bundle using the supplied key.
pub async fn restore_bundle_with_key(
    root: impl AsRef<Path>,
    staging: impl AsRef<Path>,
    key: &str,
) -> Result<RestoreResult> {
    if key.is_empty() {
        return Err(BackupError::Format {
            message: "decryption key must not be empty".into(),
        });
    }
    let root = root.as_ref();
    let manifest = validate_bundle_for_restore(root).await?;
    if !manifest.encrypted {
        return Err(BackupError::Format {
            message: "bundle is not encrypted".into(),
        });
    }
    let config_cipher = fs::read_to_string(root.join("config.toml"))
        .await
        .map_err(|source| BackupError::Io { source })?;
    let store_cipher = fs::read_to_string(root.join("store.sqlite"))
        .await
        .map_err(|source| BackupError::Io { source })?;
    let config =
        aes_decrypt(key, &config_cipher).map_err(|e| BackupError::Format {
            message: format!("decrypting config: {e}"),
        })?;
    let encoded =
        aes_decrypt(key, &store_cipher).map_err(|e| BackupError::Format {
            message: format!("decrypting store: {e}"),
        })?;
    let store = base64_decode(encoded).map_err(|e| BackupError::Format {
        message: format!("decoding store: {e}"),
    })?;
    let staging = staging.as_ref();
    fs::create_dir_all(staging)
        .await
        .map_err(|source| BackupError::Io { source })?;
    let staged_config = staging.join("config.toml");
    let staged_store = staging.join("store.sqlite");
    fs::write(&staged_config, config)
        .await
        .map_err(|source| BackupError::Io { source })?;
    fs::write(&staged_store, store)
        .await
        .map_err(|source| BackupError::Io { source })?;
    Ok(RestoreResult {
        manifest,
        staged_config,
        staged_store,
    })
}
