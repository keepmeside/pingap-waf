use crate::backup::{
    BUNDLE_FORMAT_VERSION, BackupError, BundleManifest, Result, sha256_file,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tokio::fs;

#[derive(Debug, Clone)]
pub struct ExportResult {
    pub root: PathBuf,
    pub manifest: BundleManifest,
}

#[derive(Serialize)]
struct ManifestFile<'a> {
    manifest: &'a BundleManifest,
}

/// Export canonical config and a point-in-time store file into a bundle directory.
///
/// The database copy is conservative: this function copies a caller-provided snapshot. It does
/// not claim to provide `VACUUM INTO`; obtaining that snapshot requires the store's serialised
/// writer connection, which is not exposed by the repository API.
pub async fn export_bundle(
    root: impl AsRef<Path>,
    canonical_config: &str,
    store_snapshot: impl AsRef<Path>,
    product_version: impl Into<String>,
    intent_schema_version: u32,
    config_version: Option<String>,
    created_at: i64,
) -> Result<ExportResult> {
    let root = root.as_ref();
    fs::create_dir_all(root)
        .await
        .map_err(|source| BackupError::Io { source })?;
    let config_path = root.join("config.toml");
    let store_path = root.join("store.sqlite");
    fs::write(&config_path, canonical_config)
        .await
        .map_err(|source| BackupError::Io { source })?;
    fs::copy(store_snapshot.as_ref(), &store_path)
        .await
        .map_err(|source| BackupError::Io { source })?;
    let mut files = BTreeMap::new();
    files.insert("config.toml".to_string(), sha256_file(&config_path).await?);
    files.insert("store.sqlite".to_string(), sha256_file(&store_path).await?);
    let manifest = BundleManifest {
        format_version: BUNDLE_FORMAT_VERSION,
        product_version: product_version.into(),
        intent_schema_version,
        config_version,
        created_at,
        encrypted: false,
        files,
    };
    let bytes = serde_json::to_vec_pretty(&ManifestFile {
        manifest: &manifest,
    })
    .map_err(|e| BackupError::Format {
        message: e.to_string(),
    })?;
    fs::write(root.join("manifest.json"), bytes)
        .await
        .map_err(|source| BackupError::Io { source })?;
    Ok(ExportResult {
        root: root.to_path_buf(),
        manifest,
    })
}
