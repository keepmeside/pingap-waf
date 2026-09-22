use crate::backup::{BackupError, BundleManifest, Result};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::fs;

pub async fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path)
        .await
        .map_err(|source| BackupError::Io { source })?;
    let digest = Sha256::digest(bytes);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

pub async fn verify_bundle_checksums(
    root: &Path,
    manifest: &BundleManifest,
) -> Result<()> {
    for (relative, expected) in &manifest.files {
        let path = root.join(relative);
        let actual = sha256_file(&path).await?;
        if actual != *expected {
            return Err(BackupError::Format {
                message: format!("checksum mismatch for {relative}"),
            });
        }
    }
    Ok(())
}
