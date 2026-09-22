use crate::backup::{
    BackupError, BundleManifest, Result, verify_bundle_checksums,
};
use std::path::Path;
use tokio::fs;

#[derive(Debug, snafu::Snafu)]
pub enum ValidationError {
    #[snafu(display("unsupported bundle format version {version}"))]
    Format { version: u32 },
    #[snafu(display(
        "bundle is marked encrypted but no decryptor is configured"
    ))]
    Encrypted,
}

pub async fn validate_bundle(root: &Path) -> Result<BundleManifest> {
    let bytes = fs::read(root.join("manifest.json"))
        .await
        .map_err(|source| BackupError::Io { source })?;
    let wrapper: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| BackupError::Format {
            message: e.to_string(),
        })?;
    let manifest: BundleManifest =
        serde_json::from_value(wrapper.get("manifest").cloned().ok_or_else(
            || BackupError::Format {
                message: "manifest.json missing manifest".into(),
            },
        )?)
        .map_err(|e| BackupError::Format {
            message: e.to_string(),
        })?;
    if manifest.format_version != crate::backup::BUNDLE_FORMAT_VERSION {
        return Err(BackupError::Format {
            message: ValidationError::Format {
                version: manifest.format_version,
            }
            .to_string(),
        });
    }
    if manifest.encrypted {
        return Err(BackupError::Format {
            message: ValidationError::Encrypted.to_string(),
        });
    }
    verify_bundle_checksums(root, &manifest).await?;
    Ok(manifest)
}
