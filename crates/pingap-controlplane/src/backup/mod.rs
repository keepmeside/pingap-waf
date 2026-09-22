//! Verifiable control-plane backup bundles.
//!
//! Bundles are represented as a directory while the format is stabilising. It contains canonical
//! config, a store snapshot, and a checksum manifest. Encryption and archive packaging are not
//! silently faked: callers must protect the directory until a key-management contract exists.

mod export;
mod integrity;
mod manifest;
mod restore;
mod validate;

pub use export::{ExportResult, export_bundle};
pub use integrity::{sha256_file, verify_bundle_checksums};
pub use manifest::{BUNDLE_FORMAT_VERSION, BundleManifest};
pub use restore::{RestoreResult, restore_bundle};
pub use validate::{ValidationError, validate_bundle};

#[derive(Debug, snafu::Snafu)]
pub enum BackupError {
    #[snafu(display("backup I/O failed: {source}"))]
    Io { source: std::io::Error },
    #[snafu(display("backup format error: {message}"))]
    Format { message: String },
    #[snafu(display("backup store error: {source}"))]
    Store { source: crate::StoreError },
}

pub type Result<T> = std::result::Result<T, BackupError>;
