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

//! The admin API: one enumerable route table, one access decision.
//!
//! Mounted into the existing admin plugin rather than served by a second HTTP server, so
//! the admin surface stays inside the one process and one binary. `src/plugin/admin.rs`
//! authenticates, builds an [`ApiRequest`], and hands it to [`dispatch`].
//!
//! The crate holds no pingora types on purpose. Every route is therefore reachable from a
//! test with no listener and no socket, which is what makes the RBAC gate an enumeration
//! over the real table rather than a sample of it.
//!
//! Config-shaped resources go through the config projection and never write config
//! directly; control-plane-only resources (users, sessions, audit) are read and written
//! against the store. A handler that writes config outside the projection breaks
//! determinism, drift detection and rollback at once.

mod error;
mod request;
mod router;
pub mod routes;

pub use error::{ApiError, Result};
pub use request::{ApiRequest, ApiResponse, Caller};
pub use router::{Access, Handler, Route, dispatch, table};

use pingap_controlplane::ControlPlaneStore;
use pingap_controlplane::projection::{Applier, ConfigSource};
use pingap_controlplane::{AuthError, TotpGuard};
use std::sync::Arc;

/// What every handler is given.
///
/// The store and the applier are supplied by the binary. The store is the control plane's own
/// state; the applier is the only way config is written, and holding it here rather than a
/// `ConfigManager` is what makes "no handler writes config directly" a property of the type
/// rather than a rule someone has to remember.
///
/// The second-factor pair is supplied rather than created here, and that is the part worth
/// stating. A `TotpGuard` keeps the set of codes it has already spent, so a second instance
/// would keep a second set and a code consumed at login would still be good for a disable —
/// the replay protection would look present and be per-call-site. The encryption key comes
/// with it because it is the same deployment fact: which key the stored secrets were sealed
/// with.
pub struct AppState {
    pub store: Arc<dyn ControlPlaneStore>,
    pub applier: Arc<Applier>,
    pub(crate) config_source: Option<Arc<dyn ConfigSource>>,
    /// The peer inventory over the config `Storage` — the etcd heartbeat, not the Turso
    /// store. `None` where there is no shared backend to read, and `/nodes` says so rather
    /// than reporting an empty cluster as if it were a real one.
    pub(crate) cluster:
        Option<Arc<pingap_controlplane::cluster::ClusterInventory>>,
    /// Where export writes bundles and where restore reads them. `None` when the deployment
    /// set no backup directory; the route answers `Unavailable` naming the setting rather
    /// than inventing a path the operator never agreed to.
    pub(crate) backup_dir: Option<std::path::PathBuf>,
    /// The store's backing file, for the snapshot an export copies. `None` for an in-memory
    /// store — there is no file to copy, and exporting one would produce a bundle with no
    /// store in it, which reads as success while being empty.
    pub(crate) store_file: Option<std::path::PathBuf>,
    totp: Arc<TotpGuard>,
    /// Private and exposed only as `Option<&str>`, because it is the one secret this crate
    /// holds. A `pub` field would put it in every struct literal and every debug print.
    totp_key: Option<String>,
}

impl AppState {
    pub fn new(
        store: Arc<dyn ControlPlaneStore>,
        applier: Arc<Applier>,
        totp: Arc<TotpGuard>,
        totp_key: Option<String>,
    ) -> Self {
        Self {
            store,
            applier,
            config_source: None,
            cluster: None,
            backup_dir: None,
            store_file: None,
            totp,
            totp_key,
        }
    }

    /// Drift reads storage, never the last config the process already knows about.
    pub fn with_config_source(mut self, source: Arc<dyn ConfigSource>) -> Self {
        self.config_source = Some(source);
        self
    }

    /// The peer inventory, when the deployment runs on a shared backend.
    pub fn with_cluster(
        mut self,
        cluster: Arc<pingap_controlplane::cluster::ClusterInventory>,
    ) -> Self {
        self.cluster = Some(cluster);
        self
    }

    /// The directory export writes to and restore reads from.
    pub fn with_backup_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.backup_dir = Some(dir);
        self
    }

    /// The directory, when the deployment configured one — the `Option`-carrying form so a
    /// builder can pass the setting straight through without a branch.
    pub fn with_optional_backup_dir(
        mut self,
        dir: Option<std::path::PathBuf>,
    ) -> Self {
        self.backup_dir = dir;
        self
    }

    /// The store's backing file, for export to snapshot.
    pub fn with_store_file(mut self, path: std::path::PathBuf) -> Self {
        self.store_file = Some(path);
        self
    }

    /// The guard that spends a code, shared with the login path.
    pub(crate) fn totp(&self) -> &TotpGuard {
        &self.totp
    }

    /// Seal a freshly enrolled secret with the deployment's key.
    ///
    /// An absent key is an error naming the setting rather than a default: a secret sealed
    /// with a key everyone can guess is a secret in plaintext, and the store would not be
    /// able to tell the difference.
    pub(crate) fn seal_totp_secret(&self, secret: &str) -> Result<String> {
        pingap_controlplane::encrypt_totp_secret(
            secret,
            self.totp_key.as_deref(),
        )
        .map_err(|e| match e {
            AuthError::MissingEncryptionKey => ApiError::Conflict {
                reason:
                    "second-factor enrolment needs an encryption key, and this \
                             deployment has none configured"
                        .to_string(),
            },
            other => ApiError::Internal {
                reason: other.to_string(),
            },
        })
    }

    /// Open a stored secret, to check a code against it.
    pub(crate) fn open_totp_secret(&self, stored: &str) -> Result<String> {
        pingap_controlplane::decrypt_totp_secret(
            stored,
            self.totp_key.as_deref(),
        )
        .map_err(|e| ApiError::Internal {
            reason: format!(
                "the stored second-factor secret is unreadable: {e}"
            ),
        })
    }
}
