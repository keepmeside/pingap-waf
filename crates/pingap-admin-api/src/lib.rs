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
//! Config-shaped resources go through the Phase 08 projection and never write config
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
use pingap_controlplane::projection::Applier;
use std::sync::Arc;

/// What every handler is given.
///
/// Both are supplied by the binary. The store is the control plane's own state; the
/// applier is the only way config is written, and holding it here rather than a
/// `ConfigManager` is what makes "no handler writes config directly" a property of the
/// type rather than a rule someone has to remember.
pub struct AppState {
    pub store: Arc<dyn ControlPlaneStore>,
    pub applier: Arc<Applier>,
}

impl AppState {
    pub fn new(
        store: Arc<dyn ControlPlaneStore>,
        applier: Arc<Applier>,
    ) -> Self {
        Self { store, applier }
    }
}
