//! Drift detection: has the running config diverged from the last applied version?
//!
//! Two things make this honest rather than noisy. The comparison is between *canonical
//! forms* — the on-disk config is re-parsed and re-serialised the same way the projection
//! was, so reformatting, key order and comments cannot fire it. And the verdict is
//! **reported, never corrected**: a manual edit is either an emergency change somebody
//! made on purpose, or evidence that somebody bypassed the control plane. Both are things
//! a human should hear about, and silently overwriting either destroys the information.

use super::{Projected, hash};
use crate::repository::{ConfigStatus, ControlPlaneStore};
use pingap_config::PingapConfig;
use pingap_core::{Notification, NotificationData, NotificationLevel};
use std::sync::Arc;

/// What a drift check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
    /// The running config hashes to the last applied version.
    None { version_id: String },
    /// The running config is not what the last applied version generated.
    Detected {
        version_id: String,
        expected_hash: String,
        actual_hash: String,
        /// Which categories differ, by name only — never the contents. Config holds
        /// TLS keys and access-list credentials, and a notification is not the place
        /// for them.
        differing: Vec<String>,
    },
    /// Nothing has ever been applied, so there is nothing to compare against.
    NoBaseline,
}

/// Where the running config is read from.
///
/// Async because the answer that matters comes off **storage**, not out of the process's
/// own memory. A source reading the in-memory `PingapConfig` would compare the control
/// plane against itself: an edit an operator makes on disk is invisible until something
/// reloads it, and with `--autoreload` off it stays invisible forever. Reading storage
/// makes the check answer the question the criterion asks.
#[async_trait::async_trait]
pub trait ConfigSource: Send + Sync {
    async fn current(&self) -> Result<PingapConfig, String>;
}

pub struct DriftDetector {
    store: Arc<dyn ControlPlaneStore>,
    source: Arc<dyn ConfigSource>,
    notifier: Option<Arc<dyn Notification + Send + Sync>>,
}

impl DriftDetector {
    pub fn new(
        store: Arc<dyn ControlPlaneStore>,
        source: Arc<dyn ConfigSource>,
        notifier: Option<Arc<dyn Notification + Send + Sync>>,
    ) -> Self {
        Self {
            store,
            source,
            notifier,
        }
    }

    /// Compare once, notify if it differs, and say what was found.
    pub async fn check(&self) -> Result<Drift, String> {
        let Some(applied) = self
            .store
            .latest_applied_config_version()
            .await
            .map_err(|e| e.to_string())?
        else {
            return Ok(Drift::NoBaseline);
        };
        debug_assert_eq!(applied.status, ConfigStatus::Applied);

        let running = Projected::from_config(self.source.current().await?)
            .map_err(|e| e.to_string())?;
        let actual = hash(&running);
        if actual == applied.hash {
            return Ok(Drift::None {
                version_id: applied.id,
            });
        }

        // Which categories moved, for the operator. Regenerate the expected config from
        // the version's intent rather than storing a second copy of the TOML.
        let expected_intent: super::Intent =
            serde_json::from_str(&applied.intent_json)
                .map_err(|e| format!("intent of `{}`: {e}", applied.id))?;
        let expected =
            super::generate(&expected_intent).map_err(|e| e.to_string())?;
        let differing = differing_categories(&expected.config, &running.config);

        if let Some(notifier) = &self.notifier {
            notifier
                .notify(NotificationData {
                    category: "config_drift".to_string(),
                    level: NotificationLevel::Warn,
                    title: "running config differs from the applied version"
                        .to_string(),
                    message: format!(
                        "version {} expected {}, running config hashes to {}; \
                         differing: {}. Not corrected automatically — a manual edit is \
                         either deliberate or a bypass, and both need a human.",
                        applied.id,
                        &applied.hash[..12.min(applied.hash.len())],
                        &actual[..12.min(actual.len())],
                        if differing.is_empty() {
                            "(basic)".to_string()
                        } else {
                            differing.join(", ")
                        }
                    ),
                })
                .await;
        }
        Ok(Drift::Detected {
            version_id: applied.id,
            expected_hash: applied.hash,
            actual_hash: actual,
            differing,
        })
    }
}

/// Category names whose entries differ, in a fixed order.
fn differing_categories(a: &PingapConfig, b: &PingapConfig) -> Vec<String> {
    let mut out = Vec::new();
    let mut check = |name: &str, same: bool| {
        if !same {
            out.push(name.to_string());
        }
    };
    check("basic", toml_of(&a.basic) == toml_of(&b.basic));
    check("upstreams", toml_of(&a.upstreams) == toml_of(&b.upstreams));
    check("locations", toml_of(&a.locations) == toml_of(&b.locations));
    check("servers", toml_of(&a.servers) == toml_of(&b.servers));
    check("plugins", toml_of(&a.plugins) == toml_of(&b.plugins));
    check(
        "certificates",
        toml_of(&a.certificates) == toml_of(&b.certificates),
    );
    check("storages", toml_of(&a.storages) == toml_of(&b.storages));
    out
}

/// Comparable form of one category. `toml::Value::try_from` sorts table keys, so two
/// `HashMap`s with the same content compare equal here regardless of iteration order.
fn toml_of<T: serde::Serialize>(value: &T) -> Option<toml::Value> {
    toml::Value::try_from(value).ok()
}
