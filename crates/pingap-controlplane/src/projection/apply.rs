//! Generate → validate → commit → verify, as one operation with one record.
//!
//! The step that earns this module its own file is the last one. pingap's reload path
//! fails **silently open** at four layers: the provider map is stored even when a plugin
//! failed to construct, a Location's unresolvable plugin name is dropped with no log, an
//! empty plugin list means "continue to upstream", and the reload error is logged without
//! aborting the config swap. So "commit succeeded" says nothing about whether the WAF is
//! running, and a `ConfigVersion` becomes `applied` only when [`Applier::verify`] has read
//! the data plane back and found every policy the config named, at the config it named.
//!
//! Rollback is the same operation pointed at an earlier version's stored intent. Nothing
//! here patches a file; every path regenerates the whole config.

use super::{
    Intent, PluginCheck, Projected, Validator, Verdict, generate, hash,
};
use crate::repository::{
    ConfigStatus, ConfigVersion, ControlPlaneStore, NewActivity,
    NewConfigVersion,
};
use pingap_config::PluginConf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, snafu::Snafu)]
pub enum ApplyError {
    #[snafu(display("{source}"))]
    Projection { source: super::ProjectionError },

    #[snafu(display("{source}"))]
    Store {
        source: crate::repository::StoreError,
    },

    #[snafu(display("commit: {reason}"))]
    Commit { reason: String },

    #[snafu(display(
        "intent for version `{version_id}` is unreadable: {reason}"
    ))]
    CorruptIntent { version_id: String, reason: String },

    #[snafu(display("no applied version to roll back to"))]
    NothingToRollBackTo,
}

impl From<super::ProjectionError> for ApplyError {
    fn from(source: super::ProjectionError) -> Self {
        Self::Projection { source }
    }
}

impl From<crate::repository::StoreError> for ApplyError {
    fn from(source: crate::repository::StoreError) -> Self {
        Self::Store { source }
    }
}

pub type Result<T> = std::result::Result<T, ApplyError>;

/// Who is applying, for the audit row and the version row.
#[derive(Debug, Clone)]
pub struct Actor {
    pub id: Option<String>,
    pub username: String,
}

/// Where a committed config goes, and what the data plane reports afterwards.
///
/// Two traits rather than one because they are answered by different things — the config
/// manager writes, the plugin provider is what a request would actually resolve — and
/// because a test of the *sequencing* (verify before applied, rollback on mismatch) should
/// not need a real gateway.
#[async_trait::async_trait]
pub trait ConfigSink: Send + Sync {
    /// Write the whole config. The canonical TOML is the input so the sink cannot
    /// serialise something other than what was validated.
    async fn commit(
        &self,
        canonical_toml: &str,
    ) -> std::result::Result<(), String>;
}

/// What the data plane currently has.
pub trait DataPlane: Send + Sync {
    /// The `config_key()` of the running instance named `name`, or `None` if no such
    /// instance is running — which is the case both for a name nobody configured and for
    /// one whose constructor rejected its config.
    fn running_config_key(&self, name: &str) -> Option<String>;
}

/// What one policy should look like once applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectation {
    pub name: String,
    pub config_key: String,
}

/// Per-plugin expectations for a projection, in name order.
///
/// `get_hash_key` is what every plugin's `config_key()` returns, so equality here means
/// "the running instance was built from exactly this config".
pub fn expectations(projected: &Projected) -> Vec<Expectation> {
    let mut out: Vec<Expectation> = projected
        .config
        .plugins
        .iter()
        .map(|(name, conf)| Expectation {
            name: name.clone(),
            config_key: plugin_config_key(conf),
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The same derivation as `pingap_plugin::get_hash_key`, which every plugin's
/// `config_key()` returns. Duplicated rather than depended on: `pingap-plugin` is the
/// plugin *implementations* crate, and pulling it in here would make the control plane
/// depend on every plugin's dependencies for one ten-line function. Pinned to the
/// original byte-for-byte by a test in the binary, where both are linked.
pub fn plugin_config_key(conf: &PluginConf) -> String {
    let mut items: Vec<_> = conf.iter().collect();
    items.sort_unstable_by_key(|(k, _)| *k);
    let mut buf = String::with_capacity(256);
    for (i, (key, value)) in items.iter().enumerate() {
        if i > 0 {
            buf.push('\n');
        }
        buf.push_str(key);
        buf.push(':');
        buf.push_str(&value.to_string());
    }
    format!("{:X}", crc32fast::hash(buf.as_bytes()))
}

/// The result of an apply, whatever happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub version: ConfigVersion,
    /// Set when the version failed *after* commit and an earlier version was restored.
    pub rolled_back_to: Option<String>,
}

pub struct Applier {
    store: Arc<dyn ControlPlaneStore>,
    validator: Validator,
    plugins: Arc<dyn PluginCheck>,
    sink: Arc<dyn ConfigSink>,
    data_plane: Arc<dyn DataPlane>,
    /// How long after commit to wait for the reload before reading the data plane back.
    reload_window: Duration,
}

impl Applier {
    pub fn new(
        store: Arc<dyn ControlPlaneStore>,
        validator: Validator,
        plugins: Arc<dyn PluginCheck>,
        sink: Arc<dyn ConfigSink>,
        data_plane: Arc<dyn DataPlane>,
        reload_window: Duration,
    ) -> Self {
        Self {
            store,
            validator,
            plugins,
            sink,
            data_plane,
            reload_window,
        }
    }

    /// Generate, validate, commit, verify. One version row, one audit row.
    ///
    /// The version row is written *before* the sink is touched, as `pending`, so a crash
    /// between commit and verification leaves a row that says "unconfirmed" rather than
    /// no row at all. `applied` is set only by [`Self::verify`].
    pub async fn apply(
        &self,
        intent: &Intent,
        actor: &Actor,
        action: &str,
        now: i64,
    ) -> Result<Outcome> {
        let projected = generate(intent)?;
        let intent_json =
            serde_json::to_string(intent).map_err(|e| ApplyError::Commit {
                reason: format!("intent does not serialise: {e}"),
            })?;

        let verdict =
            self.validator.validate(&projected, &*self.plugins).await?;
        if let Verdict::Rejected { reason } = verdict {
            // Born failed. Nothing was written, and the row says why.
            let version = self
                .store
                .record_config_version(
                    NewConfigVersion {
                        hash: hash(&projected),
                        status: ConfigStatus::Failed,
                        actor_id: actor.id.clone(),
                        actor_username: actor.username.clone(),
                        intent_json,
                        error: Some(reason),
                    },
                    now,
                )
                .await?;
            self.audit(actor, action, &version, now).await?;
            return Ok(Outcome {
                version,
                rolled_back_to: None,
            });
        }

        let version = self
            .store
            .record_config_version(
                NewConfigVersion {
                    hash: hash(&projected),
                    status: ConfigStatus::Pending,
                    actor_id: actor.id.clone(),
                    actor_username: actor.username.clone(),
                    intent_json,
                    error: None,
                },
                now,
            )
            .await?;
        self.audit(actor, action, &version, now).await?;

        // The previous applied version is what we fall back to, resolved *before* the
        // commit so a rollback does not depend on reading the store mid-failure.
        let previous = self.store.latest_applied_config_version().await?;

        if let Err(reason) = self.sink.commit(&projected.toml).await {
            self.store
                .set_config_version_status(
                    &version.id,
                    ConfigStatus::Failed,
                    Some(&format!("commit: {reason}")),
                    now,
                )
                .await?;
            return self.reload_version(version.id).await;
        }

        self.verify(&version, &projected, previous.as_ref(), now)
            .await
    }

    /// Read the data plane back and settle the version.
    ///
    /// Every plugin the projection named must be running at the config it named. A
    /// missing one is exactly the constructor-rejected case pingap swallows, and a
    /// mismatched one is a reload that did not happen. Either fails the version and
    /// restores the previous applied one.
    async fn verify(
        &self,
        version: &ConfigVersion,
        projected: &Projected,
        previous: Option<&ConfigVersion>,
        now: i64,
    ) -> Result<Outcome> {
        tokio::time::sleep(self.reload_window).await;
        self.settle(version, projected, previous, now).await
    }

    /// Settle any version left `pending`.
    ///
    /// `pending` means "nobody has checked whether this is enforcing", and a process that
    /// commits and then dies leaves exactly that: the row says the config was written and
    /// says nothing about whether the reload brought the policy up. Without a sweep those
    /// rows stay `pending` forever, and `latest_applied_config_version` — the rollback
    /// target — silently skips them, so an operator's rollback list is missing the version
    /// actually running.
    ///
    /// No `reload_window` sleep: a stranded version is by definition older than the window.
    pub async fn settle_pending(&self, now: i64) -> Result<Vec<Outcome>> {
        let versions = self.store.list_config_versions(None).await?;
        let mut out = Vec::new();
        for version in versions
            .into_iter()
            .filter(|v| v.status == ConfigStatus::Pending)
        {
            let projected = generate(&intent_of(&version)?)?;
            let previous = self.store.latest_applied_config_version().await?;
            out.push(
                self.settle(&version, &projected, previous.as_ref(), now)
                    .await?,
            );
        }
        Ok(out)
    }

    async fn settle(
        &self,
        version: &ConfigVersion,
        projected: &Projected,
        previous: Option<&ConfigVersion>,
        now: i64,
    ) -> Result<Outcome> {
        let mut missing = Vec::new();
        for expected in expectations(projected) {
            match self.data_plane.running_config_key(&expected.name) {
                Some(key) if key == expected.config_key => {},
                Some(key) => missing.push(format!(
                    "`{}` is running an older config ({key}, expected {})",
                    expected.name, expected.config_key
                )),
                None => missing.push(format!(
                    "`{}` is not running — its constructor rejected the config, or \
                     the reload did not reach it",
                    expected.name
                )),
            }
        }

        if missing.is_empty() {
            if let Some(prev) = previous {
                self.store
                    .set_config_version_status(
                        &prev.id,
                        ConfigStatus::Superseded,
                        None,
                        now,
                    )
                    .await?;
            }
            self.store
                .set_config_version_status(
                    &version.id,
                    ConfigStatus::Applied,
                    None,
                    now,
                )
                .await?;
            return self.reload_version(version.id.clone()).await;
        }

        let reason =
            format!("post-commit verification failed: {}", missing.join("; "));
        self.store
            .set_config_version_status(
                &version.id,
                ConfigStatus::Failed,
                Some(&reason),
                now,
            )
            .await?;

        // Restore the previous applied version. Its intent regenerates its config; the
        // sink is written directly rather than through `apply`, because that would record
        // a fresh version for what is a restoration of an existing one.
        let Some(prev) = previous else {
            return self.reload_version(version.id.clone()).await;
        };
        let prev_intent = intent_of(prev)?;
        let restored = generate(&prev_intent)?;
        self.sink.commit(&restored.toml).await.map_err(|reason| {
            ApplyError::Commit {
                reason: format!(
                    "rollback to `{}` failed: {reason}; the data plane may be running a \
                     config no version describes",
                    prev.id
                ),
            }
        })?;
        Ok(Outcome {
            version: self
                .store
                .config_version(&version.id)
                .await?
                .unwrap_or_else(|| version.clone()),
            rolled_back_to: Some(prev.id.clone()),
        })
    }

    /// Explicit rollback to `version_id`, which must be a version that was applied.
    ///
    /// Regenerates from that version's stored intent and runs the full apply, so the
    /// restored config is validated and verified like any other and gets its own row.
    pub async fn rollback(
        &self,
        version_id: &str,
        actor: &Actor,
        now: i64,
    ) -> Result<Outcome> {
        let target =
            self.store
                .config_version(version_id)
                .await?
                .ok_or_else(|| ApplyError::Store {
                    source: crate::repository::StoreError::NotFound {
                        kind: "config version".to_string(),
                        id: version_id.to_string(),
                    },
                })?;
        // Only a version that was once confirmed enforcing is a rollback target. Rolling
        // back to one that failed would restore the failure.
        if !matches!(
            target.status,
            ConfigStatus::Applied | ConfigStatus::Superseded
        ) {
            return Err(ApplyError::Commit {
                reason: format!(
                    "version `{version_id}` is {:?}, not a version that was ever applied",
                    target.status
                ),
            });
        }
        let intent = intent_of(&target)?;
        self.apply(
            &intent,
            actor,
            &format!("config.rollback:{version_id}"),
            now,
        )
        .await
    }

    async fn audit(
        &self,
        actor: &Actor,
        action: &str,
        version: &ConfigVersion,
        now: i64,
    ) -> Result<()> {
        self.store
            .record_activity(
                NewActivity {
                    actor_id: actor.id.clone(),
                    actor_username: actor.username.clone(),
                    action: action.to_string(),
                    target: "config".to_string(),
                    config_version: Some(version.id.clone()),
                    ip: None,
                    user_agent: None,
                    detail: Some(format!("hash {}", version.hash)),
                },
                now,
            )
            .await?;
        Ok(())
    }

    async fn reload_version(&self, id: String) -> Result<Outcome> {
        let version =
            self.store.config_version(&id).await?.ok_or_else(|| {
                ApplyError::Store {
                    source: crate::repository::StoreError::NotFound {
                        kind: "config version".to_string(),
                        id,
                    },
                }
            })?;
        Ok(Outcome {
            version,
            rolled_back_to: None,
        })
    }
}

fn intent_of(version: &ConfigVersion) -> Result<Intent> {
    serde_json::from_str(&version.intent_json).map_err(|e| {
        ApplyError::CorruptIntent {
            version_id: version.id.clone(),
            reason: e.to_string(),
        }
    })
}
