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

//! The binary's side of the config projection.
//!
//! `pingap-controlplane` defines the projection against four traits — where a committed
//! config goes, where the running one is read from, what the data plane is running,
//! whether a plugin can be built — and cannot implement any of them: the config manager,
//! the plugin provider and the plugin factory all live above it. This module is where they
//! are wired to the real things, and where the scheduled drift check is assembled.
//!
//! Everything here takes its dependencies as arguments rather than reading the process
//! globals directly. That is not ceremony: `CONFIG_MANAGER` and `PLUGIN_PROVIDER` are
//! `OnceLock`/`LazyLock` singletons, so a module that reached for them internally could be
//! tested exactly once per process, and the second test would silently exercise the first
//! test's config.

use crate::plugin::new_plugin_provider;
use pingap_config::{
    ConfigManager, PingapConfig, PingapTomlConfig, PluginConf,
};
use pingap_controlplane::projection::{
    Applier, ConfigSink, ConfigSource, DataPlane, Drift, DriftDetector,
    PluginCheck, Validator,
};
use pingap_controlplane::repository::ControlPlaneStore;
use pingap_core::{
    BackgroundTask, Notification, NotificationData, NotificationSender,
    PluginProvider,
};
use pingap_plugin::get_plugin_factory;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

const LOG_TARGET: &str = "projection";

/// How long after a commit to wait before reading the data plane back.
///
/// The reload is driven by whichever service is watching config — the etcd observer or the
/// file poller — so this has to outlast the slower of the two. `new_auto_restart_service`
/// polls on an interval the operator sets, which is why the value is a constructor
/// argument in [`new_applier`] and this is only the default.
pub const DEFAULT_RELOAD_WINDOW: Duration = Duration::from_secs(10);

/// Writes a committed config through a live [`ConfigManager`].
///
/// `save_all` rather than per-item `update`: the projection is total, and writing it as one
/// unit is what keeps the on-disk state a pure function of intent. The existing
/// auto-restart or observer service then notices the change and reloads, exactly as it
/// would for an edit through the admin UI — which is also why this works unchanged on the
/// file, etcd and memory backends.
pub struct ConfigManagerSink {
    manager: Arc<ConfigManager>,
}

impl ConfigManagerSink {
    pub fn new(manager: Arc<ConfigManager>) -> Self {
        Self { manager }
    }
}

#[async_trait::async_trait]
impl ConfigSink for ConfigManagerSink {
    async fn commit(&self, canonical_toml: &str) -> Result<(), String> {
        let config: PingapTomlConfig =
            toml::from_str(canonical_toml).map_err(|e| e.to_string())?;
        self.manager
            .save_all(&config)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Reads the running config back **off storage**, for drift detection.
///
/// Storage rather than `get_current_config()`, and the difference is the whole point of the
/// check: the in-memory config is what the control plane last handed the process, so
/// comparing against it would compare the control plane with itself. An operator's hand
/// edit only exists on disk until something reloads it.
pub struct ConfigManagerSource {
    manager: Arc<ConfigManager>,
}

impl ConfigManagerSource {
    pub fn new(manager: Arc<ConfigManager>) -> Self {
        Self { manager }
    }
}

#[async_trait::async_trait]
impl ConfigSource for ConfigManagerSource {
    async fn current(&self) -> Result<PingapConfig, String> {
        self.manager
            .load_all()
            .await
            .map_err(|e| e.to_string())?
            // `false`: an `include` is resolved for the running process but is not part of
            // what this config *says*, and expanding it here would report drift against
            // every version generated before the included file changed.
            .to_pingap_config(false)
            .map_err(|e| e.to_string())
    }
}

/// What the plugin provider is actually holding.
///
/// This is the read-back that decides `applied`. A plugin whose constructor rejected the
/// new config is absent here — `try_init_plugins` stores the provider map regardless of
/// construction errors — so the control plane sees the failure that pingap's reload path
/// would otherwise swallow.
pub struct ProviderDataPlane {
    provider: Arc<dyn PluginProvider>,
}

impl ProviderDataPlane {
    pub fn new(provider: Arc<dyn PluginProvider>) -> Self {
        Self { provider }
    }
}

impl DataPlane for ProviderDataPlane {
    fn running_config_key(&self, name: &str) -> Option<String> {
        self.provider
            .get(name)
            .map(|plugin| plugin.config_key().to_string())
    }
}

/// Asks the real plugin factory whether a config can be built.
///
/// This is the check `pingap-waf -t` cannot do for a category the build lacks, and it runs
/// against the same registry the reload will use, so a config it accepts is one the reload
/// can construct.
pub struct FactoryPluginCheck;

impl PluginCheck for FactoryPluginCheck {
    fn check(&self, _name: &str, conf: &PluginConf) -> Result<(), String> {
        get_plugin_factory()
            .create(conf)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// Bridges the notification sender the binary owns to the trait object the detector takes.
///
/// `NotificationSender` is a `Box<dyn Notification>` behind an `Arc`, and `DriftDetector`
/// wants an `Arc<dyn Notification>`. One newtype rather than widening the vendored alias.
struct SenderNotifier(Arc<NotificationSender>);

#[async_trait::async_trait]
impl Notification for SenderNotifier {
    async fn notify(&self, data: NotificationData) {
        self.0.notify(data).await;
    }
}

/// The process-global control-plane store, opened on first use.
///
/// Deferred rather than opened while services are assembled, and the reason is fork safety:
/// pingora forks for daemon mode after `bootstrap()` and before the service runtimes start,
/// so a database connection opened earlier would be handed to a process that never opened
/// it. `LazyAdminAuth` defers for the same reason.
struct LazyStore {
    path: String,
    opened: tokio::sync::OnceCell<Arc<dyn ControlPlaneStore>>,
}

impl LazyStore {
    fn at(path: String) -> Self {
        Self {
            path,
            opened: tokio::sync::OnceCell::new(),
        }
    }

    /// Over a store somebody else owns. Tests use this: `TursoStore::shared` is
    /// process-global and would hand every test the first one's database.
    #[cfg(test)]
    fn ready(store: Arc<dyn ControlPlaneStore>) -> Self {
        let opened = tokio::sync::OnceCell::new();
        let _ = opened.set(store);
        Self {
            path: String::new(),
            opened,
        }
    }

    /// `TursoStore::shared` rather than `open`: every writer in the process must be the one
    /// writer, and a second handle on the same file would serialise nothing.
    async fn get(&self) -> Result<&Arc<dyn ControlPlaneStore>, String> {
        self.opened
            .get_or_try_init(|| async {
                let store =
                    pingap_controlplane::store::TursoStore::shared(&self.path)
                        .await
                        .map_err(|e| e.to_string())?;
                Ok(store as Arc<dyn ControlPlaneStore>)
            })
            .await
    }
}

/// The drift check on a schedule.
///
/// Reports and never corrects. Silently overwriting a manual edit would destroy an
/// operator's emergency change and hide the fact that somebody bypassed the control plane;
/// both are things a human needs to hear about.
pub struct DriftTask {
    store: LazyStore,
    manager: Arc<ConfigManager>,
    notifier: Option<Arc<dyn Notification + Send + Sync>>,
}

#[async_trait::async_trait]
impl BackgroundTask for DriftTask {
    async fn execute(&self, _count: u32) -> Result<bool, pingap_core::Error> {
        let invalid = |message: String| pingap_core::Error::Invalid { message };
        let detector = DriftDetector::new(
            self.store.get().await.map_err(invalid)?.clone(),
            Arc::new(ConfigManagerSource::new(self.manager.clone())),
            self.notifier.clone(),
        );
        match detector.check().await {
            // `true` means "did meaningful work", which is what a divergence is. A clean
            // check and a store with nothing applied yet are both silence.
            Ok(Drift::Detected { .. }) => Ok(true),
            Ok(_) => Ok(false),
            Err(message) => Err(invalid(message)),
        }
    }
}

/// Settles config versions left `pending` by a process that committed and then died.
///
/// `pending` means nobody has confirmed the config is enforcing. Left alone those rows stay
/// pending forever and `latest_applied_config_version` — the rollback target — skips them,
/// so an operator's rollback list is missing the version actually running. The sweep reads
/// the data plane back and settles each one the way the committing process would have.
pub struct PendingVerificationTask {
    store: LazyStore,
    manager: Arc<ConfigManager>,
    reload_window: Duration,
}

#[async_trait::async_trait]
impl BackgroundTask for PendingVerificationTask {
    async fn execute(&self, _count: u32) -> Result<bool, pingap_core::Error> {
        let invalid = |message: String| pingap_core::Error::Invalid { message };
        let applier = new_applier(
            self.store.get().await.map_err(invalid)?.clone(),
            self.manager.clone(),
            self.reload_window,
        )
        .map_err(invalid)?;
        let settled = applier
            .settle_pending(pingap_core::now_sec() as i64)
            .await
            .map_err(|e| invalid(e.to_string()))?;
        for outcome in &settled {
            match &outcome.rolled_back_to {
                Some(target) => error!(
                    target: LOG_TARGET,
                    version = outcome.version.id,
                    rolled_back_to = target,
                    reason = outcome.version.error.as_deref().unwrap_or_default(),
                    "a config version was left unconfirmed and the data plane does not \
                     have it; rolled back"
                ),
                None => info!(
                    target: LOG_TARGET,
                    version = outcome.version.id,
                    status = ?outcome.version.status,
                    "settled a config version left unconfirmed by an earlier process"
                ),
            }
        }
        Ok(!settled.is_empty())
    }
}

/// The projection, assembled from the live config manager, plugin provider and factory.
///
/// `Validator::for_current_exe` deliberately: a different build may have a different plugin
/// feature set, and validating with one would clear a config the running process cannot
/// load.
pub fn new_applier(
    store: Arc<dyn ControlPlaneStore>,
    manager: Arc<ConfigManager>,
    reload_window: Duration,
) -> Result<Applier, String> {
    Ok(Applier::new(
        store,
        Validator::for_current_exe().map_err(|e| e.to_string())?,
        Arc::new(FactoryPluginCheck),
        Arc::new(ConfigManagerSink::new(manager)),
        Arc::new(ProviderDataPlane::new(new_plugin_provider())),
        reload_window,
    ))
}

/// The scheduled drift check, ready to add to a [`pingap_core::BackgroundTaskService`].
///
/// A background service rather than a thread: pingora forks for daemon mode after
/// `bootstrap()` and before the service runtimes start, and `fork()` carries only the
/// calling thread — so a `std::thread` started earlier does not exist in the daemon.
pub fn new_drift_detection_task(
    store_path: String,
    manager: Arc<ConfigManager>,
    notifier: Option<Arc<NotificationSender>>,
) -> Box<dyn BackgroundTask> {
    Box::new(DriftTask {
        store: LazyStore::at(store_path),
        manager,
        notifier: notifier.map(|s| Arc::new(SenderNotifier(s)) as _),
    })
}

/// The scheduled sweep that settles config versions nobody confirmed.
pub fn new_pending_verification_task(
    store_path: String,
    manager: Arc<ConfigManager>,
    reload_window: Duration,
) -> Box<dyn BackgroundTask> {
    Box::new(PendingVerificationTask {
        store: LazyStore::at(store_path),
        manager,
        reload_window,
    })
}

/// Report the posture taken when a security-enforcing plugin is configured but not running.
///
/// Logged rather than left implicit because `fail_open` is the choice that serves
/// unprotected traffic, and an operator who set it — or inherited it from a config they did
/// not write — should be able to see it in the boot log rather than infer it from a 200
/// that should have been a 503.
///
/// `configured` is the raw `basic.on_policy_unavailable` value, because a *typo* is the
/// case worth a warning: `set_policy_unavailable_mode` treats anything it does not
/// recognise as `fail_closed`, which is the safe branch but not the one the operator
/// thought they were choosing.
pub fn log_policy_unavailable_posture(configured: &Option<String>) {
    match configured.as_deref() {
        Some("fail_open") => error!(
            target: LOG_TARGET,
            posture = "fail_open",
            "on_policy_unavailable is fail_open: a security policy that fails to build \
             will be skipped and the request served unprotected"
        ),
        None | Some("fail_closed") => info!(
            target: LOG_TARGET,
            posture = "fail_closed",
            "on_policy_unavailable is fail_closed: a request needing a security policy \
             that failed to build is refused with 503"
        ),
        Some(other) => warn!(
            target: LOG_TARGET,
            configured = other,
            posture = "fail_closed",
            "on_policy_unavailable is not a value pingap knows; treating it as \
             fail_closed. Valid values are fail_closed and fail_open"
        ),
    }
    debug_assert_eq!(
        pingap_core::policy_fails_open(),
        matches!(configured.as_deref(), Some("fail_open")),
        "the posture logged is not the posture in effect"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::try_init_plugins;
    use pingap_controlplane::projection::{
        Actor, Backend, Domain, Intent, Listener, PolicyBinding, Upstream,
        expectations, generate, plugin_config_key,
    };
    use pingap_controlplane::repository::{ConfigStatus, NewConfigVersion};
    use pingap_controlplane::store::TursoStore;
    use pretty_assertions::assert_eq;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// An intent with one domain, one upstream, one listener and a WAF profile whose
    /// `paranoia` is the knob every test turns.
    fn intent(paranoia: i64) -> Intent {
        let mut upstreams = BTreeMap::new();
        upstreams.insert(
            "app".to_string(),
            Upstream {
                backends: vec![Backend {
                    addr: "127.0.0.1:8080".to_string(),
                    weight: None,
                }],
                lb_algorithm: None,
                health_check: None,
                discovery: None,
                tls_sni: None,
                verify_cert: None,
            },
        );
        let mut listeners = BTreeMap::new();
        listeners.insert(
            "http".to_string(),
            Listener {
                addr: "127.0.0.1:6188".to_string(),
                http2: None,
                tls: None,
                access_log: None,
                server_timing: None,
            },
        );
        let mut domains = BTreeMap::new();
        domains.insert(
            "site".to_string(),
            Domain {
                hostnames: vec!["site.test".to_string()],
                path: None,
                listener: "http".to_string(),
                upstream: "app".to_string(),
                priority: None,
                notes: None,
                client_max_body_size: None,
                grpc_web: false,
                reverse_proxy_headers: None,
                max_processing: None,
                max_retries: None,
                policies: vec![PolicyBinding::Waf("strict".to_string())],
            },
        );
        let mut policies = BTreeMap::new();
        let mut waf = PluginConf::new();
        waf.insert("category".into(), "waf".into());
        waf.insert("paranoia".into(), paranoia.into());
        policies.insert("waf:strict".to_string(), waf);
        Intent {
            upstreams,
            listeners,
            domains,
            policies,
            trusted_proxies: None,
        }
    }

    fn actor() -> Actor {
        Actor {
            id: Some("u1".to_string()),
            username: "admin".to_string(),
        }
    }

    /// A file-backed config manager and a store, each in its own temp dir.
    ///
    /// Both are process-global in production (`CONFIG_MANAGER`, `TursoStore::shared`) and
    /// neither is here: the singletons would make the first test the only one that runs
    /// against its own fixture.
    struct Harness {
        _dir: tempfile::TempDir,
        conf_dir: std::path::PathBuf,
        manager: Arc<ConfigManager>,
        store: Arc<dyn ControlPlaneStore>,
    }

    async fn harness() -> Harness {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let conf_dir = dir.path().join("conf");
        std::fs::create_dir_all(&conf_dir).expect("conf dir");
        let manager = Arc::new(
            pingap_config::new_file_config_manager(
                conf_dir.to_str().expect("utf8 path"),
            )
            .expect("file config manager"),
        );
        let store = TursoStore::open(
            dir.path().join("cp.db").to_str().expect("utf8 path"),
        )
        .await
        .expect("store opens");
        store.migrate().await.expect("migrates");
        Harness {
            _dir: dir,
            conf_dir,
            manager,
            store: Arc::new(store),
        }
    }

    /// Commit through the real sink, then do what the observer would: reload the plugin
    /// provider from what landed. `reload` off makes it the "commit succeeded, reload never
    /// happened" case, which is what post-commit verification exists to catch.
    struct ReloadingSink {
        inner: ConfigManagerSink,
        manager: Arc<ConfigManager>,
        reload: bool,
        commits: Mutex<usize>,
    }

    #[async_trait::async_trait]
    impl ConfigSink for ReloadingSink {
        async fn commit(&self, canonical_toml: &str) -> Result<(), String> {
            self.inner.commit(canonical_toml).await?;
            *self.commits.lock().expect("lock") += 1;
            if self.reload {
                let loaded = self
                    .manager
                    .load_all()
                    .await
                    .map_err(|e| e.to_string())?
                    .to_pingap_config(false)
                    .map_err(|e| e.to_string())?;
                try_init_plugins(&loaded.plugins);
            }
            Ok(())
        }
    }

    fn applier_over(
        h: &Harness,
        reload: bool,
    ) -> (Applier, Arc<ReloadingSink>) {
        let sink = Arc::new(ReloadingSink {
            inner: ConfigManagerSink::new(h.manager.clone()),
            manager: h.manager.clone(),
            reload,
            commits: Mutex::new(0),
        });
        let applier = Applier::new(
            h.store.clone(),
            Validator::new(gateway_binary()),
            Arc::new(FactoryPluginCheck),
            sink.clone(),
            Arc::new(ProviderDataPlane::new(new_plugin_provider())),
            // Nothing to wait for: the sink reloads synchronously.
            Duration::from_millis(0),
        );
        (applier, sink)
    }

    /// `PLUGIN_PROVIDER` is one process-global map and `try_init_plugins` replaces it
    /// wholesale, so two tests reloading it concurrently would read each other's plugins.
    ///
    /// A `tokio` mutex rather than a `std` one: the guard has to stay held across the
    /// awaits that commit and verify, which is exactly the shape a blocking guard must not
    /// be used for.
    static PROVIDER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// The gateway binary this workspace builds.
    ///
    /// `std::env::current_exe()` is the libtest harness inside a unit test, so a validator
    /// pointed at it would run libtest instead of the gateway — exit non-zero for the wrong
    /// reason and produce a rejection that proves nothing.
    ///
    /// `CARGO_BIN_EXE_<name>` would be the obvious answer, but cargo only sets it for
    /// integration tests and benchmarks, not for unit tests inside the binary target. So
    /// the name is spelled out here and must match `[[bin]] name` in the root Cargo.toml.
    fn gateway_binary() -> std::path::PathBuf {
        let mut dir = std::env::current_exe().expect("current exe");
        dir.pop(); // deps/
        dir.pop(); // debug/
        let candidate = dir.join("pingap-waf");
        assert!(
            candidate.is_file(),
            "no gateway binary at {candidate:?}; build it before running this test"
        );
        candidate
    }

    /// The commit path is the vendored `Storage` abstraction, unchanged, and what it wrote
    /// reads back as the same config — which is what makes the hash in `config_versions`
    /// comparable to anything.
    #[tokio::test]
    async fn test_the_sink_commits_through_the_config_manager_and_reads_back_equal()
     {
        let h = harness().await;
        let projected = generate(&intent(2)).expect("generates");
        ConfigManagerSink::new(h.manager.clone())
            .commit(&projected.toml)
            .await
            .expect("commits");

        // Written where pingap's own loader looks, not into a file of our own naming.
        assert!(
            std::fs::read_dir(&h.conf_dir)
                .expect("conf dir")
                .filter_map(|e| e.ok())
                .count()
                > 0,
            "save_all wrote nothing"
        );

        let read_back = ConfigManagerSource::new(h.manager.clone())
            .current()
            .await
            .expect("reads back");
        assert_eq!(
            pingap_controlplane::projection::hash(
                &pingap_controlplane::projection::Projected::from_config(
                    read_back
                )
                .expect("hashable")
            ),
            pingap_controlplane::projection::hash(&projected),
            "a config committed and read back is not the config that was hashed"
        );
    }

    /// The source must read **storage**, not `get_current_config()`. A source reading the
    /// in-memory copy would compare the control plane against itself and never see a hand
    /// edit, which is the one thing drift detection exists to find.
    #[tokio::test]
    async fn test_the_source_reads_storage_rather_than_the_in_memory_config() {
        let h = harness().await;
        let on_disk = generate(&intent(4)).expect("generates");
        ConfigManagerSink::new(h.manager.clone())
            .commit(&on_disk.toml)
            .await
            .expect("commits");
        // A different config in memory, as a reload that has not happened yet would leave
        // it.
        h.manager.set_current_config(
            generate(&intent(1)).expect("generates").config,
        );

        let seen = ConfigManagerSource::new(h.manager.clone())
            .current()
            .await
            .expect("reads");
        let paranoia = seen
            .plugins
            .get("waf:strict")
            .and_then(|c| c.get("paranoia"))
            .and_then(|v| v.as_integer());
        assert_eq!(
            paranoia,
            Some(4),
            "the source answered from memory instead of storage"
        );
    }

    #[derive(Default)]
    struct Captured(Mutex<Vec<(String, String)>>);

    #[async_trait::async_trait]
    impl Notification for Captured {
        async fn notify(&self, data: NotificationData) {
            self.0
                .lock()
                .expect("lock")
                .push((data.category, data.message));
        }
    }

    /// Record `intent` as the applied version and put its config on disk, which is the
    /// state a successful apply leaves behind.
    async fn applied_baseline(h: &Harness, paranoia: i64) -> String {
        let projected = generate(&intent(paranoia)).expect("generates");
        ConfigManagerSink::new(h.manager.clone())
            .commit(&projected.toml)
            .await
            .expect("commits");
        let version = h
            .store
            .record_config_version(
                NewConfigVersion {
                    hash: pingap_controlplane::projection::hash(&projected),
                    status: ConfigStatus::Pending,
                    actor_id: None,
                    actor_username: "test".to_string(),
                    intent_json: serde_json::to_string(&intent(paranoia))
                        .expect("serialises"),
                    error: None,
                },
                1_000,
            )
            .await
            .expect("records");
        h.store
            .set_config_version_status(
                &version.id,
                ConfigStatus::Applied,
                None,
                1_000,
            )
            .await
            .expect("applies");
        version.id
    }

    /// A drift task over the harness's own store, since `TursoStore::shared` is
    /// process-global and would hand every test the first one's database.
    fn drift_task(h: &Harness, notes: Arc<Captured>) -> DriftTask {
        DriftTask {
            store: LazyStore::ready(h.store.clone()),
            manager: h.manager.clone(),
            notifier: Some(Arc::new(SenderNotifier(sender(notes)))),
        }
    }

    fn sweep_task(h: &Harness) -> PendingVerificationTask {
        PendingVerificationTask {
            store: LazyStore::ready(h.store.clone()),
            manager: h.manager.clone(),
            reload_window: Duration::from_millis(0),
        }
    }

    /// The scheduled task's own contract: an untouched config is silence.
    #[tokio::test]
    async fn test_the_drift_task_is_quiet_when_the_config_matches() {
        let h = harness().await;
        applied_baseline(&h, 2).await;
        let notes = Arc::new(Captured::default());
        assert_eq!(
            drift_task(&h, notes.clone())
                .execute(1)
                .await
                .expect("checks"),
            false,
            "a matching config was reported as work done"
        );
        assert!(notes.0.lock().expect("lock").is_empty());
    }

    /// The criterion: an edit made straight to the config file is reported within one
    /// scheduled interval, and is **not** corrected.
    #[tokio::test]
    async fn test_a_hand_edit_on_disk_is_reported_by_the_scheduled_task() {
        let h = harness().await;
        applied_baseline(&h, 2).await;

        // An operator turns the WAF down on disk, bypassing the control plane entirely.
        let before = ConfigManagerSource::new(h.manager.clone())
            .current()
            .await
            .expect("reads");
        ConfigManagerSink::new(h.manager.clone())
            .commit(&generate(&intent(1)).expect("generates").toml)
            .await
            .expect("commits the edit");

        let notes = Arc::new(Captured::default());
        assert_eq!(
            drift_task(&h, notes.clone())
                .execute(1)
                .await
                .expect("checks"),
            true
        );

        // Scoped rather than dropped at the end: the guard must not be alive across the
        // `await` below, and a lexical block is what says so to both the reader and clippy.
        {
            let notes = notes.0.lock().expect("lock");
            assert_eq!(notes.len(), 1, "one check, one notification");
            assert_eq!(notes[0].0, "config_drift");
            assert!(notes[0].1.contains("plugins"), "{}", notes[0].1);
            // The category is named; the contents never are. Config holds TLS key paths
            // and access-list credentials.
            assert!(
                !notes[0].1.contains("paranoia"),
                "config contents leaked into a notification: {}",
                notes[0].1
            );
        }

        // Reported, not corrected: the edit is still on disk.
        let after = ConfigManagerSource::new(h.manager.clone())
            .current()
            .await
            .expect("reads");
        assert_ne!(
            pingap_controlplane::projection::canonical_toml(&before)
                .expect("canonical"),
            pingap_controlplane::projection::canonical_toml(&after)
                .expect("canonical"),
            "the drift check silently overwrote an operator's edit"
        );
    }

    /// Wraps the capture as the `NotificationSender` the binary hands around.
    fn sender(notes: Arc<Captured>) -> Arc<NotificationSender> {
        Arc::new(Box::new(CapturedSender(notes)) as NotificationSender)
    }

    struct CapturedSender(Arc<Captured>);

    #[async_trait::async_trait]
    impl Notification for CapturedSender {
        async fn notify(&self, data: NotificationData) {
            self.0.notify(data).await;
        }
    }

    /// The whole loop over the real parts: generate, validate with the real factory, commit
    /// through the real config manager, and read the real plugin provider back.
    #[tokio::test]
    async fn test_an_apply_the_reload_reaches_is_applied_and_the_plugin_is_running()
     {
        let _guard = PROVIDER.lock().await;
        let h = harness().await;
        let (applier, sink) = applier_over(&h, true);

        let out = applier
            .apply(&intent(2), &actor(), "domain.create", 1_000)
            .await
            .expect("applies");
        assert_eq!(out.version.status, ConfigStatus::Applied);
        assert_eq!(out.rolled_back_to, None);
        assert_eq!(*sink.commits.lock().expect("lock"), 1);

        // `applied` is a claim about the data plane, so check the data plane.
        let projected = generate(&intent(2)).expect("generates");
        for expected in expectations(&projected) {
            assert_eq!(
                ProviderDataPlane::new(new_plugin_provider())
                    .running_config_key(&expected.name),
                Some(expected.config_key.clone()),
                "`{}` is not running the config the version claims",
                expected.name
            );
        }

        // And the audit row names the version it produced.
        let rows = h
            .store
            .read_activity(pingap_controlplane::repository::TimeRange {
                limit: Some(10),
                ..Default::default()
            })
            .await
            .expect("reads activity");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].config_version.as_deref(),
            Some(out.version.id.as_str())
        );
        assert_eq!(rows[0].action, "domain.create");
    }

    /// The failure pingap swallows: the config lands, nothing reloads, and the gateway is
    /// left running policy the control plane no longer describes. The version must not
    /// reach `applied`, and N-1's config must be back on disk.
    #[tokio::test]
    async fn test_a_commit_the_reload_never_reaches_fails_and_restores_the_previous_config()
     {
        let _guard = PROVIDER.lock().await;
        let h = harness().await;

        let (reloading, _) = applier_over(&h, true);
        let first = reloading
            .apply(&intent(2), &actor(), "domain.create", 1_000)
            .await
            .expect("applies");
        assert_eq!(first.version.status, ConfigStatus::Applied);
        let baseline = ConfigManagerSource::new(h.manager.clone())
            .current()
            .await
            .expect("reads");

        // Same projection path, but nothing reloads the provider afterwards.
        let (stalled, sink) = applier_over(&h, false);
        let out = stalled
            .apply(&intent(4), &actor(), "domain.update", 2_000)
            .await
            .expect("returns an outcome rather than erroring");

        assert_eq!(out.version.status, ConfigStatus::Failed);
        assert_eq!(
            out.rolled_back_to.as_deref(),
            Some(first.version.id.as_str())
        );
        let error = out.version.error.unwrap_or_default();
        assert!(
            error.contains("waf:strict") && error.contains("older config"),
            "the failure does not say which policy was stale: {error}"
        );
        // Two commits through this sink: the candidate, then the restoration.
        assert_eq!(*sink.commits.lock().expect("lock"), 2);

        let restored = ConfigManagerSource::new(h.manager.clone())
            .current()
            .await
            .expect("reads");
        assert_eq!(
            pingap_controlplane::projection::canonical_toml(&restored)
                .expect("canonical"),
            pingap_controlplane::projection::canonical_toml(&baseline)
                .expect("canonical"),
            "rollback did not put the previous version's config back on disk"
        );
        // And the version that was applied is still the one that is applied.
        assert_eq!(
            h.store
                .latest_applied_config_version()
                .await
                .expect("reads")
                .map(|v| v.id),
            Some(first.version.id)
        );
    }

    /// The scheduled sweep is what makes a version stranded by a crash settle at all: the
    /// process that committed it is gone, so nothing else will ever read the data plane
    /// back for it.
    #[tokio::test]
    async fn test_the_sweep_settles_a_version_the_gateway_did_reload() {
        let _guard = PROVIDER.lock().await;
        let h = harness().await;
        let stranded = stranded_pending(&h, 2).await;
        // The commit landed and the reload happened; only the read-back was missed.
        let loaded = ConfigManagerSource::new(h.manager.clone())
            .current()
            .await
            .expect("reads");
        try_init_plugins(&loaded.plugins);

        assert_eq!(sweep_task(&h).execute(1).await.expect("sweeps"), true);
        assert_eq!(
            h.store
                .config_version(&stranded)
                .await
                .expect("reads")
                .map(|v| v.status),
            Some(ConfigStatus::Applied)
        );
    }

    /// And the other direction: a version the data plane does not have must not be left
    /// looking like it might be enforcing.
    #[tokio::test]
    async fn test_the_sweep_fails_a_version_the_data_plane_does_not_have() {
        let _guard = PROVIDER.lock().await;
        let h = harness().await;
        // Nothing running at all.
        try_init_plugins(&Default::default());
        let stranded = stranded_pending(&h, 2).await;

        assert_eq!(sweep_task(&h).execute(1).await.expect("sweeps"), true);
        let settled = h
            .store
            .config_version(&stranded)
            .await
            .expect("reads")
            .expect("the version is still there");
        assert_eq!(settled.status, ConfigStatus::Failed);
        assert!(
            settled.error.unwrap_or_default().contains("waf:strict"),
            "the failure does not name the policy that is missing"
        );
    }

    /// A sweep with nothing to settle must be silent and must write no config: it runs on
    /// every interval, and one that rewrote config would fight the operator.
    #[tokio::test]
    async fn test_the_sweep_is_a_no_op_when_nothing_is_pending() {
        let h = harness().await;
        applied_baseline(&h, 2).await;
        let before = ConfigManagerSource::new(h.manager.clone())
            .current()
            .await
            .expect("reads");

        assert_eq!(sweep_task(&h).execute(1).await.expect("sweeps"), false);

        let after = ConfigManagerSource::new(h.manager.clone())
            .current()
            .await
            .expect("reads");
        assert_eq!(
            pingap_controlplane::projection::canonical_toml(&before)
                .expect("canonical"),
            pingap_controlplane::projection::canonical_toml(&after)
                .expect("canonical")
        );
    }

    /// A version committed to disk but never confirmed — what a crash between commit and
    /// verification leaves behind. Returns its id.
    async fn stranded_pending(h: &Harness, paranoia: i64) -> String {
        let projected = generate(&intent(paranoia)).expect("generates");
        ConfigManagerSink::new(h.manager.clone())
            .commit(&projected.toml)
            .await
            .expect("commits");
        h.store
            .record_config_version(
                NewConfigVersion {
                    hash: pingap_controlplane::projection::hash(&projected),
                    status: ConfigStatus::Pending,
                    actor_id: None,
                    actor_username: "crashed".to_string(),
                    intent_json: serde_json::to_string(&intent(paranoia))
                        .expect("serialises"),
                    error: None,
                },
                1_000,
            )
            .await
            .expect("records")
            .id
    }

    /// The control plane re-derives `config_key()` without depending on `pingap-plugin`.    /// This is the only place both are linked, so it is where the two are held equal — and
    /// it is what makes post-commit verification's "running at the expected config"
    /// comparison meaningful at all.
    #[test]
    fn test_control_plane_config_key_matches_pingap_plugin_get_hash_key() {
        let confs = [
            r#"
category = "waf"
paranoia = 2
anomaly_threshold = 5
"#,
            r#"
category = "acl"
default_action = "deny"
[[rules]]
field = "ip"
operator = "in_cidr"
values = ["10.0.0.0/8"]
action = "allow"
"#,
            r#"
category = "compression"
gzip_level = 6
br_level = 6
zstd_level = 3
"#,
        ];
        for raw in confs {
            let conf: PluginConf = toml::from_str(raw).expect("parses");
            assert_eq!(
                pingap_plugin::get_hash_key(&conf),
                plugin_config_key(&conf),
                "the two derivations diverged on:\n{raw}"
            );
        }
    }

    /// And that key is what a real, constructed plugin reports — closing the loop from
    /// projected config to running instance.
    #[test]
    fn test_a_built_plugin_reports_the_projected_config_key() {
        let conf: PluginConf = toml::from_str(
            r#"
category = "compression"
gzip_level = 6
"#,
        )
        .expect("parses");
        let plugin = get_plugin_factory().create(&conf).expect("builds");
        assert_eq!(plugin.config_key(), plugin_config_key(&conf));
    }

    /// The factory check refuses what `pingap-waf -t` passes: a category this build does not
    /// have.
    #[test]
    fn test_factory_check_refuses_an_unknown_category() {
        let conf: PluginConf =
            toml::from_str(r#"category = "no_such_category""#).expect("parses");
        let err = FactoryPluginCheck
            .check("x", &conf)
            .expect_err("an unknown category must be refused");
        assert!(err.contains("no_such_category"), "{err}");
    }

    /// The posture is reported, and what is reported is what is in effect.
    ///
    /// The `debug_assert` inside is the real assertion — a log line saying `fail_closed`
    /// while the static says otherwise is worse than no log at all.
    #[test]
    fn test_the_logged_posture_is_the_posture_in_effect() {
        for configured in [
            None,
            Some("fail_closed".to_string()),
            Some("fail_open".to_string()),
            // A typo takes the safe branch, and the log says so rather than staying silent.
            Some("fail-open".to_string()),
        ] {
            pingap_core::set_policy_unavailable_mode(&configured);
            log_policy_unavailable_posture(&configured);
        }
        pingap_core::set_policy_unavailable_mode(&None);
    }

    /// The security criterion behind the subprocess rule, asserted rather than argued.
    ///
    /// `pingap-waf -t` calls `set_trusted_proxies` before it reaches its own `--test` branch, so
    /// an *in-process* validation of a candidate config would repoint this process's
    /// trusted-proxy table — and a rejected candidate would not put it back. Every
    /// XFF-derived ACL and rate-limit decision would then be silently wrong, with nothing to
    /// indicate it.
    ///
    /// Asserted on observable behaviour, not just the flag: a spoofed `X-Forwarded-For` from
    /// an untrusted peer must resolve to the peer both before and after a validation run
    /// that is *rejected*, and the candidate's own trusted-proxy list must never take effect
    /// in this process.
    #[tokio::test]
    async fn test_a_rejected_validation_leaves_client_ip_resolution_untouched()
    {
        use pingap_controlplane::projection::Verdict;

        // This process trusts only 10.0.0.0/8, so a request arriving directly must not be
        // able to claim an address via XFF.
        pingap_core::set_trusted_proxies(&Some(vec!["10.0.0.0/8".to_string()]));
        let spoofed_resolves_to_peer = || {
            let mock_io = tokio_test::io::Builder::new()
                .read(b"GET / HTTP/1.1\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n")
                .build();
            async move {
                let mut session =
                    pingora::proxy::Session::new_h1(Box::new(mock_io));
                session.read_request().await.expect("reads");
                // No real peer on a mock connection, so the spoofed value must not be
                // returned: an untrusted (here, unknown) peer's XFF is ignored.
                pingap_core::get_client_ip(&session)
            }
        };
        let before = spoofed_resolves_to_peer().await;
        assert_ne!(
            before, "1.2.3.4",
            "the spoofed header was honoured with a trusted-proxy list configured"
        );
        assert!(pingap_core::trusted_proxies_enabled());

        // A candidate that trusts everything — the dangerous value — and whose WAF
        // `paranoia` is outside 1..=4, so the constructor rejects it and the gate refuses.
        let mut candidate_intent = intent(99);
        candidate_intent.trusted_proxies = Some(vec!["0.0.0.0/0".to_string()]);
        let candidate = generate(&candidate_intent).expect("generates");

        // The real gateway binary, not `current_exe()`: in a unit test that is the libtest
        // harness, which would reject `-t` for its own reasons and make this test pass
        // without ever running the gate.
        let verdict = Validator::new(gateway_binary())
            .validate(&candidate, &FactoryPluginCheck)
            .await
            .expect("the gate runs");
        // The reason is asserted, not just the verdict: a rejection for the wrong reason
        // would satisfy `Rejected` while proving nothing.
        match &verdict {
            Verdict::Rejected { reason } => assert!(
                reason.contains("waf:strict") && reason.contains("paranoia"),
                "the gate refused for the wrong reason: {reason}"
            ),
            Verdict::Accepted => {
                panic!("a WAF with paranoia = 99 was accepted")
            },
        }

        assert!(
            pingap_core::trusted_proxies_enabled(),
            "validation cleared this process's trusted-proxy list"
        );
        assert_eq!(
            spoofed_resolves_to_peer().await,
            before,
            "validation changed how this process resolves a spoofed client IP"
        );
        pingap_core::set_trusted_proxies(&None);
    }
}
