//! The apply sequence: generate → validate → commit → verify → settle.
//!
//! The data plane here is a stand-in that answers "what config key is `name` running",
//! which is the one question post-commit verification asks. That is enough to test the
//! sequencing that matters — `applied` is never set by a successful write, a plugin that
//! did not come up fails the version and restores the previous one — without a gateway.
//! The end-to-end request-outcome criterion is covered in the binary, where the real
//! provider is linked.

use pingap_controlplane::projection::{
    Actor, Applier, Backend, ConfigSink, DataPlane, Domain, Intent, Listener,
    NoPluginCheck, PolicyBinding, Upstream, Validator, expectations, generate,
    plugin_config_key,
};
use pingap_controlplane::repository::{
    ConfigStatus, NewConfigVersion, TimeRange,
};
use pingap_controlplane::{ControlPlaneStore, TursoStore};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn intent(paranoia: i64) -> Intent {
    let mut upstreams = BTreeMap::new();
    upstreams.insert(
        "u".to_string(),
        Upstream {
            backends: vec![Backend {
                addr: "127.0.0.1:1".to_string(),
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
        "l".to_string(),
        Listener {
            addr: "127.0.0.1:9".to_string(),
            http2: None,
            tls: None,
            access_log: None,
            server_timing: None,
        },
    );
    let mut domains = BTreeMap::new();
    domains.insert(
        "d".to_string(),
        Domain {
            hostnames: vec!["example.test".to_string()],
            path: None,
            listener: "l".to_string(),
            upstream: "u".to_string(),
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
    let mut waf = toml::Table::new();
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

/// Records every commit. Behaves like a config manager whose write always succeeds.
#[derive(Default)]
struct RecordingSink {
    commits: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl ConfigSink for RecordingSink {
    async fn commit(&self, canonical_toml: &str) -> Result<(), String> {
        self.commits
            .lock()
            .expect("lock")
            .push(canonical_toml.to_string());
        Ok(())
    }
}

/// A data plane whose running plugins are whatever the test says they are.
#[derive(Default)]
struct FakeDataPlane {
    running: Mutex<BTreeMap<String, String>>,
}

impl FakeDataPlane {
    /// Pretend the reload brought up exactly the plugins in `toml`.
    fn reload_from(&self, toml: &str) {
        let config = pingap_config::PingapConfig::new(toml.as_bytes(), true)
            .expect("the committed config parses");
        let mut running = self.running.lock().expect("lock");
        running.clear();
        for (name, conf) in &config.plugins {
            running.insert(name.clone(), plugin_config_key(conf));
        }
    }
}

impl DataPlane for FakeDataPlane {
    fn running_config_key(&self, name: &str) -> Option<String> {
        self.running.lock().expect("lock").get(name).cloned()
    }
}

/// A sink that also reloads the fake data plane, like a real commit would, unless the
/// config names a plugin whose constructor "rejects" it.
struct ReloadingSink {
    sink: RecordingSink,
    data_plane: Arc<FakeDataPlane>,
    /// Plugin names the fake constructor refuses to build.
    refuse: Vec<String>,
}

#[async_trait::async_trait]
impl ConfigSink for ReloadingSink {
    async fn commit(&self, canonical_toml: &str) -> Result<(), String> {
        self.sink.commit(canonical_toml).await?;
        self.data_plane.reload_from(canonical_toml);
        // pingap stores the provider map even when a plugin failed to construct: the
        // failed one is simply absent. Model exactly that.
        let mut running = self.data_plane.running.lock().expect("lock");
        for name in &self.refuse {
            running.remove(name);
        }
        Ok(())
    }
}

struct Harness {
    applier: Applier,
    store: Arc<TursoStore>,
    sink: Arc<ReloadingSink>,
    data_plane: Arc<FakeDataPlane>,
    _dir: tempfile::TempDir,
}

async fn harness(refuse: &[&str]) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(
        TursoStore::open(dir.path().join("cp.db").to_str().expect("utf-8"))
            .await
            .expect("opens"),
    );
    store.migrate().await.expect("migrates");
    let data_plane = Arc::new(FakeDataPlane::default());
    let sink = Arc::new(ReloadingSink {
        sink: RecordingSink::default(),
        data_plane: data_plane.clone(),
        refuse: refuse.iter().map(|s| s.to_string()).collect(),
    });
    let applier = Applier::new(
        store.clone(),
        // A binary that does not exist: these tests are about the sequence after the
        // gate, and `NoPluginCheck` plus a binary the validator cannot spawn would
        // fail every apply. So the validator is pointed at `true`, which exits 0.
        Validator::new("/bin/true"),
        Arc::new(NoPluginCheck),
        sink.clone(),
        data_plane.clone(),
        Duration::from_millis(1),
    );
    Harness {
        applier,
        store,
        sink,
        data_plane,
        _dir: dir,
    }
}

fn actor() -> Actor {
    Actor {
        id: Some("u1".to_string()),
        username: "alice".to_string(),
    }
}

#[tokio::test]
async fn a_successful_apply_is_pending_until_verified_and_then_applied() {
    let h = harness(&[]).await;
    let out = h
        .applier
        .apply(&intent(1), &actor(), "domain.create", 1_000)
        .await
        .expect("applies");
    assert_eq!(out.version.status, ConfigStatus::Applied);
    assert_eq!(out.rolled_back_to, None);
    assert_eq!(h.sink.sink.commits.lock().expect("lock").len(), 1);

    // Exactly one activity row, naming the version it produced.
    let log = h
        .store
        .read_activity(TimeRange::default())
        .await
        .expect("read");
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].action, "domain.create");
    assert_eq!(
        log[0].config_version.as_deref(),
        Some(out.version.id.as_str())
    );
}

#[tokio::test]
async fn a_config_whose_waf_fails_to_construct_never_reaches_applied() {
    // The plan-level criterion. The WAF plugin "constructs" fine at validation — the
    // gate passes — and is then absent from the provider after reload, which is what
    // pingap does with a plugin whose constructor rejected it. The version must be
    // `failed`, the previous config must be back, and nothing may say `applied`.
    let h = harness(&[]).await;
    let first = h
        .applier
        .apply(&intent(1), &actor(), "domain.create", 1_000)
        .await
        .expect("applies");
    assert_eq!(first.version.status, ConfigStatus::Applied);

    // Now the data plane refuses to build the WAF on the next reload.
    let h2 = Harness {
        sink: Arc::new(ReloadingSink {
            sink: RecordingSink::default(),
            data_plane: h.data_plane.clone(),
            refuse: vec!["waf:strict".to_string()],
        }),
        ..h
    };
    let applier = Applier::new(
        h2.store.clone(),
        Validator::new("/bin/true"),
        Arc::new(NoPluginCheck),
        h2.sink.clone(),
        h2.data_plane.clone(),
        Duration::from_millis(1),
    );
    let second = applier
        .apply(&intent(2), &actor(), "waf.update", 2_000)
        .await
        .expect("the apply runs to a settled outcome");

    assert_eq!(second.version.status, ConfigStatus::Failed);
    assert!(
        second.version.error.as_deref().is_some_and(|e| e
            .contains("waf:strict")
            && e.contains("not running")),
        "the failure must name the plugin: {:?}",
        second.version.error
    );
    assert_eq!(
        second.rolled_back_to.as_deref(),
        Some(first.version.id.as_str()),
        "the previous applied version was not restored"
    );
    // Two commits on the second sink: the failed config, then the restoration. Read out
    // under a scoped guard, because the lock must not be alive across the await below.
    let commits = {
        let held = h2.sink.sink.commits.lock().expect("lock");
        held.clone()
    };
    assert_eq!(commits.len(), 2);
    assert_eq!(
        commits[1],
        generate(&intent(1)).expect("generates").toml,
        "the restored config is not the previous version's"
    );

    // The rollback target is still the first version, and nothing is `applied` that
    // was not verified.
    assert_eq!(
        h2.store
            .latest_applied_config_version()
            .await
            .expect("lookup")
            .map(|v| v.id),
        Some(first.version.id)
    );
}

#[tokio::test]
async fn a_rejected_projection_writes_nothing_and_records_why() {
    // The validator is a binary that exits 1 with a message on stderr.
    let h = harness(&[]).await;
    let applier = Applier::new(
        h.store.clone(),
        Validator::new("/bin/false"),
        Arc::new(NoPluginCheck),
        h.sink.clone(),
        h.data_plane.clone(),
        Duration::from_millis(1),
    );
    let out = applier
        .apply(&intent(1), &actor(), "domain.create", 1_000)
        .await
        .expect("a rejection is an outcome, not an error");
    assert_eq!(out.version.status, ConfigStatus::Failed);
    assert!(out.version.error.is_some());
    assert!(
        h.sink.sink.commits.lock().expect("lock").is_empty(),
        "a rejected config was committed"
    );
    // Still audited: an operator tried to change config and it was refused, which is a
    // fact worth having in the log.
    assert_eq!(
        h.store
            .read_activity(TimeRange::default())
            .await
            .expect("read")
            .len(),
        1
    );
}

#[tokio::test]
async fn explicit_rollback_regenerates_from_the_stored_intent_and_verifies() {
    let h = harness(&[]).await;
    let v1 = h
        .applier
        .apply(&intent(1), &actor(), "domain.create", 1_000)
        .await
        .expect("applies");
    let v2 = h
        .applier
        .apply(&intent(2), &actor(), "waf.update", 2_000)
        .await
        .expect("applies");
    assert_eq!(v2.version.status, ConfigStatus::Applied);
    assert_eq!(
        h.store
            .config_version(&v1.version.id)
            .await
            .expect("lookup")
            .expect("there")
            .status,
        ConfigStatus::Superseded
    );

    let back = h
        .applier
        .rollback(&v1.version.id, &actor(), 3_000)
        .await
        .expect("rolls back");
    assert_eq!(back.version.status, ConfigStatus::Applied);
    assert_eq!(
        back.version.hash, v1.version.hash,
        "rollback did not reproduce v1"
    );
    assert_ne!(
        back.version.id, v1.version.id,
        "rollback must be its own version"
    );
    // And the data plane is running v1's WAF config again.
    let expected = expectations(&generate(&intent(1)).expect("generates"));
    assert_eq!(
        h.data_plane.running_config_key("waf:strict"),
        Some(expected[0].config_key.clone())
    );
}

#[tokio::test]
async fn rollback_refuses_a_version_that_was_never_applied() {
    let h = harness(&[]).await;
    let applier = Applier::new(
        h.store.clone(),
        Validator::new("/bin/false"),
        Arc::new(NoPluginCheck),
        h.sink.clone(),
        h.data_plane.clone(),
        Duration::from_millis(1),
    );
    let failed = applier
        .apply(&intent(1), &actor(), "domain.create", 1_000)
        .await
        .expect("outcome");
    assert_eq!(failed.version.status, ConfigStatus::Failed);
    let err = h
        .applier
        .rollback(&failed.version.id, &actor(), 2_000)
        .await
        .expect_err(
            "rolling back to a failed version would restore the failure",
        );
    let msg = err.to_string();
    assert!(
        msg.contains("Failed") && msg.contains("ever applied"),
        "{msg}"
    );
}

// ---- pending sweep --------------------------------------------------------------------

/// A version that was committed by a process which then died is left `pending`, and
/// `pending` means "nobody has checked whether this is enforcing". The sweep is what
/// settles it, and with nothing running it must settle to `failed`.
#[tokio::test]
async fn a_version_left_pending_by_a_crash_is_failed_by_the_sweep() {
    let h = harness(&[]).await;
    // An applied baseline to roll back to.
    let first = h
        .applier
        .apply(&intent(1), &actor(), "domain.create", 1_000)
        .await
        .expect("applies");
    assert_eq!(first.version.status, ConfigStatus::Applied);

    // A second version recorded as `pending` with nothing committed — the crash case.
    let projected = pingap_controlplane::projection::generate(&intent(3))
        .expect("generates");
    let stranded = h
        .store
        .record_config_version(
            NewConfigVersion {
                hash: pingap_controlplane::projection::hash(&projected),
                status: ConfigStatus::Pending,
                actor_id: None,
                actor_username: "crashed".to_string(),
                intent_json: serde_json::to_string(&intent(3))
                    .expect("serialises"),
                error: None,
            },
            2_000,
        )
        .await
        .expect("records");

    let settled = h.applier.settle_pending(3_000).await.expect("sweeps");
    assert_eq!(settled.len(), 1, "exactly the stranded version");
    assert_eq!(settled[0].version.id, stranded.id);
    assert_eq!(settled[0].version.status, ConfigStatus::Failed);
    assert_eq!(
        settled[0].rolled_back_to.as_deref(),
        Some(first.version.id.as_str())
    );
    // And the applied version is untouched.
    assert_eq!(
        h.store
            .latest_applied_config_version()
            .await
            .expect("reads")
            .map(|v| v.id),
        Some(first.version.id)
    );
}

/// The other half: a version the data plane does confirm becomes `applied` even though the
/// process that committed it never got to check.
#[tokio::test]
async fn a_pending_version_the_data_plane_confirms_becomes_applied() {
    let h = harness(&[]).await;
    let projected = pingap_controlplane::projection::generate(&intent(3))
        .expect("generates");
    let stranded = h
        .store
        .record_config_version(
            NewConfigVersion {
                hash: pingap_controlplane::projection::hash(&projected),
                status: ConfigStatus::Pending,
                actor_id: None,
                actor_username: "crashed".to_string(),
                intent_json: serde_json::to_string(&intent(3))
                    .expect("serialises"),
                error: None,
            },
            2_000,
        )
        .await
        .expect("records");
    // The commit did land and the reload did happen; only the read-back was missed.
    h.data_plane.reload_from(&projected.toml);

    let settled = h.applier.settle_pending(3_000).await.expect("sweeps");
    assert_eq!(settled.len(), 1);
    assert_eq!(settled[0].version.id, stranded.id);
    assert_eq!(settled[0].version.status, ConfigStatus::Applied);
    assert_eq!(settled[0].rolled_back_to, None);
}

/// The sweep must be free when there is nothing to settle: it runs on a schedule, and a
/// version it re-checked would be one it could re-fail after a transient miss.
#[tokio::test]
async fn a_sweep_with_nothing_pending_does_nothing() {
    let h = harness(&[]).await;
    h.applier
        .apply(&intent(1), &actor(), "domain.create", 1_000)
        .await
        .expect("applies");
    let commits_before = h.sink.sink.commits.lock().expect("lock").len();

    assert!(
        h.applier
            .settle_pending(2_000)
            .await
            .expect("sweeps")
            .is_empty()
    );
    assert_eq!(
        h.sink.sink.commits.lock().expect("lock").len(),
        commits_before,
        "the sweep wrote config with nothing to settle"
    );
}

// ---- drift ----------------------------------------------------------------------------
use pingap_controlplane::projection::{ConfigSource, Drift, DriftDetector};
use pingap_core::{Notification, NotificationData};

/// The running config is whatever was last committed to the sink.
struct SinkAsSource(Arc<ReloadingSink>);

#[async_trait::async_trait]
impl ConfigSource for SinkAsSource {
    async fn current(&self) -> Result<pingap_config::PingapConfig, String> {
        let commits = self.0.sink.commits.lock().expect("lock");
        let last = commits.last().ok_or("nothing committed")?;
        pingap_config::PingapConfig::new(last.as_bytes(), true)
            .map_err(|e| e.to_string())
    }
}

/// A config somebody edited by hand.
struct EditedSource(String);

#[async_trait::async_trait]
impl ConfigSource for EditedSource {
    async fn current(&self) -> Result<pingap_config::PingapConfig, String> {
        pingap_config::PingapConfig::new(self.0.as_bytes(), true)
            .map_err(|e| e.to_string())
    }
}

#[derive(Default)]
struct CapturedNotifications(Mutex<Vec<(String, String)>>);

#[async_trait::async_trait]
impl Notification for CapturedNotifications {
    async fn notify(&self, data: NotificationData) {
        self.0
            .lock()
            .expect("lock")
            .push((data.category, data.message));
    }
}

#[tokio::test]
async fn an_unedited_config_reports_no_drift() {
    let h = harness(&[]).await;
    let out = h
        .applier
        .apply(&intent(1), &actor(), "domain.create", 1_000)
        .await
        .expect("applies");
    let notes = Arc::new(CapturedNotifications::default());
    let detector = DriftDetector::new(
        h.store.clone(),
        Arc::new(SinkAsSource(h.sink.clone())),
        Some(notes.clone()),
    );
    assert_eq!(
        detector.check().await.expect("checks"),
        Drift::None {
            version_id: out.version.id
        }
    );
    assert!(
        notes.0.lock().expect("lock").is_empty(),
        "no drift, no notice"
    );
}

#[tokio::test]
async fn a_manual_edit_raises_a_notification_and_is_not_corrected() {
    let h = harness(&[]).await;
    let out = h
        .applier
        .apply(&intent(1), &actor(), "domain.create", 1_000)
        .await
        .expect("applies");

    // An operator changes the WAF paranoia on disk, bypassing the control plane.
    let committed = h.sink.sink.commits.lock().expect("lock")[0].clone();
    let edited = committed.replace("paranoia = 1", "paranoia = 3");
    assert_ne!(
        committed, edited,
        "the fixture must actually change something"
    );

    let notes = Arc::new(CapturedNotifications::default());
    let detector = DriftDetector::new(
        h.store.clone(),
        Arc::new(EditedSource(edited.clone())),
        Some(notes.clone()),
    );
    let drift = detector.check().await.expect("checks");
    let Drift::Detected {
        version_id,
        expected_hash,
        actual_hash,
        differing,
    } = drift
    else {
        panic!("a hand edit was not detected: {drift:?}");
    };
    assert_eq!(version_id, out.version.id);
    assert_eq!(expected_hash, out.version.hash);
    assert_ne!(actual_hash, expected_hash);
    assert_eq!(differing, vec!["plugins".to_string()]);

    let notes = notes.0.lock().expect("lock");
    assert_eq!(notes.len(), 1, "exactly one notification per check");
    assert_eq!(notes[0].0, "config_drift");
    assert!(notes[0].1.contains("plugins"), "{}", notes[0].1);
    // The notification names the category, never the contents.
    assert!(
        !notes[0].1.contains("paranoia"),
        "config contents leaked into a notification: {}",
        notes[0].1
    );
    drop(notes);

    // And nothing was written back: the sink saw exactly the one original commit.
    assert_eq!(h.sink.sink.commits.lock().expect("lock").len(), 1);
}

#[tokio::test]
async fn reformatting_the_config_is_not_drift() {
    // The hash is over the canonical form, so a config that means the same thing in a
    // different byte order must not fire. Re-parse and re-emit with pingap's own
    // serialiser, which orders keys differently from the projection's.
    let h = harness(&[]).await;
    h.applier
        .apply(&intent(1), &actor(), "domain.create", 1_000)
        .await
        .expect("applies");
    let committed = h.sink.sink.commits.lock().expect("lock")[0].clone();
    let parsed = pingap_config::PingapConfig::new(committed.as_bytes(), true)
        .expect("parses");
    let reformatted = toml::to_string(&parsed).expect("serialises");
    assert_ne!(committed, reformatted, "the fixture must differ byte-wise");

    let detector = DriftDetector::new(
        h.store.clone(),
        Arc::new(EditedSource(reformatted)),
        None,
    );
    assert!(
        matches!(detector.check().await.expect("checks"), Drift::None { .. }),
        "a byte-level reformat was reported as drift"
    );
}

#[tokio::test]
async fn with_nothing_applied_there_is_no_baseline() {
    let h = harness(&[]).await;
    let detector = DriftDetector::new(
        h.store.clone(),
        Arc::new(SinkAsSource(h.sink.clone())),
        None,
    );
    assert_eq!(detector.check().await.expect("checks"), Drift::NoBaseline);
}
