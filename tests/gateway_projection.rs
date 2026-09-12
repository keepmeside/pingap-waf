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

//! The projection's criteria that can only be answered by a request.
//!
//! Everything else about the projection is testable in-process, and is. These are not: the
//! phase's criteria say "asserted at the backend" and "asserted by request outcome" because
//! the failure they guard against is a gateway that reports healthy while serving traffic
//! nothing inspected. A status field cannot answer that; only an upstream that received the
//! request, or did not, can.
//!
//! So each test here runs the real `pingap` binary against a real listener with a real
//! backend behind it, and reads the answer off the socket.

use pingap_config::PingapTomlConfig;
use pingap_controlplane::projection::{
    Backend, Domain, Intent, Listener, PolicyBinding, Upstream, generate,
};
// The plugin categories these tests project are registered by a `#[ctor]` in each plugin
// crate, and an rlib nothing references is dropped at link time — so without these imports
// the factory check refuses every WAF config with "Plugin waf not found" and the tests
// would fail for entirely the wrong reason, while the gateway beside them builds one
// happily. `src/main.rs` carries the same three imports for the same reason.
#[allow(unused_imports)]
use pingap_acl::plugin::Acl;
#[allow(unused_imports)]
use pingap_bot::plugin::Bot;
#[allow(unused_imports)]
use pingap_waf::plugin::Waf;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// An upstream that counts what reached it.
///
/// The count is the assertion in half these tests: "the WAF blocked it" and "the WAF is
/// broken and the request went through anyway" look identical from the client when the
/// upstream would have answered 200 either way.
struct CountingBackend {
    addr: String,
    hits: Arc<AtomicUsize>,
}

impl CountingBackend {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("backend binds");
        let addr = listener.local_addr().expect("addr").to_string();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                counter.fetch_add(1, Ordering::SeqCst);
                // Read just the head. Nothing here needs the body, and reading to EOF on a
                // keep-alive connection would block until the client goes away.
                let mut reader =
                    BufReader::new(stream.try_clone().expect("clone"));
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 0 {
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                    line.clear();
                }
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
                let _ = stream.flush();
            }
        });
        Self { addr, hits }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// A running gateway, killed when the test ends.
///
/// `Drop` rather than an explicit stop: a test that fails mid-way must not leave a process
/// holding a port, and a panic unwinds through `Drop`.
struct Gateway {
    child: Child,
    addr: String,
    conf_dir: PathBuf,
    log: PathBuf,
    _dir: tempfile::TempDir,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Gateway {
    /// Start with `config` on disk, `--autoreload` so a later write is picked up.
    async fn start(config: &str, port: u16) -> Self {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let conf_dir = dir.path().join("conf");
        std::fs::create_dir_all(&conf_dir).expect("conf dir");
        write_config(&conf_dir, config).await;
        let log = dir.path().join("pingap.log");

        // Straight to stderr and captured into a file, rather than `--log`: that flag
        // installs a *rolling* file writer whose real filename carries a date suffix, and a
        // test asserting on log contents must know where to read.
        let child = Command::new(env!("CARGO_BIN_EXE_pingap"))
            .arg("-c")
            .arg(&conf_dir)
            .arg("--autoreload")
            .env("RUST_LOG", "info")
            .env("PINGAP_DISABLE_ACME", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&log).expect("log file")))
            .spawn()
            .expect("the gateway starts");

        let gateway = Self {
            child,
            addr: format!("127.0.0.1:{port}"),
            conf_dir,
            log,
            _dir: dir,
        };
        gateway.wait_until_serving();
        gateway
    }

    fn wait_until_serving(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if TcpStream::connect(&self.addr).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "the gateway never listened on {}; log:\n{}",
            self.addr,
            self.log_text()
        );
    }

    /// Overwrite the config exactly the way the projection's sink does.
    async fn rewrite(&self, config: &str) {
        write_config(&self.conf_dir, config).await;
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// One request, one status code. Connection: close, so nothing is pooled across a
    /// reload and a test cannot read a pre-reload answer off a kept-alive socket.
    fn get(&self, path: &str) -> u16 {
        let mut stream = TcpStream::connect(&self.addr).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n"
        )
        .expect("writes request");
        stream.flush().expect("flush");
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        status_of(&response).unwrap_or_else(|| {
            panic!("no status line in response: {response:?}")
        })
    }

    /// Poll `path` until it answers `want`, which is how "within one hot-reload cycle"
    /// is asserted without sleeping for a fixed interval and hoping.
    fn wait_for_status(&self, path: &str, want: u16, within: Duration) -> u16 {
        let deadline = Instant::now() + within;
        let mut last = 0;
        while Instant::now() < deadline {
            last = self.get(path);
            if last == want {
                return last;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        last
    }
}

fn status_of(response: &str) -> Option<u16> {
    response
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// Write a config the way the projection's sink does: `ConfigManager::save_all`.
///
/// Not `fs::write` of a single `pingap.toml`. pingap migrates a single-file config
/// directory into per-category files on load (`migrate_config_layout`), so a test writing
/// the original filename afterwards would be editing a file the gateway no longer reads —
/// and the reload it was waiting for would never come.
async fn write_config(conf_dir: &Path, toml: &str) {
    let manager = pingap_config::new_file_config_manager(
        conf_dir.to_str().expect("utf-8 path"),
    )
    .expect("file config manager");
    let config: PingapTomlConfig =
        toml::from_str(toml).expect("the generated config parses");
    manager.save_all(&config).await.expect("writes config");
}

/// A free port, held only long enough to learn its number.
///
/// A deterministic port per test would be better for the process-management rule about
/// stale owners, but two `cargo test` runs on one machine would then collide; the gateway
/// under test is killed on `Drop`, so nothing outlives the test to reclaim.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("binds")
        .local_addr()
        .expect("addr")
        .port()
}

/// The projected config for one domain, with the policies given.
fn intent_for(
    port: u16,
    backend: &str,
    policies: Vec<PolicyBinding>,
    plugins: Vec<(&str, &str)>,
) -> Intent {
    let mut upstreams = BTreeMap::new();
    upstreams.insert(
        "app".to_string(),
        Upstream {
            backends: vec![Backend {
                addr: backend.to_string(),
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
            addr: format!("127.0.0.1:{port}"),
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
            policies,
        },
    );
    let mut policy_confs = BTreeMap::new();
    for (name, toml_body) in plugins {
        policy_confs.insert(
            name.to_string(),
            toml::from_str(toml_body).expect("plugin conf parses"),
        );
    }
    Intent {
        upstreams,
        listeners,
        domains,
        policies: policy_confs,
        trusted_proxies: None,
    }
}

fn config_for(
    port: u16,
    backend: &str,
    policies: Vec<PolicyBinding>,
    plugins: Vec<(&str, &str)>,
) -> String {
    generate(&intent_for(port, backend, policies, plugins))
        .expect("generates")
        .toml
}

/// The gateway's *first* config, with the reload poll shortened.
///
/// The file backend is polled and the default interval is 90 seconds — a sensible
/// production default and a terrible test one. The interval is read once at startup
/// (`main.rs` hands it to the service), so shortening it here is enough: a later config
/// without the key still gets picked up at this cadence, which is what lets a projection
/// generated from the contract's own fields drive the reload tests.
fn boot_config(
    port: u16,
    backend: &str,
    policies: Vec<PolicyBinding>,
    plugins: Vec<(&str, &str)>,
) -> String {
    let toml = config_for(port, backend, policies, plugins).replace(
        "[basic]",
        &format!("[basic]\nauto_restart_check_interval = \"{POLL_SECS}s\""),
    );
    assert!(
        toml.contains("auto_restart_check_interval"),
        "the generated config has no [basic] table to shorten the poll in"
    );
    toml
}

/// How often the gateway re-reads the config directory in these tests.
const POLL_SECS: u64 = 1;

/// Generous relative to a 1-second poll, and bounded so a broken reload fails the test
/// rather than hanging it.
const RELOAD_WINDOW: Duration = Duration::from_secs(30);

/// A WAF that blocks SQL injection.
const WAF_BLOCKING: &str = r#"
category = "waf"
[categories]
sql_injection = "block"
"#;

/// The same WAF with the category turned off — the "rule toggle" of the hot-reload
/// criterion.
const WAF_OFF: &str = r#"
category = "waf"
[categories]
sql_injection = "off"
"#;

/// A WAF whose constructor rejects its config: `paranoia` is outside 1..=4. This is the
/// shape that reaches the provider as a *failure* rather than an instance.
const WAF_UNBUILDABLE: &str = r#"
category = "waf"
paranoia = 99
[categories]
sql_injection = "block"
"#;

const MALICIOUS: &str = "/?id=1%27%20OR%20%271%27%3D%271";

// ---------------------------------------------------------------------------------------

/// The floor everything else stands on: the *projected* config actually enforces, and a
/// benign request still reaches the upstream.
#[tokio::test]
async fn a_projected_waf_blocks_the_attack_and_passes_the_benign_request() {
    let backend = CountingBackend::start();
    let port = free_port();
    let config = boot_config(
        port,
        &backend.addr,
        vec![PolicyBinding::Waf("strict".to_string())],
        vec![("waf:strict", WAF_BLOCKING)],
    );
    let gateway = Gateway::start(&config, port).await;

    assert_eq!(gateway.get("/healthz"), 200, "log:\n{}", gateway.log_text());
    let benign_hits = backend.hits();
    assert!(benign_hits > 0, "the benign request never reached upstream");

    assert_eq!(gateway.get(MALICIOUS), 403, "log:\n{}", gateway.log_text());
    assert_eq!(
        backend.hits(),
        benign_hits,
        "a blocked request still reached the upstream"
    );
}

/// The criterion: during the reload window, a Location whose WAF failed to construct
/// answers **503**, and the upstream receives nothing.
///
/// 503 rather than 403 because the client was not denied by policy — the policy could not
/// be evaluated — and conflating the two would put config failures into block metrics.
#[tokio::test]
async fn a_location_whose_waf_cannot_be_built_answers_503_and_the_upstream_sees_nothing()
 {
    let backend = CountingBackend::start();
    let port = free_port();
    let good = boot_config(
        port,
        &backend.addr,
        vec![PolicyBinding::Waf("strict".to_string())],
        vec![("waf:strict", WAF_BLOCKING)],
    );
    let gateway = Gateway::start(&good, port).await;
    assert_eq!(gateway.get("/healthz"), 200);

    // What a reload of a config the gate did not catch looks like from the data plane's
    // side: the plugin is configured, and it did not build.
    gateway
        .rewrite(&config_for(
            port,
            &backend.addr,
            vec![PolicyBinding::Waf("strict".to_string())],
            vec![("waf:strict", WAF_UNBUILDABLE)],
        ))
        .await;
    let status = gateway.wait_for_status("/healthz", 503, RELOAD_WINDOW);
    assert_eq!(
        status,
        503,
        "a Location with an unbuildable WAF did not fail closed; log:\n{}",
        gateway.log_text()
    );

    // Counted from the first 503, not from before the rewrite: the requests
    // `wait_for_status` made while the old config was still live were served correctly and
    // *should* have reached upstream. What must not happen is a request reaching upstream
    // while the WAF is not running, which is what these are.
    let once_failing = backend.hits();
    for _ in 0..5 {
        assert_eq!(gateway.get(MALICIOUS), 503);
        assert_eq!(gateway.get("/healthz"), 503);
    }
    assert_eq!(
        backend.hits(),
        once_failing,
        "the upstream was reached while the WAF was not running"
    );
}

/// And the guard is scoped: a broken *utility* plugin must not take the site down.
#[tokio::test]
async fn a_location_whose_compression_cannot_be_built_still_serves() {
    let backend = CountingBackend::start();
    let port = free_port();
    // `compression` is not a security-enforcing category, and this level is out of range.
    let broken_compression = r#"
category = "compression"
gzip_level = 99
"#;
    let config = boot_config(
        port,
        &backend.addr,
        vec![PolicyBinding::Waf("strict".to_string())],
        vec![
            ("waf:strict", WAF_BLOCKING),
            ("compression:site", broken_compression),
        ],
    );
    // The projection only attaches what a domain binds, so bind the broken one by name.
    let config = config.replace(
        r#"plugins = ["waf:strict"]"#,
        r#"plugins = ["waf:strict", "compression:site"]"#,
    );
    assert!(
        config.contains("compression:site"),
        "the fixture did not attach the broken plugin"
    );
    let gateway = Gateway::start(&config, port).await;

    assert_eq!(
        gateway.get("/healthz"),
        200,
        "a broken compression plugin took the site down; log:\n{}",
        gateway.log_text()
    );
    assert!(backend.hits() > 0);
    // And the WAF beside it still enforces.
    assert_eq!(gateway.get(MALICIOUS), 403);
}

/// The operator escape hatch, and it has to be visible: `fail_open` serves the request and
/// says so in the log.
#[tokio::test]
async fn with_fail_open_an_unbuildable_waf_serves_and_the_log_says_so() {
    let backend = CountingBackend::start();
    let port = free_port();
    let good = boot_config(
        port,
        &backend.addr,
        vec![PolicyBinding::Waf("strict".to_string())],
        vec![("waf:strict", WAF_BLOCKING)],
    );
    let fail_open = |config: String| {
        config.replace(
            "[basic]",
            "[basic]\non_policy_unavailable = \"fail_open\"",
        )
    };
    let good = fail_open(good);
    assert!(good.contains("fail_open"), "the fixture lost the setting");
    let gateway = Gateway::start(&good, port).await;
    assert_eq!(gateway.get("/healthz"), 200);
    let before = backend.hits();

    gateway
        .rewrite(&fail_open(config_for(
            port,
            &backend.addr,
            vec![PolicyBinding::Waf("strict".to_string())],
            vec![("waf:strict", WAF_UNBUILDABLE)],
        )))
        .await;

    // Served, not refused — and the upstream really did receive it, which is the part that
    // makes `fail_open` a decision an operator should have to make on purpose.
    let deadline = Instant::now() + RELOAD_WINDOW;
    let mut served_unprotected = false;
    while Instant::now() < deadline {
        if gateway.log_text().contains("serving unprotected") {
            served_unprotected = true;
            break;
        }
        assert_eq!(gateway.get("/healthz"), 200, "fail_open refused a request");
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        served_unprotected,
        "fail_open served the request without recording that it was unprotected; log:\n{}",
        gateway.log_text()
    );
    assert!(
        backend.hits() > before,
        "fail_open did not actually reach the upstream"
    );
}

/// A rule toggle applies within one hot-reload cycle, and the process does not restart.
///
/// The PID assertion is the point: `--autoreload` swapping config in place and
/// `--autorestart` spawning a fresh process are indistinguishable from the client, and only
/// one of them is what this criterion claims.
#[tokio::test]
async fn a_waf_toggle_applies_within_one_hot_reload_cycle_without_a_restart() {
    let backend = CountingBackend::start();
    let port = free_port();
    let blocking = boot_config(
        port,
        &backend.addr,
        vec![PolicyBinding::Waf("strict".to_string())],
        vec![("waf:strict", WAF_BLOCKING)],
    );
    let gateway = Gateway::start(&blocking, port).await;
    let pid = gateway.pid();
    assert_eq!(gateway.get(MALICIOUS), 403);

    gateway
        .rewrite(&config_for(
            port,
            &backend.addr,
            vec![PolicyBinding::Waf("strict".to_string())],
            vec![("waf:strict", WAF_OFF)],
        ))
        .await;
    assert_eq!(
        gateway.wait_for_status(MALICIOUS, 200, RELOAD_WINDOW),
        200,
        "the toggle never took effect; log:\n{}",
        gateway.log_text()
    );
    assert_eq!(pid, gateway.pid(), "the process restarted");

    // And back again, which is the rollback criterion's request-level assertion: a request
    // that was blocked before a change is blocked again after the change is undone.
    gateway.rewrite(&blocking).await;
    assert_eq!(
        gateway.wait_for_status(MALICIOUS, 403, RELOAD_WINDOW),
        403,
        "rollback did not restore the earlier request outcome; log:\n{}",
        gateway.log_text()
    );
    assert_eq!(pid, gateway.pid(), "the process restarted");
}

/// The other half of the hot-reload criterion: an **upstream** change, not a policy one.
///
/// Worth its own test because the two travel different distances through the reload. A
/// plugin is rebuilt from its config table; an upstream change has to reach the discovery
/// and load-balancer machinery and produce a new backend set, and the only honest way to
/// see that is a second backend counting what arrives.
#[tokio::test]
async fn an_upstream_change_applies_within_one_hot_reload_cycle_without_a_restart()
 {
    let first = CountingBackend::start();
    let second = CountingBackend::start();
    let port = free_port();
    let gateway =
        Gateway::start(&boot_config(port, &first.addr, vec![], vec![]), port)
            .await;
    let pid = gateway.pid();
    assert_eq!(gateway.get("/healthz"), 200);
    assert!(
        first.hits() > 0,
        "the first backend never received anything"
    );
    assert_eq!(
        second.hits(),
        0,
        "the second backend received traffic early"
    );

    gateway
        .rewrite(&config_for(port, &second.addr, vec![], vec![]))
        .await;

    // Polled on the backend rather than on the status code: both backends answer 200, so
    // the status cannot tell them apart — which is the whole reason this needs two.
    let deadline = Instant::now() + RELOAD_WINDOW;
    while Instant::now() < deadline && second.hits() == 0 {
        assert_eq!(
            gateway.get("/healthz"),
            200,
            "the gateway stopped serving while the upstream was swapped; log:\n{}",
            gateway.log_text()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        second.hits() > 0,
        "an upstream change never reached the data plane; log:\n{}",
        gateway.log_text()
    );
    assert_eq!(pid, gateway.pid(), "the process restarted");
}

// ---- driven by the real Applier --------------------------------------------------------
//
// Above, the config is written the way the sink writes it. Here the whole apply runs:
// generate, validate against this very binary, commit through the config manager the
// gateway is reading, and read the outcome off the socket.
//
// One deliberate stand-in: `DataPlane`. Post-commit verification asks the *running
// process* which plugins it holds, and there is no surface for that across a process
// boundary until Phase 09's API exposes one. That read-back is what
// `src/projection.rs::test_an_apply_the_reload_reaches_is_applied_and_the_plugin_is_running`
// and its sibling assert, in-process, against the real plugin provider. What these tests
// add is the half that cannot be asserted in-process: whether the committed config changes
// what a socket answers.

use pingap_controlplane::projection::{
    Actor, Applier, ApplyError, ConfigSink, DataPlane, PluginCheck, Validator,
};
use pingap_controlplane::repository::{ConfigStatus, ControlPlaneStore};
use pingap_controlplane::store::TursoStore;

/// Commits through the same `ConfigManager` API the binary's sink uses, and records what a
/// reload of that config would bring up.
struct DirSink {
    conf_dir: PathBuf,
    reloaded: Arc<Reloaded>,
}

#[async_trait::async_trait]
impl ConfigSink for DirSink {
    async fn commit(&self, canonical_toml: &str) -> Result<(), String> {
        write_config(&self.conf_dir, canonical_toml).await;
        self.reloaded.from(canonical_toml);
        Ok(())
    }
}

/// The real plugin factory, which is the check `pingap -t` cannot perform for a
/// Location-attached plugin.
struct FactoryCheck;

impl PluginCheck for FactoryCheck {
    fn check(
        &self,
        _name: &str,
        conf: &pingap_config::PluginConf,
    ) -> Result<(), String> {
        pingap_plugin::get_plugin_factory()
            .create(conf)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// What a reload of the last committed config brings up.
///
/// The stand-in described above: it models a reload that reached the gateway, because
/// asking the *other process* which plugins it holds needs the surface Phase 09 adds. Every
/// test using it then confirms the reload independently, off the socket — so a stub that
/// lied would not make a test pass.
#[derive(Default)]
struct Reloaded {
    running: std::sync::Mutex<BTreeMap<String, String>>,
}

impl Reloaded {
    fn from(&self, canonical_toml: &str) {
        let config =
            pingap_config::PingapConfig::new(canonical_toml.as_bytes(), true)
                .expect("the committed config parses");
        let mut running = self.running.lock().expect("lock");
        running.clear();
        for (name, conf) in &config.plugins {
            running.insert(
                name.clone(),
                pingap_controlplane::projection::plugin_config_key(conf),
            );
        }
    }
}

impl DataPlane for Reloaded {
    fn running_config_key(&self, name: &str) -> Option<String> {
        self.running.lock().expect("lock").get(name).cloned()
    }
}

struct ControlPlane {
    applier: Applier,
    store: Arc<dyn ControlPlaneStore>,
    _dir: tempfile::TempDir,
}

async fn control_plane(conf_dir: &Path) -> ControlPlane {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let store =
        TursoStore::open(dir.path().join("cp.db").to_str().expect("utf-8"))
            .await
            .expect("store opens");
    store.migrate().await.expect("migrates");
    let store: Arc<dyn ControlPlaneStore> = Arc::new(store);
    let reloaded = Arc::new(Reloaded::default());
    ControlPlane {
        applier: Applier::new(
            store.clone(),
            Validator::new(env!("CARGO_BIN_EXE_pingap")),
            Arc::new(FactoryCheck),
            Arc::new(DirSink {
                conf_dir: conf_dir.to_path_buf(),
                reloaded: reloaded.clone(),
            }),
            reloaded,
            Duration::from_millis(0),
        ),
        store,
        _dir: dir,
    }
}

fn actor() -> Actor {
    Actor {
        id: Some("u1".to_string()),
        username: "admin".to_string(),
    }
}

/// The criterion, at the socket: a config whose WAF cannot be built never reaches
/// `applied`, and a request that was blocked before the change is still blocked after.
///
/// The gate refuses it before anything is written, so the "after" is not a rollback — it is
/// the live config never having moved. That is the stronger outcome and the one the
/// two-phase apply exists to produce; the rollback path is the next test.
#[tokio::test]
async fn a_config_whose_waf_cannot_be_built_is_refused_and_the_gateway_keeps_blocking()
 {
    let backend = CountingBackend::start();
    let port = free_port();
    let blocking = boot_config(
        port,
        &backend.addr,
        vec![PolicyBinding::Waf("strict".to_string())],
        vec![("waf:strict", WAF_BLOCKING)],
    );
    let gateway = Gateway::start(&blocking, port).await;
    assert_eq!(gateway.get(MALICIOUS), 403);
    let before = std::fs::read_to_string(gateway.conf_dir.join("plugins.toml"))
        .expect("the plugin config is on disk");

    let cp = control_plane(&gateway.conf_dir).await;
    let out = cp
        .applier
        .apply(
            &intent_for(
                port,
                &backend.addr,
                vec![PolicyBinding::Waf("strict".to_string())],
                vec![("waf:strict", WAF_UNBUILDABLE)],
            ),
            &actor(),
            "policy.update",
            1_000,
        )
        .await
        .expect("the apply returns an outcome rather than erroring");

    assert_eq!(out.version.status, ConfigStatus::Failed);
    let reason = out.version.error.clone().unwrap_or_default();
    assert!(
        reason.contains("waf:strict") && reason.contains("paranoia"),
        "the version was failed for the wrong reason: {reason}"
    );
    assert!(
        cp.store
            .latest_applied_config_version()
            .await
            .expect("reads")
            .is_none(),
        "a refused config reached `applied`"
    );

    // Provably unmodified, and the gateway keeps serving throughout.
    assert_eq!(
        std::fs::read_to_string(gateway.conf_dir.join("plugins.toml"))
            .expect("still there"),
        before,
        "a refused config was written to the live location"
    );
    assert_eq!(
        gateway.get(MALICIOUS),
        403,
        "the gateway stopped blocking after a refused apply; log:\n{}",
        gateway.log_text()
    );
    assert_eq!(gateway.get("/healthz"), 200, "the gateway stopped serving");
}

/// Rollback, driven by the control plane and asserted by request outcome: a request that is
/// allowed under version 2 is blocked again once version 1 is restored.
#[tokio::test]
async fn rolling_back_through_the_applier_restores_the_earlier_request_outcome()
{
    let backend = CountingBackend::start();
    let port = free_port();
    let blocking_policies = || vec![PolicyBinding::Waf("strict".to_string())];
    let gateway = Gateway::start(
        &boot_config(
            port,
            &backend.addr,
            blocking_policies(),
            vec![("waf:strict", WAF_BLOCKING)],
        ),
        port,
    )
    .await;
    assert_eq!(gateway.get(MALICIOUS), 403);

    let cp = control_plane(&gateway.conf_dir).await;
    // Version 1: the config the gateway is already running, so the control plane has a
    // recorded version to roll back *to*.
    let v1 = cp
        .applier
        .apply(
            &intent_for(
                port,
                &backend.addr,
                blocking_policies(),
                vec![("waf:strict", WAF_BLOCKING)],
            ),
            &actor(),
            "policy.create",
            1_000,
        )
        .await
        .expect("applies");
    // Version 2: the WAF category off.
    cp.applier
        .apply(
            &intent_for(
                port,
                &backend.addr,
                blocking_policies(),
                vec![("waf:strict", WAF_OFF)],
            ),
            &actor(),
            "policy.update",
            2_000,
        )
        .await
        .expect("applies");
    assert_eq!(
        gateway.wait_for_status(MALICIOUS, 200, RELOAD_WINDOW),
        200,
        "version 2 never took effect, so the rollback proves nothing; log:\n{}",
        gateway.log_text()
    );

    let rolled = cp
        .applier
        .rollback(&v1.version.id, &actor(), 3_000)
        .await
        .expect("rolls back");
    assert_ne!(
        rolled.version.id, v1.version.id,
        "a rollback must record its own version, not reuse the target's"
    );
    assert_eq!(
        gateway.wait_for_status(MALICIOUS, 403, RELOAD_WINDOW),
        403,
        "rollback did not restore the earlier request outcome; log:\n{}",
        gateway.log_text()
    );

    // Rolling back to a version that was never applied is refused rather than restoring a
    // failure.
    let refused = cp
        .applier
        .apply(
            &intent_for(
                port,
                &backend.addr,
                blocking_policies(),
                vec![("waf:strict", WAF_UNBUILDABLE)],
            ),
            &actor(),
            "policy.update",
            4_000,
        )
        .await
        .expect("returns an outcome");
    assert_eq!(refused.version.status, ConfigStatus::Failed);
    assert!(matches!(
        cp.applier
            .rollback(&refused.version.id, &actor(), 5_000)
            .await,
        Err(ApplyError::Commit { .. })
    ));
    assert_eq!(gateway.get(MALICIOUS), 403);
}

/// The same commit path on the etcd backend.
///
/// Not a second implementation: `save_all` is the one entry point and the backend is chosen
/// by URL prefix, so what this proves is that the projection's total-write shape works on a
/// key-value store as well as a directory — and that pingap's own config history, which only
/// etcd supports, still records the write.
#[tokio::test]
async fn the_commit_path_works_on_etcd_and_leaves_its_history_intact() {
    let url = format!(
        "etcd://127.0.0.1:2379/pingap-projection-{}?timeout=10s&connect_timeout=5s&enable_history=true",
        std::process::id()
    );
    let manager = match pingap_config::new_config_manager(&url) {
        Ok(manager) => manager,
        Err(e) => panic!("etcd config manager: {e}"),
    };
    assert!(
        manager.support_observer(),
        "the etcd backend should push changes rather than be polled"
    );
    assert!(
        manager.support_history(),
        "the etcd backend should keep config history"
    );

    let projected = generate(&intent_for(
        free_port(),
        "127.0.0.1:8080",
        vec![PolicyBinding::Waf("strict".to_string())],
        vec![("waf:strict", WAF_BLOCKING)],
    ))
    .expect("generates");
    let config: PingapTomlConfig =
        toml::from_str(&projected.toml).expect("parses");
    manager.save_all(&config).await.expect("commits to etcd");

    // Read back through the same manager and hash it the way drift detection would: a
    // commit whose read-back does not match is a commit that cannot be verified.
    let read_back = manager
        .load_all()
        .await
        .expect("reads back")
        .to_pingap_config(false)
        .expect("converts");
    assert_eq!(
        pingap_controlplane::projection::hash(
            &pingap_controlplane::projection::Projected::from_config(read_back)
                .expect("hashable")
        ),
        pingap_controlplane::projection::hash(&projected),
        "the config read back off etcd is not the config that was hashed"
    );

    // A second commit, so there is a previous revision for history to have.
    manager
        .save_all(
            &toml::from_str(
                &generate(&intent_for(
                    free_port(),
                    "127.0.0.1:8080",
                    vec![PolicyBinding::Waf("strict".to_string())],
                    vec![("waf:strict", WAF_OFF)],
                ))
                .expect("generates")
                .toml,
            )
            .expect("parses"),
        )
        .await
        .expect("commits again");
    let history = manager
        .history(pingap_config::Category::Plugin, "waf:strict")
        .await
        .expect("reads history")
        .unwrap_or_default();
    assert!(
        !history.is_empty(),
        "committing through the projection lost pingap's own config history"
    );
}
