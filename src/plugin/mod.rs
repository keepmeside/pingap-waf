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

use crate::process::{get_admin_addr, get_config_path};
use ahash::AHashMap;
use arc_swap::ArcSwap;
use pingap_config::PluginConf;
use pingap_core::{Plugin, PluginMiss, PluginProvider, PluginStep, Plugins};
use pingap_plugin::get_plugin_factory;
// Reuse the canonical plugin-config helpers instead of keeping a second copy.
// `get_hash_key` in particular MUST stay byte-identical to the one plugins use
// to compute their config key, otherwise hot-reload change detection breaks.
pub(crate) use pingap_plugin::{
    get_hash_key, get_int_conf, get_step_conf, get_str_conf,
};
use pingap_proxy::ServerConf;
use pingap_util::base64_encode;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use tracing::{error, info};

mod admin;
// Fork-owned. Per-user auth for the admin plugin, kept out of the vendored
// `admin.rs` so that file gains one field and one call rather than a login flow.
mod admin_auth;
mod stats;

/// UUID for the admin server plugin, generated at runtime
pub static ADMIN_SERVER_PLUGIN: &str = "pingap:admin";

static LOG_TARGET: &str = "main::plugin";

/// Query parameters on the `--admin` address, e.g.
/// `user:pass@127.0.0.1:3018/?store=/var/lib/pingap/control-plane.db`.
#[derive(Debug, PartialEq, Deserialize, Serialize, Default)]
struct AdminPluginParams {
    /// Path of the control-plane database. Defaults to
    /// `control-plane.db` beside the config file.
    store: Option<String>,
    /// Key that encrypts TOTP secrets at rest. Without it, 2FA enrolment is
    /// refused rather than stored readable.
    totp_key: Option<String>,
}

/// Where the control-plane store lives when `--admin` does not say.
///
/// Beside the config file: the one directory an operator already knows is
/// pingap's, already backs up, and already restricts. An etcd URL has no
/// directory, and neither does a missing `-c`, so those land in the working
/// directory — `store=` on the admin address is how to say otherwise.
fn default_store_path() -> String {
    if let Ok(store) = std::env::var("PINGAP_STORE")
        && !store.is_empty()
    {
        return store;
    }
    let conf = get_config_path()
        .map(|c| pingap_util::resolve_path(&c))
        .filter(|c| !c.starts_with("etcd://"))
        .unwrap_or_default();
    let p = std::path::Path::new(&conf);
    let dir = if conf.is_empty() {
        std::path::PathBuf::from(".")
    } else if p.is_dir() {
        p.to_path_buf()
    } else {
        p.parent()
            .filter(|d| !d.as_os_str().is_empty())
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."))
    };
    dir.join("control-plane.db").to_string_lossy().to_string()
}

/// Parses admin plugin configuration from an address string.
///
/// # Arguments
/// * `addr` - The address string to parse in URL format
///
/// # Returns
/// A tuple containing:
/// - ServerConf: The server configuration
/// - String: The plugin name
/// - PluginConf: The plugin configuration
///
/// # Errors
/// Returns Error::Invalid if URL parsing fails
pub fn parse_admin_plugin(
    addr: &str,
) -> Result<(ServerConf, String, PluginConf)> {
    let info = url::Url::from_str(&format!("http://{addr}")).map_err(|e| {
        Error::Invalid {
            category: "url".to_string(),
            message: e.to_string(),
        }
    })?;
    let mut addr = info.host_str().unwrap_or_default().to_string();
    addr = format!("{addr}:{}", info.port().unwrap_or(80));

    let mut authorization = "".to_string();
    if !info.username().is_empty() {
        authorization = urlencoding::decode(info.username())
            .unwrap_or_default()
            .to_string();
        // if not base64 string
        if let Some(pass) = info.password() {
            authorization = base64_encode(format!("{authorization}:{pass}"));
        }
    }
    // The credential on `--admin` has one job now: it bootstraps the first
    // admin account into an empty store, after which it is never consulted.
    // It is therefore optional — an operator whose store already has users
    // does not need to keep a password on the command line — and its absence
    // is not the open door it used to be. With no users and no bootstrap,
    // nobody can log in, which is deny by construction rather than allow.
    //
    // Credentials also arrive by environment variable, which main.rs folds
    // into this address before calling us.
    if authorization.is_empty() {
        info!(
            target: LOG_TARGET,
            addr,
            "admin address carries no credential; the first admin must already exist in the store"
        );
    }

    let mut path = info.path().to_string();
    if path.is_empty() {
        path = "/".to_string();
    }
    let params: AdminPluginParams =
        serde_qs::from_str(info.query().unwrap_or_default())
            .unwrap_or_default();
    let store = params.store.unwrap_or_else(default_store_path);
    let totp_key = params.totp_key.unwrap_or_default();

    let data = format!(
        r#"
    category = "admin"
    path = "{path}"
    bootstrap = "{authorization}"
    store = "{store}"
    totp_key = "{totp_key}"
    remark = "Admin serve"
    "#,
    );
    Ok((
        ServerConf {
            name: "pingap:admin".to_string(),
            admin: true,
            addr,
            ..Default::default()
        },
        ADMIN_SERVER_PLUGIN.to_string(),
        toml::from_str::<PluginConf>(&data).unwrap_or_default(),
    ))
}

/// The control-plane store this process uses, or `None` when there is no admin listener.
///
/// Resolved through `parse_admin_plugin` rather than re-deriving the path, because the
/// store is a single-writer database (`TursoStore::shared` refuses a second path) and two
/// subsystems computing it two ways is how a process ends up with two of them — one holding
/// the users, the other the config versions. There is no store without `--admin`: the
/// gateway proxies from config alone.
pub fn admin_store_path() -> Option<String> {
    let addr = get_admin_addr()?;
    let (_, _, conf) = parse_admin_plugin(&addr).ok()?;
    conf.get("store")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Error types for plugin operations
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Plugin {category} invalid, message: {message}"))]
    Invalid { category: String, message: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

/// Returns a list of built-in plugins with their default configurations.
///
/// Includes plugins for:
/// - Compression (gzip, br, zstd)
/// - Ping health check
/// - Stats reporting
/// - Request ID generation
/// - Accept-Encoding adjustment
pub fn get_builtin_proxy_plugins() -> Vec<(String, PluginConf)> {
    vec![
        // default level, gzip:6 br:6 zstd:3
        (
            "pingap:compression".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "compression"
gzip_level = 6
br_level = 6
zstd_level = 6
remark = "Compression for http, support zstd:6, br:6, gzip:6"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:compressionUpstream".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "compression"
gzip_level = 6
br_level = 6
zstd_level = 6 
mode = "upstream"
remark = "Compression for upstream response, support zstd:6, br:6, gzip:6"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:ping".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "ping"
path = "/ping"
remark = "Ping pong"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:stats".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "stats"
path = "/stats"
remark = "Get stats of server"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:requestId".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "request_id"
remark = "Generate a request id for service"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:acceptEncodingAdjustment".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "accept_encoding"
encodings = "zstd, br, gzip"
only_one_encoding = true
remark = "Adjust the accept encoding order and choose one encoding"
"###,
            )
            .unwrap_or_default(),
        ),
    ]
}

/// Names that were configured and failed to build, and why.
///
/// Held beside the provider map rather than folded into it, because a plugin that failed
/// has no instance to hold. Swapped together with the map so a request never sees a
/// failure set from one reload and a plugin map from another.
pub type Failures = AHashMap<String, PluginMiss>;

#[derive(Clone)]
struct DesiredPolicy {
    key: String,
    category: String,
    required: bool,
}
#[derive(Default)]
struct ProviderSnapshot {
    plugins: Arc<Plugins>,
    failures: Arc<Failures>,
    desired: Arc<HashMap<String, DesiredPolicy>>,
}
impl ProviderSnapshot {
    fn resolve(
        &self,
        name: &str,
    ) -> std::result::Result<Arc<dyn Plugin>, PluginMiss> {
        if let Some(desired) =
            self.desired.get(name).filter(|policy| policy.required)
            && self
                .plugins
                .get(name)
                .is_none_or(|plugin| plugin.config_key() != desired.key)
        {
            return Err(PluginMiss::Failed {
                category: desired.category.clone(),
                reason: "required desired policy is unavailable or awaiting publication".into(),
                enforcement_required: true,
            });
        }
        self.plugins.get(name).cloned().ok_or_else(|| {
            self.failures
                .get(name)
                .cloned()
                .unwrap_or(PluginMiss::Unknown)
        })
    }
}
struct Provider {
    snapshot: ArcSwap<ProviderSnapshot>,
}
impl Default for Provider {
    fn default() -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(ProviderSnapshot::default()),
        }
    }
}
impl Provider {
    fn store(&self, data: Plugins, failures: Failures) {
        self.store_then(data, failures, || {});
    }
    fn store_then(
        &self,
        data: Plugins,
        failures: Failures,
        after_publication: impl FnOnce(),
    ) {
        let plugins = Arc::new(data);
        let failures = Arc::new(failures);
        self.snapshot.rcu(|current| {
            Arc::new(ProviderSnapshot {
                plugins: plugins.clone(),
                failures: failures.clone(),
                desired: current.desired.clone(),
            })
        });
        after_publication();
    }
    fn stage_desired(&self, configs: &HashMap<String, PluginConf>) {
        let desired: Arc<HashMap<String, DesiredPolicy>> = Arc::new(
            configs
                .iter()
                .map(|(name, conf)| {
                    let category = conf
                        .get("category")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let required = pingap_core::security_failure_intent(
                        &category,
                        &serde_json::to_value(conf).unwrap_or_default(),
                    );
                    (
                        name.clone(),
                        DesiredPolicy {
                            key: get_hash_key(conf),
                            category,
                            required,
                        },
                    )
                })
                .collect(),
        );
        self.snapshot.rcu(|current| {
            Arc::new(ProviderSnapshot {
                plugins: current.plugins.clone(),
                failures: current.failures.clone(),
                desired: desired.clone(),
            })
        });
    }
}
static PLUGIN_PROVIDER: LazyLock<Arc<Provider>> =
    LazyLock::new(|| Arc::new(Provider::default()));

/// Last successfully constructed native namespace for each configured plugin name.
/// A failed replacement can omit or change `abuse_namespace`; the malformed desired
/// value cannot identify the live state that must survive until a valid reload.
static LAST_GOOD_ABUSE_NAMESPACES: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn next_abuse_namespaces(
    previous: &HashMap<String, String>,
    desired: &HashMap<String, PluginConf>,
    running: impl Fn(&str) -> bool,
    failed: impl Fn(&str) -> bool,
) -> (HashMap<String, String>, Vec<String>) {
    let mut next = HashMap::new();
    let mut retained = Vec::new();
    for (name, conf) in desired {
        if running(name) {
            if conf.get("category").and_then(|v| v.as_str())
                == Some("behaviour")
                && conf.get("enabled").and_then(|v| v.as_bool()) == Some(true)
                && conf
                    .get("abuse")
                    .and_then(|v| v.get("enabled"))
                    .and_then(|v| v.as_bool())
                    == Some(true)
                && let Some(namespace) =
                    conf.get("abuse_namespace").and_then(|v| v.as_str())
            {
                next.insert(name.clone(), namespace.to_string());
            }
        } else if failed(name)
            && let Some(namespace) = previous.get(name)
        {
            next.insert(name.clone(), namespace.clone());
            retained.push(namespace.clone());
        }
    }
    (next, retained)
}
impl PluginProvider for Provider {
    fn get(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        self.snapshot.load().plugins.get(name).cloned()
    }
    fn resolve(
        &self,
        name: &str,
    ) -> std::result::Result<Arc<dyn Plugin>, PluginMiss> {
        self.snapshot.load().resolve(name)
    }
    fn miss(&self, name: &str) -> PluginMiss {
        self.resolve(name).err().unwrap_or(PluginMiss::Unknown)
    }
}
/// Publish only desired metadata before any dependent location can be exposed.
/// Candidate validation does not call this runtime preparation hook.
pub(crate) fn stage_desired_plugins(configs: &HashMap<String, PluginConf>) {
    PLUGIN_PROVIDER.stage_desired(configs);
}

pub fn new_plugin_provider() -> Arc<dyn PluginProvider> {
    PLUGIN_PROVIDER.clone()
}

/// Parses plugin configurations and instantiates plugin instances.
///
/// # Arguments
/// * `configs` - Vector of (name, config) tuples for plugins to initialize
///
/// # Returns
/// HashMap mapping plugin names to initialized plugin instances
///
/// # Errors
/// Returns Error if plugin initialization fails
pub fn parse_plugins(
    configs: Vec<(String, PluginConf)>,
) -> (Plugins, Failures, Vec<Error>) {
    let mut plugins: Plugins = AHashMap::new();
    let mut failures: Failures = AHashMap::new();
    let mut errors: Vec<Error> = vec![];
    let mut namespaces = std::collections::HashMap::<&str, usize>::new();
    for (_, conf) in &configs {
        if conf.get("category").and_then(|v| v.as_str()) == Some("behaviour")
            && conf
                .get("abuse")
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool())
                == Some(true)
            && let Some(namespace) =
                conf.get("abuse_namespace").and_then(|v| v.as_str())
        {
            *namespaces.entry(namespace).or_default() += 1;
        }
    }
    for (name, conf) in configs.iter() {
        let name = name.to_string();
        let category = if let Some(value) = conf.get("category") {
            value.as_str().unwrap_or_default().to_string()
        } else {
            "".to_string()
        };
        if category.is_empty() {
            errors.push(Error::Invalid {
                category: "".to_string(),
                message: format!("category of {name} can not be empty"),
            });
            // Recorded with an empty category, so it cannot be security-enforcing and
            // falls through to today's skip-and-continue. A plugin with no category was
            // never going to build, and guessing one from the entry name would be worse.
            failures.insert(
                name.clone(),
                PluginMiss::Failed {
                    category: String::new(),
                    reason: "no category".to_string(),
                    enforcement_required: false,
                },
            );
            continue;
        }

        let duplicate = conf
            .get("abuse_namespace")
            .and_then(|v| v.as_str())
            .is_some_and(|n| namespaces.get(n).copied().unwrap_or(0) > 1);
        let created = if category == "behaviour" && duplicate {
            Err(pingap_plugin::Error::Invalid {
                category: category.clone(),
                message: "abuse_namespace must be unique".into(),
            })
        } else {
            get_plugin_factory().create(conf)
        };
        match created {
            Ok(plugin) => {
                plugins.insert(name.clone(), plugin.clone());
            },
            Err(e) => {
                // Kept, not just logged. `get_context_plugins` needs to tell a name
                // nobody configured from a security control that failed to build, and
                // only this loop knows which happened.
                failures.insert(
                    name.clone(),
                    PluginMiss::Failed {
                        category: category.clone(),
                        reason: e.to_string(),
                        enforcement_required:
                            pingap_core::security_failure_intent(
                                &category,
                                &serde_json::to_value(conf).unwrap_or_default(),
                            ),
                    },
                );
                errors.push(Error::Invalid {
                    category,
                    message: format!("create plugin {name} failed, {e}"),
                });
            },
        }
    }

    // let plugin =
    //     get_plugin_factory()
    //         .create(conf)
    //         .map_err(|e| Error::Invalid {
    //             category,
    //             message: format!("create plugin {name} failed, {}", e),
    //         })?;
    // plugins.insert(name.clone(), plugin.clone());
    // }

    (plugins, failures, errors)
}

/// Initializes or updates plugins based on configuration.
///
/// # Arguments
/// * `plugins` - HashMap of plugin names to configurations
///
/// # Returns
/// Vector of plugin names that were created or updated
///
/// # Errors
/// Returns Error if plugin initialization fails
pub fn try_init_plugins(
    plugins: &HashMap<String, PluginConf>,
) -> (Vec<String>, String) {
    // Serialize reload reconciliation with its last-good namespace map. A failed
    // construction retains only the namespace owned by that same plugin name;
    // removed or successfully disabled profiles still discard their state.
    let mut last_good_abuse_namespaces = LAST_GOOD_ABUSE_NAMESPACES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    stage_desired_plugins(plugins);
    let abuse_configs = plugins;
    // Count over the complete desired set, including instances reused below.
    // Otherwise a new colliding profile is checked alone after unchanged entries
    // are removed from the constructor batch.
    let mut abuse_namespace_counts =
        std::collections::HashMap::<&str, usize>::new();
    for conf in plugins.values() {
        if conf.get("category").and_then(|v| v.as_str()) == Some("behaviour")
            && conf
                .get("abuse")
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool())
                == Some(true)
            && let Some(namespace) =
                conf.get("abuse_namespace").and_then(|v| v.as_str())
        {
            *abuse_namespace_counts.entry(namespace).or_default() += 1;
        }
    }
    let mut plugin_configs: Vec<(String, PluginConf)> = plugins
        .iter()
        .map(|(name, value)| (name.to_string(), value.clone()))
        .collect();

    // add admin plugin
    let mut errors = vec![];
    if let Some(addr) = &get_admin_addr() {
        match parse_admin_plugin(addr) {
            Ok((_, name, proxy_plugin_info)) => {
                plugin_configs.push((name, proxy_plugin_info));
            },
            Err(e) => {
                errors.push(e);
            },
        }
    }

    plugin_configs.extend(get_builtin_proxy_plugins());

    let mut updated_plugins = vec![];
    let mut plugins = AHashMap::new();
    let plugin_configs: Vec<(String, PluginConf)> = plugin_configs
        .into_iter()
        .filter(|(name, conf)| {
            let conf_hash_key = get_hash_key(conf);
            let mut exists = false;
            if let Some(plugin) = PLUGIN_PROVIDER.get(name) {
                exists = true;
                // exists plugin with same config
                let duplicate=conf.get("abuse_namespace").and_then(|v|v.as_str()).is_some_and(|namespace|abuse_namespace_counts.get(namespace).copied().unwrap_or(0)>1);
                if !duplicate && plugin.config_key() == conf_hash_key {
                    plugins.insert(name.to_string(), plugin);
                    return false;
                }
            }
            let step = get_step_conf(conf, PluginStep::Request).to_string();
            let category = if let Some(value) = conf.get("category") {
                value.as_str().unwrap_or_default().to_string()
            } else {
                "".to_string()
            };
            if exists {
                info!(target: LOG_TARGET, name, step, category, "plugin will be reloaded");
            } else {
                info!(target: LOG_TARGET, name, step, category, "plugin will be created");
            }
            updated_plugins.push(name.to_string());
            true
        })
        .collect();
    let (new_plugins, failures, new_errors) = parse_plugins(plugin_configs);
    plugins.extend(new_plugins);
    errors.extend(new_errors);
    // Stored even when construction failed, which is upstream behaviour and stays that
    // way — but now the failures are stored with it, so a Location listing one can be
    // refused instead of silently proxying unfiltered.
    // Keep the last known-good native registry for a failed replacement while still
    // activating unrelated successful Behaviour profiles. Locations will refuse the
    // failed provider under fail-closed, but old bans/counters are not purged merely
    // because the candidate config was malformed.
    let active_abuse_configs = abuse_configs
        .iter()
        .filter(|(name, _)| plugins.contains_key(*name))
        .map(|(name, conf)| (name.clone(), conf.clone()))
        .collect();
    let (next_namespaces, retained_namespaces) = next_abuse_namespaces(
        &last_good_abuse_namespaces,
        abuse_configs,
        |name| plugins.contains_key(name),
        |name| failures.contains_key(name),
    );
    pingap_behaviour::activate_profiles_with_retained(
        &active_abuse_configs,
        &retained_namespaces,
    );
    PLUGIN_PROVIDER.store(plugins, failures);
    *last_good_abuse_namespaces = next_namespaces;
    let error = if !errors.is_empty() {
        let error = errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(";");
        error!(target: LOG_TARGET, error, "parse plugins failed");
        error
    } else {
        "".to_string()
    };

    (updated_plugins, error)
}

#[test]
pub fn initialize_test_plugins() {
    let plugins = HashMap::from([
        (
            "test:mock".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "mock"
path = "/mock"
status = 999
data = "abc"
"###,
            )
            .unwrap(),
        ),
        (
            "test:add_headers".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "response_headers"
step = "response"
add_headers = [
"X-Service:1",
"X-Service:2",
]
set_headers = [
"X-Response-Id:123"
]
remove_headers = [
"Content-Type"
]
"###,
            )
            .unwrap(),
        ),
    ]);
    let (_, error) = try_init_plugins(&plugins);
    assert!(error.is_empty());
}

#[cfg(test)]
mod tests {
    use super::{next_abuse_namespaces, parse_admin_plugin};
    use pretty_assertions::assert_eq;
    use std::collections::{HashMap, HashSet};

    fn behaviour_conf(
        namespace: Option<&str>,
        abuse_enabled: bool,
    ) -> super::PluginConf {
        let mut conf: super::PluginConf = toml::from_str(
            "category = \"behaviour\"\nenabled = true\n[abuse]\nenabled = true",
        )
        .expect("behaviour config");
        conf.get_mut("abuse")
            .and_then(toml::Value::as_table_mut)
            .expect("abuse table")
            .insert("enabled".into(), toml::Value::Boolean(abuse_enabled));
        if let Some(namespace) = namespace {
            conf.insert(
                "abuse_namespace".into(),
                toml::Value::String(namespace.into()),
            );
        }
        conf
    }

    #[test]
    fn failed_replacement_retains_last_good_namespace_by_plugin_name() {
        let previous = HashMap::from([
            ("guard".into(), "guard-old".into()),
            ("removed".into(), "removed-old".into()),
        ]);
        let running = HashSet::from(["new"]);
        let failed = HashSet::from(["guard", "never-ran"]);

        for malformed_namespace in [None, Some("guard-new")] {
            let desired = HashMap::from([
                ("guard".into(), behaviour_conf(malformed_namespace, true)),
                ("new".into(), behaviour_conf(Some("new-namespace"), true)),
                (
                    "never-ran".into(),
                    behaviour_conf(Some("never-ran-namespace"), true),
                ),
            ]);
            let (next, retained) = next_abuse_namespaces(
                &previous,
                &desired,
                |name| running.contains(name),
                |name| failed.contains(name),
            );
            assert_eq!(Some(&"guard-old".to_string()), next.get("guard"));
            assert_eq!(Some(&"new-namespace".to_string()), next.get("new"));
            assert!(!next.contains_key("removed"));
            assert!(!next.contains_key("never-ran"));
            assert_eq!(vec!["guard-old"], retained);
        }
    }

    #[test]
    fn successful_replacement_or_disable_discards_previous_namespace() {
        let previous = HashMap::from([("guard".into(), "guard-old".into())]);
        let mut disabled = behaviour_conf(Some("guard-old"), true);
        disabled.insert("enabled".into(), toml::Value::Boolean(false));
        for (conf, expected_namespace) in [
            (behaviour_conf(Some("guard-new"), true), Some("guard-new")),
            (behaviour_conf(Some("guard-old"), false), None),
            (disabled, None),
        ] {
            let desired = HashMap::from([("guard".into(), conf)]);
            let (next, retained) = next_abuse_namespaces(
                &previous,
                &desired,
                |name| name == "guard",
                |_| false,
            );
            assert_eq!(
                expected_namespace.map(str::to_string).as_ref(),
                next.get("guard")
            );
            assert!(retained.is_empty());
        }
    }

    /// `--admin` without a credential is no longer refused: the credential's
    /// only job is to bootstrap the first account into an empty store, and a
    /// store that already has users does not need a password on the command
    /// line. What guards the open-door case now is construction — with no
    /// users and no bootstrap, nobody can log in — not a parse-time check.
    #[test]
    fn test_parse_admin_plugin_without_credentials_yields_no_bootstrap() {
        for addr in ["127.0.0.1:3018", "127.0.0.1:3018/pingap", "0.0.0.0:3018"]
        {
            let (_, _, plugin_conf) =
                parse_admin_plugin(addr).unwrap_or_else(|e| {
                    panic!("admin addr {addr} must parse, got: {e}")
                });
            assert_eq!(
                Some(""),
                plugin_conf.get("bootstrap").and_then(|v| v.as_str()),
                "no credential means an empty bootstrap, never a default one"
            );
            assert_eq!(
                false,
                plugin_conf.contains_key("authorizations"),
                "the legacy key must not be generated"
            );
        }
    }

    /// Regression guard: both credential spellings the CLI accepts must still
    /// parse, and land in `bootstrap` — the key the admin plugin reads — not
    /// in `authorizations`, which it now refuses.
    #[test]
    fn test_parse_admin_plugin_accepts_credentials() {
        // spellchecker:off
        for addr in [
            "pingap:123123@127.0.0.1:3018",
            "cGluZ2FwOjEyMzEyMw==@127.0.0.1:3018",
        ] {
            // spellchecker:on
            let (server_conf, name, plugin_conf) = parse_admin_plugin(addr)
                .unwrap_or_else(|e| {
                    panic!("admin addr {addr} must be accepted, got: {e}")
                });
            assert_eq!("127.0.0.1:3018", server_conf.addr);
            assert_eq!(true, server_conf.admin);
            assert_eq!(super::ADMIN_SERVER_PLUGIN, name);
            // spellchecker:off
            assert_eq!(
                Some("cGluZ2FwOjEyMzEyMw=="),
                plugin_conf.get("bootstrap").and_then(|v| v.as_str()),
                "parsed config must carry the bootstrap credential"
            );
            // spellchecker:on
            assert_eq!(false, plugin_conf.contains_key("authorizations"));
            assert_eq!(
                true,
                plugin_conf
                    .get("store")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| s.ends_with("control-plane.db")),
                "a store path must always be generated: {plugin_conf:?}"
            );
        }
    }

    /// `store=` and `totp_key=` on the admin address reach the plugin config.
    #[test]
    fn test_parse_admin_plugin_query_params() {
        let (_, _, plugin_conf) = parse_admin_plugin(
            "127.0.0.1:3018/?store=/var/lib/pingap/cp.db&totp_key=abc",
        )
        .unwrap();
        assert_eq!(
            Some("/var/lib/pingap/cp.db"),
            plugin_conf.get("store").and_then(|v| v.as_str())
        );
        assert_eq!(
            Some("abc"),
            plugin_conf.get("totp_key").and_then(|v| v.as_str())
        );
    }
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    #[test]
    fn required_failure_is_visible_at_the_publication_boundary() {
        let provider = Arc::new(Provider::default());
        let ready = Arc::new(std::sync::Barrier::new(2));
        let finish = Arc::new(std::sync::Barrier::new(2));
        let worker = provider.clone();
        let worker_ready = ready.clone();
        let worker_finish = finish.clone();
        let task = std::thread::spawn(move || {
            let failures = AHashMap::from_iter([(
                "behaviour:block".into(),
                PluginMiss::Failed {
                    category: "behaviour".into(),
                    reason: "invalid required policy".into(),
                    enforcement_required: true,
                },
            )]);
            worker.store_then(AHashMap::new(), failures, || {
                worker_ready.wait();
                worker_finish.wait();
            });
        });
        ready.wait();
        let result = provider.resolve("behaviour:block").err();
        finish.wait();
        task.join().expect("publisher finishes");
        assert!(
            matches!(
                result,
                Some(PluginMiss::Failed {
                    enforcement_required: true,
                    ..
                })
            ),
            "publication must never expose Unknown for the required policy"
        );
    }
    struct Healthy;
    impl Plugin for Healthy {
        fn config_key(&self) -> std::borrow::Cow<'_, str> {
            std::borrow::Cow::Borrowed("healthy")
        }
    }
    #[test]
    fn held_snapshot_does_not_mix_with_a_new_failure_generation() {
        let provider = Provider::default();
        provider.store(
            AHashMap::from_iter([(
                "behaviour:block".into(),
                Arc::new(Healthy) as Arc<dyn Plugin>,
            )]),
            AHashMap::new(),
        );
        let held = provider.snapshot.load_full();
        provider.store(
            AHashMap::new(),
            AHashMap::from_iter([(
                "behaviour:block".into(),
                PluginMiss::Failed {
                    category: "behaviour".into(),
                    reason: "bad".into(),
                    enforcement_required: true,
                },
            )]),
        );
        assert!(held.resolve("behaviour:block").is_ok());
        assert!(matches!(
            provider.resolve("behaviour:block"),
            Err(PluginMiss::Failed {
                enforcement_required: true,
                ..
            })
        ));
    }
    #[test]
    fn desired_required_policy_is_not_unknown_before_construction() {
        let provider = Arc::new(Provider::default());
        let config:PluginConf=toml::from_str("category=\"behaviour\"\nenabled=true\n[abuse]\nenabled=true\n[abuse.scan]\nmode=\"block\"\nthreshold=0").expect("config");
        provider.stage_desired(&HashMap::from_iter([(
            "behaviour:new".into(),
            config,
        )]));
        // A reader is paused at the new-location boundary while construction has
        // deliberately not occurred. Staged intent must already refuse it.
        let ready = Arc::new(std::sync::Barrier::new(2));
        let reader = provider.clone();
        let gate = ready.clone();
        let request = std::thread::spawn(move || {
            gate.wait();
            reader.resolve("behaviour:new").err()
        });
        ready.wait();
        assert!(matches!(
            request.join().expect("request"),
            Some(PluginMiss::Failed {
                enforcement_required: true,
                ..
            })
        ));
        assert!(matches!(
            provider.resolve("legacy:unconfigured"),
            Err(PluginMiss::Unknown)
        ));
        let advisory: PluginConf = toml::from_str(
            "category=\"behaviour\"\nenabled=true\nclient_ip_from_peer=true\nabuse_namespace=\"behaviour:advisory\"\n[abuse]\nenabled=true\n[abuse.scan]\nmode=\"detect\"\nwindow=\"30s\"\nthreshold=2\nban_ttl=\"1m\"",
        )
        .expect("config");
        provider.stage_desired(&HashMap::from_iter([(
            "behaviour:advisory".into(),
            advisory,
        )]));
        assert!(matches!(
            provider.resolve("behaviour:advisory"),
            Err(PluginMiss::Unknown)
        ));
        let malformed: PluginConf = toml::from_str(
            "category=\"behaviour\"\nenabled=true\n[abuse]\nenabled=true\n[abuse.scan]\nmode=\"detect\"\nthreshold=0",
        )
        .expect("config");
        provider.stage_desired(&HashMap::from_iter([(
            "behaviour:malformed-detect".into(),
            malformed,
        )]));
        assert!(matches!(
            provider.resolve("behaviour:malformed-detect"),
            Err(PluginMiss::Failed {
                enforcement_required: true,
                ..
            })
        ));
    }
}
