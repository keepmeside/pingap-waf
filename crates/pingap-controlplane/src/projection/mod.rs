//! Config projection: control-plane intent in, pingap config out.
//!
//! This is the seam between the two stores, and the place where a bug silently breaks the
//! data plane. Three properties hold it together, and each is a test rather than a
//! convention:
//!
//! - **Total, never patched.** [`generate`] emits every projected category from intent
//!   alone. Partial updates are how drift enters: two writers touch adjacent keys, one
//!   wins, and the on-disk state matches neither intent. Total regeneration makes the
//!   config a pure function of stored intent, which is also what makes the hash in
//!   [`hash`] mean anything.
//! - **Deterministic.** `PingapConfig` holds `HashMap`s, so serialising one directly
//!   leaks iteration order into the output. Everything here is keyed by [`BTreeMap`] and
//!   the canonical form is assembled in sorted order, so the same intent produces the
//!   same bytes.
//! - **Contract-complete.** Every key emitted below has a row in
//!   `docs/domain-model.md`, and a test reads that file to keep it so. A domain field
//!   with no config counterpart is a design error, because the alternative is projecting
//!   something an operator can set and no request will ever consult.
//!
//! What this module deliberately does **not** do is decide that a generated config is
//! safe. `pingap-waf -t` passes three of four invalid-config classes (Spike D,
//! and it mutates process-global state before returning, so validation is a subprocess
//! against a staged copy and lives in `validate.rs`.

mod apply;
mod drift;
mod generate;
mod hash;
mod validate;

pub use apply::{
    Actor, Applier, ApplyError, ConfigSink, DataPlane, Expectation, Outcome,
    expectations, plugin_config_key,
};
pub use drift::{ConfigSource, Drift, DriftDetector};
pub use generate::generate;
pub use hash::{canonical_toml, hash};
pub use validate::{NoPluginCheck, PluginCheck, Validator, Verdict};

use pingap_config::{PingapConfig, PluginConf};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq, snafu::Snafu)]
pub enum ProjectionError {
    /// A domain names an upstream, listener or policy that intent does not define.
    ///
    /// Refused rather than dropped. pingap resolves a Location's plugin list by name and
    /// silently omits a name it cannot find, so a dangling policy binding would produce a
    /// Location that proxies unfiltered while the control plane reports it protected.
    #[snafu(display(
        "projection: {kind} `{name}` referenced by domain `{domain}` is not defined"
    ))]
    Dangling {
        kind: String,
        name: String,
        domain: String,
    },

    #[snafu(display("projection: {field} `{value}` is not usable: {reason}"))]
    BadValue {
        field: String,
        value: String,
        reason: String,
    },

    #[snafu(display(
        "projection: could not serialise the generated config: {reason}"
    ))]
    Serialise { reason: String },
}

pub type Result<T> = std::result::Result<T, ProjectionError>;

/// One backend behind an upstream.
///
/// `weight` is emitted as the space-separated second field of the address string, which is
/// how `pingap-discovery` reads it (`format_addrs`). A struct rather than a bare string so
/// the projection cannot produce `"10.0.0.1:8080 notanumber"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backend {
    pub addr: String,
    pub weight: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upstream {
    pub backends: Vec<Backend>,
    pub lb_algorithm: Option<String>,
    pub health_check: Option<String>,
    /// `static`, `dns`, `docker` or `transparent`.
    pub discovery: Option<String>,
    pub tls_sni: Option<String>,
    pub verify_cert: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TlsSettings {
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub cipher_list: Option<String>,
    pub ciphersuites: Option<String>,
}

/// A listening socket, shared by every domain bound to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listener {
    pub addr: String,
    pub http2: Option<bool>,
    pub tls: Option<TlsSettings>,
    pub access_log: Option<String>,
    pub server_timing: Option<bool>,
}

/// Which policy a domain binds, and under which profile name.
///
/// The variant is the plugin category and the payload is the profile, so the config entry
/// name is `category:profile` — `waf:strict`. That naming is what makes isolation
/// explicit: two domains needing independently-counted policy bind two *different*
/// profiles, because a plugin instance is process-global and keyed by entry name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyBinding {
    Waf(String),
    Acl(String),
    Bot(String),
}

impl PolicyBinding {
    pub fn category(&self) -> &'static str {
        match self {
            Self::Waf(_) => "waf",
            Self::Acl(_) => "acl",
            Self::Bot(_) => "bot",
        }
    }

    pub fn profile(&self) -> &str {
        match self {
            Self::Waf(p) | Self::Acl(p) | Self::Bot(p) => p,
        }
    }

    /// The config-entry name, which is also the key in [`Intent::policies`].
    pub fn entry_name(&self) -> String {
        format!("{}:{}", self.category(), self.profile())
    }
}

/// A domain: a hostname, where its traffic goes, and what policy applies.
///
/// Projects onto one `[locations.<name>]` plus a membership in its listener's
/// `locations` list. There is no domain object in the data plane and this does not add
/// one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Domain {
    /// One Location can serve several names; they are joined with commas, which is how
    /// `locations.<n>.host` is read.
    pub hostnames: Vec<String>,
    pub path: Option<String>,
    /// Key into [`Intent::listeners`].
    pub listener: String,
    /// Key into [`Intent::upstreams`].
    pub upstream: String,
    pub priority: Option<u16>,
    pub notes: Option<String>,
    /// Parsed as a `ByteSize`, e.g. `8mb`.
    pub client_max_body_size: Option<String>,
    pub grpc_web: bool,
    pub reverse_proxy_headers: Option<bool>,
    pub max_processing: Option<i32>,
    pub max_retries: Option<u8>,
    /// Evaluated in order, and the first plugin to answer terminates the request. The
    /// projection preserves the order given: putting the cheapest gate first is the
    /// operator's call, not something to normalise away.
    pub policies: Vec<PolicyBinding>,
}

/// Everything the control plane knows, in one value.
///
/// `BTreeMap` throughout rather than `HashMap`: this is the input to a hash that drift
/// detection compares, so iteration order is part of the contract.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Intent {
    pub upstreams: BTreeMap<String, Upstream>,
    pub listeners: BTreeMap<String, Listener>,
    pub domains: BTreeMap<String, Domain>,
    /// Keyed by config-entry name (`waf:strict`), holding the plugin's own config table.
    /// The projection does not interpret these — the owning plugin validates its own
    /// parameters — it only checks that every binding names one that exists.
    pub policies: BTreeMap<String, PluginConf>,
    /// Process-global, not per-domain: `basic.trusted_proxies` is one list for the whole
    /// process. A per-domain real-IP control is not expressible and must not be offered.
    pub trusted_proxies: Option<Vec<String>>,
}

impl Intent {
    /// Every config key this projection can emit.
    ///
    /// Asserted against `docs/domain-model.md` by test. The direction that matters is
    /// this one: a key emitted here with no row in the contract means an operator can set
    /// something the document does not describe, and nobody reviewing the document would
    /// notice.
    pub const CONTRACT_KEYS: &'static [&'static str] = &[
        "locations.<n>.host",
        "locations.<n>.path",
        "locations.<n>.upstream",
        "locations.<n>.weight",
        "locations.<n>.remark",
        "locations.<n>.client_max_body_size",
        "locations.<n>.enable_reverse_proxy_headers",
        "locations.<n>.grpc_web",
        "locations.<n>.max_processing",
        "locations.<n>.max_retries",
        "upstreams.<n>.addrs",
        "upstreams.<n>.algo",
        "upstreams.<n>.health_check",
        "upstreams.<n>.discovery",
        "upstreams.<n>.sni",
        "upstreams.<n>.verify_cert",
        "servers.<n>.addr",
        "servers.<n>.access_log",
        "servers.<n>.enabled_h2",
        "servers.<n>.enable_server_timing",
        "servers.<n>.modules",
        "servers.<n>.tls_min_version",
        "tls_max_version",
        "tls_cipher_list",
        "tls_ciphersuites",
        "basic.trusted_proxies",
    ];
}

/// A generated config, together with the canonical form everything else is computed from.
///
/// The two travel together because they must not disagree: the hash recorded in
/// `config_versions`, the bytes handed to validation, and the config committed are all
/// this one value.
#[derive(Debug, Clone)]
pub struct Projected {
    pub config: PingapConfig,
    /// Deterministic TOML. See [`canonical_toml`].
    pub toml: String,
}

impl Projected {
    /// Wrap a config that came from somewhere other than [`generate`] — a config read
    /// back off disk during drift detection, say — so it can be hashed the same way.
    pub fn from_config(config: PingapConfig) -> Result<Self> {
        let toml = canonical_toml(&config)?;
        Ok(Self { config, toml })
    }
}
