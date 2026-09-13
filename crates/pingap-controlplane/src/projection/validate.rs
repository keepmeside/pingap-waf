//! The validation gate: does this generated config actually load?
//!
//! Two checks, because neither alone is enough. Phase 02's Spike D measured `pingap-waf -t`
//! against four classes of invalid config and it **exited 0 on three of them**:
//!
//! | Invalid config | `pingap-waf -t` |
//! | --- | --- |
//! | Malformed TOML | caught, with file/line/column |
//! | Unknown plugin category | passes |
//! | Real category compiled out of this build | passes |
//! | Known category with an invalid parameter | passes, and the plugin name never appears in the output |
//!
//! So `-t` is a syntax and structure check. Whether any plugin in the config can be
//! *built* is a separate question, and it is the one that matters here: a plugin that
//! fails to construct is dropped from the provider map with no error and no log, and a
//! Location whose plugin list resolves to empty proxies straight upstream.
//!
//! **`-t` runs as a subprocess, never in-process.** Spike D also confirmed why: a `-t` run
//! calls `set_trusted_proxies` and initialises the webhook sender *before* reaching the
//! `args.test` branch. Validating in-process would repoint the live gateway's
//! trusted-proxy table at a candidate config, and rejecting that candidate would not put
//! it back — every XFF-derived ACL and rate-limit decision would then be silently wrong.

use super::{Projected, Result};
use pingap_config::PluginConf;
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// Whether a candidate config may be committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    /// Carries the reason verbatim, for the `config_versions` row and the operator. Never
    /// interpolated into a shell command — it is parser output, treated as data.
    Rejected {
        reason: String,
    },
}

impl Verdict {
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// How the gate asks whether a plugin config can actually be built.
///
/// A callback rather than a direct call into `pingap_plugin::get_plugin_factory`, and the
/// indirection is load-bearing: that registry is populated by `#[ctor]` registration in
/// each plugin crate, so a check compiled into *this* crate would run against an empty
/// registry in this crate's own tests and pass everything it was written to catch. The
/// binary, where every plugin crate is linked, supplies the real implementation.
pub trait PluginCheck: Send + Sync {
    /// `Err(reason)` if the plugin named `name` cannot be constructed from `conf`.
    fn check(
        &self,
        name: &str,
        conf: &PluginConf,
    ) -> std::result::Result<(), String>;
}

/// A check that accepts everything.
///
/// For a caller that has no plugin registry to consult — drift detection comparing two
/// hashes, say. Named rather than passed as `None` so that "nothing checked the plugins"
/// is visible at the call site.
pub struct NoPluginCheck;

impl PluginCheck for NoPluginCheck {
    fn check(
        &self,
        _: &str,
        _: &PluginConf,
    ) -> std::result::Result<(), String> {
        Ok(())
    }
}

/// Runs `pingap-waf -t` against a staged copy.
pub struct Validator {
    binary: PathBuf,
}

impl Validator {
    /// `binary` is the pingap executable to validate with.
    ///
    /// Defaults to the running one via [`Self::for_current_exe`], which is almost always
    /// what you want: a different build may have a different plugin feature set, and then
    /// the gate would be validating a config for a process that is not this one.
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
        }
    }

    pub fn for_current_exe() -> std::io::Result<Self> {
        Ok(Self::new(std::env::current_exe()?))
    }

    pub fn binary(&self) -> &Path {
        &self.binary
    }

    /// Check `projected`, cheapest first.
    ///
    /// The plugin checks run before the subprocess because they are in-process and free,
    /// and because they are the ones that catch what `-t` cannot.
    pub async fn validate(
        &self,
        projected: &Projected,
        plugins: &dyn PluginCheck,
    ) -> Result<Verdict> {
        for (name, conf) in &projected.config.plugins {
            if let Err(reason) = plugins.check(name, conf) {
                return Ok(Verdict::Rejected {
                    reason: format!(
                        "plugin `{name}` cannot be built: {reason}. `pingap-waf -t` does not \
                         catch this — a Location-attached plugin is never constructed \
                         during a config test"
                    ),
                });
            }
        }
        self.run_config_test(projected).await
    }

    /// Stage the config into a temporary directory and run `pingap-waf -t -c <dir>`.
    async fn run_config_test(&self, projected: &Projected) -> Result<Verdict> {
        let dir = tempfile::tempdir().map_err(|e| {
            super::ProjectionError::Serialise {
                reason: format!("cannot stage a config for validation: {e}"),
            }
        })?;
        let path = dir.path().join("pingap.toml");
        tokio::fs::write(&path, &projected.toml)
            .await
            .map_err(|e| super::ProjectionError::Serialise {
                reason: format!("cannot write the staged config: {e}"),
            })?;

        let output = tokio::process::Command::new(&self.binary)
            .arg("-t")
            .arg("-c")
            .arg(dir.path())
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| super::ProjectionError::Serialise {
                reason: format!(
                    "cannot run `{} -t`: {e}",
                    self.binary.to_string_lossy()
                ),
            })?;

        if output.status.success() {
            return Ok(Verdict::Accepted);
        }
        // Both streams: pingap reports a parse failure through the logger, which is on
        // stderr, but a validation message could land on either and losing it would leave
        // an operator with "rejected" and no reason.
        let mut reason =
            String::from_utf8_lossy(&output.stderr).trim().to_string();
        let out = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !out.is_empty() {
            if !reason.is_empty() {
                reason.push('\n');
            }
            reason.push_str(&out);
        }
        if reason.is_empty() {
            reason = format!("`pingap-waf -t` exited with {}", output.status);
        }
        Ok(Verdict::Rejected { reason })
    }
}
