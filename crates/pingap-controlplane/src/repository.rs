//! The repository trait, and the domain types it speaks in.
//!
//! Written before any driver code, which is the whole reason the driver is swappable. A
//! trait that grows up around a driver leaks that driver's types, and the swap-out
//! justifying the pre-1.0 risk posture stops being cheap. **No signature below mentions a
//! Turso type**; treat one appearing as a blocking review finding.
//!
//! Two shapes here are deliberate absences rather than omissions:
//!
//! - There is **no update or delete method for `activity_log` or `alert_history`**.
//!   Append-only cannot be enforced by a trigger on this store, so it is enforced by the
//!   surface simply not offering the operation — and asserted by test, because "we did not
//!   add one" is not a guarantee anybody can check later.
//! - There is **no transaction handle**. Callers cannot compose their own multi-statement
//!   work, because a failed statement inside `BEGIN` on this driver is *skipped* rather
//!   than aborting the transaction: the next statement is accepted and `COMMIT` succeeds,
//!   so an incomplete record commits while reporting success. Multi-statement mutations
//!   are therefore repository methods that own their own rollback.

use crate::rbac::{AuthLevel, Role};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, snafu::Snafu)]
pub enum StoreError {
    #[snafu(display("control-plane store: {message}"))]
    Backend { message: String },

    #[snafu(display("control-plane store: no such {kind}: {id}"))]
    NotFound { kind: String, id: String },

    #[snafu(display("control-plane store: {kind} `{value}` already exists"))]
    Conflict { kind: String, value: String },

    /// The store is not reachable. Distinct from [`Self::Backend`] because the gateway is
    /// required to keep serving in this case, and the admin API is required to say so
    /// rather than return a 500 that reads like a crash.
    #[snafu(display("control-plane store: unavailable: {reason}"))]
    Unavailable { reason: String },
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: Role,
    pub is_active: bool,
    pub created_at: i64,
}

/// A new user, with the password already hashed.
///
/// Taking a hash rather than a password keeps the KDF out of the store: a repository that
/// accepted plaintext would be one refactor away from writing it.
#[derive(Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role: Role,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub auth_level: AuthLevel,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
}

impl Session {
    /// Whether this session may be used right now.
    ///
    /// Revocation is checked here rather than by deleting the row, so a revoked session
    /// remains listable — an operator investigating an incident needs to see that a
    /// session existed and when it was cut off.
    pub fn is_usable(&self, now: i64) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

/// One audit entry. No `id` and no `created_at`: the store assigns both, so two callers
/// cannot disagree about the clock or collide on a key.
#[derive(Debug, Clone)]
pub struct NewActivity {
    pub actor_id: Option<String>,
    /// Recorded as text as well as by id, so the entry stays readable after the user is
    /// deleted. An audit trail that becomes anonymous when an account is removed is not
    /// an audit trail.
    pub actor_username: String,
    pub action: String,
    pub target: String,
    pub config_version: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Activity {
    pub id: String,
    pub actor_id: Option<String>,
    pub actor_username: String,
    pub action: String,
    pub target: String,
    pub config_version: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub detail: Option<String>,
    pub created_at: i64,
}

/// A session being opened.
///
/// A struct rather than eight positional arguments: `ip` and `user_agent` are both
/// `Option<&str>` and `now` and `expires_at` are both `i64`, so at a call site the
/// positional form is two swaps away from a session that never expires or one that
/// records the wrong address.
#[derive(Debug, Clone, Copy)]
pub struct NewSession<'a> {
    pub user_id: &'a str,
    /// Already hashed. The store never holds a replayable bearer credential.
    pub token_hash: &'a str,
    pub auth_level: AuthLevel,
    pub ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub now: i64,
    pub expires_at: i64,
}

/// A window over the audit log. Ranges rather than offsets, because the log only grows and
/// an offset shifts under a concurrent insert.
#[derive(Debug, Clone, Copy, Default)]
pub struct TimeRange {
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub limit: Option<u32>,
}

/// Where a generated config got to.
///
/// `Applied` is not set by a successful write. pingap stores its provider map even when a
/// plugin failed to construct, drops a Location's unresolvable plugin name with no log, and
/// treats an empty plugin list as "continue to upstream" — so a committed config can be a
/// gateway serving unfiltered traffic while reporting healthy. Only post-commit
/// verification, reading back what the data plane actually has, may set this to `Applied`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigStatus {
    /// Generated and recorded; not yet confirmed to be enforcing.
    Pending,
    /// Verified present in the data plane.
    Applied,
    /// Rejected by validation, or committed and then not confirmed.
    Failed,
    /// Superseded by a later version, without having failed.
    Superseded,
}

impl ConfigStatus {
    pub const ALL: [ConfigStatus; 4] = [
        ConfigStatus::Pending,
        ConfigStatus::Applied,
        ConfigStatus::Failed,
        ConfigStatus::Superseded,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Failed => "failed",
            Self::Superseded => "superseded",
        }
    }

    /// `None` on unrecognised text, for the same reason as [`crate::rbac::Role::from_key`]:
    /// a default would decide from a typo, and defaulting to `Applied` would make a
    /// corrupt row look like a confirmed policy.
    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.key() == key)
    }
}

/// A generation of pingap config from control-plane intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigVersion {
    pub id: String,
    /// Content hash of the canonical form. What drift detection compares.
    pub hash: String,
    pub status: ConfigStatus,
    pub actor_id: Option<String>,
    pub actor_username: String,
    /// The whole intent, not a diff: rollback regenerates from this, so it must not depend
    /// on any other version still being present.
    pub intent_json: String,
    /// Why it failed, when it did.
    pub error: Option<String>,
    pub created_at: i64,
    /// When it reached a terminal status.
    pub settled_at: Option<i64>,
}

/// A version being recorded. The store assigns the id and the timestamp.
#[derive(Debug, Clone)]
pub struct NewConfigVersion {
    pub hash: String,
    pub status: ConfigStatus,
    pub actor_id: Option<String>,
    pub actor_username: String,
    pub intent_json: String,
    pub error: Option<String>,
}

/// Everything the control plane stores.
///
/// One trait rather than several, because the swap-out is all-or-nothing: a driver that
/// implements half of this is not a driver.
#[async_trait::async_trait]
pub trait ControlPlaneStore: Send + Sync {
    /// Apply any migrations the store has not yet seen.
    async fn migrate(&self) -> Result<u32>;

    /// Whether the store is reachable. The admin API answers "unavailable" from this
    /// rather than from a failed query, so a missing store reads as a state and not a
    /// crash.
    async fn health(&self) -> Result<()>;

    // ---- users ---------------------------------------------------------------------
    async fn create_user(&self, user: NewUser, now: i64) -> Result<User>;
    async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<User>>;
    /// By primary key. What a session row carries, and what every authenticated
    /// request resolves — so it is keyed by the one thing a rename cannot move.
    async fn find_user_by_id(&self, user_id: &str) -> Result<Option<User>>;
    async fn password_hash_for(&self, user_id: &str) -> Result<Option<String>>;
    async fn list_users(&self) -> Result<Vec<User>>;
    async fn set_user_active(
        &self,
        user_id: &str,
        active: bool,
        now: i64,
    ) -> Result<()>;

    // ---- second factor -------------------------------------------------------------
    /// Stores the *encrypted* secret. The repository never sees a readable one.
    async fn set_totp_secret(
        &self,
        user_id: &str,
        secret_encrypted: &str,
        enabled: bool,
        now: i64,
    ) -> Result<()>;
    async fn totp_secret_for(
        &self,
        user_id: &str,
    ) -> Result<Option<(String, bool)>>;

    // ---- sessions ------------------------------------------------------------------
    async fn create_session(&self, session: NewSession<'_>) -> Result<Session>;
    async fn session_by_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<Session>>;
    async fn list_sessions(&self, user_id: &str) -> Result<Vec<Session>>;
    /// Takes effect immediately, not at next expiry.
    async fn revoke_session(&self, session_id: &str, now: i64) -> Result<()>;
    /// Promote a password-only session once its second factor completes. The only
    /// mutation a session row accepts besides revocation.
    async fn complete_second_factor(&self, session_id: &str) -> Result<()>;

    // ---- audit ---------------------------------------------------------------------
    //
    // Insert and read. Deliberately nothing else — see the module docs.
    async fn record_activity(
        &self,
        entry: NewActivity,
        now: i64,
    ) -> Result<Activity>;
    async fn read_activity(&self, range: TimeRange) -> Result<Vec<Activity>>;

    // ---- config versions -----------------------------------------------------------
    //
    // Not append-only: a version's `status` is the one thing that legitimately changes
    // after the fact, because whether a config is *enforcing* can only be known after the
    // reload window. The intent, hash, actor and timestamp never change, and there is no
    // delete — a version an operator might roll back to must not be removable.
    async fn record_config_version(
        &self,
        version: NewConfigVersion,
        now: i64,
    ) -> Result<ConfigVersion>;
    /// Move a version to a terminal status. `error` is recorded only for `Failed`.
    async fn set_config_version_status(
        &self,
        version_id: &str,
        status: ConfigStatus,
        error: Option<&str>,
        now: i64,
    ) -> Result<()>;
    async fn config_version(
        &self,
        version_id: &str,
    ) -> Result<Option<ConfigVersion>>;
    /// The newest version, whatever its status. What a generation compares against.
    async fn latest_config_version(&self) -> Result<Option<ConfigVersion>>;
    /// The newest version confirmed to be enforcing. The rollback target.
    async fn latest_applied_config_version(
        &self,
    ) -> Result<Option<ConfigVersion>>;
    /// Newest first, capped.
    async fn list_config_versions(
        &self,
        limit: Option<u32>,
    ) -> Result<Vec<ConfigVersion>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_revoked_or_expired_session_is_not_usable() {
        let base = Session {
            id: "s".into(),
            user_id: "u".into(),
            auth_level: AuthLevel::TwoFactor,
            ip: None,
            user_agent: None,
            created_at: 100,
            expires_at: 200,
            revoked_at: None,
        };
        assert!(base.is_usable(150));
        assert!(!base.is_usable(250), "an expired session was usable");
        assert!(
            !Session {
                revoked_at: Some(120),
                ..base.clone()
            }
            .is_usable(150),
            "revocation did not take effect immediately"
        );
    }

    /// The append-only guarantee, checked against the trait's own source text.
    ///
    /// A trigger would be the natural enforcement and is unavailable on this driver, so
    /// the guarantee reduces to "the surface offers no such method". That is only worth
    /// anything if something notices when a method is added, and review is not that
    /// something.
    #[test]
    fn the_trait_exposes_no_mutation_path_for_an_append_only_table() {
        let source = include_str!("repository.rs");
        let trait_body = source
            .split("pub trait ControlPlaneStore")
            .nth(1)
            .expect("the trait is declared here");
        for forbidden in [
            "update_activity",
            "delete_activity",
            "purge_activity",
            "update_alert_history",
            "delete_alert_history",
            // A config version's intent and hash are the record of what was generated.
            // Only its `status` may move, which is why that method is named for the one
            // field it touches rather than being a general update.
            "update_config_version",
            "delete_config_version",
        ] {
            assert!(
                !trait_body.contains(forbidden),
                "`{forbidden}` appeared on the store trait; `{}` are append-only",
                crate::schema::APPEND_ONLY_TABLES.join(" and ")
            );
        }
        // And no general escape hatch, which would make the absence above cosmetic.
        for hatch in [
            "fn execute",
            "fn raw_sql",
            "fn transaction",
            "fn connection",
        ] {
            assert!(
                !trait_body.contains(hatch),
                "`{hatch}` lets a caller write whatever it likes, including an update to \
                 an append-only table"
            );
        }
    }

    #[test]
    fn a_config_status_round_trips_and_does_not_default() {
        // Stored as TEXT, so this is a persistence format. Defaulting on unrecognised
        // text would be worse here than elsewhere: `applied` is the claim that the data
        // plane is actually enforcing a config, and a corrupt row must not be able to
        // make that claim.
        for status in ConfigStatus::ALL {
            assert_eq!(ConfigStatus::from_key(status.key()), Some(status));
        }
        for junk in ["", "APPLIED", "ok", "done", "active"] {
            assert_eq!(
                ConfigStatus::from_key(junk),
                None,
                "`{junk}` parsed as a config status"
            );
        }
    }
}
