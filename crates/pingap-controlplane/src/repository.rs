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

/// One rollup row to store.
///
/// No `id`: the store assigns it, for the reason it does on every other table.
#[derive(Debug, Clone, PartialEq)]
pub struct NewPerformanceMetric {
    /// Which node computed this. Peers share a store, and a total that silently mixes two
    /// nodes is a number nobody can act on.
    pub node: String,
    pub metric: String,
    pub value: f64,
    /// Start of the bucket, floor-aligned to the epoch so two nodes rolling up independently
    /// produce rows that line up.
    pub bucket_start: i64,
    pub bucket_secs: i64,
}

/// One stored rollup row.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PerformanceMetricRecord {
    pub id: String,
    pub node: String,
    pub metric: String,
    pub value: f64,
    pub bucket_start: i64,
    pub bucket_secs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationChannel {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub config: String,
    pub enabled: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewNotificationChannel {
    pub name: String,
    pub kind: String,
    pub config: String,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct NewAlertRule {
    pub name: String,
    pub metric: String,
    pub comparator: crate::alerts::Comparison,
    pub threshold: f64,
    pub window_secs: i64,
    pub severity: String,
    pub enabled: bool,
    pub channel_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertRuleRecord {
    pub rule: crate::alerts::AlertRule,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewAlertHistory {
    pub rule_id: Option<String>,
    pub rule_name: String,
    pub severity: String,
    pub observed: f64,
    pub threshold: f64,
    pub delivered: bool,
    pub delivery_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertHistory {
    pub id: String,
    pub rule_id: Option<String>,
    pub rule_name: String,
    pub severity: String,
    pub observed: f64,
    pub threshold: f64,
    pub delivered: bool,
    pub delivery_error: Option<String>,
    pub created_at: i64,
}

/// Which findings to read back.
///
/// Every field optional, and an absent one is not a filter rather than a filter that matches
/// nothing. `blocked` is the one that carries a wart: the table has a single flag, so asking
/// for "not blocked" returns detections *and* redactions, which the queue treats as different
/// things. Widening the column is a migration; until then the ambiguity is named here rather
/// than hidden behind a field called `verdict`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WafEventFilter {
    pub range: TimeRange,
    pub domain: Option<String>,
    pub rule_id: Option<u32>,
    pub category: Option<String>,
    pub blocked: Option<bool>,
}

/// One stored WAF finding.
///
/// The queue's `WafEvent` plus the `id` the store assigned. A separate type rather than an
/// added field on that one because a producer must not be able to choose a primary key: two
/// nodes writing to a shared store would collide, and a caller that could set `id` could also
/// overwrite a row it did not write.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WafEventRecord {
    pub id: String,
    pub node: String,
    pub domain: String,
    pub profile: String,
    pub rule_id: Option<u32>,
    pub category: Option<String>,
    pub severity: Option<String>,
    pub score: u32,
    /// The `blocked` column. A redaction is stored as not-blocked, which loses the
    /// distinction the queue's drop policy cares about; see `events::Verdict`.
    pub blocked: bool,
    pub client_ip: Option<String>,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub created_at: i64,
}

/// A window over the audit log. Ranges rather than offsets, because the log only grows and
/// an offset shifts under a concurrent insert.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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

/// A scheduled backup, as stored.
///
/// `cron` is the schedule expression and `retain` the number of bundles to keep. The row
/// is the schedule itself; what it produced is in [`BackupFileRecord`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupScheduleRecord {
    pub id: String,
    pub name: String,
    pub cron: String,
    pub retain: i64,
    pub enabled: bool,
    pub created_at: i64,
}

/// A schedule being created. The store assigns the id and the timestamp.
#[derive(Debug, Clone)]
pub struct NewBackupSchedule {
    pub name: String,
    pub cron: String,
    pub retain: i64,
    pub enabled: bool,
}

/// A bundle on disk, as recorded when an export completed.
///
/// `schedule_id` is `None` for a manual export — the bundle exists but was not produced by
/// any schedule. `path` is the bundle root, so a restore can be pointed at it and a prune
/// can find it; `sha256` is the manifest checksum the restore re-verifies before staging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupFileRecord {
    pub id: String,
    pub schedule_id: Option<String>,
    pub path: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub created_at: i64,
}

/// A bundle being recorded. The store assigns the id.
#[derive(Debug, Clone)]
pub struct NewBackupFile {
    pub schedule_id: Option<String>,
    pub path: String,
    pub size_bytes: i64,
    pub sha256: String,
}

/// The durable record of a node, mirroring the etcd heartbeat.
///
/// Written on heartbeat so "this node existed" survives etcd being unreachable; read by the
/// nodes view alongside the live inventory. `reaped_at` is the only post-insert write: it is
/// set when a peer deletes the heartbeat key, so a reaped node stays on the record as reaped
/// rather than vanishing — the difference between "node left" and "never heard of it".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStatusRecord {
    pub node: String,
    pub version: Option<String>,
    pub config_version: Option<String>,
    pub last_seen_at: i64,
    pub reaped_at: Option<i64>,
}

/// A heartbeat write. `node` is the primary key, so an upsert refreshes the row in place.
#[derive(Debug, Clone)]
pub struct NewNodeStatus {
    pub node: String,
    pub version: Option<String>,
    pub config_version: Option<String>,
    pub last_seen_at: i64,
}

/// The learned hourly baseline the adaptive detector keeps per domain.
///
/// `payload` is the serialised `pingap_adaptive::Baseline` — the store treats it as
/// opaque JSON because the aggregate's shape belongs to the adaptive crate, not to the
/// schema. The two facts the store does need to know are on the record: `domain`, the
/// key everything else in the plan is keyed by, and `learned_at_secs`, the timestamp a
/// restored baseline is judged stale against. Derived aggregate data only — no client
/// information — so it carries no privacy exposure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdaptiveBaselineRecord {
    pub domain: String,
    pub payload: String,
    pub learned_at_secs: i64,
    pub updated_at: i64,
}

/// A baseline write. `domain` is the primary key, so an upsert refreshes the row in
/// place as new aggregates land — a baseline is replaced, never appended.
#[derive(Debug, Clone)]
pub struct NewAdaptiveBaseline {
    pub domain: String,
    pub payload: String,
    pub learned_at_secs: i64,
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
    /// Replaces an account's contact address.
    ///
    /// The email alone, and not the rest of what `user_profiles` holds: `username` is the
    /// identity every session and audit row names, so changing it would rewrite the meaning of
    /// rows already written, and `full_name`, `timezone` and `locale` have a table and no
    /// reader. A duplicate address is a `Conflict` naming it.
    async fn set_user_email(
        &self,
        user_id: &str,
        email: &str,
        now: i64,
    ) -> Result<()>;
    /// Replaces the stored hash. Takes a hash and not a password, so the repository never
    /// sees a credential in the clear — the caller derives it with [`crate::hash_password`],
    /// whose output carries its own parameters, so a later parameter change does not
    /// invalidate the hashes already stored.
    async fn set_password_hash(
        &self,
        user_id: &str,
        password_hash: &str,
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

    // ---- alerts ------------------------------------------------------------------------
    async fn create_notification_channel(
        &self,
        channel: NewNotificationChannel,
        now: i64,
    ) -> Result<NotificationChannel>;
    async fn list_notification_channels(
        &self,
    ) -> Result<Vec<NotificationChannel>>;
    async fn create_alert_rule(
        &self,
        rule: NewAlertRule,
        now: i64,
    ) -> Result<AlertRuleRecord>;
    async fn list_alert_rules(&self) -> Result<Vec<AlertRuleRecord>>;
    async fn record_alert_history(
        &self,
        entry: NewAlertHistory,
        now: i64,
    ) -> Result<AlertHistory>;
    async fn read_alert_history(
        &self,
        range: TimeRange,
    ) -> Result<Vec<AlertHistory>>;

    // ---- WAF findings ------------------------------------------------------------------
    /// Appends WAF findings, in one transaction for the whole slice.
    ///
    /// A slice and not one call per finding, and that is the load-bearing part of the
    /// signature: measured against this store, 330 rows/s inserted serially against 71,330
    /// inside one transaction. Per-request findings at serial speed cannot be absorbed at any
    /// real traffic level, so batching is what makes the table viable rather than an
    /// optimisation of it. One transaction also means a batch either lands or does not — a
    /// half-written batch is a gap in the middle of an incident, which is worse than none
    /// because it looks complete.
    ///
    /// Each event carries its own `created_at`, taken when the finding happened rather than
    /// when it was written, so a queue that fell behind dates events correctly instead of
    /// bunching them at the moment the writer caught up.
    async fn record_waf_events(
        &self,
        events: &[crate::events::WafEvent],
    ) -> Result<()>;

    /// Reads findings back, newest first, narrowed by whatever the filter names.
    ///
    /// Ranges rather than offsets, for the reason the audit log uses them: this table only
    /// grows, and an offset shifts under a concurrent insert, so a paginating caller would
    /// see one finding twice and miss another. Paging is `until` set to the oldest
    /// `created_at` already seen.
    async fn read_waf_events(
        &self,
        filter: WafEventFilter,
    ) -> Result<Vec<WafEventRecord>>;

    // ---- retention ---------------------------------------------------------------------
    /// Removes findings older than a cutoff. Returns how many went.
    ///
    /// A cutoff rather than a window, so the arithmetic lives in one place
    /// ([`crate::metrics::Retention::cutoffs`]) and cannot be done two ways. Strictly older:
    /// a row exactly at the cutoff stays, which is what makes a sweep idempotent when run
    /// twice against the same `now`.
    ///
    /// Deliberately absent for `activity_log` and `alert_history`. Those are append-only and
    /// the trait exposes no delete for them at all; see `crate::metrics::retention`.
    async fn prune_waf_events(&self, older_than: i64) -> Result<u64>;

    // ---- rollups -----------------------------------------------------------------------
    /// Appends rollup rows, in one transaction for the whole slice.
    ///
    /// Batched for the reason the findings write is: a rollup of one bucket produces a handful
    /// of rows per rule and category that fired, and writing them one at a time turns a
    /// background job into a burst of serial inserts against the process's single writer.
    async fn record_performance_metrics(
        &self,
        rows: &[NewPerformanceMetric],
    ) -> Result<()>;

    /// Reads rollup rows back, oldest bucket first.
    ///
    /// Oldest first and not newest, unlike every other read here: a rollup is a series, and a
    /// caller drawing it wants it in the order it happened rather than having to reverse it.
    /// `metric` narrows to one name; `None` is all of them.
    async fn read_performance_metrics(
        &self,
        metric: Option<&str>,
        range: TimeRange,
    ) -> Result<Vec<PerformanceMetricRecord>>;

    /// Removes rollup buckets older than a cutoff. Returns how many went.
    ///
    /// A rollup is derived data, so pruning it loses less than pruning the findings it
    /// summarised — but it is kept far longer for the same reason: once the findings are
    /// gone it is the only record left.
    async fn prune_performance_metrics(&self, older_than: i64) -> Result<u64>;

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

    // ---- backups ---------------------------------------------------------------
    //
    // `backup_schedules` is a writable registry the admin edits; `backup_files` is the
    // inventory of bundles that exist on disk. Neither is append-only — a schedule is
    // edited and a deleted bundle is removed from the listing — but both are audit-logged
    // at the handler so the *change* is still on the record even though the row is not.

    /// A backup schedule row as stored.
    async fn list_backup_schedules(&self) -> Result<Vec<BackupScheduleRecord>>;
    /// Create a schedule; a duplicate `name` is a [`StoreError::Conflict`].
    async fn create_backup_schedule(
        &self,
        schedule: NewBackupSchedule,
        now: i64,
    ) -> Result<BackupScheduleRecord>;
    /// Remove a schedule by id; a miss is [`StoreError::NotFound`].
    async fn delete_backup_schedule(&self, schedule_id: &str) -> Result<()>;

    /// The recorded bundles, newest first.
    async fn list_backup_files(&self) -> Result<Vec<BackupFileRecord>>;
    /// Record that a bundle was produced. The row is the inventory entry the listing and
    /// the retention sweep agree on.
    async fn record_backup_file(
        &self,
        file: NewBackupFile,
        now: i64,
    ) -> Result<BackupFileRecord>;

    // ---- node liveness ---------------------------------------------------------
    //
    // `node_status` is the durable mirror of the etcd heartbeat: the heartbeat can be lost
    // with etcd, but "was this node ever here" must survive it. `reaped_at` is the one
    // field written after insert, so the table is update-shaped rather than append-only.

    /// Every node the control plane has ever seen, whether currently live or reaped.
    async fn list_node_status(&self) -> Result<Vec<NodeStatusRecord>>;
    /// Insert or refresh a node's durable record on heartbeat.
    async fn upsert_node_status(
        &self,
        node: NewNodeStatus,
        now: i64,
    ) -> Result<()>;
    /// Mark a node reaped. Idempotent — a second sweep over the same node is a no-op.
    async fn reap_node_status(&self, node: &str, now: i64) -> Result<()>;

    // ---- adaptive baselines --------------------------------------------------------
    //
    // Derived aggregates the learner restores across a restart. Upsert-shaped: each
    // domain's row is replaced as new baselines land, so there is one row per domain —
    // never a growing history of them.

    /// Every persisted baseline, for the restore sweep that runs at startup.
    async fn list_adaptive_baselines(
        &self,
    ) -> Result<Vec<AdaptiveBaselineRecord>>;
    /// A single domain's baseline, for an on-demand restore of a cold learner.
    async fn find_adaptive_baseline(
        &self,
        domain: &str,
    ) -> Result<Option<AdaptiveBaselineRecord>>;
    /// Replace a domain's baseline with the latest aggregate.
    async fn upsert_adaptive_baseline(
        &self,
        baseline: NewAdaptiveBaseline,
        now: i64,
    ) -> Result<()>;
    /// Drop a domain's baseline — the learner asked to forget it, or the domain went away.
    async fn delete_adaptive_baseline(&self, domain: &str) -> Result<()>;
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
            // Retention is a prune, and a prune is a delete by another name. These are here
            // because bounded growth is a real requirement and the obvious way to meet it is
            // to add a window to the audit trail — which would quietly undo the append-only
            // decision. The reclaim path for those two tables is `VACUUM INTO` at backup
            // time, not a sweep; see `crate::metrics::retention`.
            "prune_activity",
            "prune_alert_history",
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
