//! Versioned schema.
//!
//! Plain `CREATE TABLE IF NOT EXISTS` statements applied in order, with the applied
//! version recorded in `schema_version`. Not a migration framework: the store is
//! recreatable from scratch — losing it costs history, not the gateway — so the machinery
//! a framework buys is machinery nobody here needs.
//!
//! Three constraints from Phase 02's Spike B shape every statement below, and none of
//! them is speculation:
//!
//! - **No `CREATE TRIGGER ... INSTEAD OF`.** Unsupported. Append-only for `activity_log`
//!   and `alert_history` is enforced by the repository exposing no update or delete path,
//!   and asserted by test.
//! - **`PRAGMA foreign_key_check` is a silent no-op** — it returns zero rows on a database
//!   with unambiguous orphans. Declared foreign keys are documentation here; referential
//!   checks that matter belong in application code, and that pragma must never be called.
//! - **No `BEGIN CONCURRENT`, ever.** MVCC is experimental and can silently roll a
//!   committed write back. For an audit log, silent loss is the worst available failure.

/// One migration: the version it brings the store to, and the statements to get there.
pub struct Migration {
    pub version: u32,
    pub statements: &'static [&'static str],
}

/// Bookkeeping for the applied version. Applied before anything else.
pub const VERSION_TABLE: &str = "CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL PRIMARY KEY,
    applied_at INTEGER NOT NULL
)";

/// Every migration, in order. Append only — editing a shipped one leaves existing stores
/// on a schema no code expects.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        statements: &[
            // ---- identity -------------------------------------------------------------
            "CREATE TABLE IF NOT EXISTS users (
            id TEXT NOT NULL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )",
            "CREATE TABLE IF NOT EXISTS user_profiles (
            user_id TEXT NOT NULL PRIMARY KEY,
            full_name TEXT,
            timezone TEXT,
            locale TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )",
            // `secret_encrypted` never holds a readable secret: unlike a password hash this
            // is a *shared* secret, so an attacker who reads it can mint valid codes forever.
            "CREATE TABLE IF NOT EXISTS two_factor_auth (
            user_id TEXT NOT NULL PRIMARY KEY,
            secret_encrypted TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            enrolled_at INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )",
            // Both token tables store a hash. They are bearer credentials, so the database
            // must not hold anything replayable.
            "CREATE TABLE IF NOT EXISTS user_sessions (
            id TEXT NOT NULL PRIMARY KEY,
            user_id TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            auth_level TEXT NOT NULL,
            ip TEXT,
            user_agent TEXT,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked_at INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )",
            "CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id)",
            "CREATE TABLE IF NOT EXISTS refresh_tokens (
            id TEXT NOT NULL PRIMARY KEY,
            user_id TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked_at INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )",
            // ---- audit ----------------------------------------------------------------
            //
            // Append-only. No `updated_at`, because there is no update. `config_version` ties
            // a mutation to the projected config it produced, which is what makes Phase 08's
            // rollback explainable after the fact.
            "CREATE TABLE IF NOT EXISTS activity_log (
            id TEXT NOT NULL PRIMARY KEY,
            actor_id TEXT,
            actor_username TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            config_version TEXT,
            ip TEXT,
            user_agent TEXT,
            detail TEXT,
            created_at INTEGER NOT NULL
        )",
            "CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_log(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_activity_actor ON activity_log(actor_id)",
            // ---- alerting -------------------------------------------------------------
            //
            // Rule *definitions* live here rather than in pingap config, unlike policy: an
            // alert rule is control-plane state that no data-plane request consults.
            "CREATE TABLE IF NOT EXISTS notification_channels (
            id TEXT NOT NULL PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            config TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL
        )",
            "CREATE TABLE IF NOT EXISTS alert_rules (
            id TEXT NOT NULL PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            metric TEXT NOT NULL,
            comparator TEXT NOT NULL,
            threshold REAL NOT NULL,
            window_secs INTEGER NOT NULL,
            severity TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL
        )",
            "CREATE TABLE IF NOT EXISTS alert_rule_channels (
            rule_id TEXT NOT NULL,
            channel_id TEXT NOT NULL,
            PRIMARY KEY (rule_id, channel_id),
            FOREIGN KEY (rule_id) REFERENCES alert_rules(id),
            FOREIGN KEY (channel_id) REFERENCES notification_channels(id)
        )",
            // Append-only, same as the audit log, and for the same reason: history that can
            // be edited is not history.
            "CREATE TABLE IF NOT EXISTS alert_history (
            id TEXT NOT NULL PRIMARY KEY,
            rule_id TEXT,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            observed REAL NOT NULL,
            threshold REAL NOT NULL,
            delivered INTEGER NOT NULL DEFAULT 0,
            delivery_error TEXT,
            created_at INTEGER NOT NULL
        )",
            "CREATE INDEX IF NOT EXISTS idx_alert_history_created ON alert_history(created_at)",
            // ---- metrics and operations ------------------------------------------------
            //
            // Rollups, not raw samples. Deltas and moving averages are computed in Rust:
            // Turso's window functions lack `lag`, `lead` and custom frames.
            "CREATE TABLE IF NOT EXISTS performance_metrics (
            id TEXT NOT NULL PRIMARY KEY,
            node TEXT NOT NULL,
            metric TEXT NOT NULL,
            value REAL NOT NULL,
            bucket_start INTEGER NOT NULL,
            bucket_secs INTEGER NOT NULL
        )",
            "CREATE INDEX IF NOT EXISTS idx_metrics_bucket ON performance_metrics(metric, bucket_start)",
            "CREATE TABLE IF NOT EXISTS backup_schedules (
            id TEXT NOT NULL PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            cron TEXT NOT NULL,
            retain INTEGER NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL
        )",
            "CREATE TABLE IF NOT EXISTS backup_files (
            id TEXT NOT NULL PRIMARY KEY,
            schedule_id TEXT,
            path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (schedule_id) REFERENCES backup_schedules(id)
        )",
            // `last_seen_at` rather than a lease: Phase 14 decides liveness by timestamp
            // threshold, because `pingap-config` has no lease API and adding one was not
            // worth a vendored file.
            "CREATE TABLE IF NOT EXISTS node_status (
            node TEXT NOT NULL PRIMARY KEY,
            version TEXT,
            config_version TEXT,
            last_seen_at INTEGER NOT NULL,
            reaped_at INTEGER
        )",
            // WAF verdicts, as structured data. The whole reason this fork computes inside
            // the proxy instead of regex-parsing access logs afterwards.
            "CREATE TABLE IF NOT EXISTS waf_events (
            id TEXT NOT NULL PRIMARY KEY,
            node TEXT NOT NULL,
            domain TEXT NOT NULL,
            profile TEXT NOT NULL,
            rule_id INTEGER,
            category TEXT,
            severity TEXT,
            score INTEGER,
            blocked INTEGER NOT NULL,
            client_ip TEXT,
            method TEXT,
            uri TEXT,
            created_at INTEGER NOT NULL
        )",
            "CREATE INDEX IF NOT EXISTS idx_waf_events_created ON waf_events(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_waf_events_domain ON waf_events(domain, created_at)",
        ],
    },
    Migration {
        version: 2,
        statements: &[
            // ---- config versions ------------------------------------------------------
            //
            // One row per generation of pingap config from control-plane intent.
            //
            // `intent_json` is the whole input, not a diff: rollback regenerates from it, and
            // a diff chain would make rollback depend on every version between here and
            // there being intact. It is also what makes a version reproducible after the
            // intent tables have moved on.
            //
            // `status` is `pending` on generation, and only ever becomes `applied` when
            // post-commit verification confirms the data plane actually has the policy — a
            // successful write is not the same as an enforced config, because a plugin whose
            // constructor rejected the new config is dropped from the provider map with no
            // error and no log.
            "CREATE TABLE IF NOT EXISTS config_versions (
            id TEXT NOT NULL PRIMARY KEY,
            hash TEXT NOT NULL,
            status TEXT NOT NULL,
            actor_id TEXT,
            actor_username TEXT NOT NULL,
            intent_json TEXT NOT NULL,
            error TEXT,
            created_at INTEGER NOT NULL,
            settled_at INTEGER
        )",
            "CREATE INDEX IF NOT EXISTS idx_config_versions_created ON config_versions(created_at)",
            // Drift detection asks "what is the newest applied version and what did it
            // hash to", on a schedule, so that pair is what the index serves.
            "CREATE INDEX IF NOT EXISTS idx_config_versions_status ON config_versions(status, created_at)",
        ],
    },
];

/// The version a fully-migrated store is at.
///
/// Derived from the list rather than written down twice: the versions are asserted
/// contiguous from 1, so the count *is* the newest version, and appending a migration
/// cannot leave this stale.
pub const LATEST_VERSION: u32 = MIGRATIONS.len() as u32;

/// Tables the repository must never expose an update or delete path for.
///
/// A trigger would be the obvious guard and is unavailable here, so this list exists to be
/// asserted against the trait surface instead.
pub const APPEND_ONLY_TABLES: &[&str] = &["activity_log", "alert_history"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_schema_declares_all_sixteen_tables() {
        let sql = MIGRATIONS
            .iter()
            .flat_map(|m| m.statements.iter())
            .copied()
            .collect::<Vec<_>>()
            .join("\n");
        for table in [
            "users",
            "user_profiles",
            "two_factor_auth",
            "refresh_tokens",
            "user_sessions",
            "activity_log",
            "notification_channels",
            "alert_rules",
            "alert_rule_channels",
            "alert_history",
            "performance_metrics",
            "backup_schedules",
            "backup_files",
            "node_status",
            "waf_events",
            "config_versions",
        ] {
            assert!(
                sql.contains(&format!("CREATE TABLE IF NOT EXISTS {table} (")),
                "the schema is missing `{table}`"
            );
        }
    }

    #[test]
    fn no_statement_uses_a_mechanism_turso_cannot_honour() {
        // Each of these was measured in Phase 02, and each fails *silently* — which is
        // why the absence is asserted rather than trusted to review.
        let sql = MIGRATIONS
            .iter()
            .flat_map(|m| m.statements.iter())
            .copied()
            .collect::<Vec<_>>()
            .join("\n")
            .to_uppercase();
        assert!(
            !sql.contains("BEGIN CONCURRENT"),
            "MVCC can silently roll a committed write back"
        );
        assert!(
            !sql.contains("CREATE TRIGGER"),
            "`INSTEAD OF` triggers are unsupported; append-only is a repository property"
        );
        assert!(
            !sql.contains("FOREIGN_KEY_CHECK"),
            "that pragma returns zero rows on a database with real orphans"
        );
    }

    #[test]
    fn an_append_only_table_has_no_updated_at_column() {
        // A column nothing can ever write is a standing invitation to write it.
        let sql = MIGRATIONS
            .iter()
            .flat_map(|m| m.statements.iter())
            .copied()
            .collect::<Vec<_>>()
            .join("\n");
        for table in APPEND_ONLY_TABLES {
            let start = sql
                .find(&format!("CREATE TABLE IF NOT EXISTS {table} ("))
                .expect("table present");
            let body = &sql[start..];
            let end = body.find(')').unwrap_or(body.len());
            assert!(
                !body[..end].contains("updated_at"),
                "`{table}` is append-only but declares `updated_at`"
            );
        }
    }

    #[test]
    fn migration_versions_are_unique_and_ascending() {
        let versions: Vec<u32> = MIGRATIONS.iter().map(|m| m.version).collect();
        let mut sorted = versions.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            versions, sorted,
            "migrations must be append-only and in order"
        );
        assert_eq!(versions.first(), Some(&1));
        assert_eq!(
            versions.last(),
            Some(&(MIGRATIONS.len() as u32)),
            "versions must be contiguous from 1, or `applied_version` skips one"
        );
    }
}
