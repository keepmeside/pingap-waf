//! The Turso backend behind [`ControlPlaneStore`].
//!
//! Everything here answers to a measurement taken against the real driver rather than to
//! taste — see docs/spikes/turso-finding.md — so the shape is worth stating before the code:
//!
//! - **One writer for the whole process.** With four tasks writing on their own
//!   connections, the spike lost 153–166 of 200 inserts to `SQLITE_BUSY`, and the busy
//!   handler never fired. There is no retry policy that fixes that; there is only not
//!   doing it. [`Writer`] owns the single write connection and every mutation in this
//!   crate goes through it. Reads open their own connections, which do not contend.
//! - **Explicit `ROLLBACK`.** A failed statement inside `BEGIN` is *skipped* on this
//!   driver: the next statement is accepted and `COMMIT` succeeds, so a half-written
//!   record commits while reporting success. [`Writer::transaction`] therefore rolls back
//!   by hand on the first error instead of trusting the driver to invalidate anything.
//! - **No MVCC.** `BEGIN CONCURRENT` can silently roll a committed write back. For an
//!   audit trail, silent loss is the worst available failure, so plain transactions only.
//!
//! Nothing in this module is on the request path. The gateway serves from config alone,
//! and a store that will not open is [`StoreError::Unavailable`] — a state the admin API
//! reports, not a crash.

use crate::rbac::{AuthLevel, Role};
use crate::repository::{
    Activity, AdaptiveBaselineRecord, AlertHistory, AlertRuleRecord,
    BackupFileRecord, BackupScheduleRecord, ConfigStatus, ConfigVersion,
    ControlPlaneStore, NewActivity, NewAdaptiveBaseline, NewAlertHistory,
    NewAlertRule, NewBackupFile, NewBackupSchedule, NewConfigVersion,
    NewNodeStatus, NewNotificationChannel, NewSession, NewUser,
    NodeStatusRecord, NotificationChannel, Result, Session, StoreError,
    TimeRange, User,
};
use crate::schema::{MIGRATIONS, VERSION_TABLE};
use std::sync::Arc;
use tokio::sync::{Mutex, OnceCell};
use turso::{Builder, Connection, Database, Row, Value};

/// The ceiling on an unbounded [`TimeRange`] read.
///
/// The audit log only grows, so "no limit" cannot mean "every row": one call would
/// eventually try to materialise the whole table. A caller that wants more pages by range.
const DEFAULT_READ_LIMIT: u32 = 1_000;

fn backend(err: turso::Error) -> StoreError {
    StoreError::Backend {
        message: err.to_string(),
    }
}

/// Whether an error is a `UNIQUE` violation, which callers translate into a conflict.
fn is_unique_violation(err: &turso::Error) -> bool {
    err.to_string().contains("UNIQUE constraint")
}

/// The single write connection for the process.
///
/// Named, rather than left as an implementation detail of [`TursoStore`], because later
/// phases add independent writers — a batched WAF-event writer, an alert evaluator, a
/// `VACUUM INTO` maintenance job, a node heartbeat — and each one opening its own
/// connection is exactly the arrangement the spike measured as an 80% write-loss rate.
/// They route through here.
///
/// The mutex is what serialises them, so its scope is the contract: one `Writer` per
/// store, one store per process (see [`TursoStore::shared`]). A mutex held per connection
/// would serialise nothing.
pub struct Writer {
    conn: Mutex<Connection>,
}

impl Writer {
    /// Run one statement, returning the number of rows it changed.
    pub(crate) async fn execute(
        &self,
        sql: &str,
        params: Vec<Value>,
    ) -> Result<u64> {
        let conn = self.conn.lock().await;
        conn.execute(sql, params).await.map_err(backend)
    }

    /// Run one statement, mapping a `UNIQUE` violation through `on_conflict`.
    async fn execute_unique(
        &self,
        sql: &str,
        params: Vec<Value>,
        on_conflict: impl FnOnce() -> StoreError,
    ) -> Result<u64> {
        let conn = self.conn.lock().await;
        conn.execute(sql, params).await.map_err(|e| {
            if is_unique_violation(&e) {
                on_conflict()
            } else {
                backend(e)
            }
        })
    }

    /// Run several statements as one unit.
    ///
    /// Rolls back explicitly on the first failure. That is not belt-and-braces: on this
    /// driver a failed statement inside `BEGIN` is skipped rather than aborting, so
    /// without the `ROLLBACK` below the remaining statements would run, `COMMIT` would
    /// succeed, and a partial record would persist while the call reported an error.
    ///
    /// `on_conflict` maps a `UNIQUE` violation, which is the expected failure for the
    /// mutations that use this, into something a handler can answer.
    async fn transaction(
        &self,
        statements: Vec<(&str, Vec<Value>)>,
        on_conflict: impl FnOnce() -> StoreError,
    ) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("BEGIN", ()).await.map_err(backend)?;
        for (sql, params) in statements {
            if let Err(err) = conn.execute(sql, params).await {
                // Ordered deliberately: roll back first, report second. Returning early
                // would leave the connection inside an open transaction that the next
                // caller would silently join.
                let rolled_back = conn.execute("ROLLBACK", ()).await;
                return Err(match rolled_back {
                    Ok(_) if is_unique_violation(&err) => on_conflict(),
                    Ok(_) => backend(err),
                    // A failed rollback is worse than the original error: the connection
                    // is the process's only writer and its transaction state is now
                    // unknown, so say so rather than reporting a tidy conflict.
                    Err(rollback_err) => StoreError::Backend {
                        message: format!(
                            "{err}; and the rollback also failed: {rollback_err}"
                        ),
                    },
                });
            }
        }
        conn.execute("COMMIT", ()).await.map_err(backend)?;
        Ok(())
    }
}

/// The process-global store, once opened.
static SHARED: OnceCell<Arc<TursoStore>> = OnceCell::const_new();

/// The control-plane store on a local Turso database.
pub struct TursoStore {
    path: String,
    db: Database,
    writer: Writer,
}

/// Only the path.
///
/// Hand-written rather than derived because the driver handles are not `Debug`, and because
/// the useful fact in a test failure or a log line is which file the store is talking to —
/// not the internals of a connection whose contents include hashed credentials.
impl std::fmt::Debug for TursoStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TursoStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl TursoStore {
    /// Open — creating if absent — the store at `path`.
    ///
    /// A failure here is [`StoreError::Unavailable`] rather than [`StoreError::Backend`]:
    /// the gateway is required to boot and serve with no store at all, so "cannot open" is
    /// a state the admin API reports, not an error that propagates as a 500.
    pub async fn open(path: &str) -> Result<Self> {
        let db = Builder::new_local(path).build().await.map_err(|e| {
            StoreError::Unavailable {
                reason: format!("cannot open `{path}`: {e}"),
            }
        })?;
        let conn = db.connect().map_err(|e| StoreError::Unavailable {
            reason: format!("cannot connect to `{path}`: {e}"),
        })?;
        // Declared foreign keys are documentation on this driver — `PRAGMA
        // foreign_key_check` is a silent no-op — but enforcement at write time does work,
        // and it is the half that prevents an orphan being written in the first place.
        conn.execute("PRAGMA foreign_keys = ON", ())
            .await
            .map_err(|e| StoreError::Unavailable {
                reason: format!("cannot configure `{path}`: {e}"),
            })?;
        Ok(Self {
            path: path.to_string(),
            db,
            writer: Writer {
                conn: Mutex::new(conn),
            },
        })
    }

    /// The process-global store, opened on first call.
    ///
    /// This is the accessor later phases use, and the reason it takes a path only to
    /// *establish* the store: the single-writer guarantee is a property of there being one
    /// instance, so a second call naming a different file is a bug — two subsystems
    /// writing two databases, each believing it holds the audit trail — and is reported
    /// rather than quietly served from the first.
    pub async fn shared(path: &str) -> Result<Arc<Self>> {
        let store = SHARED
            .get_or_try_init(|| async { Self::open(path).await.map(Arc::new) })
            .await?;
        if store.path != path {
            return Err(StoreError::Backend {
                message: format!(
                    "the control-plane store is already open at `{}`; refusing to also \
                     serve `{path}`, because a second store would silently split the \
                     audit trail",
                    store.path
                ),
            });
        }
        Ok(store.clone())
    }

    /// Where this store lives.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The one writer. Every mutation in this crate goes through it.
    pub(crate) fn writer(&self) -> &Writer {
        &self.writer
    }

    /// A fresh read connection.
    ///
    /// Reads get their own connection because they do not contend the way writes do, and
    /// sharing the writer's connection would make a slow report block the audit log.
    fn reader(&self) -> Result<Connection> {
        self.db.connect().map_err(|e| StoreError::Unavailable {
            reason: format!("cannot connect to `{}`: {e}", self.path),
        })
    }

    /// Every row a query returns, decoded by `decode`.
    async fn rows<T>(
        &self,
        sql: &str,
        params: Vec<Value>,
        decode: impl Fn(&Row) -> Result<T>,
    ) -> Result<Vec<T>> {
        let conn = self.reader()?;
        let mut rows = conn.query(sql, params).await.map_err(backend)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(backend)? {
            out.push(decode(&row)?);
        }
        Ok(out)
    }

    /// The first row a query returns, if any.
    async fn row<T>(
        &self,
        sql: &str,
        params: Vec<Value>,
        decode: impl Fn(&Row) -> Result<T>,
    ) -> Result<Option<T>> {
        let conn = self.reader()?;
        let mut rows = conn.query(sql, params).await.map_err(backend)?;
        match rows.next().await.map_err(backend)? {
            Some(row) => decode(&row).map(Some),
            None => Ok(None),
        }
    }

    /// Whether a row with this id exists.
    ///
    /// Used to turn "the UPDATE matched nothing" into [`StoreError::NotFound`]. The driver
    /// reports `changes()` only partially, so the count an `UPDATE` returns is not a
    /// reliable answer, and silently succeeding would let the admin API return 200 for
    /// editing something that is not there.
    async fn exists(&self, table: &str, id: &str) -> Result<bool> {
        // `table` is never caller-supplied — every call site passes a literal — so the
        // format is not an injection surface. Identifiers cannot be bound as parameters.
        let sql = format!("SELECT 1 FROM {table} WHERE id = ?1 LIMIT 1");
        Ok(self
            .row(&sql, vec![Value::Text(id.to_string())], |_| Ok(()))
            .await?
            .is_some())
    }

    /// Which of `username` or `email` is already taken.
    ///
    /// Asked after a `UNIQUE` violation rather than parsed out of the driver's message,
    /// which does not reliably name the column. Reporting the wrong field sends an operator
    /// to change the one thing that was fine.
    async fn clashing_identity(
        &self,
        username: &str,
        email: &str,
    ) -> Result<String> {
        let taken = self
            .row(
                "SELECT username, email FROM users WHERE username = ?1 OR email = ?2 \
                 LIMIT 1",
                vec![
                    Value::Text(username.to_string()),
                    Value::Text(email.to_string()),
                ],
                |row| Ok((text(row, 0)?, text(row, 1)?)),
            )
            .await?;
        Ok(match taken {
            Some((existing, _)) if existing == username => existing,
            Some((_, existing)) => existing,
            // The row went away between the failed insert and this lookup. Nothing else
            // deletes users, so this is close to unreachable; naming the username is a
            // better answer than an empty string.
            None => username.to_string(),
        })
    }

    /// The highest migration version recorded as applied, or 0 on a fresh store.
    async fn applied_version(&self) -> Result<u32> {
        let highest = self
            .row("SELECT MAX(version) FROM schema_version", vec![], |row| {
                opt_int(row, 0)
            })
            .await?
            .flatten()
            .unwrap_or(0);
        Ok(u32::try_from(highest).unwrap_or(0))
    }
}

/// A column that must be text.
///
/// A type mismatch is an error rather than a lossy coercion: these columns hold role
/// names, auth levels and token hashes, and a silently defaulted one is a security
/// decision made by a corrupt row.
fn text(row: &Row, idx: usize) -> Result<String> {
    match row.get_value(idx).map_err(backend)? {
        Value::Text(s) => Ok(s),
        other => Err(StoreError::Backend {
            message: format!("column {idx} should be text, found {other:?}"),
        }),
    }
}

fn opt_text(row: &Row, idx: usize) -> Result<Option<String>> {
    match row.get_value(idx).map_err(backend)? {
        Value::Null => Ok(None),
        Value::Text(s) => Ok(Some(s)),
        other => Err(StoreError::Backend {
            message: format!(
                "column {idx} should be text or null, found {other:?}"
            ),
        }),
    }
}

fn int(row: &Row, idx: usize) -> Result<i64> {
    match row.get_value(idx).map_err(backend)? {
        Value::Integer(i) => Ok(i),
        other => Err(StoreError::Backend {
            message: format!(
                "column {idx} should be an integer, found {other:?}"
            ),
        }),
    }
}

fn opt_int(row: &Row, idx: usize) -> Result<Option<i64>> {
    match row.get_value(idx).map_err(backend)? {
        Value::Null => Ok(None),
        Value::Integer(i) => Ok(Some(i)),
        other => Err(StoreError::Backend {
            message: format!(
                "column {idx} should be an integer or null, found {other:?}"
            ),
        }),
    }
}

fn flag(row: &Row, idx: usize) -> Result<bool> {
    Ok(int(row, idx)? != 0)
}

/// A new primary key.
///
/// UUIDv7 rather than v4: it is time-ordered, so an append-heavy table's primary-key index
/// stays append-friendly instead of writing into a random page on every insert, and rows
/// sort by creation without consulting a timestamp column.
fn new_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

// The column lists below are shared by every `SELECT` and its decoder, because the
// decoders read positionally: a column added to one and not the other would not fail to
// compile, it would silently shift every field after it.

const USER_COLUMNS: &str = "id, username, email, role, is_active, created_at";

fn decode_user(row: &Row) -> Result<User> {
    let role = text(row, 3)?;
    Ok(User {
        id: text(row, 0)?,
        username: text(row, 1)?,
        email: text(row, 2)?,
        role: Role::from_key(&role).ok_or_else(|| StoreError::Backend {
            message: format!(
                "stored role `{role}` is not one this build knows; refusing to guess, \
                 because every guess is an authorisation decision"
            ),
        })?,
        is_active: flag(row, 4)?,
        created_at: int(row, 5)?,
    })
}

const SESSION_COLUMNS: &str = "id, user_id, auth_level, ip, user_agent, created_at, \
     expires_at, revoked_at";

fn decode_session(row: &Row) -> Result<Session> {
    let level = text(row, 2)?;
    Ok(Session {
        id: text(row, 0)?,
        user_id: text(row, 1)?,
        auth_level: AuthLevel::from_key(&level).ok_or_else(|| {
            StoreError::Backend {
                message: format!(
                    "stored auth level `{level}` is not one this build knows; refusing to \
                     guess, because guessing `two_factor` would let a corrupt row mutate"
                ),
            }
        })?,
        ip: opt_text(row, 3)?,
        user_agent: opt_text(row, 4)?,
        created_at: int(row, 5)?,
        expires_at: int(row, 6)?,
        revoked_at: opt_int(row, 7)?,
    })
}

const ACTIVITY_COLUMNS: &str = "id, actor_id, actor_username, action, target, \
     config_version, ip, user_agent, detail, created_at";

fn decode_activity(row: &Row) -> Result<Activity> {
    Ok(Activity {
        id: text(row, 0)?,
        actor_id: opt_text(row, 1)?,
        actor_username: text(row, 2)?,
        action: text(row, 3)?,
        target: text(row, 4)?,
        config_version: opt_text(row, 5)?,
        ip: opt_text(row, 6)?,
        user_agent: opt_text(row, 7)?,
        detail: opt_text(row, 8)?,
        created_at: int(row, 9)?,
    })
}

fn decode_channel(row: &Row) -> Result<NotificationChannel> {
    Ok(NotificationChannel {
        id: text(row, 0)?,
        name: text(row, 1)?,
        kind: text(row, 2)?,
        config: text(row, 3)?,
        enabled: flag(row, 4)?,
        created_at: int(row, 5)?,
    })
}

fn decode_alert_rule(row: &Row) -> Result<AlertRuleRecord> {
    let comparator = text(row, 3)?;
    let comparator = serde_json::from_str(&format!("\"{comparator}\""))
        .map_err(|e| StoreError::Backend {
            message: format!("invalid alert comparator: {e}"),
        })?;
    Ok(AlertRuleRecord {
        rule: crate::alerts::AlertRule {
            id: text(row, 0)?,
            name: text(row, 1)?,
            metric: text(row, 2)?,
            comparator,
            threshold: numeric(row, 4)?,
            window_secs: int(row, 5)?,
            severity: text(row, 6)?,
            enabled: flag(row, 7)?,
            channel_ids: vec![],
        },
        created_at: int(row, 8)?,
    })
}

fn decode_alert_history(row: &Row) -> Result<AlertHistory> {
    Ok(AlertHistory {
        id: text(row, 0)?,
        rule_id: opt_text(row, 1)?,
        rule_name: text(row, 2)?,
        severity: text(row, 3)?,
        observed: numeric(row, 4)?,
        threshold: numeric(row, 5)?,
        delivered: flag(row, 6)?,
        delivery_error: opt_text(row, 7)?,
        created_at: int(row, 8)?,
    })
}

fn alert_comparator_key(c: crate::alerts::Comparison) -> &'static str {
    match c {
        crate::alerts::Comparison::Greater => "greater",
        crate::alerts::Comparison::GreaterOrEqual => "greater_or_equal",
        crate::alerts::Comparison::Less => "less",
        crate::alerts::Comparison::LessOrEqual => "less_or_equal",
        crate::alerts::Comparison::Equal => "equal",
    }
}

fn numeric(row: &Row, idx: usize) -> Result<f64> {
    match row.get_value(idx).map_err(backend)? {
        Value::Real(v) => Ok(v),
        Value::Integer(v) => Ok(v as f64),
        other => Err(StoreError::Backend {
            message: format!("column {idx} should be numeric, found {other:?}"),
        }),
    }
}

/// `Some(text)` as a bound value, `NULL` otherwise.
fn nullable(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::Text)
}

const WAF_EVENT_COLUMNS: &str = "id, node, domain, profile, rule_id, category, \
     severity, score, blocked, client_ip, method, uri, created_at";

/// One row of `waf_events`, by position.
///
/// Positional and therefore fragile against a column reorder, which is exactly what the
/// write path's parameter list is too. Both are pinned by the round-trip test: a transposed
/// pair shows up as a value in the wrong field rather than as an error, and only reading the
/// row back catches it.
fn decode_waf_event(row: &Row) -> Result<crate::repository::WafEventRecord> {
    // The two narrow columns are `u32` in Rust and `INTEGER` — 64-bit — in SQLite, so a value
    // that does not fit is a corrupt row. Refused rather than clamped: clamping would invent a
    // rule ID or a score that was never written, and an audit record that quietly means
    // something else is worse than a read that fails and says so.
    let rule_id = match opt_int(row, 4)? {
        None => None,
        Some(id) => Some(narrow_u32("waf_events.rule_id", id)?),
    };
    let score = narrow_u32("waf_events.score", int(row, 7)?)?;
    Ok(crate::repository::WafEventRecord {
        id: text(row, 0)?,
        node: text(row, 1)?,
        domain: text(row, 2)?,
        profile: text(row, 3)?,
        rule_id,
        category: opt_text(row, 5)?,
        severity: opt_text(row, 6)?,
        score,
        blocked: flag(row, 8)?,
        client_ip: opt_text(row, 9)?,
        method: opt_text(row, 10)?,
        uri: opt_text(row, 11)?,
        created_at: int(row, 12)?,
    })
}

fn decode_performance_metric(
    row: &Row,
) -> Result<crate::repository::PerformanceMetricRecord> {
    Ok(crate::repository::PerformanceMetricRecord {
        id: text(row, 0)?,
        node: text(row, 1)?,
        metric: text(row, 2)?,
        value: match row.get_value(3).map_err(backend)? {
            Value::Real(value) => value,
            // SQLite stores a whole number in a `REAL` column as an integer, so a rollup of
            // exactly 3 comes back as `Integer(3)`. Rejecting it would make a bucket with no
            // fractional part unreadable, which is the common case for a count.
            Value::Integer(value) => value as f64,
            other => {
                return Err(StoreError::Backend {
                    message: format!(
                        "performance_metrics.value should be a number, found {other:?}"
                    ),
                });
            },
        },
        bucket_start: int(row, 4)?,
        bucket_secs: int(row, 5)?,
    })
}

/// A stored integer that Rust holds narrower than SQLite does.
fn narrow_u32(column: &str, value: i64) -> Result<u32> {
    u32::try_from(value).map_err(|_| StoreError::Backend {
        message: format!("{column} holds {value}, which is outside u32"),
    })
}

const CONFIG_VERSION_COLUMNS: &str = "id, hash, status, actor_id, \
     actor_username, intent_json, error, created_at, settled_at";

fn decode_config_version(row: &Row) -> Result<ConfigVersion> {
    let status = text(row, 2)?;
    Ok(ConfigVersion {
        id: text(row, 0)?,
        hash: text(row, 1)?,
        status: ConfigStatus::from_key(&status).ok_or_else(|| {
            StoreError::Backend {
                message: format!(
                    "stored config status `{status}` is not one this build knows; \
                     refusing to guess, because guessing `applied` would claim the data \
                     plane is enforcing a config nobody confirmed"
                ),
            }
        })?,
        actor_id: opt_text(row, 3)?,
        actor_username: text(row, 4)?,
        intent_json: text(row, 5)?,
        error: opt_text(row, 6)?,
        created_at: int(row, 7)?,
        settled_at: opt_int(row, 8)?,
    })
}

/// Seconds since the epoch, for bookkeeping columns no caller supplies.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

const BACKUP_SCHEDULE_COLUMNS: &str =
    "id, name, cron, retain, enabled, created_at";
const BACKUP_FILE_COLUMNS: &str =
    "id, schedule_id, path, size_bytes, sha256, created_at";
const NODE_STATUS_COLUMNS: &str =
    "node, version, config_version, last_seen_at, reaped_at";
const ADAPTIVE_BASELINE_COLUMNS: &str =
    "domain, payload, learned_at_secs, updated_at";

fn decode_adaptive_baseline(row: &Row) -> Result<AdaptiveBaselineRecord> {
    Ok(AdaptiveBaselineRecord {
        domain: text(row, 0)?,
        payload: text(row, 1)?,
        learned_at_secs: int(row, 2)?,
        updated_at: int(row, 3)?,
    })
}

fn decode_backup_schedule(row: &Row) -> Result<BackupScheduleRecord> {
    Ok(BackupScheduleRecord {
        id: text(row, 0)?,
        name: text(row, 1)?,
        cron: text(row, 2)?,
        retain: int(row, 3)?,
        enabled: flag(row, 4)?,
        created_at: int(row, 5)?,
    })
}

fn decode_backup_file(row: &Row) -> Result<BackupFileRecord> {
    Ok(BackupFileRecord {
        id: text(row, 0)?,
        schedule_id: opt_text(row, 1)?,
        path: text(row, 2)?,
        size_bytes: int(row, 3)?,
        sha256: text(row, 4)?,
        created_at: int(row, 5)?,
    })
}

fn decode_node_status(row: &Row) -> Result<NodeStatusRecord> {
    Ok(NodeStatusRecord {
        node: text(row, 0)?,
        version: opt_text(row, 1)?,
        config_version: opt_text(row, 2)?,
        last_seen_at: int(row, 3)?,
        reaped_at: opt_int(row, 4)?,
    })
}

#[async_trait::async_trait]
impl ControlPlaneStore for TursoStore {
    async fn migrate(&self) -> Result<u32> {
        self.writer().execute(VERSION_TABLE, vec![]).await?;
        let mut at = self.applied_version().await?;
        for migration in MIGRATIONS {
            if migration.version <= at {
                continue;
            }
            // Deliberately not one transaction. DDL inside a transaction is unverified on
            // this driver, and every statement is `IF NOT EXISTS`, so the safe ordering is
            // to apply then record: a crash midway leaves the version unrecorded and the
            // next boot re-applies harmlessly. The reverse — recording first — would skip
            // the remainder forever.
            for statement in migration.statements {
                self.writer().execute(statement, vec![]).await?;
            }
            self.writer()
                .execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
                    vec![
                        Value::Integer(i64::from(migration.version)),
                        Value::Integer(now_secs()),
                    ],
                )
                .await?;
            at = migration.version;
        }
        Ok(at)
    }

    async fn health(&self) -> Result<()> {
        // A read, not a write: health is asked often and must not queue behind the writer.
        self.row("SELECT 1", vec![], |_| Ok(())).await?;
        Ok(())
    }

    async fn create_user(&self, user: NewUser, now: i64) -> Result<User> {
        let id = new_id();
        let created = User {
            id: id.clone(),
            username: user.username.clone(),
            email: user.email.clone(),
            role: user.role,
            is_active: true,
            created_at: now,
        };
        // Two tables, one unit. A user with no profile row is a half-created user, and
        // this is the mutation where the driver's skip-on-error transaction behaviour
        // would otherwise leave one behind.
        let outcome = self
            .writer()
            .transaction(
                vec![
                    (
                        "INSERT INTO users (id, username, email, password_hash, role, \
                         is_active, created_at, updated_at) \
                         VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6)",
                        vec![
                            Value::Text(id.clone()),
                            Value::Text(user.username),
                            Value::Text(user.email),
                            Value::Text(user.password_hash),
                            Value::Text(user.role.key().to_string()),
                            Value::Integer(now),
                        ],
                    ),
                    (
                        "INSERT INTO user_profiles (user_id, full_name, timezone, locale) \
                         VALUES (?1, NULL, NULL, NULL)",
                        vec![Value::Text(id)],
                    ),
                ],
                || StoreError::Conflict {
                    kind: "user".to_string(),
                    // Replaced below. The driver's message does not reliably name the
                    // column, so the clashing value is resolved by asking.
                    value: String::new(),
                },
            )
            .await;
        match outcome {
            Ok(()) => Ok(created),
            Err(StoreError::Conflict { kind, .. }) => {
                Err(StoreError::Conflict {
                    kind,
                    value: self
                        .clashing_identity(&created.username, &created.email)
                        .await?,
                })
            },
            Err(other) => Err(other),
        }
    }

    async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<User>> {
        self.row(
            &format!("SELECT {USER_COLUMNS} FROM users WHERE username = ?1"),
            vec![Value::Text(username.to_string())],
            decode_user,
        )
        .await
    }

    async fn find_user_by_id(&self, user_id: &str) -> Result<Option<User>> {
        self.row(
            &format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?1"),
            vec![Value::Text(user_id.to_string())],
            decode_user,
        )
        .await
    }

    async fn password_hash_for(&self, user_id: &str) -> Result<Option<String>> {
        self.row(
            "SELECT password_hash FROM users WHERE id = ?1",
            vec![Value::Text(user_id.to_string())],
            |row| text(row, 0),
        )
        .await
    }

    async fn list_users(&self) -> Result<Vec<User>> {
        self.rows(
            &format!(
                "SELECT {USER_COLUMNS} FROM users ORDER BY created_at, username"
            ),
            vec![],
            decode_user,
        )
        .await
    }

    async fn set_user_active(
        &self,
        user_id: &str,
        active: bool,
        now: i64,
    ) -> Result<()> {
        if !self.exists("users", user_id).await? {
            return Err(StoreError::NotFound {
                kind: "user".to_string(),
                id: user_id.to_string(),
            });
        }
        self.writer()
            .execute(
                "UPDATE users SET is_active = ?2, updated_at = ?3 WHERE id = ?1",
                vec![
                    Value::Text(user_id.to_string()),
                    Value::Integer(i64::from(active)),
                    Value::Integer(now),
                ],
            )
            .await?;
        Ok(())
    }

    async fn set_user_email(
        &self,
        user_id: &str,
        email: &str,
        now: i64,
    ) -> Result<()> {
        if !self.exists("users", user_id).await? {
            return Err(StoreError::NotFound {
                kind: "user".to_string(),
                id: user_id.to_string(),
            });
        }
        self.writer()
            .transaction(
                vec![(
                    "UPDATE users SET email = ?2, updated_at = ?3 WHERE id = ?1",
                    vec![
                        Value::Text(user_id.to_string()),
                        Value::Text(email.to_string()),
                        Value::Integer(now),
                    ],
                )],
                || StoreError::Conflict {
                    kind: "user".to_string(),
                    // The username is not changing, so the address being written is the only
                    // thing that can clash. Named here rather than resolved by asking, which
                    // is what `create_user` has to do because either of its two identities
                    // could be the one that was taken.
                    value: email.to_string(),
                },
            )
            .await
    }

    async fn set_password_hash(
        &self,
        user_id: &str,
        password_hash: &str,
        now: i64,
    ) -> Result<()> {
        if !self.exists("users", user_id).await? {
            return Err(StoreError::NotFound {
                kind: "user".to_string(),
                id: user_id.to_string(),
            });
        }
        self.writer()
            .execute(
                "UPDATE users SET password_hash = ?2, updated_at = ?3 WHERE id = ?1",
                vec![
                    Value::Text(user_id.to_string()),
                    Value::Text(password_hash.to_string()),
                    Value::Integer(now),
                ],
            )
            .await?;
        Ok(())
    }

    async fn set_totp_secret(
        &self,
        user_id: &str,
        secret_encrypted: &str,
        enabled: bool,
        now: i64,
    ) -> Result<()> {
        if !self.exists("users", user_id).await? {
            return Err(StoreError::NotFound {
                kind: "user".to_string(),
                id: user_id.to_string(),
            });
        }
        // An upsert, so confirming an enrolment updates the pending row instead of leaving
        // two secrets where only one can be the real one.
        self.writer()
            .execute(
                "INSERT INTO two_factor_auth (user_id, secret_encrypted, enabled, \
                 enrolled_at) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT (user_id) DO UPDATE SET \
                 secret_encrypted = ?2, enabled = ?3, enrolled_at = ?4",
                vec![
                    Value::Text(user_id.to_string()),
                    Value::Text(secret_encrypted.to_string()),
                    Value::Integer(i64::from(enabled)),
                    Value::Integer(now),
                ],
            )
            .await?;
        Ok(())
    }

    async fn totp_secret_for(
        &self,
        user_id: &str,
    ) -> Result<Option<(String, bool)>> {
        self.row(
            "SELECT secret_encrypted, enabled FROM two_factor_auth WHERE user_id = ?1",
            vec![Value::Text(user_id.to_string())],
            |row| Ok((text(row, 0)?, flag(row, 1)?)),
        )
        .await
    }

    async fn create_session(&self, session: NewSession<'_>) -> Result<Session> {
        let id = new_id();
        self.writer()
            .execute_unique(
                "INSERT INTO user_sessions (id, user_id, token_hash, auth_level, ip, \
                 user_agent, created_at, expires_at, revoked_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)",
                vec![
                    Value::Text(id.clone()),
                    Value::Text(session.user_id.to_string()),
                    Value::Text(session.token_hash.to_string()),
                    Value::Text(session.auth_level.key().to_string()),
                    nullable(session.ip.map(str::to_string)),
                    nullable(session.user_agent.map(str::to_string)),
                    Value::Integer(session.now),
                    Value::Integer(session.expires_at),
                ],
                || StoreError::Conflict {
                    kind: "session".to_string(),
                    // The token hash itself is never reported: it is the stored form of a
                    // bearer credential, and an error string is the last place it should
                    // appear. A collision here means the generator repeated, not that a
                    // caller supplied something wrong.
                    value: "token".to_string(),
                },
            )
            .await?;
        Ok(Session {
            id,
            user_id: session.user_id.to_string(),
            auth_level: session.auth_level,
            ip: session.ip.map(str::to_string),
            user_agent: session.user_agent.map(str::to_string),
            created_at: session.now,
            expires_at: session.expires_at,
            revoked_at: None,
        })
    }

    async fn session_by_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<Session>> {
        self.row(
            &format!(
                "SELECT {SESSION_COLUMNS} FROM user_sessions WHERE token_hash = ?1"
            ),
            vec![Value::Text(token_hash.to_string())],
            decode_session,
        )
        .await
    }

    async fn list_sessions(&self, user_id: &str) -> Result<Vec<Session>> {
        // Revoked and expired sessions included. The point of the list is to show an
        // operator what existed and when it was cut off; filtering would hide the incident
        // they opened it to investigate.
        self.rows(
            &format!(
                "SELECT {SESSION_COLUMNS} FROM user_sessions WHERE user_id = ?1 \
                 ORDER BY created_at DESC"
            ),
            vec![Value::Text(user_id.to_string())],
            decode_session,
        )
        .await
    }

    async fn revoke_session(&self, session_id: &str, now: i64) -> Result<()> {
        if !self.exists("user_sessions", session_id).await? {
            return Err(StoreError::NotFound {
                kind: "session".to_string(),
                id: session_id.to_string(),
            });
        }
        // `revoked_at` is only ever set once. Re-revoking would move the timestamp and
        // lose when access was actually cut off, which is the fact an incident review
        // needs.
        self.writer()
            .execute(
                "UPDATE user_sessions SET revoked_at = ?2 \
                 WHERE id = ?1 AND revoked_at IS NULL",
                vec![Value::Text(session_id.to_string()), Value::Integer(now)],
            )
            .await?;
        Ok(())
    }

    async fn complete_second_factor(&self, session_id: &str) -> Result<()> {
        if !self.exists("user_sessions", session_id).await? {
            return Err(StoreError::NotFound {
                kind: "session".to_string(),
                id: session_id.to_string(),
            });
        }
        // Scoped to one session id, and refused once revoked. Promoting by user id would
        // upgrade every password-only session that account has open, including one an
        // attacker opened with a stolen password while the real user completed their own
        // challenge.
        self.writer()
            .execute(
                "UPDATE user_sessions SET auth_level = ?2 \
                 WHERE id = ?1 AND revoked_at IS NULL",
                vec![
                    Value::Text(session_id.to_string()),
                    Value::Text(AuthLevel::TwoFactor.key().to_string()),
                ],
            )
            .await?;
        Ok(())
    }

    async fn record_activity(
        &self,
        entry: NewActivity,
        now: i64,
    ) -> Result<Activity> {
        let id = new_id();
        self.writer()
            .execute(
                "INSERT INTO activity_log (id, actor_id, actor_username, action, target, \
                 config_version, ip, user_agent, detail, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                vec![
                    Value::Text(id.clone()),
                    nullable(entry.actor_id.clone()),
                    Value::Text(entry.actor_username.clone()),
                    Value::Text(entry.action.clone()),
                    Value::Text(entry.target.clone()),
                    nullable(entry.config_version.clone()),
                    nullable(entry.ip.clone()),
                    nullable(entry.user_agent.clone()),
                    nullable(entry.detail.clone()),
                    Value::Integer(now),
                ],
            )
            .await?;
        Ok(Activity {
            id,
            actor_id: entry.actor_id,
            actor_username: entry.actor_username,
            action: entry.action,
            target: entry.target,
            config_version: entry.config_version,
            ip: entry.ip,
            user_agent: entry.user_agent,
            detail: entry.detail,
            created_at: now,
        })
    }

    async fn read_activity(&self, range: TimeRange) -> Result<Vec<Activity>> {
        // Bound parameters with sentinels rather than a built-up `WHERE`: one statement
        // shape means one thing to review, and there is no string concatenation near the
        // audit log at all.
        let sql = format!(
            "SELECT {ACTIVITY_COLUMNS} FROM activity_log \
             WHERE created_at >= ?1 AND created_at <= ?2 \
             ORDER BY created_at DESC, id DESC LIMIT ?3"
        );
        self.rows(
            &sql,
            vec![
                Value::Integer(range.since.unwrap_or(i64::MIN)),
                Value::Integer(range.until.unwrap_or(i64::MAX)),
                Value::Integer(i64::from(
                    range.limit.unwrap_or(DEFAULT_READ_LIMIT),
                )),
            ],
            decode_activity,
        )
        .await
    }

    async fn create_notification_channel(
        &self,
        channel: NewNotificationChannel,
        now: i64,
    ) -> Result<NotificationChannel> {
        let id = new_id();
        self.writer().execute_unique("INSERT INTO notification_channels (id,name,kind,config,enabled,created_at) VALUES (?1,?2,?3,?4,?5,?6)", vec![Value::Text(id.clone()), Value::Text(channel.name.clone()), Value::Text(channel.kind.clone()), Value::Text(channel.config.clone()), Value::Integer(i64::from(channel.enabled)), Value::Integer(now)], || StoreError::Conflict { kind: "notification channel".into(), value: channel.name.clone() }).await?;
        Ok(NotificationChannel {
            id,
            name: channel.name,
            kind: channel.kind,
            config: channel.config,
            enabled: channel.enabled,
            created_at: now,
        })
    }

    async fn list_notification_channels(
        &self,
    ) -> Result<Vec<NotificationChannel>> {
        self.rows("SELECT id,name,kind,config,enabled,created_at FROM notification_channels ORDER BY name,id", vec![], decode_channel).await
    }

    async fn create_alert_rule(
        &self,
        rule: NewAlertRule,
        now: i64,
    ) -> Result<AlertRuleRecord> {
        if !rule.threshold.is_finite() || rule.window_secs <= 0 {
            return Err(StoreError::Backend {
                message:
                    "alert threshold must be finite and window_secs positive"
                        .into(),
            });
        }
        let id = new_id();
        let mut statements = vec![(
            "INSERT INTO alert_rules (id,name,metric,comparator,threshold,window_secs,severity,enabled,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            vec![
                Value::Text(id.clone()),
                Value::Text(rule.name.clone()),
                Value::Text(rule.metric.clone()),
                Value::Text(alert_comparator_key(rule.comparator).into()),
                Value::Real(rule.threshold),
                Value::Integer(rule.window_secs),
                Value::Text(rule.severity.clone()),
                Value::Integer(i64::from(rule.enabled)),
                Value::Integer(now),
            ],
        )];
        for channel_id in &rule.channel_ids {
            statements.push(("INSERT INTO alert_rule_channels (rule_id,channel_id) VALUES (?1,?2)", vec![Value::Text(id.clone()), Value::Text(channel_id.clone())]));
        }
        self.writer()
            .transaction(statements, || StoreError::Conflict {
                kind: "alert rule".into(),
                value: rule.name.clone(),
            })
            .await?;
        Ok(AlertRuleRecord {
            rule: crate::alerts::AlertRule {
                id,
                name: rule.name,
                metric: rule.metric,
                comparator: rule.comparator,
                threshold: rule.threshold,
                window_secs: rule.window_secs,
                severity: rule.severity,
                enabled: rule.enabled,
                channel_ids: rule.channel_ids,
            },
            created_at: now,
        })
    }

    async fn list_alert_rules(&self) -> Result<Vec<AlertRuleRecord>> {
        let mut out = self.rows("SELECT id,name,metric,comparator,threshold,window_secs,severity,enabled,created_at FROM alert_rules ORDER BY name,id", vec![], decode_alert_rule).await?;
        for item in &mut out {
            item.rule.channel_ids = self.rows("SELECT channel_id FROM alert_rule_channels WHERE rule_id = ?1 ORDER BY channel_id", vec![Value::Text(item.rule.id.clone())], |r| text(r, 0)).await?;
        }
        Ok(out)
    }

    async fn record_alert_history(
        &self,
        entry: NewAlertHistory,
        now: i64,
    ) -> Result<AlertHistory> {
        if !entry.observed.is_finite() || !entry.threshold.is_finite() {
            return Err(StoreError::Backend {
                message: "alert history values must be finite".into(),
            });
        }
        let id = new_id();
        self.writer().execute("INSERT INTO alert_history (id,rule_id,rule_name,severity,observed,threshold,delivered,delivery_error,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)", vec![Value::Text(id.clone()), nullable(entry.rule_id.clone()), Value::Text(entry.rule_name.clone()), Value::Text(entry.severity.clone()), Value::Real(entry.observed), Value::Real(entry.threshold), Value::Integer(i64::from(entry.delivered)), nullable(entry.delivery_error.clone()), Value::Integer(now)]).await?;
        Ok(AlertHistory {
            id,
            rule_id: entry.rule_id,
            rule_name: entry.rule_name,
            severity: entry.severity,
            observed: entry.observed,
            threshold: entry.threshold,
            delivered: entry.delivered,
            delivery_error: entry.delivery_error,
            created_at: now,
        })
    }

    async fn read_alert_history(
        &self,
        range: TimeRange,
    ) -> Result<Vec<AlertHistory>> {
        self.rows("SELECT id,rule_id,rule_name,severity,observed,threshold,delivered,delivery_error,created_at FROM alert_history WHERE created_at >= ?1 AND created_at <= ?2 ORDER BY created_at DESC,id DESC LIMIT ?3", vec![Value::Integer(range.since.unwrap_or(i64::MIN)), Value::Integer(range.until.unwrap_or(i64::MAX)), Value::Integer(i64::from(range.limit.unwrap_or(DEFAULT_READ_LIMIT)))], decode_alert_history).await
    }

    async fn record_config_version(
        &self,
        version: NewConfigVersion,
        now: i64,
    ) -> Result<ConfigVersion> {
        let id = new_id();
        // A terminal status recorded at creation — a version rejected by validation is
        // born `Failed` — settles immediately. `Pending` has not settled.
        let settled_at =
            (version.status != ConfigStatus::Pending).then_some(now);
        self.writer()
            .execute(
                "INSERT INTO config_versions (id, hash, status, actor_id, \
                 actor_username, intent_json, error, created_at, settled_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                vec![
                    Value::Text(id.clone()),
                    Value::Text(version.hash.clone()),
                    Value::Text(version.status.key().to_string()),
                    nullable(version.actor_id.clone()),
                    Value::Text(version.actor_username.clone()),
                    Value::Text(version.intent_json.clone()),
                    nullable(version.error.clone()),
                    Value::Integer(now),
                    settled_at.map_or(Value::Null, Value::Integer),
                ],
            )
            .await?;
        Ok(ConfigVersion {
            id,
            hash: version.hash,
            status: version.status,
            actor_id: version.actor_id,
            actor_username: version.actor_username,
            intent_json: version.intent_json,
            error: version.error,
            created_at: now,
            settled_at,
        })
    }

    async fn record_waf_events(
        &self,
        events: &[crate::events::WafEvent],
    ) -> Result<()> {
        if events.is_empty() {
            // Not an error and not a transaction: an empty `BEGIN`/`COMMIT` pair is a
            // round trip to the writer lock for nothing, and the writer is the one
            // resource every other in-process writer is waiting on.
            return Ok(());
        }
        const INSERT: &str = "INSERT INTO waf_events (id, node, domain, profile, \
             rule_id, category, severity, score, blocked, client_ip, method, uri, \
             created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";
        let statements = events
            .iter()
            .map(|event| {
                (
                    INSERT,
                    vec![
                        Value::Text(new_id()),
                        Value::Text(event.node.clone()),
                        Value::Text(event.domain.clone()),
                        Value::Text(event.profile.clone()),
                        event.rule_id.map_or(Value::Null, |id| {
                            Value::Integer(i64::from(id))
                        }),
                        nullable(event.category.clone()),
                        nullable(event.severity.clone()),
                        Value::Integer(i64::from(event.score)),
                        Value::Integer(i64::from(event.blocked_flag())),
                        nullable(event.client_ip.clone()),
                        nullable(event.method.clone()),
                        nullable(event.uri.clone()),
                        Value::Integer(event.created_at),
                    ],
                )
            })
            .collect();
        self.writer()
            .transaction(statements, || StoreError::Conflict {
                kind: "waf_event".to_string(),
                // Ids are generated, so a collision is a bug rather than a value an
                // operator can change. Reported as a conflict because that is what the
                // helper maps a `UNIQUE` violation to, and the kind says which table.
                value: String::new(),
            })
            .await
    }

    async fn read_waf_events(
        &self,
        filter: crate::repository::WafEventFilter,
    ) -> Result<Vec<crate::repository::WafEventRecord>> {
        // One statement shape, with `? IS NULL OR column = ?` for each optional filter
        // rather than a `WHERE` built up per call. Two reasons, and the second is the one
        // that matters: a caller cannot express a filter this code did not anticipate, and
        // there is no string concatenation anywhere near a security record. The cost is that
        // an unfiltered read still evaluates four predicates, which an index on
        // `(domain, created_at)` already covers for the common case.
        let sql = format!(
            "SELECT {WAF_EVENT_COLUMNS} FROM waf_events \
             WHERE created_at >= ?1 AND created_at <= ?2 \
             AND (?4 IS NULL OR domain = ?4) \
             AND (?5 IS NULL OR rule_id = ?5) \
             AND (?6 IS NULL OR blocked = ?6) \
             AND (?7 IS NULL OR category = ?7) \
             ORDER BY created_at DESC, id DESC LIMIT ?3"
        );
        let range = filter.range;
        self.rows(
            &sql,
            vec![
                Value::Integer(range.since.unwrap_or(i64::MIN)),
                Value::Integer(range.until.unwrap_or(i64::MAX)),
                Value::Integer(i64::from(
                    range.limit.unwrap_or(DEFAULT_READ_LIMIT),
                )),
                nullable(filter.domain),
                filter
                    .rule_id
                    .map_or(Value::Null, |id| Value::Integer(i64::from(id))),
                filter.blocked.map_or(Value::Null, |blocked| {
                    Value::Integer(i64::from(blocked))
                }),
                nullable(filter.category),
            ],
            decode_waf_event,
        )
        .await
    }

    async fn record_performance_metrics(
        &self,
        rows: &[crate::repository::NewPerformanceMetric],
    ) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        if let Some(row) = rows.iter().find(|row| !row.value.is_finite()) {
            return Err(StoreError::Backend {
                message: format!(
                    "performance metric `{}` must be finite",
                    row.metric
                ),
            });
        }
        const INSERT: &str = "INSERT INTO performance_metrics (id, node, metric, \
             value, bucket_start, bucket_secs) VALUES (?1, ?2, ?3, ?4, ?5, ?6)";
        let statements = rows
            .iter()
            .map(|row| {
                (
                    INSERT,
                    vec![
                        Value::Text(new_id()),
                        Value::Text(row.node.clone()),
                        Value::Text(row.metric.clone()),
                        Value::Real(row.value),
                        Value::Integer(row.bucket_start),
                        Value::Integer(row.bucket_secs),
                    ],
                )
            })
            .collect();
        self.writer()
            .transaction(statements, || StoreError::Conflict {
                kind: "performance_metric".to_string(),
                value: String::new(),
            })
            .await
    }

    async fn read_performance_metrics(
        &self,
        metric: Option<&str>,
        range: TimeRange,
    ) -> Result<Vec<crate::repository::PerformanceMetricRecord>> {
        // One statement shape, with the optional metric name as a bound sentinel rather than
        // a branch that builds a different `WHERE`. Two shapes would be two things to review
        // and two ways to get the parameter numbering wrong.
        let sql = "SELECT id, node, metric, value, bucket_start, bucket_secs \
             FROM performance_metrics \
             WHERE bucket_start >= ?1 AND bucket_start <= ?2 \
             AND (?4 IS NULL OR metric = ?4) \
             ORDER BY bucket_start ASC, id ASC LIMIT ?3"
            .to_string();
        self.rows(
            &sql,
            vec![
                Value::Integer(range.since.unwrap_or(i64::MIN)),
                Value::Integer(range.until.unwrap_or(i64::MAX)),
                Value::Integer(i64::from(
                    range.limit.unwrap_or(DEFAULT_READ_LIMIT),
                )),
                nullable(metric.map(str::to_string)),
            ],
            decode_performance_metric,
        )
        .await
    }

    async fn prune_waf_events(&self, older_than: i64) -> Result<u64> {
        // One statement, no transaction: a `DELETE` bounded by an indexed column is atomic on
        // its own, and wrapping it would hold the process's single writer longer for nothing.
        self.writer()
            .execute(
                "DELETE FROM waf_events WHERE created_at < ?1",
                vec![Value::Integer(older_than)],
            )
            .await
    }

    async fn prune_performance_metrics(&self, older_than: i64) -> Result<u64> {
        // `bucket_start`, not `created_at`: a rollup row's age is the bucket it summarises,
        // and pruning by insertion time would keep an old bucket that was recomputed recently
        // and drop a current one written once.
        self.writer()
            .execute(
                "DELETE FROM performance_metrics WHERE bucket_start < ?1",
                vec![Value::Integer(older_than)],
            )
            .await
    }

    async fn set_config_version_status(
        &self,
        version_id: &str,
        status: ConfigStatus,
        error: Option<&str>,
        now: i64,
    ) -> Result<()> {
        if !self.exists("config_versions", version_id).await? {
            return Err(StoreError::NotFound {
                kind: "config version".to_string(),
                id: version_id.to_string(),
            });
        }
        // `error` is cleared unless the new status is `Failed`: a version that failed,
        // was rolled back, and later succeeded must not keep an error explaining a
        // different attempt.
        self.writer()
            .execute(
                "UPDATE config_versions SET status = ?2, error = ?3, settled_at = ?4 \
                 WHERE id = ?1",
                vec![
                    Value::Text(version_id.to_string()),
                    Value::Text(status.key().to_string()),
                    match (status, error) {
                        (ConfigStatus::Failed, Some(e)) => {
                            Value::Text(e.to_string())
                        },
                        _ => Value::Null,
                    },
                    if status == ConfigStatus::Pending {
                        Value::Null
                    } else {
                        Value::Integer(now)
                    },
                ],
            )
            .await?;
        Ok(())
    }

    async fn config_version(
        &self,
        version_id: &str,
    ) -> Result<Option<ConfigVersion>> {
        self.row(
            &format!(
                "SELECT {CONFIG_VERSION_COLUMNS} FROM config_versions WHERE id = ?1"
            ),
            vec![Value::Text(version_id.to_string())],
            decode_config_version,
        )
        .await
    }

    async fn latest_config_version(&self) -> Result<Option<ConfigVersion>> {
        self.row(
            &format!(
                "SELECT {CONFIG_VERSION_COLUMNS} FROM config_versions \
                 ORDER BY created_at DESC, id DESC LIMIT 1"
            ),
            vec![],
            decode_config_version,
        )
        .await
    }

    async fn latest_applied_config_version(
        &self,
    ) -> Result<Option<ConfigVersion>> {
        self.row(
            &format!(
                "SELECT {CONFIG_VERSION_COLUMNS} FROM config_versions \
                 WHERE status = ?1 ORDER BY created_at DESC, id DESC LIMIT 1"
            ),
            vec![Value::Text(ConfigStatus::Applied.key().to_string())],
            decode_config_version,
        )
        .await
    }

    async fn list_config_versions(
        &self,
        limit: Option<u32>,
    ) -> Result<Vec<ConfigVersion>> {
        self.rows(
            &format!(
                "SELECT {CONFIG_VERSION_COLUMNS} FROM config_versions \
                 ORDER BY created_at DESC, id DESC LIMIT ?1"
            ),
            vec![Value::Integer(i64::from(
                limit.unwrap_or(DEFAULT_READ_LIMIT),
            ))],
            decode_config_version,
        )
        .await
    }

    async fn list_backup_schedules(&self) -> Result<Vec<BackupScheduleRecord>> {
        self.rows(
            &format!(
                "SELECT {BACKUP_SCHEDULE_COLUMNS} FROM backup_schedules \
                 ORDER BY name, id"
            ),
            vec![],
            decode_backup_schedule,
        )
        .await
    }

    async fn create_backup_schedule(
        &self,
        schedule: NewBackupSchedule,
        now: i64,
    ) -> Result<BackupScheduleRecord> {
        let id = new_id();
        self.writer()
            .execute_unique(
                "INSERT INTO backup_schedules \
                 (id, name, cron, retain, enabled, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                vec![
                    Value::Text(id.clone()),
                    Value::Text(schedule.name.clone()),
                    Value::Text(schedule.cron.clone()),
                    Value::Integer(schedule.retain),
                    Value::Integer(i64::from(schedule.enabled)),
                    Value::Integer(now),
                ],
                || StoreError::Conflict {
                    kind: "backup schedule".into(),
                    value: schedule.name.clone(),
                },
            )
            .await?;
        self.row(
            &format!(
                "SELECT {BACKUP_SCHEDULE_COLUMNS} FROM backup_schedules \
                 WHERE id = ?1"
            ),
            vec![Value::Text(id)],
            decode_backup_schedule,
        )
        .await?
        .ok_or_else(|| StoreError::Backend {
            message: "a schedule was written but did not read back".into(),
        })
    }

    async fn delete_backup_schedule(&self, schedule_id: &str) -> Result<()> {
        if !self.exists("backup_schedules", schedule_id).await? {
            return Err(StoreError::NotFound {
                kind: "backup schedule".into(),
                id: schedule_id.to_string(),
            });
        }
        // Detach rather than cascade: a bundle recorded under a deleted schedule still
        // exists on disk, so its row must outlive the schedule with `schedule_id` cleared.
        // Deleting the files' rows instead would lose the inventory entry for a bundle
        // that is still restorable.
        self.writer()
            .transaction(
                vec![
                    (
                        "UPDATE backup_files SET schedule_id = NULL \
                         WHERE schedule_id = ?1",
                        vec![Value::Text(schedule_id.to_string())],
                    ),
                    (
                        "DELETE FROM backup_schedules WHERE id = ?1",
                        vec![Value::Text(schedule_id.to_string())],
                    ),
                ],
                || StoreError::Backend {
                    message: "a schedule delete did not apply".into(),
                },
            )
            .await?;
        Ok(())
    }

    async fn list_backup_files(&self) -> Result<Vec<BackupFileRecord>> {
        self.rows(
            &format!(
                "SELECT {BACKUP_FILE_COLUMNS} FROM backup_files \
                 ORDER BY created_at DESC, id DESC"
            ),
            vec![],
            decode_backup_file,
        )
        .await
    }

    async fn record_backup_file(
        &self,
        file: NewBackupFile,
        now: i64,
    ) -> Result<BackupFileRecord> {
        let id = new_id();
        self.writer()
            .execute(
                "INSERT INTO backup_files \
                 (id, schedule_id, path, size_bytes, sha256, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                vec![
                    Value::Text(id.clone()),
                    nullable(file.schedule_id.clone()),
                    Value::Text(file.path.clone()),
                    Value::Integer(file.size_bytes),
                    Value::Text(file.sha256.clone()),
                    Value::Integer(now),
                ],
            )
            .await?;
        self.row(
            &format!(
                "SELECT {BACKUP_FILE_COLUMNS} FROM backup_files WHERE id = ?1"
            ),
            vec![Value::Text(id)],
            decode_backup_file,
        )
        .await?
        .ok_or_else(|| StoreError::Backend {
            message: "a bundle was recorded but did not read back".into(),
        })
    }

    async fn list_node_status(&self) -> Result<Vec<NodeStatusRecord>> {
        self.rows(
            &format!(
                "SELECT {NODE_STATUS_COLUMNS} FROM node_status \
                 ORDER BY node"
            ),
            vec![],
            decode_node_status,
        )
        .await
    }

    async fn upsert_node_status(
        &self,
        node: NewNodeStatus,
        now: i64,
    ) -> Result<()> {
        // `reaped_at` is deliberately cleared on heartbeat: a node that comes back is
        // live again, and carrying the tombstone forward would read it as gone forever.
        self.writer()
            .execute(
                "INSERT INTO node_status \
                 (node, version, config_version, last_seen_at, reaped_at) \
                 VALUES (?1, ?2, ?3, ?4, NULL) \
                 ON CONFLICT(node) DO UPDATE SET \
                   version = excluded.version, \
                   config_version = excluded.config_version, \
                   last_seen_at = excluded.last_seen_at, \
                   reaped_at = NULL",
                vec![
                    Value::Text(node.node.clone()),
                    nullable(node.version.clone()),
                    nullable(node.config_version.clone()),
                    Value::Integer(node.last_seen_at.max(now)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn reap_node_status(&self, node: &str, now: i64) -> Result<()> {
        // Only stamp a row that is not already reaped — a second sweep must not move the
        // timestamp, or "when it was collected" keeps drifting forward.
        self.writer()
            .execute(
                "UPDATE node_status SET reaped_at = ?2 \
                 WHERE node = ?1 AND reaped_at IS NULL",
                vec![Value::Text(node.to_string()), Value::Integer(now)],
            )
            .await?;
        Ok(())
    }

    async fn list_adaptive_baselines(
        &self,
    ) -> Result<Vec<AdaptiveBaselineRecord>> {
        self.rows(
            &format!(
                "SELECT {ADAPTIVE_BASELINE_COLUMNS} FROM adaptive_baselines \
                 ORDER BY domain"
            ),
            vec![],
            decode_adaptive_baseline,
        )
        .await
    }

    async fn find_adaptive_baseline(
        &self,
        domain: &str,
    ) -> Result<Option<AdaptiveBaselineRecord>> {
        self.row(
            &format!(
                "SELECT {ADAPTIVE_BASELINE_COLUMNS} FROM adaptive_baselines \
                 WHERE domain = ?1"
            ),
            vec![Value::Text(domain.to_string())],
            decode_adaptive_baseline,
        )
        .await
    }

    async fn upsert_adaptive_baseline(
        &self,
        baseline: NewAdaptiveBaseline,
        now: i64,
    ) -> Result<()> {
        // `updated_at` is the store's own clock for staleness-since-write;
        // `learned_at_secs` is the learner's clock for staleness-since-calibration —
        // they answer different questions, so neither substitutes for the other.
        self.writer()
            .execute(
                "INSERT INTO adaptive_baselines \
                 (domain, payload, learned_at_secs, updated_at) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(domain) DO UPDATE SET \
                   payload = excluded.payload, \
                   learned_at_secs = excluded.learned_at_secs, \
                   updated_at = excluded.updated_at",
                vec![
                    Value::Text(baseline.domain.clone()),
                    Value::Text(baseline.payload.clone()),
                    Value::Integer(baseline.learned_at_secs),
                    Value::Integer(now),
                ],
            )
            .await?;
        Ok(())
    }

    async fn delete_adaptive_baseline(&self, domain: &str) -> Result<()> {
        self.writer()
            .execute(
                "DELETE FROM adaptive_baselines WHERE domain = ?1",
                vec![Value::Text(domain.to_string())],
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A migrated store in a temporary directory.
    async fn store() -> (TursoStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cp.db");
        let store = TursoStore::open(path.to_str().expect("utf-8"))
            .await
            .expect("opens");
        store.migrate().await.expect("migrates");
        (store, dir)
    }

    async fn user_count(store: &TursoStore) -> i64 {
        store
            .row("SELECT COUNT(*) FROM users", vec![], |row| int(row, 0))
            .await
            .expect("count runs")
            .unwrap_or_default()
    }

    const INSERT_USER: &str = "INSERT INTO users (id, username, email, \
         password_hash, role, is_active, created_at, updated_at) \
         VALUES (?1, ?2, ?3, 'h', 'viewer', 1, 0, 0)";

    fn user_params(id: &str, name: &str) -> Vec<Value> {
        vec![
            Value::Text(id.to_string()),
            Value::Text(name.to_string()),
            Value::Text(format!("{name}@example.test")),
        ]
    }

    #[tokio::test]
    async fn a_statement_failing_mid_transaction_rolls_the_earlier_work_back() {
        // The direct falsification of what the Turso spike measured. On this driver a failed
        // statement inside `BEGIN` is *skipped*: the transaction is neither aborted nor
        // poisoned, the next statement is accepted, and `COMMIT` succeeds. Without the
        // explicit `ROLLBACK` in `Writer::transaction` the first insert below would
        // persist, and a caller that received an error would have written half a record.
        let (store, _dir) = store().await;
        let err = store
            .writer()
            .transaction(
                vec![
                    (INSERT_USER, user_params("id-1", "alice")),
                    // Same username: fails, and it is not the first statement.
                    (INSERT_USER, user_params("id-2", "alice")),
                ],
                || StoreError::Conflict {
                    kind: "user".to_string(),
                    value: "alice".to_string(),
                },
            )
            .await
            .expect_err("the second insert must fail");
        assert!(matches!(err, StoreError::Conflict { .. }), "{err:?}");
        assert_eq!(
            user_count(&store).await,
            0,
            "the first insert survived a failed transaction"
        );
    }

    /// The backup registry round-trips: a schedule is created, listed, named-unique, and
    /// deleted; a bundle is recorded and listed.
    #[tokio::test]
    async fn backup_schedules_and_files_round_trip() {
        let (store, _dir) = store().await;

        let schedule = store
            .create_backup_schedule(
                NewBackupSchedule {
                    name: "nightly".to_string(),
                    cron: "0 3 * * *".to_string(),
                    retain: 7,
                    enabled: true,
                },
                1_000,
            )
            .await
            .expect("a schedule is created");
        assert_eq!(schedule.name, "nightly");

        // The name is the schedule's key, so a duplicate is a conflict, not a second row.
        let err = store
            .create_backup_schedule(
                NewBackupSchedule {
                    name: "nightly".to_string(),
                    cron: "0 4 * * *".to_string(),
                    retain: 3,
                    enabled: true,
                },
                1_001,
            )
            .await
            .expect_err("a duplicate name must conflict");
        assert!(matches!(err, StoreError::Conflict { .. }), "{err:?}");

        assert_eq!(store.list_backup_schedules().await.expect("list").len(), 1);

        let file = store
            .record_backup_file(
                NewBackupFile {
                    schedule_id: Some(schedule.id.clone()),
                    path: "/var/lib/pingap/backups/backup-1".to_string(),
                    size_bytes: 4096,
                    sha256: "deadbeef".to_string(),
                },
                1_100,
            )
            .await
            .expect("a bundle is recorded");
        assert_eq!(file.schedule_id.as_deref(), Some(schedule.id.as_str()));
        assert_eq!(store.list_backup_files().await.expect("files").len(), 1);

        store
            .delete_backup_schedule(&schedule.id)
            .await
            .expect("delete works");
        assert!(
            store
                .list_backup_schedules()
                .await
                .expect("list")
                .is_empty()
        );
        // The bundle outlives its schedule: deleting the schedule detaches the file's
        // reference rather than deleting the record, because the bundle still exists on
        // disk and is still restorable.
        let files = store
            .list_backup_files()
            .await
            .expect("files after delete");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].schedule_id, None);
        // Deleting it again is a NotFound, not a quiet second success.
        assert!(
            matches!(
                store.delete_backup_schedule(&schedule.id).await,
                Err(StoreError::NotFound { .. })
            ),
            "a second delete should report the miss"
        );
    }

    /// The node record upserts on heartbeat and is reaped once, idempotently.
    #[tokio::test]
    async fn node_status_upserts_and_reaps_idempotently() {
        let (store, _dir) = store().await;

        store
            .upsert_node_status(
                NewNodeStatus {
                    node: "node-a".to_string(),
                    version: Some("v1".to_string()),
                    config_version: Some("1".to_string()),
                    last_seen_at: 100,
                },
                100,
            )
            .await
            .expect("first heartbeat");

        // A second heartbeat updates in place rather than adding a row.
        store
            .upsert_node_status(
                NewNodeStatus {
                    node: "node-a".to_string(),
                    version: Some("v2".to_string()),
                    config_version: Some("2".to_string()),
                    last_seen_at: 200,
                },
                200,
            )
            .await
            .expect("second heartbeat");

        let nodes = store.list_node_status().await.expect("list");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].last_seen_at, 200);
        assert_eq!(nodes[0].version.as_deref(), Some("v2"));
        assert_eq!(nodes[0].reaped_at, None);

        // Reaped once; a second sweep must not move the timestamp forward.
        store.reap_node_status("node-a", 300).await.expect("reap");
        store
            .reap_node_status("node-a", 400)
            .await
            .expect("idempotent reap");
        let nodes = store.list_node_status().await.expect("list after reap");
        assert_eq!(nodes[0].reaped_at, Some(300));

        // A node that heartbeats again clears the tombstone — it is live, not gone.
        store
            .upsert_node_status(
                NewNodeStatus {
                    node: "node-a".to_string(),
                    version: Some("v3".to_string()),
                    config_version: Some("3".to_string()),
                    last_seen_at: 500,
                },
                500,
            )
            .await
            .expect("a returning node clears reaped_at");
        let nodes = store.list_node_status().await.expect("list");
        assert_eq!(nodes[0].reaped_at, None);
        assert_eq!(nodes[0].last_seen_at, 500);
    }

    #[tokio::test]
    async fn adaptive_baselines_upsert_find_and_delete_round_trip() {
        let (store, _dir) = store().await;

        // Two domains keep independent baselines — the per-domain keying is the whole
        // point of the table.
        for (domain, learned) in [("a.example", 111), ("b.example", 222)] {
            store
                .upsert_adaptive_baseline(
                    NewAdaptiveBaseline {
                        domain: domain.to_string(),
                        payload: format!("{{\"domain\":\"{domain}\"}}"),
                        learned_at_secs: learned,
                    },
                    500,
                )
                .await
                .expect("upsert");
        }

        let all = store.list_adaptive_baselines().await.expect("list");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].domain, "a.example");
        assert_eq!(all[0].learned_at_secs, 111);
        assert_eq!(all[0].updated_at, 500);

        // A second upsert replaces the row rather than appending — one row per domain.
        store
            .upsert_adaptive_baseline(
                NewAdaptiveBaseline {
                    domain: "a.example".to_string(),
                    payload: "{\"domain\":\"a.example\",\"v\":2}".to_string(),
                    learned_at_secs: 333,
                },
                600,
            )
            .await
            .expect("re-upsert");

        let a = store
            .find_adaptive_baseline("a.example")
            .await
            .expect("find")
            .expect("present");
        assert_eq!(a.learned_at_secs, 333);
        assert_eq!(a.updated_at, 600);
        assert!(a.payload.contains("\"v\":2"));
        assert_eq!(
            store.list_adaptive_baselines().await.expect("list").len(),
            2,
            "an upsert must not grow the table"
        );

        store
            .delete_adaptive_baseline("a.example")
            .await
            .expect("delete");
        assert!(
            store
                .find_adaptive_baseline("a.example")
                .await
                .expect("find")
                .is_none()
        );
        assert_eq!(
            store.list_adaptive_baselines().await.expect("list").len(),
            1
        );
    }

    #[tokio::test]
    async fn the_writer_is_still_usable_after_a_rolled_back_transaction() {
        // The writer is the process's only one, so a transaction left open by an early
        // return would not fail here — it would silently enrol every later write into it,
        // and the next `BEGIN` would error. This is why the rollback is issued before the
        // error is returned rather than after.
        let (store, _dir) = store().await;
        store
            .writer()
            .transaction(
                vec![
                    (INSERT_USER, user_params("id-1", "alice")),
                    (INSERT_USER, user_params("id-2", "alice")),
                ],
                || StoreError::Conflict {
                    kind: "user".to_string(),
                    value: "alice".to_string(),
                },
            )
            .await
            .expect_err("the transaction fails");

        store
            .writer()
            .transaction(
                vec![(INSERT_USER, user_params("id-3", "bob"))],
                || StoreError::Backend {
                    message: "unexpected".to_string(),
                },
            )
            .await
            .expect("a later transaction still commits");
        assert_eq!(user_count(&store).await, 1);
    }

    #[tokio::test]
    async fn a_transaction_that_succeeds_commits_every_statement() {
        let (store, _dir) = store().await;
        store
            .writer()
            .transaction(
                vec![
                    (INSERT_USER, user_params("id-1", "alice")),
                    (INSERT_USER, user_params("id-2", "bob")),
                ],
                || StoreError::Backend {
                    message: "unexpected".to_string(),
                },
            )
            .await
            .expect("commits");
        assert_eq!(user_count(&store).await, 2);
    }

    /// The executable half of this module: no comments, no test code.
    ///
    /// Both exclusions matter. The module documentation *names* the mechanisms below in
    /// order to explain why they are absent, and the assertions themselves quote them, so a
    /// check over the raw file text would fail on its own prose.
    fn executable_source() -> String {
        include_str!("store.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("the non-test half of this module")
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn this_module_names_no_mechanism_turso_cannot_honour() {
        // The schema is already asserted against these; the backend is the other place a
        // silently-failing mechanism could be introduced, and all of them fail *quietly*,
        // which is why the absence is tested rather than reviewed.
        let source = executable_source().to_uppercase();
        assert!(
            !source.contains("BEGIN CONCURRENT"),
            "MVCC can silently roll a committed write back"
        );
        assert!(
            !source.contains("FOREIGN_KEY_CHECK"),
            "that pragma returns zero rows on a database with real orphans, so calling it \
             invites the belief that validation ran"
        );
    }

    #[test]
    fn the_only_transaction_entry_point_rolls_back_by_hand() {
        // A second `BEGIN` added elsewhere in this file would bypass the rollback, and the
        // resulting bug — a partial record committing while the call reports failure — is
        // invisible in review because the code reads correctly.
        let body = executable_source();
        assert_eq!(
            body.matches("\"BEGIN\"").count(),
            1,
            "a transaction is being opened somewhere other than `Writer::transaction`"
        );
        assert_eq!(
            body.matches("\"ROLLBACK\"").count(),
            1,
            "the number of rollbacks no longer matches the number of transactions"
        );
    }
}
