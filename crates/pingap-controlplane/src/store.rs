//! The Turso backend behind [`ControlPlaneStore`].
//!
//! Everything here answers to one of Phase 02's measurements rather than to taste, so the
//! shape is worth stating before the code:
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
    Activity, ConfigStatus, ConfigVersion, ControlPlaneStore, NewActivity,
    NewConfigVersion, NewSession, NewUser, Result, Session, StoreError,
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

/// `Some(text)` as a bound value, `NULL` otherwise.
fn nullable(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::Text)
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
        // The direct falsification of Phase 02's measurement. On this driver a failed
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
