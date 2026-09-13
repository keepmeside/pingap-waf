//! Spike B — Turso 0.7.2 under the control-plane schema shape.
//!
//! Fallback probe, not a decision gate: the outcome selects the store's driver
//! (`turso` vs `rusqlite` on the same file format), not whether the control-plane store runs.
//!
//! Eight questions, in the order the spike set asks them:
//!
//!   1. schema  — users + FK children + append-heavy log + time series
//!   2. seccomp — does it open a database at all under a hardened profile?
//!                (answered by the docker wrapper, not by this binary)
//!   3. write contention — two concurrent writes on one connection: SQLITE_BUSY
//!                with no busy-handler retry?
//!   4. rollback-only transaction state — drop an unfinished write inside BEGIN,
//!                then COMMIT. Do later statements observe partial changes?
//!   5. plain-transaction durability — no BEGIN CONCURRENT, no silent rollback
//!   6. VACUUM INTO — the backup path depends on it
//!   7. PRAGMA foreign_key_check — absent? Backup and restore must validate in app code
//!   8. audit-log write throughput — can per-request WAF events go to the DB,
//!                or must observability sample?
//!
//! Prints one `RESULT <key> <value>` line per finding so the wrapper script can
//! diff outcomes across seccomp profiles without parsing prose.

use std::time::Instant;
use turso::Builder;

macro_rules! result {
    ($k:expr, $($v:tt)*) => {
        println!("RESULT {:<28} {}", $k, format!($($v)*))
    };
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/spike-turso.db".to_string());
    let _ = std::fs::remove_file(&path);

    // Q2 is decided here for the in-container case: if io_uring is blocked and
    // there is no portable fallback, this is where it fails.
    let t0 = Instant::now();
    let db = match Builder::new_local(&path).build().await {
        Ok(db) => {
            result!("open", "ok in {:?}", t0.elapsed());
            db
        },
        Err(e) => {
            result!("open", "FAILED {e}");
            result!("verdict", "cannot open database — driver unusable here");
            return Ok(());
        },
    };
    let conn = db.connect()?;

    // ---- Q1: schema resembling the control-plane target -------------------------------
    // users with FK children (sessions), an append-heavy log (activity_log),
    // and a time series (performance_metrics).
    conn.execute("PRAGMA foreign_keys = ON", ()).await.ok();
    for (name, ddl) in [
        (
            "users",
            "CREATE TABLE users (
               id INTEGER PRIMARY KEY,
               email TEXT NOT NULL UNIQUE,
               password_hash TEXT NOT NULL,
               role TEXT NOT NULL
             )",
        ),
        (
            "user_sessions",
            "CREATE TABLE user_sessions (
               id INTEGER PRIMARY KEY,
               user_id INTEGER NOT NULL REFERENCES users(id),
               token_hash TEXT NOT NULL,
               created_at INTEGER NOT NULL
             )",
        ),
        (
            "activity_log",
            "CREATE TABLE activity_log (
               id INTEGER PRIMARY KEY,
               actor_id INTEGER,
               action TEXT NOT NULL,
               target TEXT,
               config_version TEXT,
               ip TEXT,
               created_at INTEGER NOT NULL
             )",
        ),
        (
            "performance_metrics",
            "CREATE TABLE performance_metrics (
               id INTEGER PRIMARY KEY,
               bucket_start INTEGER NOT NULL,
               metric TEXT NOT NULL,
               value REAL NOT NULL
             )",
        ),
    ] {
        match conn.execute(ddl, ()).await {
            Ok(_) => result!(format!("ddl.{name}"), "ok"),
            Err(e) => result!(format!("ddl.{name}"), "FAILED {e}"),
        }
    }

    conn.execute(
        "INSERT INTO users (id, email, password_hash, role)
         VALUES (1, 'a@example.com', 'argon2id$dummy', 'admin')",
        (),
    )
    .await?;

    // ---- Q7: is PRAGMA foreign_key_check available? -----------------------
    // Restore validation depends on the answer. Insert a deliberate
    // orphan first so a working check would have something to report.
    conn.execute("PRAGMA foreign_keys = OFF", ()).await.ok();
    let orphan = conn
        .execute(
            "INSERT INTO user_sessions (id, user_id, token_hash, created_at)
             VALUES (99, 4242, 'x', 0)",
            (),
        )
        .await;
    result!(
        "fk.orphan_insert",
        "{}",
        match &orphan {
            Ok(_) => "accepted with foreign_keys=OFF".to_string(),
            Err(e) => format!("rejected: {e}"),
        }
    );
    match conn.query("PRAGMA foreign_key_check", ()).await {
        Ok(mut rows) => {
            let mut n = 0;
            while let Ok(Some(_)) = rows.next().await {
                n += 1;
            }
            result!("fk.foreign_key_check", "supported, reported {n} violation(s)");
        },
        Err(e) => result!("fk.foreign_key_check", "UNSUPPORTED: {e}"),
    }
    conn.execute("DELETE FROM user_sessions WHERE id = 99", ()).await.ok();
    conn.execute("PRAGMA foreign_keys = ON", ()).await.ok();

    // ---- Q5: plain transaction durability ---------------------------------
    match conn.execute("BEGIN", ()).await {
        Ok(_) => {
            conn.execute(
                "INSERT INTO activity_log (action, created_at) VALUES ('tx.a', 1)",
                (),
            )
            .await?;
            conn.execute(
                "INSERT INTO activity_log (action, created_at) VALUES ('tx.b', 2)",
                (),
            )
            .await?;
            match conn.execute("COMMIT", ()).await {
                Ok(_) => {
                    let n = count(&conn, "SELECT COUNT(*) FROM activity_log").await;
                    result!("tx.plain_commit", "committed, rows={n} (expect 2)");
                },
                Err(e) => result!("tx.plain_commit", "COMMIT FAILED {e}"),
            }
        },
        Err(e) => result!("tx.plain_commit", "BEGIN FAILED {e}"),
    }

    // ---- Q4: rollback-only state after a dropped write --------------------
    // Start a transaction, issue a statement that errors, then try to continue
    // and commit. The documented pre-1.0 hazard is that the transaction becomes
    // rollback-only and later statements can observe partial changes.
    conn.execute("BEGIN", ()).await.ok();
    conn.execute(
        "INSERT INTO activity_log (action, created_at) VALUES ('rb.before', 3)",
        (),
    )
    .await
    .ok();
    let bad = conn
        .execute("INSERT INTO users (id, email, password_hash, role)
                  VALUES (1, 'dup@example.com', 'x', 'viewer')", ())
        .await;
    result!(
        "tx.conflict_stmt",
        "{}",
        match &bad {
            Ok(_) => "unexpectedly succeeded".to_string(),
            Err(e) => format!("errored as expected: {}", first_line(&e.to_string())),
        }
    );
    let after = conn
        .execute(
            "INSERT INTO activity_log (action, created_at) VALUES ('rb.after', 4)",
            (),
        )
        .await;
    result!(
        "tx.stmt_after_error",
        "{}",
        match &after {
            Ok(_) => "accepted".to_string(),
            Err(e) => format!("rejected: {}", first_line(&e.to_string())),
        }
    );
    let commit = conn.execute("COMMIT", ()).await;
    result!(
        "tx.commit_after_error",
        "{}",
        match &commit {
            Ok(_) => "committed".to_string(),
            Err(e) => format!("rejected: {}", first_line(&e.to_string())),
        }
    );
    if commit.is_err() {
        conn.execute("ROLLBACK", ()).await.ok();
    }
    let n = count(&conn, "SELECT COUNT(*) FROM activity_log WHERE action LIKE 'rb.%'").await;
    result!("tx.partial_visible", "rb.* rows persisted = {n}");

    // ---- Q3: write contention across concurrent tasks ---------------------
    // The control-plane store must know whether a per-connection lock is sufficient. Spawn
    // concurrent writers on separate connections and count SQLITE_BUSY.
    let mut set = tokio::task::JoinSet::new();
    for w in 0..4u32 {
        let c = db.connect()?;
        set.spawn(async move {
            let mut ok = 0u32;
            let mut busy = 0u32;
            let mut other = 0u32;
            for i in 0..50u32 {
                let r = c
                    .execute(
                        "INSERT INTO activity_log (action, created_at)
                         VALUES ('concurrent', ?1)",
                        turso::params::Params::Positional(vec![turso::Value::Integer(
                            (w * 1000 + i) as i64,
                        )]),
                    )
                    .await;
                match r {
                    Ok(_) => ok += 1,
                    Err(e) => {
                        let s = e.to_string().to_lowercase();
                        if s.contains("busy") || s.contains("locked") {
                            busy += 1;
                        } else {
                            other += 1;
                        }
                    },
                }
            }
            (ok, busy, other)
        });
    }
    let (mut ok, mut busy, mut other) = (0u32, 0u32, 0u32);
    while let Some(joined) = set.join_next().await {
        let (a, b, c) = joined?;
        ok += a;
        busy += b;
        other += c;
    }
    result!(
        "write.concurrent_4x50",
        "ok={ok} busy={busy} other_err={other}"
    );

    // ---- Q8: audit-log write throughput ----------------------------------
    let n = 2000u32;
    let t = Instant::now();
    let mut written = 0u32;
    for i in 0..n {
        if conn
            .execute(
                "INSERT INTO activity_log (action, created_at) VALUES ('bench', ?1)",
                turso::params::Params::Positional(vec![turso::Value::Integer(i as i64)]),
            )
            .await
            .is_ok()
        {
            written += 1;
        }
    }
    let el = t.elapsed();
    result!(
        "write.throughput_serial",
        "{written}/{n} rows in {:?} = {:.0} rows/s",
        el,
        written as f64 / el.as_secs_f64()
    );

    // Batched inside one transaction, which is how the batch writer works.
    conn.execute("BEGIN", ()).await.ok();
    let t = Instant::now();
    let mut batched = 0u32;
    for i in 0..n {
        if conn
            .execute(
                "INSERT INTO activity_log (action, created_at) VALUES ('batch', ?1)",
                turso::params::Params::Positional(vec![turso::Value::Integer(i as i64)]),
            )
            .await
            .is_ok()
        {
            batched += 1;
        }
    }
    let commit_ok = conn.execute("COMMIT", ()).await.is_ok();
    let el = t.elapsed();
    result!(
        "write.throughput_batched",
        "{batched}/{n} rows in {:?} = {:.0} rows/s (commit_ok={commit_ok})",
        el,
        batched as f64 / el.as_secs_f64()
    );

    // ---- Q6: VACUUM INTO, which the backup path depends on ---------------------
    let snap = format!("{path}.snapshot");
    let _ = std::fs::remove_file(&snap);
    match conn
        .execute(&format!("VACUUM INTO '{snap}'"), ())
        .await
    {
        Ok(_) => {
            let sz = std::fs::metadata(&snap).map(|m| m.len()).unwrap_or(0);
            result!("vacuum_into", "ok, snapshot {sz} bytes");
        },
        Err(e) => result!("vacuum_into", "UNSUPPORTED: {}", first_line(&e.to_string())),
    }

    // ---- window functions observability must not rely on ----------------------
    match conn
        .query(
            "SELECT metric, value, lag(value) OVER (ORDER BY bucket_start)
             FROM performance_metrics",
            (),
        )
        .await
    {
        Ok(_) => result!("window.lag", "supported"),
        Err(e) => result!("window.lag", "UNSUPPORTED: {}", first_line(&e.to_string())),
    }

    result!("verdict", "see docs/spikes/turso-finding.md");
    Ok(())
}

async fn count(conn: &turso::Connection, sql: &str) -> i64 {
    match conn.query(sql, ()).await {
        Ok(mut rows) => match rows.next().await {
            Ok(Some(row)) => row.get_value(0).ok().and_then(|v| match v {
                turso::Value::Integer(i) => Some(i),
                _ => None,
            }).unwrap_or(-1),
            _ => -1,
        },
        Err(_) => -1,
    }
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").chars().take(90).collect()
}
