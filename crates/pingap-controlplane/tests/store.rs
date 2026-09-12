//! The Turso backend, exercised against a real database file.
//!
//! These are integration tests on purpose: the interesting failures in this driver are
//! not logic errors, they are semantics that only appear when statements actually run.
//! Phase 02's spike measured three of them — writes failing with `SQLITE_BUSY` under any
//! concurrency, a failed statement inside `BEGIN` being *skipped* rather than aborting the
//! transaction, and `PRAGMA foreign_key_check` returning zero rows on a database with real
//! orphans. A mock store would pass every test below while the real one lost audit rows.

use pingap_controlplane::repository::{
    ConfigStatus, ControlPlaneStore, NewActivity, NewConfigVersion, NewSession,
    NewUser, StoreError, TimeRange,
};
use pingap_controlplane::schema::LATEST_VERSION;
use pingap_controlplane::store::TursoStore;
use pingap_controlplane::{AuthLevel, Role};
use tempfile::TempDir;

/// A migrated store, plus the directory that must outlive it.
async fn store() -> (TursoStore, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("control-plane.db");
    let store = TursoStore::open(path.to_str().expect("utf-8 path"))
        .await
        .expect("the store opens");
    store.migrate().await.expect("migrations apply");
    (store, dir)
}

fn new_user(name: &str) -> NewUser {
    NewUser {
        username: name.to_string(),
        email: format!("{name}@example.test"),
        // Shaped like a real PHC string but never produced by the KDF: the store must not
        // care what a hash looks like, and a test that hashes for real pays 19 MiB of
        // argon2 per user for no coverage.
        password_hash: format!("$argon2id$v=19$m=19456,t=2,p=1$salt${name}"),
        role: Role::Operator,
    }
}

#[tokio::test]
async fn migrating_twice_applies_nothing_the_second_time() {
    // `CREATE TABLE IF NOT EXISTS` makes each statement idempotent, but the version
    // bookkeeping must not re-run them or a later non-idempotent migration would apply
    // twice on every boot.
    let (store, _dir) = store().await;
    let again = store.migrate().await.expect("a second migrate is safe");
    assert_eq!(
        again, LATEST_VERSION,
        "the store reported a version it is not at"
    );
}

#[tokio::test]
async fn a_user_round_trips_and_the_stored_hash_is_not_part_of_the_domain_type()
{
    let (store, _dir) = store().await;
    let created = store
        .create_user(new_user("alice"), 1_000)
        .await
        .expect("the user is created");
    assert!(!created.id.is_empty(), "the store assigned no id");
    assert_eq!(created.username, "alice");
    assert_eq!(created.role, Role::Operator);
    assert!(created.is_active, "a new user starts deactivated");
    assert_eq!(created.created_at, 1_000);

    let found = store
        .find_user_by_username("alice")
        .await
        .expect("the lookup runs")
        .expect("the user is there");
    assert_eq!(
        found, created,
        "the row read back differs from the row written"
    );

    // The hash is reachable only by the one method whose name says so, so a handler that
    // serialises a `User` cannot leak it by accident.
    let hash = store
        .password_hash_for(&created.id)
        .await
        .expect("the lookup runs")
        .expect("the hash is stored");
    assert!(
        hash.starts_with("$argon2id$"),
        "the hash did not survive: {hash}"
    );
    assert!(
        !format!("{created:?}").contains("argon2"),
        "the domain type carries the password hash"
    );
}

#[tokio::test]
async fn a_user_is_found_by_id_which_is_what_a_session_carries() {
    let (store, _dir) = store().await;
    let created = store
        .create_user(new_user("alice"), 1_000)
        .await
        .expect("created");
    assert_eq!(
        store.find_user_by_id(&created.id).await.expect("lookup"),
        Some(created)
    );
    assert!(
        store
            .find_user_by_id("no-such-id")
            .await
            .expect("lookup")
            .is_none()
    );
}

#[tokio::test]
async fn an_unknown_username_is_absent_rather_than_an_error() {
    // A login handler distinguishes "no such user" from "the store is broken", and
    // collapsing the two would turn an outage into a wrong-password message.
    let (store, _dir) = store().await;
    assert!(
        store
            .find_user_by_username("nobody")
            .await
            .expect("the lookup runs")
            .is_none()
    );
}

#[tokio::test]
async fn a_duplicate_username_is_a_conflict_and_leaves_no_half_written_user() {
    // Creating a user writes two tables, so a rejected create is the one place where
    // Phase 02's measured transaction behaviour bites: a failed statement inside `BEGIN`
    // is skipped rather than aborting, so without an explicit `ROLLBACK` the surrounding
    // work commits and the store keeps a profile row for a user that does not exist.
    let (store, _dir) = store().await;
    store
        .create_user(new_user("alice"), 1_000)
        .await
        .expect("the first create succeeds");

    let err = store
        .create_user(new_user("alice"), 2_000)
        .await
        .expect_err("a duplicate username must not be accepted");
    assert!(
        matches!(&err, StoreError::Conflict { kind, value } if kind == "user" && value == "alice"),
        "a unique violation surfaced as something a handler cannot answer: {err:?}"
    );

    // And exactly one user survived, under the original timestamp.
    let users = store.list_users().await.expect("the list runs");
    assert_eq!(users.len(), 1, "the rejected create left a row behind");
    assert_eq!(users[0].created_at, 1_000);
}

#[tokio::test]
async fn a_duplicate_email_is_refused_even_when_the_username_is_free() {
    // Both columns are UNIQUE, and only reporting the username would send an operator
    // looking at the wrong field.
    let (store, _dir) = store().await;
    store
        .create_user(new_user("alice"), 1_000)
        .await
        .expect("the first create succeeds");
    let mut clash = new_user("bob");
    clash.email = "alice@example.test".to_string();
    let err = store
        .create_user(clash, 2_000)
        .await
        .expect_err("a duplicate email must not be accepted");
    assert!(
        matches!(&err, StoreError::Conflict { value, .. } if value == "alice@example.test"),
        "the conflict named the wrong field: {err:?}"
    );
}

#[tokio::test]
async fn deactivating_a_user_is_visible_to_the_next_read() {
    let (store, _dir) = store().await;
    let alice = store
        .create_user(new_user("alice"), 1_000)
        .await
        .expect("created");
    store
        .set_user_active(&alice.id, false, 2_000)
        .await
        .expect("the update runs");
    let found = store
        .find_user_by_username("alice")
        .await
        .expect("the lookup runs")
        .expect("the user is still listed");
    assert!(
        !found.is_active,
        "a deactivated account still reads as active"
    );

    // Deactivation is not deletion: the row stays so the audit trail keeps resolving.
    assert_eq!(store.list_users().await.expect("list").len(), 1);
}

#[tokio::test]
async fn updating_a_user_who_does_not_exist_is_reported_rather_than_ignored() {
    // Turso's `changes()` is partial, so "the UPDATE matched nothing" cannot be read off
    // the driver. Silently succeeding here would let an admin API return 200 for editing
    // an account that was deleted a moment earlier.
    let (store, _dir) = store().await;
    let err = store
        .set_user_active("no-such-id", false, 1_000)
        .await
        .expect_err("updating an absent user must not report success");
    assert!(
        matches!(&err, StoreError::NotFound { kind, .. } if kind == "user"),
        "{err:?}"
    );
}

#[tokio::test]
async fn the_totp_secret_round_trips_as_opaque_ciphertext() {
    // The store never sees a readable secret; it stores whatever the auth layer encrypted
    // and hands the same bytes back.
    let (store, _dir) = store().await;
    let alice = store
        .create_user(new_user("alice"), 1_000)
        .await
        .expect("created");
    assert!(
        store
            .totp_secret_for(&alice.id)
            .await
            .expect("the lookup runs")
            .is_none(),
        "a new user already has a second factor"
    );

    store
        .set_totp_secret(&alice.id, "ciphertext-one", false, 2_000)
        .await
        .expect("enrolment stores the secret");
    assert_eq!(
        store.totp_secret_for(&alice.id).await.expect("read"),
        Some(("ciphertext-one".to_string(), false)),
        "an enrolled-but-unconfirmed second factor read back as enabled"
    );

    // Confirming enrolment is an upsert on the same row, not a second row.
    store
        .set_totp_secret(&alice.id, "ciphertext-two", true, 3_000)
        .await
        .expect("confirmation updates the row");
    assert_eq!(
        store.totp_secret_for(&alice.id).await.expect("read"),
        Some(("ciphertext-two".to_string(), true))
    );
}

/// A session for `user_id`, expiring well after `now`.
fn new_session<'a>(user_id: &'a str, token_hash: &'a str) -> NewSession<'a> {
    NewSession {
        user_id,
        token_hash,
        auth_level: AuthLevel::PasswordOnly,
        ip: Some("203.0.113.7"),
        user_agent: Some("test-agent/1.0"),
        now: 1_000,
        expires_at: 100_000,
    }
}

#[tokio::test]
async fn a_session_is_found_by_its_token_hash_and_never_by_its_token() {
    let (store, _dir) = store().await;
    let alice = store
        .create_user(new_user("alice"), 1_000)
        .await
        .expect("created");
    let hash = pingap_controlplane::hash_token("the-bearer-token");
    let session = store
        .create_session(new_session(&alice.id, &hash))
        .await
        .expect("the session opens");
    assert!(session.is_usable(2_000), "a fresh session was not usable");
    assert_eq!(session.auth_level, AuthLevel::PasswordOnly);
    assert_eq!(session.ip.as_deref(), Some("203.0.113.7"));

    assert_eq!(
        store.session_by_token(&hash).await.expect("lookup"),
        Some(session.clone())
    );
    // The raw token is not a key into the store, so a leaked database is not a set of
    // usable credentials.
    assert!(
        store
            .session_by_token("the-bearer-token")
            .await
            .expect("lookup")
            .is_none(),
        "the store is keyed by the token itself"
    );
}

#[tokio::test]
async fn revoking_a_session_takes_effect_on_the_next_lookup() {
    // The named success criterion. Revocation marks the row rather than deleting it, so
    // an operator investigating an incident can still see the session existed.
    let (store, _dir) = store().await;
    let alice = store
        .create_user(new_user("alice"), 1_000)
        .await
        .expect("created");
    let hash = pingap_controlplane::hash_token("token");
    let session = store
        .create_session(new_session(&alice.id, &hash))
        .await
        .expect("opened");

    store
        .revoke_session(&session.id, 5_000)
        .await
        .expect("revocation runs");

    let after = store
        .session_by_token(&hash)
        .await
        .expect("lookup")
        .expect("the row is still there");
    assert_eq!(after.revoked_at, Some(5_000));
    assert!(
        !after.is_usable(6_000),
        "a revoked session was still usable"
    );
    assert_eq!(
        store.list_sessions(&alice.id).await.expect("list").len(),
        1,
        "revocation deleted the row instead of marking it"
    );
}

#[tokio::test]
async fn revoking_a_session_that_does_not_exist_is_reported() {
    let (store, _dir) = store().await;
    let err = store
        .revoke_session("no-such-session", 1_000)
        .await
        .expect_err("revoking nothing must not report success");
    assert!(
        matches!(&err, StoreError::NotFound { kind, .. } if kind == "session"),
        "{err:?}"
    );
}

#[tokio::test]
async fn completing_a_second_factor_promotes_only_that_session() {
    // Promotion is per session, not per user: completing the challenge on a laptop must
    // not silently upgrade a password-only session opened from somewhere else.
    let (store, _dir) = store().await;
    let alice = store
        .create_user(new_user("alice"), 1_000)
        .await
        .expect("created");
    let laptop = pingap_controlplane::hash_token("laptop");
    let elsewhere = pingap_controlplane::hash_token("elsewhere");
    let a = store
        .create_session(new_session(&alice.id, &laptop))
        .await
        .expect("opened");
    store
        .create_session(new_session(&alice.id, &elsewhere))
        .await
        .expect("opened");

    store
        .complete_second_factor(&a.id)
        .await
        .expect("promotion runs");

    assert_eq!(
        store
            .session_by_token(&laptop)
            .await
            .expect("lookup")
            .expect("there")
            .auth_level,
        AuthLevel::TwoFactor
    );
    assert_eq!(
        store
            .session_by_token(&elsewhere)
            .await
            .expect("lookup")
            .expect("there")
            .auth_level,
        AuthLevel::PasswordOnly,
        "completing one session's challenge promoted another"
    );
}

fn activity(action: &str) -> NewActivity {
    NewActivity {
        actor_id: Some("actor-1".to_string()),
        actor_username: "alice".to_string(),
        action: action.to_string(),
        target: "domain/example.test".to_string(),
        config_version: Some("v7".to_string()),
        ip: Some("203.0.113.7".to_string()),
        user_agent: Some("test-agent/1.0".to_string()),
        detail: None,
    }
}

#[tokio::test]
async fn the_activity_log_appends_and_reads_back_newest_first() {
    let (store, _dir) = store().await;
    for (i, action) in ["create", "update", "delete"].iter().enumerate() {
        store
            .record_activity(activity(action), 1_000 + i as i64)
            .await
            .expect("the entry is recorded");
    }
    let all = store
        .read_activity(TimeRange::default())
        .await
        .expect("the read runs");
    assert_eq!(all.len(), 3);
    // Newest first: an operator opening the log wants the last thing that happened, and
    // a range query cannot be paged from the wrong end.
    assert_eq!(all[0].action, "delete");
    assert_eq!(all[2].action, "create");
    assert_eq!(all[0].config_version.as_deref(), Some("v7"));
    assert_eq!(all[0].actor_username, "alice");
}

#[tokio::test]
async fn an_activity_range_excludes_what_falls_outside_it() {
    let (store, _dir) = store().await;
    for i in 0..5i64 {
        store
            .record_activity(activity("touch"), 1_000 + i * 100)
            .await
            .expect("recorded");
    }
    let window = store
        .read_activity(TimeRange {
            since: Some(1_100),
            until: Some(1_300),
            limit: None,
        })
        .await
        .expect("the read runs");
    assert_eq!(
        window.len(),
        3,
        "the window is inclusive at both ends: 1100, 1200, 1300"
    );
    let capped = store
        .read_activity(TimeRange {
            limit: Some(2),
            ..Default::default()
        })
        .await
        .expect("the read runs");
    assert_eq!(capped.len(), 2, "the limit was not applied");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers_all_land_because_they_share_one_writer() {
    // Phase 02's spike measured 153-166 of 200 writes failing with `SQLITE_BUSY` when four
    // tasks wrote on their own connections, with no busy handler to make them wait. This
    // is that experiment re-run through the store under the real schema, and it is the
    // reason the writer is one process-global handle: the audit log is a security control,
    // and a dropped row under load is exactly the failure it cannot have.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("control-plane.db");
    let store = std::sync::Arc::new(
        TursoStore::open(path.to_str().expect("utf-8 path"))
            .await
            .expect("the store opens"),
    );
    store.migrate().await.expect("migrations apply");

    const WRITERS: i64 = 4;
    const EACH: i64 = 50;
    let mut set = tokio::task::JoinSet::new();
    for writer in 0..WRITERS {
        let store = store.clone();
        set.spawn(async move {
            for i in 0..EACH {
                store
                    .record_activity(
                        activity(&format!("writer-{writer}")),
                        10_000 + writer * EACH + i,
                    )
                    .await
                    .map_err(|e| format!("writer {writer} entry {i}: {e}"))?;
            }
            Ok::<(), String>(())
        });
    }
    while let Some(joined) = set.join_next().await {
        joined
            .expect("the task did not panic")
            .expect("every write succeeded");
    }

    let rows = store
        .read_activity(TimeRange::default())
        .await
        .expect("the read runs");
    assert_eq!(
        rows.len() as i64,
        WRITERS * EACH,
        "writes were lost under concurrency, which is what the single writer exists to \
         prevent"
    );
}

#[tokio::test]
async fn rows_survive_closing_and_reopening_the_store() {
    // Durability, stated plainly. Turso's MVCC mode can silently roll a committed write
    // back, which is why nothing here enables it; this is the test that would notice.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("control-plane.db");
    let path = path.to_str().expect("utf-8 path");

    let id = {
        let store = TursoStore::open(path).await.expect("opens");
        store.migrate().await.expect("migrations apply");
        let alice = store
            .create_user(new_user("alice"), 1_000)
            .await
            .expect("created");
        store
            .record_activity(activity("create"), 1_000)
            .await
            .expect("recorded");
        alice.id
    };

    let reopened = TursoStore::open(path).await.expect("reopens");
    assert_eq!(
        reopened.migrate().await.expect("migrate"),
        LATEST_VERSION,
        "reopening re-applied the schema instead of recognising it"
    );
    assert_eq!(
        reopened
            .find_user_by_username("alice")
            .await
            .expect("lookup")
            .map(|u| u.id),
        Some(id),
        "the user did not survive a reopen"
    );
    assert_eq!(
        reopened
            .read_activity(TimeRange::default())
            .await
            .expect("read")
            .len(),
        1,
        "the audit entry did not survive a reopen"
    );
}

#[tokio::test]
async fn the_shared_store_is_one_store_and_refuses_a_second_path() {
    // The single-writer guarantee is a property of there being one instance, so this is
    // the test that the guarantee is reachable at all. Everything about `shared` lives in
    // one test because the handle it establishes is process-global: a second test could
    // not establish its own without depending on which ran first.
    let dir = tempfile::tempdir().expect("tempdir");
    let first = dir.path().join("control-plane.db");
    let first = first.to_str().expect("utf-8 path");

    let a = TursoStore::shared(first).await.expect("the store opens");
    a.migrate().await.expect("migrations apply");
    let b = TursoStore::shared(first)
        .await
        .expect("the same path is served again");
    assert!(
        std::sync::Arc::ptr_eq(&a, &b),
        "a second call opened a second store, so writes are no longer serialised"
    );

    let other = dir.path().join("somewhere-else.db");
    let err = TursoStore::shared(other.to_str().expect("utf-8 path"))
        .await
        .expect_err(
            "a different path must not be quietly served from the first",
        );
    assert!(
        matches!(&err, StoreError::Backend { message } if message.contains("already open")),
        "{err:?}"
    );
    assert!(
        !other.exists(),
        "the refused path was created anyway, which is half an audit trail"
    );
}

#[tokio::test]
async fn an_open_store_reports_itself_healthy() {
    let (store, _dir) = store().await;
    store.health().await.expect("an open store is healthy");
}

#[tokio::test]
async fn a_store_that_cannot_be_opened_is_unavailable_rather_than_a_panic() {
    // The load-bearing boundary of this phase: the gateway serves from config alone and
    // must survive the store being absent, unreadable, or on a path that does not exist.
    // `Unavailable` is a distinct variant so the admin API can answer "the store is down"
    // instead of a 500 that reads like a crash.
    let err =
        TursoStore::open("/nonexistent-directory-for-a-test/control-plane.db")
            .await
            .expect_err("opening under a missing directory must fail");
    assert!(
        matches!(err, StoreError::Unavailable { .. }),
        "an unreachable store must be reported as unavailable, not as a backend error: \
         {err:?}"
    );
}

#[tokio::test]
async fn queries_against_an_unmigrated_store_are_backend_errors_not_empty_results()
 {
    // An empty result would make a fresh, schemaless store look like a store with no
    // users — and the bootstrap path would then create a second admin on every boot.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("control-plane.db");
    let store = TursoStore::open(path.to_str().expect("utf-8 path"))
        .await
        .expect("opens");
    let err = store
        .list_users()
        .await
        .expect_err("querying a missing table must not read as an empty table");
    assert!(matches!(err, StoreError::Backend { .. }), "{err:?}");
}

fn new_version(hash: &str, status: ConfigStatus) -> NewConfigVersion {
    NewConfigVersion {
        hash: hash.to_string(),
        status,
        actor_id: Some("actor-1".to_string()),
        actor_username: "alice".to_string(),
        intent_json: r#"{"domains":{}}"#.to_string(),
        error: None,
    }
}

#[tokio::test]
async fn a_config_version_is_born_pending_and_only_verification_applies_it() {
    // The distinction this table exists for: a config that was written is not a config
    // that is enforcing. pingap stores its provider map even when a plugin failed to
    // construct, so `applied` has to mean "read back from the data plane", and nothing
    // about recording a version may set it.
    let (store, _dir) = store().await;
    let v = store
        .record_config_version(new_version("aaa", ConfigStatus::Pending), 1_000)
        .await
        .expect("recorded");
    assert_eq!(v.status, ConfigStatus::Pending);
    assert_eq!(v.settled_at, None, "a pending version has not settled");
    assert!(!v.id.is_empty());

    assert!(
        store
            .latest_applied_config_version()
            .await
            .expect("lookup")
            .is_none(),
        "a pending version answered as applied"
    );

    store
        .set_config_version_status(&v.id, ConfigStatus::Applied, None, 2_000)
        .await
        .expect("verification applies it");
    let applied = store
        .config_version(&v.id)
        .await
        .expect("lookup")
        .expect("there");
    assert_eq!(applied.status, ConfigStatus::Applied);
    assert_eq!(applied.settled_at, Some(2_000));
    assert_eq!(
        store.latest_applied_config_version().await.expect("lookup"),
        Some(applied)
    );
}

#[tokio::test]
async fn a_rejected_version_records_why_and_the_reason_is_cleared_when_it_succeeds()
 {
    let (store, _dir) = store().await;
    let v = store
        .record_config_version(
            NewConfigVersion {
                error: Some("plugin `waf:strict` cannot be built".to_string()),
                ..new_version("bbb", ConfigStatus::Failed)
            },
            1_000,
        )
        .await
        .expect("recorded");
    // Born terminal, so it settled at creation rather than waiting for a status move.
    assert_eq!(v.settled_at, Some(1_000));
    assert_eq!(
        store
            .config_version(&v.id)
            .await
            .expect("lookup")
            .expect("there")
            .error
            .as_deref(),
        Some("plugin `waf:strict` cannot be built")
    );

    // A later attempt on the same version must not keep an error explaining a different
    // one, or an operator reads a stale cause for a config that is now fine.
    store
        .set_config_version_status(&v.id, ConfigStatus::Applied, None, 2_000)
        .await
        .expect("status moves");
    assert_eq!(
        store
            .config_version(&v.id)
            .await
            .expect("lookup")
            .expect("there")
            .error,
        None,
        "an applied version still carries a failure reason"
    );
}

#[tokio::test]
async fn the_rollback_target_is_the_newest_applied_version_not_the_newest_one()
{
    // Rollback goes to the last config known to be enforcing. Falling back to the newest
    // version instead would roll forward into the very config that just failed.
    let (store, _dir) = store().await;
    store
        .record_config_version(
            new_version("good", ConfigStatus::Applied),
            1_000,
        )
        .await
        .expect("recorded");
    let bad = store
        .record_config_version(new_version("bad", ConfigStatus::Failed), 2_000)
        .await
        .expect("recorded");

    assert_eq!(
        store
            .latest_config_version()
            .await
            .expect("lookup")
            .map(|v| v.id.clone()),
        Some(bad.id),
        "the newest version is the failed one"
    );
    assert_eq!(
        store
            .latest_applied_config_version()
            .await
            .expect("lookup")
            .map(|v| v.hash),
        Some("good".to_string())
    );
}

#[tokio::test]
async fn config_versions_list_newest_first_and_honour_a_limit() {
    let (store, _dir) = store().await;
    for i in 0..5i64 {
        store
            .record_config_version(
                new_version(&format!("h{i}"), ConfigStatus::Superseded),
                1_000 + i,
            )
            .await
            .expect("recorded");
    }
    let all = store.list_config_versions(None).await.expect("list");
    assert_eq!(all.len(), 5);
    assert_eq!(all[0].hash, "h4", "the list is not newest-first");
    assert_eq!(
        store
            .list_config_versions(Some(2))
            .await
            .expect("list")
            .len(),
        2
    );
}

#[tokio::test]
async fn moving_a_version_that_does_not_exist_is_reported() {
    let (store, _dir) = store().await;
    let err = store
        .set_config_version_status(
            "no-such-version",
            ConfigStatus::Applied,
            None,
            1_000,
        )
        .await
        .expect_err("applying nothing must not report success");
    assert!(
        matches!(&err, StoreError::NotFound { kind, .. } if kind == "config version"),
        "{err:?}"
    );
}

#[tokio::test]
async fn an_activity_row_can_name_the_config_version_it_produced() {
    // What makes Phase 08's rollback explainable after the fact: the audit entry and the
    // config it generated are joined, so "who changed what, and what did the gateway
    // actually run" is one question.
    let (store, _dir) = store().await;
    let version = store
        .record_config_version(new_version("ccc", ConfigStatus::Pending), 1_000)
        .await
        .expect("recorded");
    let entry = store
        .record_activity(
            NewActivity {
                config_version: Some(version.id.clone()),
                ..activity("domain.update")
            },
            1_000,
        )
        .await
        .expect("recorded");
    assert_eq!(entry.config_version, Some(version.id.clone()));
    let read = store
        .read_activity(TimeRange::default())
        .await
        .expect("read");
    assert_eq!(read[0].config_version, Some(version.id));
}
