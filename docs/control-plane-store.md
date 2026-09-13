# Control-plane store

Users, second factors, sessions and the audit trail live in a local
[Turso](https://github.com/tursodatabase/turso) database behind a repository
trait in `crates/pingap-controlplane`. This page is the operator's and
maintainer's reference for that store: where it sits, what it owns, how to
recover without it, and the driver behaviours every writer must respect.

## The boundary

| Store | Owns | Why |
| --- | --- | --- |
| pingap config (file / etcd) | domains, upstreams, TLS, WAF / ACL / bot policy, plugin instances, alert *rule definitions* | already has validation, history, an etcd watch, hot reload and `pingap-waf -t` |
| control-plane store | users, 2FA secrets, sessions, refresh tokens, activity log, alert *history*, metric rollups, backup metadata, node status, WAF events | append-heavy, queried by range, role-filtered |

**The gateway starts and serves with the store absent, deleted, or
unwritable.** That is the falsifiable form of the boundary, and it holds
because nothing in the store is on the request path. With the store
unreachable:

- the data plane proxies as configured;
- the admin login page loads;
- every admin API route answers **503** with
  `control-plane store unavailable: <reason>`, not 401 (which would send an
  operator to reset a password) and not 500 (which reads as a crash);
- `GET /api/basic` reports the reason in `control_plane_store_error`.

Deleting the store loses history and accounts. It does not lose configuration,
and the next login with the `--admin` credential recreates the first admin.

## Where it lives

`control-plane.db` **beside the config file** by default — the one directory an
operator already knows is pingap's, already backs up, and already restricts.
Override with `store=` on the admin address:

```bash
pingap-waf -c /etc/pingap/pingap.toml \
  --admin 'admin:s3cret@127.0.0.1:3018/?store=/var/lib/pingap/control-plane.db&totp_key=...'
```

| Admin-address query key | Purpose |
| --- | --- |
| `store` | Path of the database. Defaults to `control-plane.db` beside `-c`; falls back to the working directory when `-c` is an etcd URL or absent. |
| `totp_key` | Key that encrypts TOTP secrets at rest. **Without it, 2FA enrolment is refused** rather than stored readable — a shared secret in the clear lets an attacker mint valid codes forever. |

The same keys are accepted on a `category = "admin"` plugin entry in config.
The file holds 2FA secrets and the audit trail: keep it on a local filesystem
with restrictive permissions, and treat it as part of the backup set.

## Authentication

The shared `authorizations` credential list is gone from the admin plugin. It
hashed `user:pass:timestamp` on the client and could not say *who* did
anything, which is disqualifying for an audit trail.

| | Old scheme | Now |
| --- | --- | --- |
| Identity | one shared credential | per-user accounts with `admin` / `operator` / `viewer` roles |
| Header | `Authorization: <sha256>:<ts>` | `Authorization: Bearer <token>` |
| Token | derived from the password, valid for `max_age` | 256 bits from the OS per login, stored **hashed**, valid two days, **revocable** |
| Second factor | none | TOTP; a session that has not completed it can read but not mutate |
| Revocation | impossible short of changing the password | takes effect on the next request |

Routes, all under the admin listener's `/api` prefix:

| Route | Auth | Effect |
| --- | --- | --- |
| `POST /api/auth/login` `{username, password}` | none | `{token, auth_level, role, username}`; `auth_level` is `password_only` when a second factor is outstanding |
| `POST /api/auth/totp` `{code}` | bearer | promotes the calling session; a wrong or replayed code is 401 |
| `POST /api/auth/logout` | bearer | revokes the calling session |
| `GET /api/auth/me` | bearer | who the token belongs to |

Refused logins, bad tokens and refused TOTP codes all count against the
existing per-IP failure limiter (`ip_fail_limit`, default 10 per five minutes),
so password guessing meets the same wall token guessing does. A wrong password
and an unknown username are the same answer, in the same time: an unknown user
still pays a full argon2 verification against a decoy hash.

### The first admin

`--admin user:pass@addr` (or `PINGAP_ADMIN_USER` + `PINGAP_ADMIN_PASSWORD`)
now carries a **bootstrap** credential. Its one job is to create the first
admin account in an empty store on the first login. Once *any* user exists it
is never consulted again — not to add an admin, not to reactivate one — so a
credential in a service definition is not a standing privilege-escalation path.
An operator whose store already has users can drop it from the command line.

### Migrating from `authorizations`

A `category = "admin"` entry that still carries `authorizations` **fails
`pingap-waf -t`** with the replacement named. Refused rather than ignored: an
operator with the key in their config believes admin auth is configured, and
silently dropping it would leave them believed-secure but open. The rejection
is scoped to the admin plugin — `basic_auth` and `combined_auth` read the same
key legitimately and are untouched, which a regression test asserts.

The admin UI's `max_age` and `authorizations` fields are replaced by `store`
and `totp_key`.

## Driver constraints every writer must respect

Turso is pinned to exactly `0.7.2`. Phase 02 measured four behaviours in that
version, and the store's shape answers to each of them rather than to taste.
They are not speculation; three of them fail *silently*, which is why each is
asserted by a test rather than trusted to review.

### One writer per process

Four tasks writing on their own connections lost **153–166 of 200 inserts** to
`SQLITE_BUSY`, and the busy handler never fired. There is no retry policy that
fixes that. `TursoStore::shared(path)` hands out the single process-global
instance, whose `Writer` owns the one write connection behind a mutex; reads
open their own connections and do not contend.

**This is the contract for later phases.** The WAF event writer, the alert
evaluator, the `VACUUM INTO` maintenance job and the node heartbeat each route
through `TursoStore::shared`, never through their own `Builder::new_local`. A
second call naming a *different* path is refused, because two stores would
silently split the audit trail. The concurrent-writer experiment is re-run
under the real schema by `tests/store.rs::concurrent_writers_all_land_because_they_share_one_writer`.

### Explicit `ROLLBACK`

A failed statement inside `BEGIN` is **skipped**: the next statement is
accepted, `COMMIT` succeeds, and a half-written record persists while the call
reports an error. `Writer::transaction` rolls back by hand on the first error,
*before* returning it, so the only writer is never left inside an open
transaction the next caller would silently join. A test counts the `"BEGIN"`
and `"ROLLBACK"` literals in the module and fails if they diverge, so a second
transaction entry point cannot be added without the same guard.

### No MVCC, no triggers, no `foreign_key_check`

- `BEGIN CONCURRENT` can silently roll a committed write back. Plain
  transactions only, asserted against both the schema and the backend's source.
- `CREATE TRIGGER ... INSTEAD OF` is unsupported, so **append-only for
  `activity_log` and `alert_history` is a property of the repository trait**:
  it exposes no update or delete for those tables and no `execute` / `raw_sql`
  / `transaction` escape hatch, and a test reads the trait's own source to keep
  it that way.
- `PRAGMA foreign_key_check` returns zero rows on a database with real orphans.
  Declared foreign keys are documentation; `PRAGMA foreign_keys = ON` is set so
  write-time enforcement — the half that works — prevents orphans being written,
  and nothing ever calls the check pragma.

Window functions lack `lag` / `lead` / custom frames; metric deltas are
computed in Rust.

## Swapping the driver

`ControlPlaneStore` (`repository.rs`) is the only surface the rest of the
binary sees, and **no signature on it mentions a Turso type** — treat one
appearing as a blocking review finding. The file format is SQLite's, so a swap
to `rusqlite` on the same file is a new `impl ControlPlaneStore` in `store.rs`
and no schema change. The plan holds this as insurance rather than a planned
migration: io_uring degrades cleanly and nothing measured so far requires it.

## Schema

Fifteen tables, applied by plain `CREATE TABLE IF NOT EXISTS` in `schema.rs`
with the version recorded in `schema_version`. Migrations are append-only;
editing a shipped one leaves existing stores on a schema no code expects.
Primary keys are UUIDv7, so append-heavy tables stay append-friendly and rows
sort by creation.

| Group | Tables |
| --- | --- |
| identity | `users`, `user_profiles`, `two_factor_auth`, `user_sessions`, `refresh_tokens` |
| audit | `activity_log` (append-only) |
| alerting | `notification_channels`, `alert_rules`, `alert_rule_channels`, `alert_history` (append-only) |
| operations | `performance_metrics`, `backup_schedules`, `backup_files`, `node_status`, `waf_events` |

Password hashes are argon2id PHC strings carrying their own parameters, so the
cost can be raised later without invalidating existing logins. Session and
refresh tokens are stored as SHA-256 hashes and compared in constant time.
TOTP secrets are encrypted with `totp_key`.

## Tests that guard the above

| Concern | Test |
| --- | --- |
| Concurrent writers lose nothing | `crates/pingap-controlplane/tests/store.rs::concurrent_writers_all_land_because_they_share_one_writer` |
| Failed statement mid-transaction rolls earlier work back | `store.rs::tests::a_statement_failing_mid_transaction_rolls_the_earlier_work_back` |
| Only one `BEGIN`, only one `ROLLBACK` | `store.rs::tests::the_only_transaction_entry_point_rolls_back_by_hand` |
| No append-only mutation path, no escape hatch | `repository.rs::tests::the_trait_exposes_no_mutation_path_for_an_append_only_table` |
| No `BEGIN CONCURRENT` / trigger / `foreign_key_check` | `schema.rs::tests::no_statement_uses_a_mechanism_turso_cannot_honour`, `store.rs::tests::this_module_names_no_mechanism_turso_cannot_honour` |
| Rows survive a reopen | `tests/store.rs::rows_survive_closing_and_reopening_the_store` |
| Unavailable store is 503, UI still loads | `src/plugin/admin.rs::tests::test_store_unavailable_is_503_and_the_ui_still_loads` |
| Revocation on the next request | `src/plugin/admin.rs::tests::test_login_then_logout_revokes_on_the_next_request` |
| Bootstrap never consulted once a user exists | `src/plugin/admin_auth.rs::tests::the_bootstrap_credential_is_never_consulted_once_a_user_exists` |
| Legacy key refused on admin, accepted on `basic_auth` / `combined_auth` | `admin.rs::tests::test_legacy_authorizations_key_is_rejected_on_the_admin_plugin`, `test_basic_auth_and_combined_auth_still_accept_authorizations` |
