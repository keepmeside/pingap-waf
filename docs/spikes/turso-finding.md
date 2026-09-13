# Spike B — Turso 0.7.2 under the control-plane schema

**Verdict: GO on `turso 0.7.2`. No driver swap needed.** io_uring blocking
degrades cleanly, `VACUUM INTO` works, plain transactions commit durably.

But three findings change the control-plane store, observability and backup/restore —
and one of them contradicts an assumption the schema was built on, which is worse than
merely differing from it.

Run 2026-09-02. Harness `spikes/turso-probe/`. Executed three ways: host, Docker
with the default seccomp profile, and Docker with a profile that returns `EPERM`
for `io_uring_setup`/`io_uring_enter`/`io_uring_register`.

## Q2 — io_uring under container seccomp: degrades cleanly

| Environment | Open | All DDL | `VACUUM INTO` | Serial writes |
|---|---|---|---|---|
| Host | ok, 1.95 ms | ok | ok | 330 rows/s |
| Docker, default seccomp | ok, 4.86 ms | ok | ok | 324 rows/s |
| Docker, **io_uring blocked** | ok, 1.70 ms | ok | ok | 289 rows/s |

Unambiguous, as the criterion demanded: **degrades cleanly**. Blocking all three
io_uring syscalls costs ~12% throughput and nothing else. The `rusqlite` fallback
is not needed on this ground, and the repository trait's justification shifts from
"we will probably need it" to genuine insurance.

## `PRAGMA foreign_key_check` is a silent no-op — worse than absent

The schema was designed assuming this pragma was **absent**, so backup and restore would validate in
application code. It is not absent. It parses, executes, returns zero rows, and
reports nothing — on a database that demonstrably contains orphans.

Isolated with an unambiguous case (two child rows referencing parent IDs that do
not exist):

```
orphan child rows present: 2
PRAGMA foreign_key_check reported: 0 violation(s)
```

Control, real `sqlite3` CLI against **the same file**:

```
child|1|parent|0
child|2|parent|0
```

Two violations, found by sqlite, missed by Turso. An absent pragma would raise an
error and force the app-level check; a silent no-op returns success and invites an
implementer to believe validation ran. **Backup and restore must never call
`PRAGMA foreign_key_check` — not even as a belt-and-braces second check** — because
its zero-row result is indistinguishable from a clean database.

The store's constraint list should be corrected from "`PRAGMA foreign_key_check` /
`defer_foreign_keys` absent" to "present but non-functional, returning no rows on
a database with known violations".

## Write contention: serialisation is mandatory, and BUSY is the common case

Four concurrent writers on separate connections, 50 inserts each (200 total):

| Environment | Succeeded | `SQLITE_BUSY` | Other errors |
|---|---|---|---|
| Host | 47 | 153 | 0 |
| Docker, default | 43 | 157 | 0 |
| Docker, io_uring blocked | 34 | 166 | 0 |

**~77–83% of concurrent writes fail with BUSY, and no busy handler retries them.**
This is not a tail case to handle defensively — under any concurrency it is the
dominant outcome. The store's single process-global writer handle is confirmed
mandatory, and a per-connection lock would serialise nothing, exactly as the
red-team review argued.

## Throughput: batching is a 200× difference, not an optimisation

| Path | Rows | Time | Rate |
|---|---|---|---|
| Serial, one statement per commit | 2000 | 6.07 s | **330 rows/s** |
| Batched in one transaction | 2000 | 28 ms | **71,330 rows/s** |

330 rows/s cannot absorb per-request WAF events on any real traffic level — a
single moderately busy site would exceed it. Observability's bounded queue plus batch
writer is therefore load-bearing, and its transaction batching is the thing that
makes the store viable at all. Verdict-aware sampling stays necessary
as a backstop, but the batch path is what buys the headroom.

## Transaction behaviour after a failed statement

Not the documented rollback-only hazard, but a different shape with the same
consequence:

```
tx.conflict_stmt       errored as expected: UNIQUE constraint failed: users.id (19)
tx.stmt_after_error    accepted
tx.commit_after_error  committed
tx.partial_visible     rb.* rows persisted = 2
```

The transaction did **not** become rollback-only. A statement issued after the
error was accepted, `COMMIT` succeeded, and both surrounding writes persisted. So
an error mid-transaction neither aborts the transaction nor poisons it — it is
simply skipped, and the partial work commits.

For an append-only audit log this is the wrong default: a multi-statement mutation
where one statement fails would commit an incomplete record while reporting
success. **The store's repository layer must explicitly `ROLLBACK` on any statement
error inside a transaction rather than relying on the driver to invalidate it.**

## Confirmed as expected

- **Plain transactions commit durably.** `BEGIN` / two inserts / `COMMIT` yields
  exactly 2 rows in all three environments. No silent rollback observed without
  `BEGIN CONCURRENT`, which is already ruled out.
- **`VACUUM INTO` works**, producing a 106,496-byte snapshot in every environment.
  The backup path is sound.
- **`lag()` is unsupported**: `Parse error: no such function: lag`. Confirms
  Rust-side aggregation, and the CI `grep` assertion against window
  functions.
- **`turso 0.7.2` resolves as a real published version.** Worth recording because
  `cargo search turso` currently surfaces only `0.8.0-pre.7`, the pre-release line
  this workspace rejects; an inexact version requirement would drift onto it.
  The spike pins `=0.7.2`.

## Consequences

| Phase | Change |
|---|---|
| 07 | Correct the FK-check constraint: present but non-functional, not absent. Require explicit `ROLLBACK` on any in-transaction statement error. Single process-global writer confirmed mandatory (77–83% BUSY under 4 writers). |
| 11 | Batch writer is load-bearing: 330 rows/s serial vs 71k batched. Keep verdict-aware sampling as a backstop. |
| 13 | Never call `PRAGMA foreign_key_check`; app-level validation is the only option, and the pragma's silent success is a trap. `VACUUM INTO` confirmed. |
| — | No `rusqlite` swap. The repository trait stays as insurance rather than a planned migration. |
