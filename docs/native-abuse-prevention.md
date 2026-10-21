# Native abuse prevention and administration

Implementation follows the approved six-phase plan. No website is protected merely by creating a profile: attach a supported policy to a domain and check the applied version. Production deployment is separate.

## Policy writes and errors

Policy entries use `category:profile`; the complete PUT body must contain the matching category. Editors preserve all existing configuration fields, and reject a conflicting category rather than silently replacing it. The API also rejects missing/mismatched categories before any version is created.

A successful save means the projection reports `applied`. Validation/conflict/unavailable errors retain the HTTP status and provide readable text. Only HTTP401 clears the session; permission errors do not. After a network timeout the result is uncertain: reload policies/config versions and activity to reconcile before retrying; do not blindly repeat a write.

Container runtime uses a read-only root and writable `/tmp` tmpfs for candidate validation. Test harnesses own an isolated configuration, control-plane database, network and ports; they never read deployment secrets or alter existing containers.

Config PUT uses a finite20-second request timeout: the existing10-second reload verification window plus one ordinary10-second network/validation allowance. On timeout it reads config versions once, invalidates resource/version queries, and reports an unconfirmed outcome; it never retries PUT automatically or claims success from the timeout.

Login initialization checks the server's account capability list before fetching legacy raw configuration. Viewers initialize the normal console without that privileged read. Raw configuration cached by an earlier account is cleared when permission is absent or the account check fails; 401/503 errors still propagate normally. Server RBAC is unchanged.

On logout or acceptance of a new login token, clear authenticated query data and legacy raw-config state. A role change in the same SPA must not reuse an administrator's cached capabilities or configuration. Browser verification uses a private work copy and run-specific artifacts so its dependency installation cannot replace a concurrent frontend build's node_modules. Text failure artifacts redact ephemeral canary passwords.

Pending raw-config reads are scoped to the login token that started them: a response from a logged-out or replaced session cannot repopulate raw configuration or full-config text after clearing the cache.

A delayed401 from a replaced session is still returned as an error to its caller, but cannot clear the newer login token. Current-session401 behavior remains unchanged.

## Runtime bans and permanent history

Native protection remains process-local. `GET /api/abuse/bans` lists active
bans with their runtime epoch, fixed expiry and remaining lifetime. Optional
`profile` and `domain` filters are applied before pagination. A cursor belongs
to one runtime epoch; refresh from the first page after a restart. The list
requires `ViewEvents` and describes enforcement, not durable audit delivery.

`DELETE /api/abuse/bans/{id}` requires `EditPolicy` and a two-factor session.
Its JSON body names `profile`, `domain`, and `client_ip`. All four identity
components must match the active decision. A stale or absent ID returns
`already_absent` and never resets a newer decision or produces a second audit
transition. A successful release returns `released` with `audit: queued` or
`degraded`. Queued means admitted to the bounded writer queue, not persisted.
Release changes runtime state and does not create a configuration version.

The shared event queue transports typed lifecycle notifications. Detection,
creation, operator release and lazily observed expiry map to `native.abuse.detected`,
`native.ban.created`, `native.ban.released`, and `native.ban.expired` in the
existing append-only activity history (`ViewEvents`). Detail JSON is versioned
and contains only profile/domain/IP/scenario/epoch/transition metadata. It
contains no URL, body, cookies, tokens or credentials. Stored history is never
purged automatically. The WAF findings view (`ViewLogs`) remains telemetry with
its existing retention; creating a ban is not an HTTP403 or a blocked request.
An actual subsequent blocked request produces Block telemetry. Detection-mode
crossings produce Detect telemetry. Release and expiry produce no WAF event.

Queue saturation and failed writes expose degraded/loss counters. Enforcement
continues independently of audit storage. A failed writer retries only entries
not yet acknowledged; no unbounded secondary queue is created. Expiry records
both the fixed expiry and when it was first observed; no traffic means no
promise of a notification at the expiry instant.

The executable installs one shared event queue when an admin store is configured.
Its capacity reuses `DEFAULT_BATCH` (256), with one writer batch per second through
the existing process background-task service. This is an in-process consumer,
not another container or external scheduler. The database opens lazily after
Pingora service startup for fork safety. With no admin store, enforcement still
runs and native audit delivery reports degraded. Worker-open and flush failures
are counted; `native_event_delivery` in detection metrics exposes queue/write
health. The runtime-state counters also count lifecycle notifications that
could not enter a queue. Neither counter claims those events were persisted.

### Measured storage and operator response

The isolated 16 MiB candidate fixture on 2026-10-20 persisted 163 native
detection/creation/release/expiry rows in 3.651 seconds (44.65 rows/second observed). Its database
was 4,096 bytes and its WAL grew from 440,872 to 3,386,672 bytes: 18,072.39 bytes
of database-plus-uncheckpointed-WAL growth per lifecycle row in that short run.
This includes transaction/index overhead and is not a steady checkpointed row
size or a maximum. The earlier synthetic SQLite estimate of about 479 bytes
per row does not describe this real writer/WAL pattern. At a hypothetical one
transition/second with the same observed pattern, growth would be 1.56 GB/day,
46.84 GB/30 days or 569.93 GB/year. These are projections, not reserved capacity.
The final cumulative resource gate must also measure its configured state and
metadata. Evidence: `.cross-review/implementation/native-api.if4hyeg8/result.json`.

The fixture filled the remaining test volume with a run-owned pressure file
(13,385,728 bytes). Existing committed rows remained readable, protected
traffic still received403, an administrative write returned503, and the native
writer failure counter increased. Removing only that pressure file restored
capacity; the queued history then persisted, the original rows remained, and
protection still returned403. No activity row was removed to recover space.

Before rollout, resolve the actual database directory from the operator config.
Measure its filesystem with `df -Pk <db-directory>` and database/WAL/backup sizes
with `du -k <db-file> <wal-file> <backup-directory>`. Sample both over a
representative traffic interval, including a checkpoint and backup cycle. Compute
remaining ingest time from available bytes minus the measured backup/checkpoint
working-space requirement, divided by observed growth per second. Use that
value in the existing external disk monitor: warn before the actual storage
expansion/backup lead time plus the operator response window is exhausted.
There is no universal safe percentage or unlimited finite volume.

On warning, provision more capacity or migrate a consistent backup to a larger
volume. Rehearse export/restore on a copy using the existing backup API/runbook,
compare history counts and readable IDs, then schedule the separate production
rollout. Keep the original until the restored copy verifies. Never purge native
history to free space. If full, preserve the database/WAL, inspect delivery/write
failure counters and administrative errors, add capacity, then verify new rows
resume and previous history stays readable. No monitor, volume expansion or
production migration is installed by this plan execution.

## Website-bound rate limits

A website may bind `{ "limit": "profile" }` alongside existing policy types.
The ordered binding must refer to a real `limit:profile`; removing the binding
stops enforcement on that website without deleting the shared profile. A bound
limiter that cannot construct follows the existing fail-closed503/fail-open
posture. An unbound or legacy direct-file limiter keeps its existing behavior.
No policy is attached automatically.

The existing limiter semantics are preserved: rate `max` is divided by
`max(interval_seconds, 1)`, while inflight `max` is concurrent requests. Weight is
clamped to0..100. Zero/negative values and sub-second or zero intervals retain
the engine behavior; the editor explains their consequences rather than adding
new rejection rules. Shared profiles share their existing limiter counters;
use separate profiles when sites require separate budgets. Response steps
cannot enforce a limiter, and callers may choose429 instead of a challenge.

Limiter numeric fields use integer extraction. A fractional max retains the legacy fallback of zero; a fractional weight falls back to50 before clamping. The editor previews these actual fallbacks and warns about a zero ceiling, without rejecting legacy zero, negative, or subsecond inputs.
