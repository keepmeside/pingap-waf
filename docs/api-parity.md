# Admin API parity

Every mount path the reference product exposes, and what this gateway answers for it.

The reference is `TinyActive/nginx-love`: an Express API beside an nginx it configures by
writing text and shelling out to `nginx -t && nginx -s reload`. This API is inside the
proxy, so the shape differs even where the feature does not — there is no reload to
trigger, no config text to regenerate, and no node-to-node sync because peers share an
etcd keyspace. **A row that says "mapped differently" is not a gap; a row that says
"deferred" or "waived" is, and says which.**

Mount list taken from `apps/api/src/routes/index.ts` at the pinned reference commit: 19
`router.use` mounts plus the inline `GET /health`.

Everything below is served by the admin listener from the one process, under `/api`.

## Mapped

| Reference | Ours | Notes |
| --- | --- | --- |
| `GET /health` | `GET /api/health` | Unauthenticated in both. Ours returns `{"status":"ok"}` and nothing else — no version, build, pid or store path, which the reference's does return |
| `/domains` | `GET /api/domains`, `GET/PUT/DELETE /api/domains/:name` | The domain is intent, not a data-plane object: see [the domain model](./domain-model.md). `PUT` replaces rather than patches |
| `/system` | `GET /api/basic`, `POST /api/restart` | Retained from pingap. `/basic` is process and system introspection; `restart` needs `RestartProcess` |
| `/ssl` | `GET /api/ssl`, `GET/PUT/DELETE /api/ssl/:name` | Certificate *definitions*, written through the projection. Live issuer and expiry status is the retained `GET /api/certificates`, which answers from the running provider |
| `/users` | `GET/POST /api/users`, `PATCH /api/users/:id`, `POST /api/users/:id/2fa/reset` | `PATCH` sets activation only — the store has no method that writes `role`, so the field is absent rather than accepted and ignored. The reset has no reference counterpart; see Partial |
| `/modsec` | `GET/PUT/DELETE /api/policies[/:name]`, `GET /api/waf/categories` | Mapped differently, see below |
| `/acl` | `GET/PUT/DELETE /api/policies[/:name]` | Mapped differently, see below |
| `/access-lists` | `GET/PUT/DELETE /api/policies[/:name]` | A named access list is a key in the `acl` profile's own config table, not a separate resource |
| `/bot-manager` | `GET/PUT/DELETE /api/policies[/:name]` | Profiles and rules only. Its analytics routes are deferred with `logs` and `dashboard` |
| `/backup` | `GET /api/backup`, `POST/DELETE /api/backup/schedules[/:id]`, `POST /api/backup/export`, `POST /api/backup/restore` | Schedules, manual export, staged restore. The export reads the canonical projection and the store file, not drifted on-disk config |
| `/slave` | `GET /api/nodes` | Peer inventory over the shared config backend — last-seen, version, config hash, and a status that separates convergence lag (`stale`) from divergence (`drifted`) from a missed heartbeat (`offline`). There is no `/slave` enrolment route; see Waived |

### Why three reference mounts are one route here

`/modsec`, `/acl` and `/bot-manager` are three mounts in the reference because they are
three databases. Here they are three values of one field: a policy profile is a config
entry named `category:profile` — `waf:strict`, `acl:edge`, `bot:deny-unknown` — and every
profile is a plugin config table the projection validates and the owning plugin interprets.

One route over the whole map is deliberate rather than economical. A plugin instance is
process-global and keyed by its config-entry name, so two domains that must count
independently have to bind two *different* profiles. `/waf/profiles` would suggest the
category owns a namespace it does not, and the naming rule that prevents cross-domain
counter bleed would be invisible at the API boundary.

What the reference does per-category and this does not offer:

- **`/modsec/crs/rules` and its per-rule toggles.** Rule content is compiled into the WAF crate
  and selected by `paranoia` and per-category mode, not edited row by row, so there is no rule
  row to toggle. What the reference's rule browser shows instead — the categories and their CRS
  lineage — is `GET /api/waf/categories`, read off the engine's own table rather than restated
  beside it, and [published as a document](./waf-category-mapping.md). That route also carries
  the modes each category accepts, because a response-side category cannot block: a UI offering
  `block` for `data_leakage` is offering a write that either fails at apply or is silently
  treated as `redact`, leaving an operator believing a leak is suppressed when it is only
  rewritten.
- **`/modsec/global`, `/acl/preview`, `/acl/apply`, `/bot-manager/preview`, `/bot-manager/apply`.**
  A preview/apply split exists where applying means regenerating a config file and hoping
  the reload takes. Here every write is a projection, and the projection is validated and
  read back before the version is called `applied` — see [config projection](./config-projection.md).
  There is no second step to preview.
- **Custom rule CRUD as its own route.** A custom rule is a key in the profile's config
  table, so it is written by `PUT /api/policies/:name` with the rest of the profile. The
  engine's own cost gate refuses a rule whose shape is quadratic, at write time and with
  the reason.

## Partial

| Reference | Ours | Missing |
| --- | --- | --- |
| `/auth` — `login`, `verify-2fa`, `logout`, `refresh`, `first-login/change-password` | `POST /api/auth/login`, `POST /api/auth/totp`, `POST /api/auth/logout`, `GET /api/auth/me` | `refresh` is waived, below. A forced password change on first login is not implemented |
| `/logs` — list, `stats`, `domains`, `download` | `GET /api/logs/waf-events` | Aggregates and the export. The reference reads nginx's access-log *files*; this reads the findings the WAF wrote to the store, so there is no file to tail and no `download` of one |
| `/account` — `profile` GET/PUT, `password`, `2fa` GET/setup/enable/disable, `activity`, `sessions` GET, `sessions/:id` DELETE | `GET/PATCH /api/account`, `POST /api/account/password`, `GET/DELETE /api/account/sessions[/:id]`, `GET /api/account/2fa`, `POST /api/account/2fa/{setup,enable,disable}`, `GET /api/activity` | Four of the reference's five profile fields, waived below |

Sessions are opaque bearer tokens held in the store, hashed. There is no refresh token and
no JWT to renew, so `/auth/refresh` has nothing to act on: a session that has expired is
re-authenticated, and one that has not needs no renewal. Listed as a waiver rather than a
gap for that reason.

Session revocation is two capabilities rather than one, and the split is not decoration.
`ViewOwnSessions` is a read and `RevokeOwnSession` is a mutation, so only the revocation
waits on a completed second factor; a single capability would have to be non-mutating to
keep the listing reachable, and would then let a password-only session cut one off. Every
role holds both, and ownership is decided by the handler from the caller's own listing —
`revoke_session` takes no user id, so a handler that passed the path straight to it would
let a viewer revoke an administrator's session. Someone else's session, an unknown id and
one already revoked all answer 404, which is one status for what is, from where the caller
stands, one fact.

### Removing a second factor takes a code here, and did not there

`POST /api/account/2fa/disable` requires a code from the device that has it. The reference's
equivalent takes none — a session is enough — and that is a posture this fork does not copy: a
stolen session could silently disarm the second factor, leaving the password as the only thing
between an attacker and the account.

Requiring a code creates a lockout for someone who genuinely lost their device, so
`POST /api/users/:id/2fa/reset` exists beside it: `manage_users`, no code, clears the secret so
the account can be enrolled again. An administrator cannot produce a code from a device they do
not hold either, which is exactly why the route is theirs and not the account owner's.

Enrolment is refused while a second factor is enabled, for the same reason `disable` needs a
code — `setup` replaces the stored secret, so allowing it would be a second way to disarm the
factor without one. A wrong code and a replayed one are the same `401`, because distinguishing
them makes the endpoint an oracle for codes an attacker has collected. The replay window is
shared with the login path rather than a second one beside it: both spend a code against the
user id, so a code presented at `POST /api/auth/totp` cannot then be presented to `disable`.
Enrolment with no encryption key configured is a `409` naming the missing setting rather than a
`500`, and sealing with a default key is not the alternative: a literal default is
indistinguishable from no encryption once the row is written.

### A password change cuts off every other session

`POST /api/account/password` revokes the caller's other sessions and keeps the one making the
change. The reason is what a password change usually means: if the password is being changed
because it may have been compromised, leaving the other devices signed in defeats the change,
and the whole point of rotating a credential is to stop whoever else has it. Keeping the
caller's own session is so the request that made the change is not the one left holding a
revoked token.

The response reports how many were revoked, because a number the caller did not expect is
itself the interesting fact — it says how many other devices were signed in.

A wrong current password is a `401` and changes nothing, including the sessions.

### Findings are queried, not tailed

`GET /api/logs/waf-events` reads the `waf_events` table, filtered by domain, rule ID, category,
verdict and time, paged by a time bound rather than an offset. The reference's `/logs` reads
nginx's access-log files and derives verdicts from them by regex, because it sits outside nginx;
this gateway is inside the proxy, so the finding is structured data the moment it is decided and
there is no file to tail, no format to couple to, and no parser to break. `download` has no
counterpart for the same reason — there is no log file to hand over.

An unparseable or empty filter parameter is ignored rather than refused. These are filters, and
answering a malformed bookmark with `400` would break it the moment a parameter's shape changed;
a request body is the opposite case, where an unknown field means the caller believes they set
something they did not.

### The profile is one field, not five

`PATCH /api/account` changes the email address and nothing else. The reference's `PUT /profile`
takes `fullName`, `email`, `phone`, `timezone` and `language`; four of those are waived rather
than deferred, for two different reasons.

- **`fullName` and `phone`** have no column and no consumer. `user_profiles` holds
  `full_name`, `timezone` and `locale` and is written with three NULLs at account creation,
  and nothing reads it — the gateway does not send mail to a display name or dial a number.
  A route that wrote them would be a form that saves to nowhere, which is the same failure as
  accepting a field and ignoring it, one step earlier.
- **`timezone` and `locale`** have columns but the same problem. Per-user localisation is a
  browser decision here: the admin UI's catalogue is client-side, and every timestamp the API
  returns is Unix seconds, which need no timezone to render correctly.

`username` is not editable either, and that one is a rule rather than an absence: it is the
identity every session and every audit row names, so changing it would rewrite the meaning of
rows already written. An audit entry saying `admin did X` would stop pointing at whoever holds
the name.

The email is the one field that is both stored and used, and it is scoped to the caller by the
handler rather than by anything the request carries — there is no id in the path or the body,
which is what keeps a capability every role holds from becoming a way to rewrite another
account's contact address.

## Deferred to the phase that owns the data

These mounts are not stubs and not waivers: the API has nothing to serve until the
subsystem behind them exists.

| Reference | Owned by | What it will supply |
| --- | --- | --- |
| `/logs` (partly mapped, see Partial) | Observability | WAF verdicts and JA4H fingerprints as structured `Ctx` data rather than log-file scraping; `/api/logs/waf-events` is the query surface |
| `/performance`, `/dashboard` | Observability | Stored rollup rows, oldest-first, with bounded time/metric filters; dashboard also reports storage-backed config drift without correcting it |
| `/alerts` | Alerts | Rules (projected) and channels, plus delivery history (store-only) |
| `/slave` | Cluster via etcd Peers | Peer inventory, last-seen, version, config hash |
| `/bot-manager` analytics | Observability | Top fingerprints, hit rates |

## Waived

| Reference | Why |
| --- | --- |
| `/nlb` | L4 load balancing is a non-goal. Pingora's `ServerAddress` is `Tcp` or `Uds`, so UDP cannot be listened on without patching Pingora, and the TCP half is not in scope for v1 |
| `/system-config` — `node-mode`, `connect-master`, `disconnect-master`, `test-master-connection`, `sync` | There is no master. Peers share an etcd keyspace, so there is no mode to set, no master to connect to and no sync to trigger |
| `/node-sync` — `export`, `import`, `current-hash` | The same decision. Node-to-node API transfer with a per-node key is what etcd distribution replaces; a config hash is still observable, through `/api/config-versions` |
| `/domains/nginx/reload` | There is no nginx and no config text to reload. A write through the projection commits, reloads and is verified before it is reported |
| `/auth/refresh` | No refresh token exists to refresh — see Partial |

## Routes with no reference counterpart

| Ours | Why it exists |
| --- | --- |
| `GET/PUT/DELETE /api/listeners[/:name]` | A listening socket is shared by every domain on it and is a first-class config object in pingap. The reference has no counterpart because nginx `listen` directives live inside a server block |
| `GET /api/config-versions`, `POST /api/config-versions/:id/rollback` | The reference has no versioned config; it has files and a reload. Here every write produces a version that is only called `applied` once the data plane has been read back and found to be enforcing it, and rollback regenerates from a stored intent rather than restoring a file |
| `GET /api/activity` | One row per mutation, with actor, action, target and the config version it produced |
| `GET /api/policies[/:name]` | See "Why three reference mounts are one route here" |
| `GET /api/metrics/detection` | The detection stack's per-domain counters — challenge, behaviour, adaptive and threat-feed statistics, plus the count of challenge markers the waf/acl entries wrote — assembled by the binary from the crates that produce them. The marker-written count is the write-side half of a mis-ordering signal: a row that moves while the same label's `challenge.issued` stays at zero means markers are being written that no challenge entry ever reads. Aggregate and per-domain only, keyed by the classified domain label, never client identity; `view_metrics`-gated, and it answers 503 naming the missing provider rather than an empty object when the detection stack is not wired in |

## The retained raw-config surface

These predate the route table and are answered before it, in `src/plugin/admin.rs`:

| Route | Capability |
| --- | --- |
| `GET /api/configs/<category>[/<name>]` | `ViewRawConfig` |
| `POST /api/configs/import`, `POST/DELETE /api/configs/<category>/<name>` | `WriteRawConfig` |
| `GET /api/config-history/<category>/<name>` | `ViewRawConfig` |
| `GET /api/certificates` | `ViewRawConfig` |

**All four are admin-only, reads included.** That is not caution about the write half. The
config *is* every secret this process holds, verbatim — TLS private keys, basic-auth
credentials, JWT signing keys — so `GET /api/configs/full` is a read of all of them.
Redacting it instead would mean enumerating every key every plugin can hold, which is a
denylist that leaks the first time someone adds a plugin.

The consequence is worth stating plainly: an `operator` or `viewer` cannot use the vendored
admin UI's config pages, because that UI reads config as text. It uses the projected
resources instead, which is what the role matrix intends.

`POST` and `DELETE` on `/api/configs` write config **directly**, bypassing the projection.
That is a deliberate escape hatch and it is the reason these routes are not in the route
table's write path: a write through them produces no version row, runs no validation and
no post-commit verification, and drift detection will legitimately flag the result. It is
documented here so the flag is recognised rather than investigated.

They are audited, though, and that is not a detail. An escape hatch that produces no version is
exactly the write an audit trail most needs to show, because nothing else records it: without a
row, an administrator could change the gateway's configuration and the trail would have a gap
where the unversioned write happened. So `config.update` and `config.delete` rows carry the
actor, the `category/name` target, the client address, `config_version: null` and
`detail: "bypassed the projection"` — the last being what makes them findable, and the null
being asserted as carefully as the row's existence, since a row naming a version it did not
produce would tie the trail to an unrelated config state.

If the control-plane store is unreachable the write still succeeds and the row cannot be
written. That is logged at `error` rather than failing the request: the write has already
happened, so a 500 would misreport what the caller did.

`GET /api/certificates` answers from the running certificate provider rather than from
intent, and returns expiry, issuer, domains and ACME state only. It previously serialised
the provider's certificate struct, which carries the PEM private key.

## What a caller may do

`GET /api/account` returns a `capabilities` list alongside the role: every capability
`authorize` would grant this session right now, in the matrix's own spelling.

It exists so no client has to hold a copy of the matrix. A UI that hardcodes "viewer can read,
operator can edit domains" is a second list that drifts from the first, and the drift arrives
as a control that always answers 403 — which reads as a server bug rather than as a permission
the caller does not have. It is filtered by the authorisation decision rather than by role
alone, so a session that has not completed its second factor is told only the reads it
actually has: the list can be too short, which hides a control until the caller confirms, and
never too long.

This is advisory. The router is the enforcement point and decides every request independently;
a client that ignores `capabilities` gets a 403 with the reason, not a silent wrong answer.

## The machine-readable spec
[`openapi.yaml`](../openapi.yaml) describes both halves of the surface: the router's paths
and the retained ones. It is checked against the router rather than trusted, by
`crates/pingap-admin-api/tests/openapi.rs`:

- every registered route appears in the spec, carrying the capability the router enforces,
  so a route added without a spec entry — or with the wrong access declared — fails;
- every operation in the spec is either a registered route or one of the retained paths
  above, pinned by name, so an operation whose route was renamed or deleted fails instead
  of quietly documenting a 404;
- every operation declares `x-required-capability`, so neither direction can pass
  vacuously.

The capability strings are serde's own `snake_case` rendering of
`pingap_controlplane::Capability` — the encoding the matrix is already stored as — so a
renamed variant is a failure here rather than a permission no role holds.

Both checks run under `make test`, which is a CI gate; no separate workflow step is needed.
