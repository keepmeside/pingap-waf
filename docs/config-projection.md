# Config projection

The control plane stores **intent** — domains, upstreams, listeners, policy bindings. The
data plane reads **pingap config**. This document describes the seam between the two: how
intent becomes config, what is guaranteed about the result, and which failures the seam is
built to catch.

The short version: generation is total and deterministic, validation runs out of process
against a staged copy, and a config version is only `applied` once the running gateway has
been read back and found to be enforcing it. Nothing here trusts "the write succeeded".

Code: `crates/pingap-controlplane/src/projection/` (`generate`, `hash`, `validate`,
`apply`, `drift`) and `src/projection.rs`, which wires the four traits to the real config
manager, plugin provider and plugin factory.

## The pipeline

```
intent (Turso)
   │
   │ generate      total, deterministic, every reference resolved
   ▼
Projected { config, canonical toml }
   │
   │ validate      PluginCheck (in-process)  →  `pingap -t -c <staged tmpdir>` (subprocess)
   │                    │
   │                    └── rejected ──► ConfigVersion { status: failed, error }, nothing written
   ▼
   │ commit        ConfigManager::save_all — file, etcd or memory, unchanged
   ▼
   │ (reload window: the observer or the file poller picks the change up)
   ▼
   │ verify        every projected plugin is running, at the config that was projected
   │                    │
   │                    └── mismatch ──► status: failed, regenerate and commit version N-1
   ▼
ConfigVersion { status: applied }
```

One `apply` writes exactly one `config_versions` row and one activity row, and the row is
written **before** the sink is touched, as `pending`. A process that dies between commit
and verification therefore leaves a row that says "unconfirmed" rather than no row at all.

## Total and deterministic

`generate` emits every projected category from intent alone — never a patch. Partial
updates are how drift enters: two writers touch adjacent keys, one wins, and the on-disk
state matches neither intent. Total regeneration makes the config a pure function of
stored intent, which is also what makes the hash mean anything.

Determinism is not automatic. `PingapConfig` holds `HashMap`s, so serialising one directly
leaks iteration order into the output. `Intent` is `BTreeMap` throughout, and
`canonical_toml` assembles the document from tables built in sorted key order. The hash is
SHA-256 over that canonical form, not over the file bytes, so reformatting, key order and
comments cannot produce a false drift signal.

Empty categories are omitted rather than written as empty tables, so adding the first
entry to a category is a content change and not also a structural one.

Every config key the projection can emit is listed in `Intent::CONTRACT_KEYS` and checked
against the field-mapping tables in [the domain model](./domain-model.md) by a test. A key
the projection emits with no row in that document would let an operator set something the
contract does not describe; a domain field with no key would let them set something no
request consults.

## A dangling reference is refused, not dropped

pingap resolves a Location's plugin list by name and silently omits a name it cannot find,
and a Location whose list resolves to empty proxies straight upstream. So a policy binding
naming a profile that intent does not define would produce a Location serving unfiltered
traffic while the control plane reported it protected. `generate` refuses it, and does the
same for an unknown upstream or listener.

## Validation

Two checks, because neither alone is enough.

**`PluginCheck`, in process.** Each projected `[plugins.*]` entry is handed to the real
`PluginFactory` to see whether it constructs. This is a callback rather than a direct call
from the control-plane crate, and the indirection is load-bearing: the factory registry is
filled by `#[ctor]` registration inside each plugin crate, so a check compiled into
`pingap-controlplane` would run against an empty registry in that crate's own tests and
pass everything it exists to catch. The binary supplies the real implementation
(`FactoryPluginCheck` in `src/projection.rs`).

**`pingap -t`, as a subprocess against a staged copy.** Spike D measured `-t` against four
classes of invalid config:

| Invalid config | `pingap -t` |
| --- | --- |
| Malformed TOML | rejected, with file, line and column |
| Unknown plugin category | **exits 0** — `validate_plugins` only `warn!`s |
| Real category compiled out of this build (e.g. `geo_restriction`) | **exits 0** |
| Known category with invalid parameters | rejected, and it names the plugin |

So `-t` is a syntax and structure check plus a `[plugins.*]` constructor pass. What it
cannot answer is whether this build *has* the categories the config names, which is what
`PluginCheck` covers.

`-t` is also **not read-only**, which is the real reason for the staged copy. Before
reaching its `args.test` branch, a `-t` run calls `set_trusted_proxies`, initialises the
webhook sender, and — through `migrate_config_layout` — rewrites the directory given to
`-c`, renaming a single-file `pingap.toml` and writing per-category files in its place. An
in-process validation of a *rejected* config would leave the live gateway resolving client
IPs under that config's trusted-proxy rules with no rollback, making every XFF-derived ACL
and rate-limit decision silently wrong; validating against the live directory would edit an
operator's files as a side effect of checking them. Both are why validation stages the
candidate into a temporary directory and runs the binary in a child process.

Parser output travels back as data — recorded in `config_versions.error` and shown to the
operator, never interpolated into a shell command.

## Commit is not the same as enforced

pingap's reload path fails silently **open** at four layers:

1. `try_init_plugins` collects construction errors and then stores the provider map
   regardless, so a plugin that failed to build is simply absent (`src/plugin/mod.rs`).
2. `get_context_plugins` used to drop an unresolvable plugin name with no error and no log.
3. `handle_request_plugin` over an empty list returns "not handled, continue to upstream".
4. `diff_and_update_config` logs a reload error and sets the current config anyway
   (`src/process/auto_restart.rs`).

Concretely: publish a ruleset whose regex parses but whose WAF constructor rejects, and the
provider map is stored without `waf:strict`, the Location's plugin list resolves to empty,
every request goes upstream unfiltered — and the control plane reports version N applied
and healthy. Two mechanisms close that, and both are needed.

**Post-commit verification** (`Applier::verify`). After the reload window, every plugin the
projection named must be present in the provider *and* report the `config_key()` the
projection computed for it. A missing name is the constructor-rejected case; a mismatched
key is a reload that did not happen. Either fails the version and restores the previous
applied one by regenerating from its stored intent. `config_key()` is crc32 over the
plugin's sorted `key:value` lines; the control plane recomputes it with
`projection::plugin_config_key`, pinned byte-for-byte to `pingap_plugin::get_hash_key` by a
test in the binary, where both are linked.

**Fail closed, scoped to security-enforcing categories.** A configured-but-unbuildable
plugin whose category is in `SECURITY_ENFORCING_CATEGORIES` (`waf`, `acl`, `bot`,
`access_list`) now makes `get_context_plugins` refuse the request. The provider records
*why* each name is missing (`PluginMiss::Unknown` vs `PluginMiss::Failed { category,
reason }`), so a config typo keeps the old drop-and-continue behaviour while a control that
stopped running does not.

The response is **503, not 403**. The client was not denied by policy — the policy could
not be evaluated — and conflating the two would put config failures into WAF block metrics
and tell an operator nothing about which of the two happened.

Fail-closed bounds the exposure during the reload window; verification plus rollback ends
that window in seconds. Verification alone leaves a real gap, and fail-closed alone leaves
the gateway 503ing until a human intervenes.

`basic.on_policy_unavailable = "fail_open"` is the escape hatch for an operator who would
rather serve unprotected traffic than serve none. It is logged at startup, each served
request is logged as unprotected, and any value other than the two known ones is treated as
`fail_closed` and reported — a typo must not select the permissive branch.

## Version states

| Status | Meaning |
| --- | --- |
| `pending` | Generated, validated and committed; nobody has confirmed it is enforcing |
| `applied` | Read back from the data plane and found enforcing |
| `failed` | Rejected by validation, or committed and never confirmed |
| `superseded` | Was applied, and a later version has since been confirmed |

`applied` is set only by verification, never by a successful write. Unparsed status text
maps to `None` rather than a default, because defaulting to `applied` would make a corrupt
row look like a confirmed policy.

A version left `pending` — the process committed and then died — is settled by the
`config_verify` background task, which runs on the 60-second simple-service interval and
needs no reload window, since a stranded version is by definition older than one. Without
that sweep the row stays `pending` forever and `latest_applied_config_version` skips it, so
an operator's rollback list would be missing the version actually running.

## Drift detection

The `config_drift` task, on the same 60-second interval, recomputes the hash of the config
**as read back off storage** and compares it against the last applied version.

Storage, not `get_current_config()`: the in-memory config is what the control plane last
handed the process, so comparing against it would compare the control plane with itself. A
hand edit only exists on disk until something reloads it — and with autoreload off, it stays
there indefinitely.

Drift is **reported, never corrected.** A manual edit is either a deliberate emergency
change or evidence that somebody bypassed the control plane; silently overwriting it
destroys the information in both cases. The notification goes through the existing
`Notification` trait and names the version, truncated hashes and the *categories* that
differ — never config contents, which hold TLS key references and access-list credentials.

## Rollback

`Applier::rollback` takes a version that reached `applied` or `superseded`, regenerates
from its recorded `intent_json`, and runs the full pipeline — so the restored config is
validated and verified like any other and gets its own row. A version that failed is
refused as a target, since rolling back to it would restore the failure.

Each version stores the whole intent rather than a diff, so a rollback does not depend on
any other row still being present. The caveat that remains: a rollback target predating a
change in the intent schema may regenerate a config that validates and behaves differently.
Version the intent schema alongside `ConfigVersion` and refuse rollback across an
incompatible boundary rather than producing a plausible-but-wrong config.

Rollback is `admin`-only and writes an activity row like any other mutation.

## Tests that guard the above

| Claim | Test |
| --- | --- |
| Generating twice from unchanged intent is byte-identical | `tests/projection.rs::generating_twice_from_unchanged_intent_is_byte_identical` |
| The hash tracks content, not formatting | `hashing_is_over_canonical_content_not_file_bytes` |
| Every emitted key has a contract row, and every domain field lands on it | `the_contract_file_names_every_config_key_the_projection_emits`, `every_domain_field_lands_on_the_config_key_the_contract_names` |
| A dangling upstream, listener or policy is refused | `a_domain_naming_an_unknown_upstream_or_listener_is_refused`, `a_policy_binding_with_no_matching_policy_is_refused` |
| A category this build lacks is rejected even though `-t` exits 0 | `the_gate_refuses_a_plugin_this_build_cannot_construct` |
| Validation does not touch the caller's directory | `validating_never_touches_a_directory_the_caller_owns` |
| A rejected validation leaves client-IP resolution untouched | `src/projection.rs::test_a_rejected_validation_leaves_client_ip_resolution_untouched` |
| A WAF that fails to construct never reaches `applied`, and N-1 is restored | `tests/apply.rs::a_config_whose_waf_fails_to_construct_never_reaches_applied` |
| A stranded `pending` version is settled by the sweep | `a_version_left_pending_by_a_crash_is_failed_by_the_sweep`, `a_pending_version_the_data_plane_confirms_becomes_applied` |
| A hand edit is reported and not corrected; reformatting is not drift | `a_manual_edit_raises_a_notification_and_is_not_corrected`, `reformatting_the_config_is_not_drift` |
| The control plane's `config_key` equals `pingap_plugin::get_hash_key` | `src/projection.rs::test_control_plane_config_key_matches_pingap_plugin_get_hash_key` |
| A projected config actually enforces, and a Location whose WAF failed answers 503 with the upstream untouched | `tests/gateway_projection.rs` — real binary, real listener, real backend |
| A broken non-enforcing plugin still serves; `fail_open` serves and says so | `a_location_whose_compression_cannot_be_built_still_serves`, `with_fail_open_an_unbuildable_waf_serves_and_the_log_says_so` |
| A rule toggle applies within one hot-reload cycle without a restart | `a_waf_toggle_applies_within_one_hot_reload_cycle_without_a_restart` |
| An upstream change reaches the data plane in the same cycle, asserted on a second backend | `an_upstream_change_applies_within_one_hot_reload_cycle_without_a_restart` |
| File and etcd go through one commit path, and config history survives it | `the_commit_path_works_on_etcd_and_leaves_its_history_intact` |

The `tests/gateway_projection.rs` rows run the real `pingap` binary against a real listener
with a real backend behind it, and read the answer off the socket, because the failure they
guard against is a gateway reporting healthy while serving traffic nothing inspected. A
status field cannot answer that; only an upstream that received the request, or did not,
can. The etcd row is the exception in that file: it needs a running etcd rather than a
running gateway, and CI provides one as a service for the same reason
`pingap-config`'s own etcd test does.
