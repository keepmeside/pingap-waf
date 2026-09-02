# Spike D — Out-of-process config validation

**Status: CONDITIONAL GO for Phase 08's two-phase apply. `pingap -t` is usable as
a subprocess gate, but it is porous on plugin validity and it mutates
process-global state — so it must never be called in-process.**

Decision gate for Phase 08. Run 2026-09-02 against the vendored binary at
`vendor/pingap-0.13.10`.

## Q1 — Does `pingap -t -c <dir>` validate a candidate directory?

**Yes.** A well-formed candidate directory the running gateway is not using
validates cleanly and exits 0.

## Q2 — Does it exit non-zero on every class of invalid config?

**No. Three of four classes tested pass with exit 0.** This is the finding.

| Invalid config class | Exit | Caught? |
|---|---|---|
| Malformed TOML | **1** | yes, with file, line, and column |
| Unknown plugin category (`totally_unknown_category_xyz`) | **0** | **no** — `WARN … skipping validation` |
| Real category compiled out of this build (`geo_restriction`, gated behind the `geo` feature, absent from `full`) | **0** | **no** — same warning |
| Known category with an invalid parameter value (`limit` with `type = "not_a_valid_limit_type"`) | **0** | **no**, and the plugin name never appears in the output at all |

The first two are `validate_plugins` downgrading `Error::NotFound` to `warn!`
(`src/main.rs:480-499`). The `geo_restriction` case is the dangerous one because
it is not a typo — it is a legitimate category that exists in the source and is
simply not in this build's feature set, so a config authored against a `geo`
build validates clean against a stock build and then silently has no geo
enforcement at runtime.

The fourth case is worse than the plan predicted. The red-team review anticipated
the unknown-category hole; it did not anticipate that a **known** category with
invalid parameters also passes. The plugin is never constructed during `-t` for a
Location-attached plugin in this configuration, so parameter-level errors are not
surfaced either.

## Q3 — Side effects, and can it run beside a live gateway?

**No file-level side effects. But it does mutate process-global state, and it
does more than validate.**

Confirmed clean: `-t` writes no pid file and no upgrade socket. Run concurrently
against a different candidate directory while a live gateway served on another
port, the live gateway kept listening and neither process interfered with the
other's paths.

Confirmed dirty, by call order in `src/main.rs`:

```
:581  config_manager.set_current_config(config.clone())
        -> pingap_core::set_trusted_proxies(&config.basic.trusted_proxies)   (manager.rs:325)
:621  config.validate()
:636  webhook::init_webhook_notification_sender(...)                          (global sender)
:645  if args.test { validate_plugins(&config)?; return Ok(()); }
```

Both global mutations happen **before** the `args.test` branch returns. As a
separate process this is harmless — the statics die with it. **In-process it would
repoint the live gateway's trusted-proxy table to a candidate's value and
reinitialise its webhook sender, with no rollback on rejection.** Since
trusted-proxy state governs client-IP resolution, an in-process validation of a
config that is then *rejected* would leave live traffic resolving client IPs
under the rejected config's rules — silently corrupting every XFF-based ACL and
rate-limit decision.

## Consequences for Phase 08

1. **Validation runs as a subprocess against a staged copy. Not negotiable, and
   not merely a preference** — the global-state mutation above is the reason.
2. **Exit 0 from `pingap -t` does not mean the config will load.** Phase 08's
   step 6b post-commit verification is therefore not redundant with pre-commit
   validation; it is the only thing that catches a plugin which validates and
   then fails to construct. Keep both.
3. **The control plane must validate plugin categories itself.** It knows which
   categories the running build supports (they are registered in the
   `PluginFactory` at startup); `-t` will not tell it. Phase 08 should compare
   every projected plugin's `category` against the live registry and reject
   unknown ones, rather than trusting the exit code.
4. Parameter-level plugin validation is also not covered. The control plane
   authors these configs from typed intent, so this is lower risk than an
   operator-authored file — but it means "the config validated" is a statement
   about syntax and structure, not about plugin behaviour.

## Deferred

Q4 from the phase file — enumerating every class of failure that passes `-t` but
is rejected on reload — is not fully answerable without exercising the reload
path, which belongs to Phase 08. What is established here is that the class is
**non-empty** and includes at least: unknown category, feature-gated category
absent from the build, and invalid plugin parameters. That is enough to justify
post-commit verification, which was the decision this spike gated.
