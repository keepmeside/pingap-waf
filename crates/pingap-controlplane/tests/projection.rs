//! Config projection: intent in, pingap config out.
//!
//! Three properties are load-bearing and each is asserted here rather than trusted:
//!
//! - **Total.** Generation emits every projected category from intent alone. There is no
//!   "patch this one key" path, because partial updates are how drift enters.
//! - **Deterministic.** The same intent produces byte-identical output, or the content
//!   hash that drift detection compares is noise. Asserted by generating twice.
//! - **Contract-complete.** Every field in `docs/domain-model.md` lands on the config key
//!   that document names. A domain field with no mapping is a design error, and the test
//!   for it reads the contract file rather than a second hand-maintained list.

use pingap_controlplane::projection::{
    Backend, Domain, Intent, Listener, NoPluginCheck, PluginCheck,
    PolicyBinding, Projected, TlsSettings, Upstream, Validator, Verdict,
    generate, hash,
};
use std::collections::BTreeMap;

/// One listener, two domains sharing it, two upstreams, one WAF profile bound to both
/// and an ACL profile bound to one. The smallest intent that exercises every branch.
fn intent() -> Intent {
    let mut upstreams = BTreeMap::new();
    upstreams.insert(
        "api".to_string(),
        Upstream {
            backends: vec![
                Backend {
                    addr: "10.0.0.1:8080".to_string(),
                    weight: Some(2),
                },
                Backend {
                    addr: "10.0.0.2:8080".to_string(),
                    weight: None,
                },
            ],
            lb_algorithm: Some("round_robin".to_string()),
            health_check: Some("http://api/health".to_string()),
            discovery: None,
            tls_sni: None,
            verify_cert: None,
        },
    );
    upstreams.insert(
        "web".to_string(),
        Upstream {
            backends: vec![Backend {
                addr: "10.0.0.3:80".to_string(),
                weight: None,
            }],
            lb_algorithm: None,
            health_check: None,
            discovery: Some("static".to_string()),
            tls_sni: None,
            verify_cert: None,
        },
    );

    let mut listeners = BTreeMap::new();
    listeners.insert(
        "https".to_string(),
        Listener {
            addr: "0.0.0.0:443".to_string(),
            http2: Some(true),
            tls: Some(TlsSettings {
                min_version: Some("tlsv1.2".to_string()),
                max_version: None,
                cipher_list: None,
                ciphersuites: None,
            }),
            access_log: Some("combined".to_string()),
            server_timing: None,
        },
    );

    let mut domains = BTreeMap::new();
    domains.insert(
        "api".to_string(),
        Domain {
            hostnames: vec!["api.example.test".to_string()],
            path: Some("/".to_string()),
            listener: "https".to_string(),
            upstream: "api".to_string(),
            priority: Some(10),
            notes: Some("public API".to_string()),
            client_max_body_size: Some("8mb".to_string()),
            grpc_web: false,
            reverse_proxy_headers: Some(true),
            max_processing: None,
            max_retries: Some(2),
            policies: vec![
                PolicyBinding::Acl("internal".to_string()),
                PolicyBinding::Waf("strict".to_string()),
            ],
        },
    );
    domains.insert(
        "web".to_string(),
        Domain {
            hostnames: vec![
                "example.test".to_string(),
                "www.example.test".to_string(),
            ],
            path: None,
            listener: "https".to_string(),
            upstream: "web".to_string(),
            priority: None,
            notes: None,
            client_max_body_size: None,
            grpc_web: true,
            reverse_proxy_headers: None,
            max_processing: Some(500),
            max_retries: None,
            policies: vec![PolicyBinding::Waf("strict".to_string())],
        },
    );

    let mut policies = BTreeMap::new();
    policies.insert(
        "waf:strict".to_string(),
        toml::toml! {
            category = "waf"
            profile = "strict"
            paranoia = 2
            anomaly_threshold = 5
        },
    );
    policies.insert(
        "acl:internal".to_string(),
        toml::toml! {
            category = "acl"
            default_action = "deny"
            [[rules]]
            field = "ip"
            operator = "in_cidr"
            values = ["10.0.0.0/8"]
            action = "allow"
        },
    );

    Intent {
        upstreams,
        listeners,
        domains,
        policies,
        trusted_proxies: Some(vec!["10.0.0.0/8".to_string()]),
    }
}

#[test]
fn generation_is_total_and_covers_every_projected_category() {
    let out = generate(&intent()).expect("a valid intent generates");
    // One of each category the contract names, and nothing missing.
    assert_eq!(out.config.upstreams.len(), 2);
    assert_eq!(out.config.locations.len(), 2);
    assert_eq!(out.config.servers.len(), 1);
    assert_eq!(out.config.plugins.len(), 2);
    assert_eq!(
        out.config.basic.trusted_proxies,
        Some(vec!["10.0.0.0/8".to_string()])
    );
}

#[test]
fn generating_twice_from_unchanged_intent_is_byte_identical() {
    // The named success criterion. `PingapConfig` holds `HashMap`s, so this is the test
    // that would catch iteration order leaking into the output.
    let a = generate(&intent()).expect("generates");
    let b = generate(&intent()).expect("generates");
    assert_eq!(a.toml, b.toml, "two generations of one intent differ");
    assert_eq!(hash(&a), hash(&b));
    assert!(!a.toml.is_empty());
}

#[test]
fn the_hash_moves_when_and_only_when_intent_moves() {
    let base = generate(&intent()).expect("generates");
    let mut changed = intent();
    changed.domains.get_mut("api").expect("api domain").priority = Some(11);
    let after = generate(&changed).expect("generates");
    assert_ne!(
        hash(&base),
        hash(&after),
        "a changed priority did not move the hash"
    );

    // And a change with no config counterpart — none exists by construction, which is
    // the point of the contract: there is no field to change that would not move it.
    let same = generate(&intent()).expect("generates");
    assert_eq!(hash(&base), hash(&same));
}

#[test]
fn every_domain_field_lands_on_the_config_key_the_contract_names() {
    let out = generate(&intent()).expect("generates");
    let api = &out.config.locations["api"];
    assert_eq!(api.host.as_deref(), Some("api.example.test"));
    assert_eq!(api.path.as_deref(), Some("/"));
    assert_eq!(api.upstream.as_deref(), Some("api"));
    assert_eq!(api.weight, Some(10));
    assert_eq!(api.remark.as_deref(), Some("public API"));
    // `8mb` is 8 000 000 bytes, not 8 MiB — `ByteSize` reads `mb` as decimal and `mib` as
    // binary. Asserted with the literal so the projection is pinned to pingap's own
    // parser rather than to an assumption about which one it is.
    assert_eq!(
        api.client_max_body_size.map(|b| b.as_u64()),
        Some(8_000_000)
    );
    assert_eq!(api.enable_reverse_proxy_headers, Some(true));
    assert_eq!(api.max_retries, Some(2));
    // Policy is the plugin list, in the order the domain bound it: cheapest gate first
    // is the operator's call, and the projection must not reorder it.
    assert_eq!(
        api.plugins.as_deref(),
        Some(&["acl:internal".to_string(), "waf:strict".to_string()][..])
    );

    let web = &out.config.locations["web"];
    assert_eq!(web.host.as_deref(), Some("example.test,www.example.test"));
    assert_eq!(web.max_processing, Some(500));
    assert_eq!(web.grpc_web, Some(true));

    let https = &out.config.servers["https"];
    assert_eq!(https.addr, "0.0.0.0:443");
    assert_eq!(https.enabled_h2, Some(true));
    assert_eq!(https.tls_min_version.as_deref(), Some("tlsv1.2"));
    assert_eq!(https.access_log.as_deref(), Some("combined"));
    // Both domains on the listener, in name order.
    assert_eq!(
        https.locations.as_deref(),
        Some(&["api".to_string(), "web".to_string()][..])
    );
    // gRPC-web needs two keys at two levels; setting only one is a silent no-op, so
    // the server module is derived from any domain on it opting in.
    assert_eq!(
        https.modules.as_deref(),
        Some(&["grpc-web".to_string()][..])
    );

    let api_up = &out.config.upstreams["api"];
    assert_eq!(api_up.addrs, vec!["10.0.0.1:8080 2", "10.0.0.2:8080"]);
    assert_eq!(api_up.algo.as_deref(), Some("round_robin"));
    assert_eq!(api_up.health_check.as_deref(), Some("http://api/health"));
    let web_up = &out.config.upstreams["web"];
    assert_eq!(web_up.discovery.as_deref(), Some("static"));
}

#[test]
fn the_contract_file_names_every_config_key_the_projection_emits() {
    // `docs/domain-model.md` is the contract, and this is what keeps it one. The
    // direction matters: a key emitted here with no row in the document means an operator
    // can set something nobody documented, and no amount of reading the document would
    // reveal it.
    let contract = include_str!("../../../docs/domain-model.md");
    for key in Intent::CONTRACT_KEYS {
        assert!(
            contract.contains(&format!("`{key}`")),
            "config key `{key}` is emitted by the projection but has no row in \
             docs/domain-model.md"
        );
    }
}

#[test]
fn a_domain_naming_an_unknown_upstream_or_listener_is_refused() {
    // Generation is total, so a dangling reference cannot be "filled in later" — it
    // would reach `pingap-waf -t` as a config that names an upstream that does not exist.
    let mut bad = intent();
    bad.domains.get_mut("api").expect("api").upstream = "nope".to_string();
    let err =
        generate(&bad).expect_err("a dangling upstream must not generate");
    assert!(err.to_string().contains("nope"), "{err}");

    let mut bad = intent();
    bad.domains.get_mut("api").expect("api").listener = "nope".to_string();
    let err =
        generate(&bad).expect_err("a dangling listener must not generate");
    assert!(err.to_string().contains("nope"), "{err}");
}

#[test]
fn a_policy_binding_with_no_matching_policy_is_refused() {
    // The plugin list would name an entry that does not exist, and pingap drops a
    // missing plugin name with no error and no log — the request would go upstream
    // unfiltered. Refuse at generation, where it is a message and not an exposure.
    let mut bad = intent();
    bad.domains
        .get_mut("api")
        .expect("api")
        .policies
        .push(PolicyBinding::Bot("nope".to_string()));
    let err = generate(&bad).expect_err("a dangling policy must not generate");
    assert!(err.to_string().contains("bot:nope"), "{err}");
}

#[test]
fn the_generated_config_passes_pingap_own_validation() {
    // Not the full gate — that is a subprocess `pingap-waf -t` — but the in-crate check
    // pingap-config offers, so a structurally impossible config fails here before it
    // costs a process spawn.
    let out = generate(&intent()).expect("generates");
    out.config
        .validate()
        .expect("pingap-config accepts the projection");
}

#[test]
fn hashing_is_over_canonical_content_not_file_bytes() {
    // Incidental formatting must not produce a false drift signal. Re-parsing the
    // generated TOML and re-serialising it is a different byte string with the same
    // meaning, and must hash the same.
    let out = generate(&intent()).expect("generates");
    let reparsed = pingap_config::PingapConfig::new(out.toml.as_bytes(), true)
        .expect("the projection round-trips");
    let round_tripped = Projected::from_config(reparsed).expect("serialises");
    assert_eq!(hash(&out), hash(&round_tripped));
}

/// A plugin registry stand-in: everything named here is buildable, everything else is
/// not. Stands for the real `PluginFactory`, which this crate cannot consult — its
/// registry is filled by `#[ctor]` in each plugin crate and would be empty here.
struct KnownPlugins(&'static [&'static str]);

impl PluginCheck for KnownPlugins {
    fn check(
        &self,
        name: &str,
        conf: &pingap_config::PluginConf,
    ) -> Result<(), String> {
        let category = conf
            .get("category")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("`{name}` declares no category"))?;
        if self.0.contains(&category) {
            Ok(())
        } else {
            Err(format!("category `{category}` is not in this build"))
        }
    }
}

#[tokio::test]
async fn the_gate_refuses_a_plugin_this_build_cannot_construct() {
    // Spike D's third and fourth rows: `pingap-waf -t` exits 0 on a category compiled out of
    // the build and on a known category with invalid parameters. The control plane's own
    // check is the only thing standing between those and a committed config, so it runs
    // first and the subprocess never has to be spawned.
    let out = generate(&intent()).expect("generates");
    let validator = Validator::new(
        "/nonexistent-binary-so-the-subprocess-cannot-mask-this",
    );
    // `acl` is present, `waf` is not — as if the build lacked it.
    let verdict = validator
        .validate(&out, &KnownPlugins(&["acl"]))
        .await
        .expect("the gate runs");
    match verdict {
        Verdict::Rejected { reason } => {
            assert!(reason.contains("waf:strict"), "{reason}");
            assert!(reason.contains("not in this build"), "{reason}");
            assert!(
                reason.contains("pingap-waf -t` does not catch this"),
                "the reason should say why the subprocess would have passed: {reason}"
            );
        },
        Verdict::Accepted => {
            panic!("a plugin absent from the build was accepted")
        },
    }
}

#[tokio::test]
async fn a_valid_projection_passes_the_real_pingap_t_subprocess() {
    // The gate end to end, against the actual binary this test builds alongside. A
    // subprocess and not an in-process call: `-t` mutates the trusted-proxy statics
    // before it reaches its own `args.test` branch, so validating in-process would
    // repoint the live gateway at a candidate config.
    let Some(binary) = pingap_binary() else {
        eprintln!("skipping: no pingap binary built in target/debug");
        return;
    };
    let out = generate(&intent()).expect("generates");
    let verdict = Validator::new(&binary)
        .validate(&out, &NoPluginCheck)
        .await
        .expect("the gate runs");
    assert_eq!(verdict, Verdict::Accepted, "the projection was refused");
}

#[tokio::test]
async fn a_structurally_invalid_config_is_refused_with_the_parser_reason() {
    let Some(binary) = pingap_binary() else {
        eprintln!("skipping: no pingap binary built in target/debug");
        return;
    };
    // Two servers on one address. `PingapConfig::validate` rejects it, so this is the
    // class `-t` *does* catch, and the reason must survive to the caller.
    let mut bad = intent();
    bad.listeners.insert(
        "clash".to_string(),
        Listener {
            addr: "0.0.0.0:443".to_string(),
            http2: None,
            tls: None,
            access_log: None,
            server_timing: None,
        },
    );
    let out = generate(&bad).expect("generation does not judge validity");
    let verdict = Validator::new(&binary)
        .validate(&out, &NoPluginCheck)
        .await
        .expect("the gate runs");
    match verdict {
        Verdict::Rejected { reason } => assert!(
            reason.contains("0.0.0.0:443"),
            "the parser's reason was lost: {reason}"
        ),
        Verdict::Accepted => {
            panic!("two servers on one address were accepted")
        },
    }
}

/// The pingap binary this workspace builds, if it is there.
///
/// Located rather than assumed: `cargo test -p pingap-controlplane` does not build the
/// binary, so these two tests skip instead of failing when it is absent. `make test`
/// builds the workspace, so CI runs them.
fn pingap_binary() -> Option<std::path::PathBuf> {
    let mut dir = std::env::current_exe().ok()?;
    // .../target/debug/deps/projection-<hash> -> .../target/debug
    dir.pop();
    dir.pop();
    let candidate = dir.join("pingap-waf");
    candidate.is_file().then_some(candidate)
}

#[tokio::test]
async fn validating_never_touches_a_directory_the_caller_owns() {
    // `pingap-waf -t -c <dir>` is **not** read-only: it folds the directory into the current
    // config layout before it reaches its own `--test` branch, renaming `pingap.toml` to
    // `pingap.toml.bak` and writing one file per category. Measured, not assumed — see the
    // assertions below.
    //
    // So the staged copy is not merely hygiene about process-global state, which is what
    // the config-validation spike established. Validating against the live directory
    // would rewrite an operator's config file as a side effect of checking it. This test
    // exists so nobody later "optimises away" the staging.
    let Some(binary) = pingap_binary() else {
        eprintln!("skipping: no pingap binary built in target/debug");
        return;
    };
    let live = tempfile::tempdir().expect("tempdir");
    let config = live.path().join("pingap.toml");
    let original =
        "# an operator's file\n[upstreams.u]\naddrs = [\"127.0.0.1:1\"]\n";
    std::fs::write(&config, original).expect("write");

    let out = generate(&intent()).expect("generates");
    Validator::new(&binary)
        .validate(&out, &NoPluginCheck)
        .await
        .expect("the gate runs");

    assert_eq!(
        std::fs::read_to_string(&config).expect("the file is still there"),
        original,
        "validation rewrote a config file it was never given"
    );
    let mut entries: Vec<_> = std::fs::read_dir(live.path())
        .expect("readdir")
        .filter_map(|e| {
            e.ok().map(|e| e.file_name().to_string_lossy().to_string())
        })
        .collect();
    entries.sort();
    assert_eq!(
        entries,
        vec!["pingap.toml"],
        "validation left files behind in a directory it was never given"
    );

    // And the same run *against its own staging directory* does rewrite it — which is the
    // behaviour the staging exists to absorb. Asserted so the reason above stays a fact.
    let staged = tempfile::tempdir().expect("tempdir");
    std::fs::write(staged.path().join("pingap.toml"), &out.toml)
        .expect("write");
    let status = tokio::process::Command::new(&binary)
        .arg("-t")
        .arg("-c")
        .arg(staged.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .expect("runs");
    assert!(status.success(), "the projection should validate");
    assert!(
        staged.path().join("pingap.toml.bak").is_file(),
        "`pingap-waf -t` no longer rewrites its config directory; if that is now true, this \
         test and the comment above should be simplified rather than deleted"
    );
}
