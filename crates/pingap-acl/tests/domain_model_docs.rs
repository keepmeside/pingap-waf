//! `docs/domain-model.md` is a contract, so it is checked rather than trusted.
//!
//! Config projection, the admin API and the admin UI all generate or render against that
//! document's mapping table. A table entry naming a config key that no longer exists does
//! not fail loudly — projection writes a key pingap ignores, and the operator sets
//! something that does nothing. The same drift the WAF category mapping is guarded
//! against, for the same reason.
//!
//! Deliberately not a markdown parser. The test asserts that each key the document
//! promises is present both in the document and in the source that has to implement it,
//! which is the part that drifts.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/pingap-acl sits two levels below the workspace root")
        .to_path_buf()
}

fn read(relative: &str) -> String {
    let path = workspace_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} is unreadable: {e}", path.display()))
}

/// Config keys the document maps domain fields onto, and the source file that must
/// declare each one. A rename on either side breaks this.
const MAPPED_KEYS: &[(&str, &str)] = &[
    // Location-level.
    ("host", "pingap-config/src/common.rs"),
    ("path", "pingap-config/src/common.rs"),
    ("upstream", "pingap-config/src/common.rs"),
    ("weight", "pingap-config/src/common.rs"),
    ("remark", "pingap-config/src/common.rs"),
    ("plugins", "pingap-config/src/common.rs"),
    ("client_max_body_size", "pingap-config/src/common.rs"),
    ("grpc_web", "pingap-config/src/common.rs"),
    (
        "enable_reverse_proxy_headers",
        "pingap-config/src/common.rs",
    ),
    ("max_processing", "pingap-config/src/common.rs"),
    ("max_retries", "pingap-config/src/common.rs"),
    ("max_retry_window", "pingap-config/src/common.rs"),
    // Server-level.
    ("addr", "pingap-config/src/common.rs"),
    ("access_log", "pingap-config/src/common.rs"),
    ("modules", "pingap-config/src/common.rs"),
    ("enable_server_timing", "pingap-config/src/common.rs"),
    ("enabled_h2", "pingap-config/src/common.rs"),
    ("tls_min_version", "pingap-config/src/common.rs"),
    // Upstream-level.
    ("addrs", "pingap-config/src/common.rs"),
    ("algo", "pingap-config/src/common.rs"),
    ("health_check", "pingap-config/src/common.rs"),
    ("discovery", "pingap-config/src/common.rs"),
    ("verify_cert", "pingap-config/src/common.rs"),
    // Process-global.
    ("trusted_proxies", "pingap-config/src/common.rs"),
];

#[test]
fn every_mapped_config_key_exists_in_the_config_model() {
    let doc = read("docs/domain-model.md");
    let mut missing_from_doc = Vec::new();
    let mut missing_from_source = Vec::new();

    for (key, source) in MAPPED_KEYS {
        if !doc.contains(key) {
            missing_from_doc.push(*key);
        }
        if !read(source).contains(&format!("pub {key}:")) {
            missing_from_source.push(*key);
        }
    }

    assert!(
        missing_from_doc.is_empty(),
        "the document no longer maps these keys: {missing_from_doc:?}"
    );
    assert!(
        missing_from_source.is_empty(),
        "the document maps keys the config model does not declare: \
         {missing_from_source:?}"
    );
}

#[test]
fn the_document_states_the_constraints_that_cannot_be_designed_around() {
    // Three facts a UI or API author will otherwise assume their way past, each one
    // producing a control that silently does nothing.
    let doc = read("docs/domain-model.md");
    for (claim, why) in [
        (
            "process-global",
            "real-IP configuration is not per-domain, so the API must not offer it \
             per-domain",
        ),
        (
            "distinct named entries",
            "shared plugin instances are the cross-domain state leak the domain model \
             exists to prevent",
        ),
        (
            "response_headers",
            "HSTS has no config field of its own and must map onto the existing \
             plugin rather than growing a second header writer",
        ),
    ] {
        assert!(
            doc.contains(claim),
            "the document no longer says `{claim}` — {why}"
        );
    }
}

#[test]
fn the_document_does_not_promise_a_per_domain_real_ip_control() {
    // The inverse of the check above: the mapping table has to place
    // `trusted_proxies` at process scope, not at Location or Server scope, or an
    // implementer reads the row and builds a per-domain field for it.
    let doc = read("docs/domain-model.md");
    let row = doc
        .lines()
        .find(|line| line.contains("trusted_proxies") && line.contains('|'))
        .expect("the toggle table no longer has a trusted_proxies row");
    assert!(
        row.contains("global"),
        "the trusted_proxies row must state its scope: {row}"
    );
}
