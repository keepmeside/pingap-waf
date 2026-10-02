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
    Backend, Certificate, Domain, Intent, Listener, NoPluginCheck, PluginCheck,
    PolicyBinding, Projected, TlsSettings, Upstream, Validator, Verdict,
    generate, hash,
};
use std::collections::BTreeMap;

/// The uploaded shape: a PEM pair and no issuer.
fn manual_certificate() -> Certificate {
    Certificate {
        domains: vec!["api.example.test".to_string()],
        tls_cert: Some(TEST_CERTIFICATE.to_string()),
        tls_key: Some(TEST_KEY.to_string()),
        is_default: None,
        is_ca: None,
        acme: None,
        dns_challenge: None,
        dns_provider: None,
        dns_service_url: None,
        buffer_days: None,
        remark: Some("uploaded".to_string()),
    }
}

// A throwaway pair, and the same one `pingap-config`'s own certificate tests use — not a
// secret, and not generated here so that the two crates validate against identical bytes.
// spellchecker:off
const TEST_CERTIFICATE: &str = r#"-----BEGIN CERTIFICATE-----
MIIEljCCAv6gAwIBAgIQeYUdeFj3gpzhQes3aGaMZTANBgkqhkiG9w0BAQsFADCB
pTEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMT0wOwYDVQQLDDR4aWVz
aHV6aG91QHhpZXNodXpob3VzLU1hY0Jvb2stQWlyLmxvY2FsICjosKLmoJHmtLIp
MUQwQgYDVQQDDDtta2NlcnQgeGllc2h1emhvdUB4aWVzaHV6aG91cy1NYWNCb29r
LUFpci5sb2NhbCAo6LCi5qCR5rSyKTAeFw0yMzA5MjQxMzA1MjdaFw0yNTEyMjQx
MzA1MjdaMGgxJzAlBgNVBAoTHm1rY2VydCBkZXZlbG9wbWVudCBjZXJ0aWZpY2F0
ZTE9MDsGA1UECww0eGllc2h1emhvdUB4aWVzaHV6aG91cy1NYWNCb29rLUFpci5s
b2NhbCAo6LCi5qCR5rSyKTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALuJ8lYEj9uf4iE9hguASq7re87Np+zJc2x/eqr1cR/SgXRStBsjxqI7i3xwMRqX
AuhAnM6ktlGuqidl7D9y6AN/UchqgX8AetslRJTpCcEDfL/q24zy0MqOS0FlYEgh
s4PIjWsSNoglBDeaIdUpN9cM/64IkAAtHndNt2p2vPfjrPeixLjese096SKEnZM/
xBdWF491hx06IyzjtWKqLm9OUmYZB9d/gDGnDsKpqClw8m95opKD4TBHAoE//WvI
m1mZnjNTNR27vVbmnc57d2Lx2Ib2eqJG5zMsP2hPBoqS8CKEwMRFLHAcclNkI67U
kcSEGaWgr15QGHJPN/FtjDsCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
JQQMMAoGCCsGAQUFBwMBMB8GA1UdIwQYMBaAFJo0y9bYUM/OuenDjsJ1RyHJfL3n
MDQGA1UdEQQtMCuCBm1lLmRldoIJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAA
AAAAAAABMA0GCSqGSIb3DQEBCwUAA4IBgQAlQbow3+4UyQx+E+J0RwmHBltU6i+K
soFfza6FWRfAbTyv+4KEWl2mx51IfHhJHYZvsZqPqGWxm5UvBecskegDExFMNFVm
O5QixydQzHHY2krmBwmDZ6Ao88oW/qw4xmMUhzKAZbsqeQyE/uiUdyI4pfDcduLB
rol31g9OFsgwZrZr0d1ZiezeYEhemnSlh9xRZW3veKx9axgFttzCMmWdpGTCvnav
ZVc3rB+KBMjdCwsS37zmrNm9syCjW1O5a1qphwuMpqSnDHBgKWNpbsgqyZM0oyOc
9Bkja+BV5wFO+4zH5WtestcrNMeoQ83a5lI0m42u/bUEJ/T/5BQBSFidNuvS7Ylw
IZpXa00xvlnm1BOHOfRI4Ehlfa5jmfcdnrGkQLGjiyygQtKcc7rOXGK+mSeyxwhs
sIARwslSQd4q0dbYTPKvvUHxTYiCv78vQBAsE15T2GGS80pAFDBW9vOf3upANvOf
EHjKf0Dweb4ppL4ddgeAKU5V0qn76K2fFaE=
-----END CERTIFICATE-----"#;
const TEST_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7ifJWBI/bn+Ih
PYYLgEqu63vOzafsyXNsf3qq9XEf0oF0UrQbI8aiO4t8cDEalwLoQJzOpLZRrqon
Zew/cugDf1HIaoF/AHrbJUSU6QnBA3y/6tuM8tDKjktBZWBIIbODyI1rEjaIJQQ3
miHVKTfXDP+uCJAALR53Tbdqdrz346z3osS43rHtPekihJ2TP8QXVhePdYcdOiMs
47Viqi5vTlJmGQfXf4Axpw7CqagpcPJveaKSg+EwRwKBP/1ryJtZmZ4zUzUdu71W
5p3Oe3di8diG9nqiRuczLD9oTwaKkvAihMDERSxwHHJTZCOu1JHEhBmloK9eUBhy
TzfxbYw7AgMBAAECggEALjed0FMJfO+XE+gMm9L/FMKV3W5TXwh6eJemDHG2ckg3
fQpQtouHjT2tb3par5ndro0V19tBzzmDV3hH048m3I3JAuI0ja75l/5EO4p+y+Fn
IgjoGIFSsUiGBVTNeJlNm0GWkHeJlt3Af09t3RFuYIIklKgpjNGRu4ccl5ExmslF
WHv7/1dwzeJCi8iOY2gJZz6N7qHD95VkgVyDj/EtLltONAtIGVdorgq70CYmtwSM
9XgXszqOTtSJxle+UBmeQTL4ZkUR0W+h6JSpcTn0P9c3fiNDrHSKFZbbpAhO/wHd
Ab4IK8IksVyg+tem3m5W9QiXn3WbgcvjJTi83Y3syQKBgQD5IsaSbqwEG3ruttQe
yfMeq9NUGVfmj7qkj2JiF4niqXwTpvoaSq/5gM/p7lAtSMzhCKtlekP8VLuwx8ih
n4hJAr8pGfyu/9IUghXsvP2DXsCKyypbhzY/F2m4WNIjtyLmed62Nt1PwWWUlo9Q
igHI6pieT45vJTBICsRyqC/a/wKBgQDAtLXUsCABQDTPHdy/M/dHZA/QQ/xU8NOs
ul5UMJCkSfFNk7b2etQG/iLlMSNup3bY3OPvaCGwwEy/gZ31tTSymgooXQMFxJ7G
1S/DF45yKD6xJEmAUhwz/Hzor1cM95g78UpZFCEVMnEmkBNb9pmrXRLDuWb0vLE6
B6YgiEP6xQKBgBOXuooVjg2co6RWWIQ7WZVV6f65J4KIVyNN62zPcRaUQZ/CB/U9
Xm1+xdsd1Mxa51HjPqdyYBpeB4y1iX+8bhlfz+zJkGeq0riuKk895aoJL5c6txAP
qCJ6EuReh9grNOFvQCaQVgNJsFVpKcgpsk48tNfuZcMz54Ii5qQlue29AoGAA2Sr
Nv2K8rqws1zxQCSoHAe1B5PK46wB7i6x7oWUZnAu4ZDSTfDHvv/GmYaN+yrTuunY
0aRhw3z/XPfpUiRIs0RnHWLV5MobiaDDYIoPpg7zW6cp7CqF+JxfjrFXtRC/C38q
MftawcbLm0Q6MwpallvjMrMXDwQrkrwDvtrnZ4kCgYEA0oSvmSK5ADD0nqYFdaro
K+hM90AVD1xmU7mxy3EDPwzjK1wZTj7u0fvcAtZJztIfL+lmVpkvK8KDLQ9wCWE7
SGToOzVHYX7VazxioA9nhNne9kaixvnIUg3iowAz07J7o6EU8tfYsnHxsvjlIkBU
ai02RHnemmqJaNepfmCdyec=
-----END PRIVATE KEY-----"#;
// spellchecker:on

/// One listener, two domains sharing it, two upstreams, one WAF profile bound to both
/// and an ACL profile bound to one, and the certificate the TLS listener needs. The
/// smallest intent that exercises every branch.
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

    let mut certificates = BTreeMap::new();
    certificates.insert("edge".to_string(), certificate());

    Intent {
        upstreams,
        listeners,
        domains,
        policies,
        certificates,
        trusted_proxies: Some(vec!["10.0.0.0/8".to_string()]),
    }
}

/// The issued shape: an ACME issuer and no PEM halves, because there is nothing to store
/// until it is issued. Every field set, so the mapping test below has something to read.
fn certificate() -> Certificate {
    Certificate {
        domains: vec![
            "example.test".to_string(),
            "www.example.test".to_string(),
        ],
        tls_cert: None,
        tls_key: None,
        is_default: Some(true),
        is_ca: Some(false),
        acme: Some("lets_encrypt".to_string()),
        dns_challenge: Some(true),
        dns_provider: Some("cf".to_string()),
        dns_service_url: Some("https://dns.example.test".to_string()),
        buffer_days: Some(20),
        remark: Some("issued on demand".to_string()),
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
    assert_eq!(out.config.certificates.len(), 1);
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

    // TLS termination itself is derived from the listener's `tls` block, not configured.
    assert_eq!(https.global_certificates, Some(true));

    let edge = &out.config.certificates["edge"];
    assert_eq!(
        edge.domains.as_deref(),
        Some("example.test,www.example.test")
    );
    assert_eq!(edge.acme.as_deref(), Some("lets_encrypt"));
    assert_eq!(edge.is_default, Some(true));
    assert_eq!(edge.is_ca, Some(false));
    assert_eq!(edge.dns_challenge, Some(true));
    assert_eq!(edge.dns_provider.as_deref(), Some("cf"));
    assert_eq!(
        edge.dns_service_url.as_deref(),
        Some("https://dns.example.test")
    );
    assert_eq!(edge.buffer_days, Some(20));
    assert_eq!(edge.remark.as_deref(), Some("issued on demand"));
    // The issued shape stores no key material, and must not invent any.
    assert_eq!(edge.tls_cert, None);
    assert_eq!(edge.tls_key, None);
}

#[test]
fn tls_termination_is_derived_from_the_tls_block() {
    // `global_certificates` is the only key that makes pingap treat a server as TLS —
    // `pingap-proxy` derives `is_tls` from it and from nothing else — so it cannot be
    // offered as a setting. Offering it would allow the two states that do not work: TLS
    // versions and ciphers applying to a plaintext socket, and a TLS listener that cannot
    // be turned off.
    let mut plain = intent();
    plain.listeners.get_mut("https").expect("https").tls = None;
    let plain = generate(&plain).expect("generates");
    // Absent rather than `false`: the two mean the same thing to pingap, and emitting the
    // default would read as a content change on every unrelated edit.
    assert_eq!(plain.config.servers["https"].global_certificates, None);
    assert!(
        !plain.toml.contains("global_certificates"),
        "a plaintext listener emitted the key anyway:\n{}",
        plain.toml
    );
    // The version and cipher settings went with the `tls` block, so nothing is left
    // applying to a socket that is not terminating TLS.
    assert_eq!(plain.config.servers["https"].tls_min_version, None);
}

#[test]
fn a_tls_listener_with_no_certificate_is_refused() {
    // Without this the config loads, the server has nothing to serve, and the handshake
    // falls back to a self-signed certificate — which reaches an operator as a browser
    // warning with no trail back to the write that caused it.
    let mut bad = intent();
    bad.certificates.clear();
    let err = generate(&bad).expect_err("TLS with nothing to serve");
    let reason = err.to_string();
    assert!(reason.contains("https"), "{reason}");
    assert!(reason.contains("no certificate"), "{reason}");

    // A plaintext listener needs no certificate, so clearing them is only refused because
    // of the `tls` block — asserted so the rule does not quietly become "always".
    let mut plain = intent();
    plain.certificates.clear();
    plain.listeners.get_mut("https").expect("https").tls = None;
    generate(&plain).expect("a plaintext listener needs no certificate");
}

#[test]
fn a_certificate_with_half_a_pem_pair_is_refused() {
    // `CertificateConf::validate` parses each PEM half *only if present*, so a chain with
    // no key passes it, loads nothing, and the server serves a self-signed certificate
    // instead. Refused here, where the reason can name the entry.
    for (tls_cert, tls_key, expected) in [
        (Some("chain"), None, "tls_cert with no tls_key"),
        (None, Some("key"), "tls_key with no tls_cert"),
    ] {
        let mut bad = intent();
        let cert = bad.certificates.get_mut("edge").expect("edge");
        cert.acme = None;
        cert.tls_cert = tls_cert.map(str::to_string);
        cert.tls_key = tls_key.map(str::to_string);
        let err = generate(&bad).expect_err("half a PEM pair");
        let reason = err.to_string();
        assert!(reason.contains("edge"), "{reason}");
        assert!(reason.contains(expected), "{reason}");
    }
}

#[test]
fn a_certificate_with_nothing_to_serve_and_nothing_to_obtain_one_is_refused() {
    let mut bad = intent();
    let cert = bad.certificates.get_mut("edge").expect("edge");
    cert.acme = None;
    let err = generate(&bad).expect_err("neither PEM nor issuer");
    let reason = err.to_string();
    assert!(reason.contains("edge"), "{reason}");
    assert!(
        reason.contains("no PEM pair and no ACME issuer"),
        "{reason}"
    );

    // Empty strings are the same absence, not a third shape: a UI that clears a field
    // sends "" rather than null, and treating that as present would pass the half-pair
    // check above and then load nothing.
    let mut blank = intent();
    let cert = blank.certificates.get_mut("edge").expect("edge");
    cert.acme = Some(String::new());
    cert.tls_cert = Some(String::new());
    cert.tls_key = Some(String::new());
    generate(&blank).expect_err("blank strings are absence");
}

#[test]
fn an_empty_certificate_domain_list_projects_as_absent() {
    // Comma-joined, and an empty list must not become `""`: empty means "no host
    // restriction" to the SNI matcher, and emitting it as an empty string is the same
    // value with a byte that reads as a change on every diff.
    let mut intent = intent();
    intent
        .certificates
        .get_mut("edge")
        .expect("edge")
        .domains
        .clear();
    let out = generate(&intent).expect("generates");
    assert_eq!(out.config.certificates["edge"].domains, None);
    assert!(
        !out.toml.contains("domains = \"\""),
        "an empty domain list was emitted as an empty string:\n{}",
        out.toml
    );
}

#[test]
fn a_manual_pem_pair_survives_generation_and_the_toml_round_trip() {
    // The shape the issued one cannot exercise: multi-line key material through TOML and
    // back. A PEM that loses a newline serialises fine and fails to parse, so this asserts
    // the bytes rather than the hash.
    let mut intent = intent();
    intent
        .certificates
        .insert("manual".to_string(), manual_certificate());
    let out = generate(&intent).expect("generates");

    let manual = &out.config.certificates["manual"];
    assert_eq!(manual.tls_cert.as_deref(), Some(TEST_CERTIFICATE));
    assert_eq!(manual.tls_key.as_deref(), Some(TEST_KEY));
    // The issued one is still there: both shapes coexist, and SNI picks between them.
    assert_eq!(out.config.certificates.len(), 2);

    out.config
        .validate()
        .expect("pingap-config accepts a real PEM pair");

    let reparsed = pingap_config::PingapConfig::new(out.toml.as_bytes(), true)
        .expect("the projection round-trips");
    assert_eq!(
        reparsed.certificates["manual"].tls_cert.as_deref(),
        Some(TEST_CERTIFICATE),
        "the PEM chain did not survive serialisation"
    );
    assert_eq!(
        reparsed.certificates["manual"].tls_key.as_deref(),
        Some(TEST_KEY),
        "the PEM key did not survive serialisation"
    );
    assert_eq!(
        hash(&out),
        hash(&Projected::from_config(reparsed).expect("s"))
    );
}

#[test]
fn an_intent_stored_before_certificates_existed_still_deserialises() {
    // Rollback reads the *target* version's stored intent, so a row written by an older
    // build has to parse. Without the field default, restoring such a version fails on a
    // key it could never have had — and the failure lands on the one operation an operator
    // runs when something is already wrong.
    let json = r#"{
        "upstreams": {}, "listeners": {}, "domains": {},
        "policies": {}, "trusted_proxies": null
    }"#;
    let intent: Intent =
        serde_json::from_str(json).expect("an older row parses");
    assert!(intent.certificates.is_empty());
}

#[test]
fn an_intent_missing_a_required_category_is_refused_not_defaulted() {
    // The other half of the same decision. A container-level `#[serde(default)]` would
    // make this parse as an empty intent, and the next write would then project and commit
    // a config with nothing in it — a gateway wiped by a corrupt row, reported as success.
    // A missing `certificates` is a known older shape; a missing `domains` is not.
    let json = r#"{
        "upstreams": {}, "listeners": {},
        "policies": {}, "certificates": {}, "trusted_proxies": null
    }"#;
    let err = serde_json::from_str::<Intent>(json)
        .expect_err("a row with no `domains` must not parse");
    assert!(err.to_string().contains("domains"), "{err}");
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
fn a_challenge_binding_preceding_its_marker_writer_is_refused() {
    // Plugins run in list order and a challenge entry reads the marker the
    // waf/acl entry writes, so a challenge listed first never sees one and
    // never challenges — the Location proxies unprotected while the control
    // plane reports it protected. The refusal must name both entries: the
    // challenge in `value`, the writer it precedes in the reason.
    let mut bad = intent();
    bad.policies.insert(
        "challenge:strict".to_string(),
        toml::toml! {
            category = "challenge"
            secret = "0123456789abcdef0123456789abcdef"
        },
    );
    let domain = bad.domains.get_mut("api").expect("api");
    domain.policies = vec![
        PolicyBinding::Challenge("strict".to_string()),
        PolicyBinding::Acl("internal".to_string()),
        PolicyBinding::Waf("strict".to_string()),
    ];
    let err = generate(&bad).expect_err("a challenge before its writer");
    let reason = err.to_string();
    assert!(reason.contains("challenge:strict"), "{reason}");
    assert!(reason.contains("acl:internal"), "{reason}");
    assert!(reason.contains("precedes"), "{reason}");

    // The same three entries with the writer first generate: the refusal is
    // about the order, not the combination.
    let mut good = intent();
    good.policies.insert(
        "challenge:strict".to_string(),
        toml::toml! {
            category = "challenge"
            secret = "0123456789abcdef0123456789abcdef"
        },
    );
    let domain = good.domains.get_mut("api").expect("api");
    domain.policies = vec![
        PolicyBinding::Acl("internal".to_string()),
        PolicyBinding::Waf("strict".to_string()),
        PolicyBinding::Challenge("strict".to_string()),
    ];
    generate(&good).expect("the writer-first order generates");
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
        _config: &pingap_config::PingapConfig,
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
    // Both certificate shapes. The uploaded one is the case worth the process spawn: `-t`
    // is what parses the PEM, so a pair that serialised wrongly is refused here rather
    // than at handshake.
    let mut uploaded = intent();
    uploaded
        .certificates
        .insert("manual".to_string(), manual_certificate());
    for (shape, intent) in [("issued", intent()), ("uploaded", uploaded)] {
        let out = generate(&intent).expect("generates");
        let verdict = Validator::new(&binary)
            .validate(&out, &NoPluginCheck)
            .await
            .expect("the gate runs");
        assert_eq!(verdict, Verdict::Accepted, "{shape} was refused");
    }
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
