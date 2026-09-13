//! Cost baseline for the rule engine, captured **before** any detector exists.
//!
//! Roughly two hundred inherited patterns are still to be ported into this engine.
//! Without a number recorded first, "the WAF got slower" has nothing to be measured
//! against and the regression would only surface as latency in production. So a
//! headers-only request and one carrying a 1 KB body are benchmarked here against a
//! fixed, representative ruleset.
//!
//! The ruleset is eight operator-authored patterns chosen to span what
//! `fancy-regex` is here for: a backreference, a lookahead, plain alternation, and
//! both response-side categories. They are deliberately the same eight the fuzz
//! targets use, so a cost surprise and a crash can be traced to one shared set
//! rather than to two that drifted apart.

use criterion::{Criterion, criterion_group, criterion_main};
use pingap_waf::config::{CustomRule, RawMode, WafConfig};
use pingap_waf::{
    Category, Paranoia, RequestInput, ResponseInput, RuleEngine, Severity,
};
use std::hint::black_box;

/// Same patterns as `fuzz/fuzz_targets/shared.rs`. Kept in sync by hand rather
/// than shared through a crate, because the fuzz crate is deliberately detached
/// from this workspace.
///
/// The lookahead is bounded on purpose. `(?=.*etc)(?=.*passwd)` was the original
/// choice and this benchmark is what measured it as quadratic — 1 KB = 1.0 ms,
/// 4 KB = 16.2 ms, 16 KB = 243.6 ms — which is why the config cost check now
/// rejects that shape outright.
const PATTERNS: &[(&str, Category, Severity)] = &[
    (
        r"(?i)(union|select)\s+\w+",
        Category::SqlInjection,
        Severity::Critical,
    ),
    (r"(?i)<script[^>]*>", Category::Xss, Severity::Error),
    (r"(\w+)\s+\1", Category::Generic, Severity::Notice),
    (
        r"(?i)/etc/(passwd|shadow)(?=[/?&\s]|$)",
        Category::LocalFileInclusion,
        Severity::Warning,
    ),
    (r"\.\./", Category::LocalFileInclusion, Severity::Warning),
    (
        r"(?i)eval\s*\(",
        Category::RemoteCodeExecution,
        Severity::Critical,
    ),
    (
        r"(?i)mysql_(connect|error)\(",
        Category::DataLeakage,
        Severity::Error,
    ),
    (
        r"(?i)(passthru|shell_exec)\s*\(",
        Category::WebShell,
        Severity::Critical,
    ),
];

fn config() -> WafConfig {
    let mut cfg = WafConfig {
        categories: Category::ALL
            .iter()
            .map(|c| {
                let mode = if c.is_response_side() {
                    RawMode::Redact
                } else {
                    RawMode::Block
                };
                (c.key().to_string(), mode)
            })
            .collect(),
        ..Default::default()
    };
    for (i, (pattern, category, severity)) in PATTERNS.iter().enumerate() {
        cfg.custom_rules.insert(
            format!("bench-{i}"),
            CustomRule {
                category: *category,
                pattern: (*pattern).to_string(),
                severity: *severity,
                paranoia: Paranoia::MIN,
                action: None,
            },
        );
    }
    cfg
}

fn engine() -> RuleEngine {
    let validated = config().validate().expect("bench config is valid");
    RuleEngine::build(validated, Vec::new(), Vec::new())
        .expect("bench ruleset builds")
}

/// The same config, but carrying the full native detector set on top of the eight
/// operator patterns. This is the number that matters after the port: the engine-only
/// figures above are the floor it is measured against.
fn engine_with_detectors() -> RuleEngine {
    let validated = config().validate().expect("bench config is valid");
    RuleEngine::build(
        validated,
        pingap_waf::detectors::request_rules(),
        pingap_waf::detectors::response_rules(),
    )
    .expect("native ruleset builds")
}

/// Headers a real browser sends, none of which trips a rule. The allow path is
/// the one every legitimate request takes, so it is the one whose cost matters.
const HEADERS: &[(&str, &str)] = &[
    ("host", "example.com"),
    (
        "user-agent",
        "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0",
    ),
    (
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ),
    ("accept-language", "en-GB,en;q=0.5"),
    ("accept-encoding", "gzip, deflate, br"),
    ("connection", "keep-alive"),
    ("upgrade-insecure-requests", "1"),
];

/// The request both request-side benchmarks start from, so the only difference
/// between them is the body.
///
/// Without a shared base the pair is not an A/B: an earlier version gave the body
/// case a shorter URI and no query string, and it measured *faster* than the
/// headers-only case — field count, not body size, was driving the number.
fn base_request() -> RequestInput<'static> {
    RequestInput {
        method: "GET",
        uri: "/products?page=2&sort=price",
        headers: HEADERS,
        query: QUERY,
        body: None,
        client_ip: None,
        body_truncated: false,
    }
}

const QUERY: &[(&str, &str)] = &[("page", "2"), ("sort", "price")];

fn bench_headers_only(c: &mut Criterion) {
    let engine = engine();
    let input = base_request();
    c.bench_function("evaluate_request headers only", |b| {
        b.iter(|| {
            let e = engine.evaluate_request(black_box(&input));
            debug_assert!(!e.verdict.is_enforcing());
            e
        });
    });
}

/// 1 KB of benign JSON. Built once so the benchmark measures evaluation, not
/// string construction.
fn benign_body() -> Vec<u8> {
    let mut body = String::from("{\"items\":[");
    let mut i = 0;
    while body.len() < 1000 {
        body.push_str(&format!(
            "{{\"id\":{i},\"sku\":\"AB-{i:05}\",\"name\":\"widget {i}\"}},"
        ));
        i += 1;
    }
    body.truncate(1024);
    body.into_bytes()
}

fn bench_1kb_body(c: &mut Criterion) {
    let engine = engine();
    let body = benign_body();
    let input = RequestInput {
        method: "POST",
        body: Some(&body),
        ..base_request()
    };
    c.bench_function("evaluate_request 1KB body", |b| {
        b.iter(|| engine.evaluate_request(black_box(&input)));
    });
}

/// A request that does trip a rule. Worth its own number because the block path
/// allocates a `Hit` per match and formats a matched-field name, and the detector
/// port will multiply both by its rule count.
fn bench_blocking_request(c: &mut Criterion) {
    let engine = engine();
    let query = [("q", "' union select password from users")];
    let input = RequestInput {
        uri: "/search?q=%27+union+select+password+from+users",
        query: &query,
        ..base_request()
    };
    c.bench_function("evaluate_request blocking", |b| {
        b.iter(|| {
            let e = engine.evaluate_request(black_box(&input));
            debug_assert!(e.verdict.is_enforcing());
            e
        });
    });
}

fn bench_response_prefix(c: &mut Criterion) {
    let engine = engine();
    let body = benign_body();
    let input = ResponseInput {
        status: 200,
        headers: &[
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
        ],
        body_chunk: Some(&body),
        request_score: 0,
        body_truncated: false,
    };
    c.bench_function("evaluate_response 1KB prefix", |b| {
        b.iter(|| engine.evaluate_response(black_box(&input)));
    });
}

/// Config-load cost, off the request path but on the reload path.
///
/// A config change rebuilds the plugin instance, so this is how long a reload
/// spends compiling patterns. It is the number that says whether ~200 inherited
/// patterns make a reload perceptibly slow.
fn bench_engine_build(c: &mut Criterion) {
    let cfg = config();
    c.bench_function("validate + build 8 rules", |b| {
        b.iter(|| {
            let validated =
                black_box(cfg.clone()).validate().expect("valid config");
            RuleEngine::build(validated, Vec::new(), Vec::new())
                .expect("builds")
        });
    });
}

/// The same three request shapes with the native detectors loaded.
///
/// Reported next to the engine-only numbers rather than replacing them, because the
/// question the detector port had to answer is not "is the WAF fast" but "what did
/// the detectors cost". One number cannot answer that.
fn bench_with_detectors(c: &mut Criterion) {
    let engine = engine_with_detectors();
    let body = benign_body();
    let mut group = c.benchmark_group("detectors loaded");
    group.bench_function("headers only", |b| {
        let input = base_request();
        b.iter(|| engine.evaluate_request(black_box(&input)));
    });
    group.bench_function("1KB body", |b| {
        let input = RequestInput {
            method: "POST",
            body: Some(&body),
            ..base_request()
        };
        b.iter(|| engine.evaluate_request(black_box(&input)));
    });
    group.bench_function("blocking", |b| {
        let query = [("q", "' union select password from users")];
        let input = RequestInput {
            uri: "/search?q=%27+union+select+password+from+users",
            query: &query,
            ..base_request()
        };
        b.iter(|| engine.evaluate_request(black_box(&input)));
    });
    group.bench_function("response 1KB prefix", |b| {
        let input = ResponseInput {
            status: 200,
            headers: &[("content-type", "application/json")],
            body_chunk: Some(&body),
            request_score: 0,
            body_truncated: false,
        };
        b.iter(|| engine.evaluate_response(black_box(&input)));
    });
    group.bench_function("validate + build", |b| {
        let cfg = config();
        b.iter(|| {
            let validated =
                black_box(cfg.clone()).validate().expect("valid config");
            RuleEngine::build(
                validated,
                pingap_waf::detectors::request_rules(),
                pingap_waf::detectors::response_rules(),
            )
            .expect("builds")
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_headers_only,
    bench_1kb_body,
    bench_blocking_request,
    bench_response_prefix,
    bench_engine_build,
    bench_with_detectors,
);
criterion_main!(benches);
