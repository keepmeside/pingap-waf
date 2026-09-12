//! Per-call latency percentiles for the ported detector set.
//!
//! Separate from `bench.rs`, which is a criterion A/B against the pre-detector cost
//! floor. Criterion reports the mean of a *batch* of iterations, and averaging is
//! exactly what hides a tail: a p99 computed from batch means is not a p99 of calls.
//! Phase 04 owes an absolute p50/p99, so this times each call individually, sorts, and
//! reads the quantiles off the sorted samples.
//!
//! **What this measures.** The engine, carrying the full native detector set, on the
//! three shapes the phase asks about: a headers-only request, a request with a 1 KB
//! body, and a cacheable response scanned once and then twice — the double scan being
//! the real cost of registering both response hooks, which is what keeps a body cached
//! before a rule existed from being served unredacted.
//!
//! **What it excludes.** Extracting header pairs from a pingora `Session` and the
//! `Bytes` copy the request-body buffer makes. Both are borrows and one memcpy against
//! pattern matching over the same bytes, so they do not move these numbers, but they
//! are not counted here and this file should not be read as if they were.
//!
//! The shipped default budget (10 ms) is left in place rather than raised. If a
//! measurement is cut short by it, that cut *is* the latency an operator sees, so the
//! count is reported next to the percentiles instead of being tuned away.
//!
//! Run with `cargo bench -p pingap-waf --bench latency`.

use pingap_waf::config::{RawMode, WafConfig};
use pingap_waf::{Category, RequestInput, ResponseInput, RuleEngine};
use std::time::Instant;

/// Enough samples that the 99th percentile is read off ~20 observations rather than
/// one, and still a few seconds of wall clock.
const ITERATIONS: usize = 2000;
/// Discarded before measuring, so the first-call cost of warming caches and branch
/// predictors does not land in the p99.
const WARMUP: usize = 200;

/// Every category enforcing, so no rule is gated out and the measurement is of the
/// whole set. `detect` costs the same as `block` — the gate is applied to a hit, not
/// to whether the pattern runs — so this is also the cost of the shipped default.
fn engine() -> RuleEngine {
    let cfg = WafConfig {
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
    RuleEngine::build(
        cfg.validate().expect("bench config is valid"),
        pingap_waf::detectors::request_rules(),
        pingap_waf::detectors::response_rules(),
    )
    .expect("native ruleset builds")
}

/// Headers a real browser sends, none of which trips a rule. The allow path is the one
/// every legitimate request takes, so it is the one whose latency matters.
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

const QUERY: &[(&str, &str)] = &[("page", "2"), ("sort", "price")];

/// 1 KB of ordinary form-encoded content. Benign, because the allow path is the one
/// that has to be fast; a blocked request stops at the first threshold crossing.
fn benign_body() -> Vec<u8> {
    let mut body = String::with_capacity(1100);
    let mut i = 0;
    while body.len() < 1024 {
        body.push_str(&format!("field{i}=value-{i}-ordinary-content&"));
        i += 1;
    }
    body.truncate(1024);
    body.into_bytes()
}

/// Sort the samples and report the quantiles the phase asked for.
///
/// Also the maximum, because with a backtracking engine the worst single call is the
/// number that decides whether a worker stalls, and it is invisible in a p99.
fn report(label: &str, mut samples: Vec<u128>, budget_cuts: usize) {
    samples.sort_unstable();
    let at = |q: f64| {
        let idx = ((samples.len() - 1) as f64 * q).round() as usize;
        samples[idx] as f64 / 1000.0
    };
    println!(
        "{label:<38} p50 {:>8.2} µs  p99 {:>8.2} µs  max {:>9.2} µs  \
         budget-cut {budget_cuts}/{}",
        at(0.50),
        at(0.99),
        samples[samples.len() - 1] as f64 / 1000.0,
        samples.len()
    );
}

/// Time `f` once per iteration, after a discarded warmup, counting budget exhaustions.
fn measure(label: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..WARMUP {
        f();
    }
    let mut samples = Vec::with_capacity(ITERATIONS);
    let mut cuts = 0;
    for _ in 0..ITERATIONS {
        let started = Instant::now();
        let exhausted = f();
        samples.push(started.elapsed().as_nanos());
        if exhausted {
            cuts += 1;
        }
    }
    report(label, samples, cuts);
}

fn main() {
    let engine = engine();
    let body = benign_body();

    let base = RequestInput {
        method: "GET",
        uri: "/products?page=2&sort=price",
        headers: HEADERS,
        query: QUERY,
        body: None,
        client_ip: None,
        body_truncated: false,
    };
    // Same base for both request cases, so the only difference between them is the
    // body. Without that, field count rather than body size drives the difference.
    let with_body = RequestInput {
        body: Some(&body),
        ..base
    };
    let response = ResponseInput {
        status: 200,
        headers: &[
            ("content-type", "application/json"),
            ("cache-control", "max-age=60"),
        ],
        body_chunk: Some(&body),
        request_score: 0,
        body_truncated: false,
    };

    println!(
        "pingap-waf added latency — {} native request rules, {} response rules, \
         {} samples each\n",
        engine.request_rule_count(),
        engine.response_rule_count(),
        ITERATIONS
    );

    measure("request: headers + URI + query only", || {
        engine.evaluate_request(&base).exhausted.is_some()
    });
    measure("request: same, plus a 1 KB body", || {
        engine.evaluate_request(&with_body).exhausted.is_some()
    });
    measure("response: 1 KB body, one hook", || {
        engine.evaluate_response(&response).exhausted.is_some()
    });
    // What registering both hooks actually costs on a cache miss: the upstream hook
    // sanitises what enters the cache, the serving hook covers what leaves it, and on
    // a miss both run over the same bytes.
    measure("response: 1 KB body, both hooks (miss)", || {
        let a = engine.evaluate_response(&response).exhausted.is_some();
        let b = engine.evaluate_response(&response).exhausted.is_some();
        a || b
    });
}
