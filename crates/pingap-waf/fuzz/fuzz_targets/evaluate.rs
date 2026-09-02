#![no_main]
//! Fuzz `RuleEngine::evaluate_request`.
//!
//! The request surface is the one an attacker reaches directly, and it is the one
//! that can deny traffic — so both failure directions matter here: a panic is an
//! outage for every tenant on the process, and an unjustified block is a
//! self-inflicted denial of service.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pingap_waf::RequestInput;

#[path = "shared.rs"]
mod shared;

#[derive(Arbitrary, Debug)]
struct Input {
    knobs: shared::Knobs,
    method: String,
    uri: String,
    headers: Vec<(String, String)>,
    query: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    /// The caller's own "bytes were dropped before this point" signal, fuzzed so
    /// the engine's own clamping cannot mask it.
    body_truncated: bool,
}

fn pairs(v: &[(String, String)]) -> Vec<(&str, &str)> {
    v.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect()
}

fuzz_target!(|input: Input| {
    let engine = shared::engine(&input.knobs);
    let headers = pairs(&input.headers);
    let query = pairs(&input.query);
    let request = RequestInput {
        method: &input.method,
        uri: &input.uri,
        headers: &headers,
        query: &query,
        body: input.body.as_deref(),
        client_ip: None,
        body_truncated: input.body_truncated,
    };

    let out = engine.evaluate_request(&request);
    shared::check_request(&out, engine.request_rule_count() as u32);

    // Bytes the caller already dropped can never be un-dropped by the engine.
    if input.body_truncated {
        assert!(out.truncated, "a caller-reported truncation was lost");
    }

    // Evaluation is deterministic: the same input and ruleset must produce the
    // same verdict. Without this, a false positive is unreproducible and therefore
    // untriageable. Timing fields are excluded — those are allowed to differ.
    let again = engine.evaluate_request(&request);
    assert_eq!(
        out.verdict, again.verdict,
        "evaluation is not deterministic"
    );
    assert_eq!(out.enforcing_score, again.enforcing_score);
});
