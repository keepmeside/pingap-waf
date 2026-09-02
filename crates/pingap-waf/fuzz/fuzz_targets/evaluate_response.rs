#![no_main]
//! Fuzz `RuleEngine::evaluate_response`.
//!
//! A separate target rather than a second branch inside `evaluate`, so the
//! response surface gets its own corpus and its own coverage signal. Sharing a
//! target would let request-side inputs dominate the corpus and leave the response
//! path barely explored while the run still looked clean.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pingap_waf::ResponseInput;

#[path = "shared.rs"]
mod shared;

#[derive(Arbitrary, Debug)]
struct Input {
    knobs: shared::Knobs,
    status: u16,
    headers: Vec<(String, String)>,
    body_chunk: Option<Vec<u8>>,
    /// Fuzzed across the full range specifically to attack the independence
    /// property: a large inbound score must never manufacture an outbound finding.
    request_score: u32,
    body_truncated: bool,
}

fuzz_target!(|input: Input| {
    let engine = shared::engine(&input.knobs);
    let headers: Vec<(&str, &str)> = input
        .headers
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let response = ResponseInput {
        status: input.status,
        headers: &headers,
        body_chunk: input.body_chunk.as_deref(),
        request_score: input.request_score,
        body_truncated: input.body_truncated,
    };

    let out = engine.evaluate_response(&response);
    shared::check_response(&out, engine.response_rule_count() as u32);

    if input.body_truncated {
        assert!(out.truncated, "a caller-reported truncation was lost");
    }

    // The independence property, stated as an invariant: zeroing the inbound score
    // must not change the outbound verdict. If it ever does, the two surfaces have
    // been coupled and a request allowed inbound is being re-judged on its way out.
    let zeroed = ResponseInput {
        request_score: 0,
        ..response
    };
    let control = engine.evaluate_response(&zeroed);
    assert_eq!(
        out.verdict, control.verdict,
        "the request score changed the response verdict"
    );
    assert_eq!(out.enforcing_score, control.enforcing_score);
});
