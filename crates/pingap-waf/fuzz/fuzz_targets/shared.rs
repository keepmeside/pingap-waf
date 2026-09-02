//! Shared harness for both fuzz targets.
//!
//! The targets check **invariants**, not merely the absence of a panic. Absence of
//! a panic is the floor: the release profile is `panic = "abort"`, so a panic on
//! attacker input takes down the whole gateway. But a verdict that is internally
//! inconsistent — a score that does not match its hits, an enforcing decision
//! nothing justifies — is a security bug that no crash would reveal.

// Each target `#[path]`-includes this whole file and calls only its own surface's
// checker, so the other one is legitimately unused in that binary.
#![allow(dead_code)]

use arbitrary::Arbitrary;
use pingap_waf::config::{CustomRule, RawMode, WafConfig};
use pingap_waf::{
    Category, Evaluation, Paranoia, RequestVerdict, ResponseVerdict,
    RuleEngine, Severity,
};

/// Config knobs the fuzzer may move. Every one is folded into its valid range
/// rather than rejected, so no fuzzer input is wasted on a config that cannot be
/// built.
#[derive(Arbitrary, Debug)]
pub struct Knobs {
    pub paranoia: u8,
    pub threshold: u32,
    pub budget_ms: u8,
    pub body_limit: u16,
    pub prefix_limit: u16,
    pub enforce: bool,
}

/// Patterns chosen to exercise the parts of `fancy-regex` that `regex` cannot do
/// at all — a backreference and two lookaheads — alongside ordinary alternation.
/// Those are the constructs that make backtracking possible, which is what the
/// time budget exists to bound.
///
/// The lookaheads are deliberately **bounded**. An earlier set used
/// `(?=.*etc)(?=.*passwd)`, which the cost check now rejects as quadratic — and a
/// rejected pattern here would make every `engine()` call fail and the whole fuzz
/// run vacuously clean. Kept in sync with `benches/bench.rs` by hand, because the
/// fuzz crate is detached from that workspace.
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

/// Build an engine from the knobs.
///
/// Panics rather than returning `Option`. Every knob is folded into its valid
/// range, and the patterns are constants, so the only way construction can fail is
/// a genuine regression in validation or in `build`. Returning `None` there would
/// make every subsequent iteration a no-op and the run would still report clean —
/// a fuzz gate that passes by doing nothing is worse than one that crashes.
pub fn engine(k: &Knobs) -> RuleEngine {
    let mode = |c: Category| match (k.enforce, c.is_response_side()) {
        (false, _) => RawMode::Detect,
        (true, false) => RawMode::Block,
        (true, true) => RawMode::Redact,
    };
    let mut cfg = WafConfig {
        categories: Category::ALL
            .iter()
            .map(|c| (c.key().to_string(), mode(*c)))
            .collect(),
        paranoia: Paranoia::new(k.paranoia % 4 + 1)
            .expect("1..=4 is in range by construction"),
        anomaly_threshold: k.threshold % 64 + 1,
        budget_ms: u64::from(k.budget_ms % 50) + 1,
        body_inspect_limit: usize::from(k.body_limit) + 1,
        response_prefix_limit: usize::from(k.prefix_limit) + 1,
        ..Default::default()
    };
    for (i, (pattern, category, severity)) in PATTERNS.iter().enumerate() {
        cfg.custom_rules.insert(
            format!("fuzz-{i}"),
            CustomRule {
                category: *category,
                pattern: (*pattern).to_string(),
                severity: *severity,
                paranoia: Paranoia::MIN,
                action: None,
            },
        );
    }
    let validated = cfg
        .validate()
        .expect("the fixed pattern set and folded knobs must always validate");
    RuleEngine::build(validated, Vec::new(), Vec::new())
        .expect("the fixed pattern set must always build")
}

/// Invariants that must hold for either surface.
fn check_common(
    hits: &[pingap_waf::Hit],
    score: u32,
    enforcing_score: u32,
    e_rules_checked: u32,
    exhausted: Option<&pingap_waf::Exhausted>,
    rule_count: u32,
) {
    let summed: u32 = hits.iter().map(|h| h.score).sum();
    assert_eq!(score, summed, "reported score disagrees with its own hits");
    assert!(
        enforcing_score <= score,
        "enforcing subtotal {enforcing_score} exceeds the total {score}"
    );
    assert!(
        e_rules_checked <= rule_count,
        "{e_rules_checked} rules checked out of {rule_count}"
    );
    if let Some(ex) = exhausted {
        assert_eq!(
            ex.rules_checked, e_rules_checked,
            "the exhaustion record disagrees with the evaluation counter"
        );
    }
    for h in hits {
        assert!(
            h.category.owns_id(h.rule_id.get()) || h.rule_id.is_custom(),
            "hit {} is attributed to a category that does not own it",
            h.rule_id
        );
    }
}

pub fn check_request(e: &Evaluation<RequestVerdict>, rule_count: u32) {
    let hits = e.verdict.hits();
    check_common(
        hits,
        e.verdict.score(),
        e.enforcing_score,
        e.rules_checked,
        e.exhausted.as_ref(),
        rule_count,
    );
    if matches!(e.verdict, RequestVerdict::Allow) {
        assert!(hits.is_empty(), "an Allow verdict carrying hits");
    }
    // A block is either earned on score or forced by the exhaustion policy. Any
    // third path would be a request rejected for no stated reason.
    if e.verdict.is_enforcing() {
        assert!(
            e.enforcing_score > 0 || e.exhausted.is_some(),
            "blocked with nothing to justify it"
        );
    }
}

pub fn check_response(e: &Evaluation<ResponseVerdict>, rule_count: u32) {
    let hits = e.verdict.hits();
    check_common(
        hits,
        e.verdict.score(),
        e.enforcing_score,
        e.rules_checked,
        e.exhausted.as_ref(),
        rule_count,
    );
    if matches!(e.verdict, ResponseVerdict::Allow) {
        assert!(hits.is_empty(), "an Allow verdict carrying hits");
    }
    // Response-side has no forced path: redaction with nothing found would tell
    // the caller to rewrite a span that was never located.
    if e.verdict.is_enforcing() {
        assert!(!hits.is_empty(), "redacting without a hit to redact");
        assert!(e.enforcing_score > 0);
    }
    for h in hits {
        assert!(
            h.category.is_response_side(),
            "request-side category {} scored on the response path",
            h.category
        );
    }
}
