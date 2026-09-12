//! Engine behaviour through the crate's public surface: scoring, threshold, mode
//! gates, paranoia, custom rules, the time budget, ruleset publication, and
//! response-side independence.
//!
//! Integration tests on purpose. This is the surface the detectors will be built
//! against, so anything asserted here is a contract, not an implementation detail.

use pingap_waf::config::{CustomRule, RawMode, WafConfig};
use pingap_waf::engine::EngineHandle;
use pingap_waf::{
    Category, ExhaustedPolicy, Hit, MatchedField, Paranoia, RequestInput,
    RequestRule, RequestVerdict, ResponseInput, ResponseRule, ResponseVerdict,
    Rule, RuleEngine, RuleId, Severity,
};

/// A rule that fires on a fixed substring.
///
/// Enough to exercise scoring and gating without depending on any real detector —
/// the engine's job is the verdict, not the matching.
struct Needle {
    id: RuleId,
    category: Category,
    severity: Severity,
    paranoia: Paranoia,
    needle: &'static str,
}

impl Needle {
    fn new(
        id: u32,
        category: Category,
        severity: Severity,
        needle: &'static str,
    ) -> Self {
        Self {
            id: RuleId::native(id).expect("test id is in the native range"),
            category,
            severity,
            paranoia: Paranoia::MIN,
            needle,
        }
    }

    fn at_paranoia(mut self, level: u8) -> Self {
        self.paranoia =
            Paranoia::new(level).expect("test paranoia is in range");
        self
    }
}

impl Rule for Needle {
    fn id(&self) -> RuleId {
        self.id
    }
    fn category(&self) -> Category {
        self.category
    }
    fn severity(&self) -> Severity {
        self.severity
    }
    fn paranoia(&self) -> Paranoia {
        self.paranoia
    }
}

impl RequestRule for Needle {
    fn evaluate(&self, input: &RequestInput<'_>) -> Option<Hit> {
        let body = input.body.map(String::from_utf8_lossy).unwrap_or_default();
        if !input.uri.contains(self.needle) && !body.contains(self.needle) {
            return None;
        }
        Some(Hit {
            rule_id: self.id,
            category: self.category,
            severity: self.severity,
            score: self.severity.default_score(),
            matched_field: MatchedField::Uri,
        })
    }
}

impl ResponseRule for Needle {
    fn evaluate(&self, input: &ResponseInput<'_>) -> Option<Hit> {
        let body = input
            .body_chunk
            .map(String::from_utf8_lossy)
            .unwrap_or_default();
        if !body.contains(self.needle) {
            return None;
        }
        Some(Hit {
            rule_id: self.id,
            category: self.category,
            severity: self.severity,
            score: self.severity.default_score(),
            matched_field: MatchedField::ResponseBody {
                offset: body.find(self.needle).unwrap_or(0),
                len: self.needle.len(),
            },
        })
    }
}

/// A config with the given category modes and everything else at its default.
fn config(modes: &[(&str, RawMode)]) -> WafConfig {
    WafConfig {
        categories: modes.iter().map(|(k, m)| ((*k).to_string(), *m)).collect(),
        ..Default::default()
    }
}

fn engine(cfg: WafConfig, request: Vec<Box<dyn RequestRule>>) -> RuleEngine {
    RuleEngine::build(
        cfg.validate().expect("valid config"),
        request,
        Vec::new(),
    )
    .expect("engine builds")
}

fn uri(path: &str) -> RequestInput<'_> {
    RequestInput {
        method: "GET",
        uri: path,
        ..Default::default()
    }
}

fn ids(hits: &[Hit]) -> Vec<u32> {
    hits.iter().map(|h| h.rule_id.get()).collect()
}

/// Two SQLi rules, each `warning` (3), against a default threshold of 5.
fn two_warning_rules(level: u8) -> Vec<Box<dyn RequestRule>> {
    vec![
        Box::new(
            Needle::new(
                942_001,
                Category::SqlInjection,
                Severity::Warning,
                "union",
            )
            .at_paranoia(level),
        ),
        Box::new(
            Needle::new(
                942_002,
                Category::SqlInjection,
                Severity::Warning,
                "select",
            )
            .at_paranoia(level),
        ),
    ]
}

#[test]
fn two_sub_threshold_rules_block_in_sum_and_every_id_is_reported() {
    let e = engine(
        config(&[("sql_injection", RawMode::Block)]),
        two_warning_rules(1),
    );

    // Each rule alone scores 3 against a threshold of 5 — not enough.
    let one = e.evaluate_request(&uri("/?q=union"));
    assert!(
        matches!(one.verdict, RequestVerdict::Detected { .. }),
        "3 points must not reach a threshold of 5, got {:?}",
        one.verdict
    );
    assert_eq!(one.verdict.score(), 3);

    // Together they cross it.
    let both = e.evaluate_request(&uri("/?q=union+select+1"));
    let RequestVerdict::Block { ref hits, score } = both.verdict else {
        panic!("3 + 3 must cross a threshold of 5, got {:?}", both.verdict);
    };
    assert_eq!(score, 6);
    // Every contributing rule ID, not just the last or the worst. A block that
    // names one of two rules is a block an operator cannot triage.
    assert_eq!(ids(hits), vec![942_001, 942_002]);
    assert_eq!(both.enforcing_score, 6);
}

#[test]
fn lowering_paranoia_below_the_rules_allows_the_same_request() {
    let request = uri("/?q=union+select+1");

    // At paranoia 2 the rules participate and the request is blocked.
    let strict = engine(
        WafConfig {
            paranoia: Paranoia::new(2).expect("valid"),
            ..config(&[("sql_injection", RawMode::Block)])
        },
        two_warning_rules(2),
    );
    assert!(strict.evaluate_request(&request).verdict.is_enforcing());

    // Same rules, same request, paranoia 1: neither rule runs.
    let relaxed = engine(
        WafConfig {
            paranoia: Paranoia::MIN,
            ..config(&[("sql_injection", RawMode::Block)])
        },
        two_warning_rules(2),
    );
    let v = relaxed.evaluate_request(&request);
    assert_eq!(v.verdict, RequestVerdict::Allow);
    assert_eq!(
        v.rules_checked, 0,
        "a filtered-out rule must not be counted"
    );
}

#[test]
fn detect_reports_without_blocking_and_off_reports_nothing() {
    let request = uri("/?q=union+select+1");

    let detect = engine(
        config(&[("sql_injection", RawMode::Detect)]),
        two_warning_rules(1),
    );
    let v = detect.evaluate_request(&request);
    assert_eq!(v.verdict.hits().len(), 2, "detect still records every hit");
    assert_eq!(v.verdict.score(), 6);
    assert!(
        !v.verdict.is_enforcing(),
        "6 points in detect mode must not block: {:?}",
        v.verdict
    );
    assert_eq!(
        v.enforcing_score, 0,
        "detect-mode hits contribute nothing to the enforcing subtotal"
    );

    let off = engine(
        config(&[("sql_injection", RawMode::Off)]),
        two_warning_rules(1),
    );
    let v = off.evaluate_request(&request);
    assert_eq!(v.verdict, RequestVerdict::Allow);
    assert!(v.verdict.hits().is_empty());
    assert_eq!(v.rules_checked, 0, "an off category must not run its rules");
}

#[test]
fn a_detect_category_cannot_push_a_request_over_the_threshold() {
    // A mixed profile: XSS blocks, SQLi only detects. A request tripping both must
    // be judged on the XSS score alone — otherwise turning a category down to
    // `detect` would still get requests blocked because of it, which is precisely
    // the behaviour an operator switches to `detect` to avoid.
    let e = engine(
        config(&[("xss", RawMode::Block), ("sql_injection", RawMode::Detect)]),
        vec![
            Box::new(Needle::new(
                941_001,
                Category::Xss,
                Severity::Warning,
                "<script",
            )),
            Box::new(Needle::new(
                942_001,
                Category::SqlInjection,
                Severity::Critical,
                "union",
            )),
        ],
    );
    let v = e.evaluate_request(&uri("/?a=<script&b=union"));
    assert_eq!(v.verdict.hits().len(), 2);
    assert_eq!(v.verdict.score(), 8, "the total still shows both hits");
    assert_eq!(v.enforcing_score, 3, "only the blocking category counts");
    assert!(!v.verdict.is_enforcing(), "3 < 5, so no block");
}

fn with_custom(
    mut cfg: WafConfig,
    name: &str,
    category: Category,
    pattern: &str,
    severity: Severity,
    action: Option<RawMode>,
) -> WafConfig {
    cfg.custom_rules.insert(
        name.to_string(),
        CustomRule {
            category,
            pattern: pattern.to_string(),
            severity,
            paranoia: Paranoia::MIN,
            action,
        },
    );
    cfg
}

#[test]
fn a_custom_rule_blocks_and_is_attributed_to_a_reserved_id() {
    let cfg = with_custom(
        config(&[("sql_injection", RawMode::Block)]),
        "no-legacy-admin",
        Category::SqlInjection,
        r"(?i)/wp-admin",
        Severity::Critical,
        None,
    );
    let e = engine(cfg, Vec::new());
    assert_eq!(e.request_rule_count(), 1, "the custom rule was compiled in");

    let v = e.evaluate_request(&uri("/WP-admin/index.php"));
    let RequestVerdict::Block { ref hits, score } = v.verdict else {
        panic!(
            "a critical custom rule must reach the default threshold: {:?}",
            v.verdict
        );
    };
    assert_eq!(score, 5);
    assert_eq!(hits.len(), 1);
    let id = hits[0].rule_id;
    assert!(
        id.is_custom(),
        "a custom rule must never be attributed to a native ID: {id}"
    );
    assert!(
        RuleId::native(id.get()).is_none(),
        "{id} falls inside the native range"
    );
    assert_eq!(hits[0].category, Category::SqlInjection);

    // A non-matching request is untouched.
    assert_eq!(
        e.evaluate_request(&uri("/admin")).verdict,
        RequestVerdict::Allow
    );
}

#[test]
fn a_custom_rule_action_overrides_its_category_mode() {
    // Category left at the default `detect`; the rule itself asks to block. A
    // config key that parsed but did nothing would be the worse outcome.
    let cfg = with_custom(
        WafConfig::default(),
        "hard-block-shell",
        Category::RemoteCodeExecution,
        r"/bin/sh",
        Severity::Critical,
        Some(RawMode::Block),
    );
    let e = engine(cfg, Vec::new());
    let v = e.evaluate_request(&uri("/cgi?cmd=/bin/sh"));
    assert!(
        v.verdict.is_enforcing(),
        "a rule-level `block` must win over a category-level `detect`: {:?}",
        v.verdict
    );

    // And the reverse: `off` on the rule silences it even where the category runs.
    let cfg = with_custom(
        config(&[("remote_code_execution", RawMode::Block)]),
        "muted",
        Category::RemoteCodeExecution,
        r"/bin/sh",
        Severity::Critical,
        Some(RawMode::Off),
    );
    let e = engine(cfg, Vec::new());
    let v = e.evaluate_request(&uri("/cgi?cmd=/bin/sh"));
    assert_eq!(v.verdict, RequestVerdict::Allow);
    assert_eq!(v.rules_checked, 0);
}

#[test]
fn a_custom_rule_matches_inside_a_request_body() {
    let cfg = with_custom(
        config(&[("xss", RawMode::Block)]),
        "script-tag",
        Category::Xss,
        r"(?i)<script",
        Severity::Critical,
        None,
    );
    let e = engine(cfg, Vec::new());
    let body = b"name=x&comment=<SCRIPT>alert(1)</script>";
    let input = RequestInput {
        method: "POST",
        uri: "/comment",
        body: Some(body),
        ..Default::default()
    };
    let v = e.evaluate_request(&input);
    assert!(v.verdict.is_enforcing(), "{:?}", v.verdict);
    // The field is named, and the offset locates the match — but the payload
    // itself never appears in the record.
    let field = v.verdict.hits()[0].matched_field.to_string();
    assert!(field.starts_with("body@"), "unexpected field: {field}");
    assert!(
        !field.contains("script"),
        "the payload leaked into the record"
    );
}

/// A rule that burns wall-clock time so budget enforcement can be observed.
struct Slow {
    id: RuleId,
    cost: std::time::Duration,
}

impl Rule for Slow {
    fn id(&self) -> RuleId {
        self.id
    }
    fn category(&self) -> Category {
        Category::SqlInjection
    }
    fn severity(&self) -> Severity {
        Severity::Notice
    }
}

impl RequestRule for Slow {
    fn evaluate(&self, _input: &RequestInput<'_>) -> Option<Hit> {
        // Spin rather than sleep: this stands in for a backtracking regex, which
        // burns CPU rather than yielding.
        let until = std::time::Instant::now() + self.cost;
        while std::time::Instant::now() < until {
            std::hint::spin_loop();
        }
        None
    }
}

#[test]
fn the_budget_stops_evaluation_early_and_says_so() {
    let cost = std::time::Duration::from_millis(2);
    let rules: Vec<Box<dyn RequestRule>> = (0..50)
        .map(|i| {
            Box::new(Slow {
                id: RuleId::native(942_100 + i).expect("native id"),
                cost,
            }) as Box<dyn RequestRule>
        })
        .collect();
    let cfg = WafConfig {
        budget_ms: 10,
        ..config(&[("sql_injection", RawMode::Block)])
    };
    let e = engine(cfg, rules);

    let v = e.evaluate_request(&uri("/"));
    let ex = v
        .exhausted
        .as_ref()
        .expect("50 x 2ms against a 10ms budget must exhaust it");
    assert_eq!(ex.policy, ExhaustedPolicy::Allow);
    assert!(
        v.rules_checked < 50,
        "evaluation must stop early, not finish"
    );
    assert_eq!(
        ex.rules_checked, v.rules_checked,
        "the record must agree with the counter"
    );
    // The budget is checked *between* rules, so the worst-case overshoot is one
    // rule's cost. Anything beyond that means a check was skipped. The generous
    // slack keeps this from flaking on a loaded CI box while still failing if the
    // loop ran to completion (which would be ~100ms).
    assert!(
        v.elapsed < std::time::Duration::from_millis(10) + cost * 8,
        "overshoot beyond one rule's cost: {:?}",
        v.elapsed
    );
    // Fail-open default: an incomplete evaluation with no hits does not block.
    assert_eq!(v.verdict, RequestVerdict::Allow);
}

#[test]
fn the_block_policy_blocks_an_evaluation_it_could_not_finish() {
    let rules: Vec<Box<dyn RequestRule>> = (0..20)
        .map(|i| {
            Box::new(Slow {
                id: RuleId::native(942_200 + i).expect("native id"),
                cost: std::time::Duration::from_millis(2),
            }) as Box<dyn RequestRule>
        })
        .collect();
    let cfg = WafConfig {
        budget_ms: 4,
        on_budget_exhausted: ExhaustedPolicy::Block,
        ..config(&[("sql_injection", RawMode::Block)])
    };
    let v = engine(cfg, rules).evaluate_request(&uri("/"));

    assert!(v.exhausted.is_some());
    // No rule matched, yet the request is rejected: the operator chose to treat
    // "could not finish inspecting" as grounds to refuse. The hit list is empty,
    // which is why `exhausted` has to travel with the verdict — it is the only
    // thing that explains the block.
    assert!(
        matches!(v.verdict, RequestVerdict::Block { ref hits, score: 0 } if hits.is_empty()),
        "{:?}",
        v.verdict
    );
}

#[test]
fn an_over_cap_body_is_inspected_up_to_the_limit_and_the_shortfall_is_recorded()
{
    let cfg = with_custom(
        config(&[("xss", RawMode::Block)]),
        "needle",
        Category::Xss,
        "NEEDLE",
        Severity::Critical,
        None,
    );
    let e = engine(
        WafConfig {
            body_inspect_limit: 64,
            ..cfg
        },
        Vec::new(),
    );

    // Inside the cap: found, and nothing is reported as missed.
    let mut body = b"NEEDLE".to_vec();
    body.resize(32, b'x');
    let v = e.evaluate_request(&RequestInput {
        method: "POST",
        uri: "/",
        body: Some(&body),
        ..Default::default()
    });
    assert!(v.verdict.is_enforcing());
    assert!(!v.truncated);

    // Past the cap: not found — and the verdict says the body was only partly
    // inspected, so an `Allow` here is not mistaken for a clean bill of health.
    let mut body = vec![b'x'; 200];
    body.extend_from_slice(b"NEEDLE");
    let v = e.evaluate_request(&RequestInput {
        method: "POST",
        uri: "/",
        body: Some(&body),
        ..Default::default()
    });
    assert_eq!(v.verdict, RequestVerdict::Allow);
    assert!(
        v.truncated,
        "bytes past the cap were dropped and must be reported"
    );
}

fn response_engine(
    cfg: WafConfig,
    rules: Vec<Box<dyn ResponseRule>>,
) -> RuleEngine {
    RuleEngine::build(cfg.validate().expect("valid config"), Vec::new(), rules)
        .expect("engine builds")
}

/// One 950-lineage rule and one 955-lineage rule, on signatures CRS uses for the
/// same groups. These are detection signatures, not secrets.
fn response_rules() -> Vec<Box<dyn ResponseRule>> {
    vec![
        Box::new(Needle::new(
            950_001,
            Category::DataLeakage,
            Severity::Critical,
            "mysql_connect()",
        )),
        Box::new(Needle::new(
            955_001,
            Category::WebShell,
            Severity::Critical,
            "eval($_POST[",
        )),
    ]
}

fn body(bytes: &[u8]) -> ResponseInput<'_> {
    ResponseInput {
        status: 200,
        body_chunk: Some(bytes),
        ..Default::default()
    }
}

#[test]
fn response_side_scores_both_lineages_and_redacts() {
    let e = response_engine(
        config(&[
            ("data_leakage", RawMode::Redact),
            ("web_shell", RawMode::Redact),
        ]),
        response_rules(),
    );

    let leak = e.evaluate_response(&body(
        b"<b>Warning</b>: mysql_connect(): Access denied for user",
    ));
    let ResponseVerdict::Redact { ref hits, .. } = leak.verdict else {
        panic!("a 950-lineage signature must redact: {:?}", leak.verdict);
    };
    assert_eq!(ids(hits), vec![950_001]);
    assert_eq!(hits[0].category.crs_group(), 950);

    let shell = e.evaluate_response(&body(b"<?php eval($_POST['x']); ?>"));
    let ResponseVerdict::Redact { ref hits, .. } = shell.verdict else {
        panic!("a 955-lineage signature must redact: {:?}", shell.verdict);
    };
    assert_eq!(ids(hits), vec![955_001]);
    assert_eq!(hits[0].category.crs_group(), 955);

    // Clean body, no hits.
    assert_eq!(
        e.evaluate_response(&body(b"<html>ok</html>")).verdict,
        ResponseVerdict::Allow
    );
}

#[test]
fn response_side_honours_off_and_detect() {
    let leak = b"Warning: mysql_connect(): Access denied".as_slice();

    let detect = response_engine(
        config(&[("data_leakage", RawMode::Detect)]),
        response_rules(),
    );
    let v = detect.evaluate_response(&body(leak));
    assert!(
        matches!(v.verdict, ResponseVerdict::Detected { .. }),
        "detect must record without rewriting: {:?}",
        v.verdict
    );
    assert_eq!(v.verdict.hits().len(), 1);
    assert_eq!(v.enforcing_score, 0);

    let off = response_engine(
        config(&[("data_leakage", RawMode::Off)]),
        response_rules(),
    );
    let v = off.evaluate_response(&body(leak));
    assert_eq!(v.verdict, ResponseVerdict::Allow);
    assert_eq!(v.rules_checked, 1, "only web_shell remained eligible");
}

#[test]
fn the_response_score_is_independent_of_the_request_score() {
    // A request that was allowed inbound is not retroactively re-judged outbound,
    // and its response could not be denied even if it were. Summing the two would
    // be an easy and invisible mistake, so it is pinned here.
    let e = response_engine(
        config(&[("data_leakage", RawMode::Redact)]),
        response_rules(),
    );

    let clean = ResponseInput {
        status: 200,
        body_chunk: Some(b"<html>ok</html>"),
        request_score: 10_000,
        ..Default::default()
    };
    let v = e.evaluate_response(&clean);
    assert_eq!(
        v.verdict,
        ResponseVerdict::Allow,
        "a large request score must not manufacture a response finding"
    );
    assert_eq!(v.enforcing_score, 0);

    // And a real response hit scores only itself.
    let dirty = ResponseInput {
        status: 200,
        body_chunk: Some(b"Warning: mysql_connect(): denied"),
        request_score: 10_000,
        ..Default::default()
    };
    let v = e.evaluate_response(&dirty);
    assert_eq!(v.verdict.score(), 5, "one critical hit, not 10_005");
    assert_eq!(v.enforcing_score, 5);
}

#[test]
fn the_response_prefix_cap_bounds_inspection_and_reports_the_shortfall() {
    let e = response_engine(
        WafConfig {
            response_prefix_limit: 32,
            ..config(&[("data_leakage", RawMode::Redact)])
        },
        response_rules(),
    );

    let mut long = vec![b'.'; 64];
    long.extend_from_slice(b"mysql_connect()");
    let v = e.evaluate_response(&body(&long));
    assert_eq!(
        v.verdict,
        ResponseVerdict::Allow,
        "past the prefix cap nothing is inspected"
    );
    assert!(
        v.truncated,
        "the uninspected remainder must be recorded, not silently dropped"
    );
}

#[test]
fn a_response_side_rule_never_runs_on_the_request_path() {
    // The surfaces are separated by category, not by hope: a 950-lineage rule
    // handed to the request list would still be gated off.
    let e = RuleEngine::build(
        config(&[("data_leakage", RawMode::Redact)])
            .validate()
            .expect("valid"),
        vec![Box::new(Needle::new(
            950_001,
            Category::DataLeakage,
            Severity::Critical,
            "leak",
        ))],
        Vec::new(),
    )
    .expect("builds");
    let v = e.evaluate_request(&uri("/?x=leak"));
    assert_eq!(v.verdict, RequestVerdict::Allow);
    assert_eq!(v.rules_checked, 0);
}

#[test]
fn a_custom_rule_on_a_response_category_lands_on_the_response_side() {
    let cfg = with_custom(
        config(&[("web_shell", RawMode::Redact)]),
        "shell-marker",
        Category::WebShell,
        r"passthru\(",
        Severity::Critical,
        None,
    );
    let e = RuleEngine::build(
        cfg.validate().expect("valid"),
        Vec::new(),
        Vec::new(),
    )
    .expect("builds");
    assert_eq!(e.request_rule_count(), 0, "must not be on the request side");
    assert_eq!(e.response_rule_count(), 1);

    let v = e.evaluate_response(&body(b"<?php passthru($_GET['c']); ?>"));
    assert!(v.verdict.is_enforcing(), "{:?}", v.verdict);
    assert!(v.verdict.hits()[0].rule_id.is_custom());
}

/// A rule that counts its own drop, so ruleset publication can be checked for
/// leaks directly instead of by watching RSS.
struct Counted {
    id: RuleId,
    live: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.live.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Rule for Counted {
    fn id(&self) -> RuleId {
        self.id
    }
    fn category(&self) -> Category {
        Category::SqlInjection
    }
    fn severity(&self) -> Severity {
        Severity::Notice
    }
}

impl RequestRule for Counted {
    fn evaluate(&self, _input: &RequestInput<'_>) -> Option<Hit> {
        None
    }
}

#[test]
fn ten_thousand_ruleset_swaps_free_every_superseded_ruleset() {
    use std::sync::atomic::Ordering;
    let live = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let build = || {
        live.fetch_add(1, Ordering::Relaxed);
        engine(
            config(&[("sql_injection", RawMode::Block)]),
            vec![Box::new(Counted {
                id: RuleId::native(942_900).expect("native id"),
                live: std::sync::Arc::clone(&live),
            })],
        )
    };

    let handle = EngineHandle::new(build());
    for _ in 0..10_000 {
        handle.publish(build());
        // Load between swaps so the request path is exercised against a ruleset
        // that is being replaced underneath it.
        assert_eq!(
            handle.load().evaluate_request(&uri("/")).verdict,
            RequestVerdict::Allow
        );
    }

    // 10_001 built, 10_000 superseded. Anything above 1 is a ruleset that was
    // swapped out and never freed — the shape unbounded memory growth would take.
    assert_eq!(
        live.load(Ordering::Relaxed),
        1,
        "superseded rulesets were not dropped"
    );
    drop(handle);
    assert_eq!(live.load(Ordering::Relaxed), 0, "the last ruleset leaked");
}
