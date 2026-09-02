//! The rule engine: two evaluation surfaces, one scoring model.
//!
//! `evaluate_request` and `evaluate_response` share the scoring model, the
//! paranoia filter, the mode gate, and the threshold comparison. They differ in
//! the input type, the wiring point, and — load-bearing — the enforcement action
//! available. Request-side can deny. Response-side cannot: by the time a body
//! hook runs the status line is already downstream, so the strongest available
//! action is rewriting bytes. That asymmetry is expressed as two verdict types
//! rather than one enum with a variant that is unreachable on one surface, so a
//! caller cannot write a match arm for a response-side block that never comes.
//!
//! The engine is a pure function over its input: no I/O, no session reference,
//! no knowledge that Pingora exists. That is what makes it fuzzable in isolation,
//! and it is worth defending — the moment a detector needs a `Session`, widen the
//! input type instead.

use crate::budget::{Budget, Exhausted};
use crate::categories::Category;
use crate::config::{
    ConfigError, RawMode, RequestMode, ResponseMode, ValidatedConfig,
    ValidatedCustomRule,
};
use crate::rule::{
    Hit, MatchedField, Paranoia, RequestRule, ResponseRule, Rule, RuleId,
    Severity,
};
use arc_swap::ArcSwap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// One request, flattened to exactly what a rule may look at.
///
/// Borrowed throughout: the engine allocates nothing proportional to input size,
/// which would otherwise hand an attacker a memory amplifier. `Copy` because every
/// field is a reference or a scalar — the engine rebuilds it once per evaluation
/// with the body clamped to the configured limit.
#[derive(Debug, Default, Clone, Copy)]
pub struct RequestInput<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub query: &'a [(&'a str, &'a str)],
    pub body: Option<&'a [u8]>,
    pub client_ip: Option<IpAddr>,
    /// Set by the caller when bytes were dropped before reaching the engine — a
    /// body larger than the plugin was willing to buffer, for instance. Recorded
    /// on the evaluation so an `Allow` over a partial body is distinguishable
    /// from an `Allow` over a whole one.
    pub body_truncated: bool,
}

/// One response, flattened the same way.
///
/// `body_chunk` is a **bounded prefix**, never a whole body. Full-body buffering
/// would break pingap's streaming response path and fight its cache, so a
/// response longer than the configured prefix is inspected up to the cap and the
/// shortfall is recorded rather than dropped silently.
#[derive(Debug, Default, Clone, Copy)]
pub struct ResponseInput<'a> {
    pub status: u16,
    pub headers: &'a [(&'a str, &'a str)],
    pub body_chunk: Option<&'a [u8]>,
    /// The anomaly score the matching request accumulated inbound.
    ///
    /// Carried for correlation in the log record only. It deliberately does **not**
    /// feed the response threshold: a request that was allowed inbound is not
    /// retroactively re-judged on its way out, and the response could not be
    /// denied even if it were. Asserted by test, because summing the two would be
    /// an easy and invisible mistake.
    pub request_score: u32,
    pub body_truncated: bool,
}

/// Request-side outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestVerdict {
    /// No rule matched.
    Allow,
    /// Rules matched but enforcement was not reached — either their categories
    /// are in `detect`, or the enforcing subtotal stayed under the threshold.
    Detected { hits: Vec<Hit>, score: u32 },
    /// Reject the request.
    Block { hits: Vec<Hit>, score: u32 },
}

/// Response-side outcome. Same shape as [`RequestVerdict`], with `Redact` where
/// request-side has `Block`.
///
/// There is no `Block` here and there cannot be: `ResponseBodyPluginResult` has
/// no `Respond` variant, and the status line has already gone downstream.
/// `Redact` means "rewrite the matched span out of the body" — the response still
/// completes with its original status, and it must never be described as a denial
/// in config, API, or UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseVerdict {
    Allow,
    Detected { hits: Vec<Hit>, score: u32 },
    Redact { hits: Vec<Hit>, score: u32 },
}

macro_rules! verdict_accessors {
    ($t:ty, $enforce:ident) => {
        impl $t {
            /// Every rule that contributed, in evaluation order. An unexplainable
            /// block is an untriageable false positive, so the full list travels
            /// with the verdict rather than just the last or worst hit.
            pub fn hits(&self) -> &[Hit] {
                match self {
                    Self::Allow => &[],
                    Self::Detected { hits, .. }
                    | Self::$enforce { hits, .. } => hits,
                }
            }

            /// Total accumulated anomaly score across all hits, including hits
            /// from categories in `detect` that could not contribute to
            /// enforcement.
            pub fn score(&self) -> u32 {
                match self {
                    Self::Allow => 0,
                    Self::Detected { score, .. }
                    | Self::$enforce { score, .. } => *score,
                }
            }

            /// Whether the verdict calls for enforcement.
            pub fn is_enforcing(&self) -> bool {
                matches!(self, Self::$enforce { .. })
            }
        }
    };
}

// Two near-identical impls generated rather than hand-copied. The types stay
// distinct — which is the whole point — while the accessors cannot drift apart.
verdict_accessors!(RequestVerdict, Block);
verdict_accessors!(ResponseVerdict, Redact);

/// A verdict plus how it was reached.
///
/// The verdict stays a small matchable enum; everything an operator needs for
/// triage lives here. Splitting them keeps `match` arms on the decision short
/// while this record is free to grow.
#[derive(Debug, Clone)]
pub struct Evaluation<V> {
    pub verdict: V,
    /// Rules that actually ran. "Budget blew at rule 3" and "budget blew at rule
    /// 300" are different problems.
    pub rules_checked: u32,
    /// True when some input bytes were never inspected — either the caller
    /// dropped them or the engine clamped to its configured limit. An `Allow`
    /// with this set is a weaker statement than one without.
    pub truncated: bool,
    /// Present when the time budget ran out mid-evaluation. Never silent: this is
    /// the field that turns "we did not finish" into a log line.
    pub exhausted: Option<Exhausted>,
    pub elapsed: Duration,
    /// The subtotal that was compared against the threshold: hits from categories
    /// whose mode can enforce. Kept next to `verdict.score()` (the total across
    /// all hits) because the gap between the two is exactly what an operator
    /// tuning `detect` versus `block` needs to see.
    pub enforcing_score: u32,
}

/// Accumulates hits and decides whether enforcement is reached.
///
/// Two subtotals, deliberately. `total` is what an operator sees as the request's
/// anomaly score; `enforcing` counts only hits from categories in an enforcing
/// mode. Without the split, a category left in `detect` could push a request over
/// the threshold and cause the very block the operator turned it off to avoid.
#[derive(Debug)]
struct Scorer {
    hits: Vec<Hit>,
    total: u32,
    enforcing: u32,
    threshold: u32,
}

impl Scorer {
    fn new(threshold: u32) -> Self {
        Self {
            hits: Vec::new(),
            total: 0,
            enforcing: 0,
            threshold,
        }
    }

    fn record(&mut self, hit: Hit, enforcing: bool) {
        self.total = self.total.saturating_add(hit.score);
        if enforcing {
            self.enforcing = self.enforcing.saturating_add(hit.score);
        }
        self.hits.push(hit);
    }

    /// `>=`, not `>`: the threshold is the score at which enforcement happens, so
    /// a single `critical` (5) reaches the default threshold of 5.
    fn reached(&self) -> bool {
        self.enforcing >= self.threshold
    }
}

/// The longest valid UTF-8 prefix of `bytes`, without allocating.
///
/// A lossy conversion would allocate a copy of every body the engine inspects —
/// bounded by the configured limit, but still a per-request allocation the size of
/// the payload. The cost of this choice is real and worth stating: a pattern whose
/// match would span an invalid byte will not fire. Detectors that need to see
/// past that (the encoding-aware matchers that arrive with the detectors) work on
/// the raw bytes instead.
fn text_prefix(bytes: &[u8]) -> &str {
    match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => {
            // `valid_up_to()` is a guaranteed char boundary, so this cannot split
            // a code point and cannot fail.
            std::str::from_utf8(&bytes[..e.valid_up_to()]).unwrap_or("")
        },
    }
}

/// Clamp a body to the configured inspection limit.
///
/// Returns the slice actually inspected and whether anything was left out. The
/// engine clamps rather than trusting the caller to have done it: a caller that
/// forgets is a memory and latency bug in the request path, and the engine is the
/// component that knows the limit.
fn clamp(body: Option<&[u8]>, limit: usize) -> (Option<&[u8]>, bool) {
    match body {
        None => (None, false),
        Some(b) if b.len() > limit => (Some(&b[..limit]), true),
        Some(b) => (Some(b), false),
    }
}

/// An operator-authored rule, compiled.
///
/// Implements both rule traits so one type covers a custom rule attributed to
/// either surface; which trait object list it lands in is decided by its
/// category, not by the operator.
struct CompiledCustomRule {
    id: RuleId,
    category: Category,
    severity: Severity,
    paranoia: Paranoia,
    pattern: fancy_regex::Regex,
    /// Explicit per-rule action, overriding the category mode when set.
    action: Option<RawMode>,
}

impl Rule for CompiledCustomRule {
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
    fn action_override(&self) -> Option<RawMode> {
        self.action
    }
}

impl CompiledCustomRule {
    /// Match position within `text`, or `None`.
    ///
    /// A `fancy-regex` error — a hit backtrack limit, most plausibly — is treated
    /// as **no match**, not as a match and not as a panic. That is a deliberate
    /// fail-open at the single-rule level: the alternative is blocking traffic
    /// because a pattern was too expensive, which turns an operator's bad regex
    /// into an outage. The budget is what makes the cost visible.
    fn find_at(&self, text: &str) -> Option<usize> {
        self.pattern.find(text).ok().flatten().map(|m| m.start())
    }

    fn hit(&self, field: MatchedField) -> Hit {
        Hit {
            rule_id: self.id,
            category: self.category,
            severity: self.severity,
            score: self.score(),
            matched_field: field,
        }
    }
}

impl RequestRule for CompiledCustomRule {
    fn evaluate(&self, input: &RequestInput<'_>) -> Option<Hit> {
        if self.find_at(input.uri).is_some() {
            return Some(self.hit(MatchedField::Uri));
        }
        for (key, value) in input.query {
            if self.find_at(value).is_some() {
                return Some(self.hit(MatchedField::Query {
                    key: (*key).to_string(),
                }));
            }
        }
        for (name, value) in input.headers {
            if self.find_at(value).is_some() {
                return Some(self.hit(MatchedField::Header {
                    name: (*name).to_string(),
                }));
            }
        }
        let offset = self.find_at(text_prefix(input.body?))?;
        Some(self.hit(MatchedField::Body { offset }))
    }
}

impl ResponseRule for CompiledCustomRule {
    fn evaluate(&self, input: &ResponseInput<'_>) -> Option<Hit> {
        for (name, value) in input.headers {
            if self.find_at(value).is_some() {
                return Some(self.hit(MatchedField::ResponseHeader {
                    name: (*name).to_string(),
                }));
            }
        }
        let offset = self.find_at(text_prefix(input.body_chunk?))?;
        Some(self.hit(MatchedField::ResponseBody { offset }))
    }
}

/// Derive a custom rule's ID from its name.
///
/// Deliberately *not* the rule's position in the config map. Position-derived IDs
/// shift when a rule is inserted above them, which silently changes which rule a
/// historical log line refers to — the exact failure the reserved-range scheme
/// exists to prevent. A name hash is stable across insertions, reorderings, and
/// reloads.
///
/// FNV-1a: not cryptographic, and it does not need to be. Collisions are possible,
/// so they are detected and rejected at build time rather than hoped away.
fn custom_id_for(name: &str) -> RuleId {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for b in name.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(PRIME);
    }
    RuleId::custom_wrapping(h as u32)
}

/// A compiled, published ruleset behind a pointer swap.
///
/// The swap is scoped to **one plugin instance's construction**: compile off the
/// request path, then publish. It is not a cross-version hot-swap mechanism.
/// pingap already owns that — `try_init_plugins` rebuilds plugin instances on any
/// config change and reuses an instance only when its config hash is unchanged, so
/// a WAF config edit replaces the instance outright and discards whatever this
/// held. Building warm-state preservation here would be a second reload path that
/// can disagree with the first.
pub struct EngineHandle {
    current: Arc<ArcSwap<RuleEngine>>,
}

impl EngineHandle {
    pub fn new(engine: RuleEngine) -> Self {
        Self {
            current: Arc::new(ArcSwap::from_pointee(engine)),
        }
    }

    /// Cheap enough for the request path: an atomic load, no lock.
    pub fn load(&self) -> arc_swap::Guard<Arc<RuleEngine>> {
        self.current.load()
    }

    /// Publish a freshly compiled ruleset. The previous one is dropped once the
    /// last in-flight request finishes with it.
    pub fn publish(&self, engine: RuleEngine) {
        self.current.store(Arc::new(engine));
    }
}

/// The engine: a validated config plus the rules it will run.
pub struct RuleEngine {
    config: ValidatedConfig,
    request_rules: Vec<Box<dyn RequestRule>>,
    response_rules: Vec<Box<dyn ResponseRule>>,
}

impl std::fmt::Debug for RuleEngine {
    /// Counts, not contents. Trait objects have nothing printable, and a ruleset
    /// dump in a log would be noise at best.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleEngine")
            .field("request_rules", &self.request_rules.len())
            .field("response_rules", &self.response_rules.len())
            .field("threshold", &self.config.anomaly_threshold)
            .field("paranoia", &self.config.paranoia.get())
            .field("budget", &self.config.budget)
            .finish()
    }
}

impl RuleEngine {
    /// Compile a config and a set of native rules into a runnable engine.
    ///
    /// Custom rules arrive already compiled — validation owns pattern parsing and
    /// the cost check — so the only failure left here is an ID collision between
    /// two rule names.
    pub fn build(
        config: ValidatedConfig,
        mut request_rules: Vec<Box<dyn RequestRule>>,
        mut response_rules: Vec<Box<dyn ResponseRule>>,
    ) -> Result<Self, ConfigError> {
        let mut seen: Vec<(RuleId, &str)> = Vec::new();
        for (name, validated) in &config.custom_rules {
            let compiled = build_custom(name, validated);
            if let Some((_, other)) =
                seen.iter().find(|(id, _)| *id == compiled.id)
            {
                return Err(ConfigError::CustomRuleIdCollision {
                    name: name.clone(),
                    other: (*other).to_string(),
                    id: compiled.id.get(),
                });
            }
            seen.push((compiled.id, name));
            if compiled.category.is_response_side() {
                response_rules.push(Box::new(compiled));
            } else {
                request_rules.push(Box::new(compiled));
            }
        }
        Ok(Self {
            config,
            request_rules,
            response_rules,
        })
    }

    pub fn config(&self) -> &ValidatedConfig {
        &self.config
    }

    pub fn request_rule_count(&self) -> usize {
        self.request_rules.len()
    }

    pub fn response_rule_count(&self) -> usize {
        self.response_rules.len()
    }
}

/// Attach a name-derived ID to an already-validated custom rule.
///
/// Infallible: the pattern was parsed and cost-checked during validation, so
/// nothing here can fail. Only the ID collision check in `build` can.
fn build_custom(
    name: &str,
    validated: &ValidatedCustomRule,
) -> CompiledCustomRule {
    let spec = validated.spec();
    CompiledCustomRule {
        id: custom_id_for(name),
        category: spec.category,
        severity: spec.severity,
        paranoia: spec.paranoia,
        pattern: validated.pattern().clone(),
        action: spec.action,
    }
}

/// A mode reduced to what evaluation needs. Both surfaces collapse into this so
/// the two loops share one gate, rather than each re-deriving the distinction
/// between "does not run" and "runs but cannot enforce".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gate {
    Skip,
    Detect,
    Enforce,
}

impl From<RequestMode> for Gate {
    fn from(m: RequestMode) -> Self {
        match m {
            RequestMode::Off => Self::Skip,
            RequestMode::Detect => Self::Detect,
            RequestMode::Block => Self::Enforce,
        }
    }
}

impl From<ResponseMode> for Gate {
    fn from(m: ResponseMode) -> Self {
        match m {
            ResponseMode::Off => Self::Skip,
            ResponseMode::Detect => Self::Detect,
            ResponseMode::Redact => Self::Enforce,
        }
    }
}

/// Apply a rule's own declared action on top of its category's mode.
fn resolve_gate(
    category: Gate,
    declared: Option<RawMode>,
    response_side: bool,
) -> Gate {
    match declared {
        None => category,
        Some(RawMode::Off) => Gate::Skip,
        Some(RawMode::Detect) => Gate::Detect,
        Some(RawMode::Block) if !response_side => Gate::Enforce,
        Some(RawMode::Redact) if response_side => Gate::Enforce,
        // Validation rejects an action its surface cannot perform, so a loaded
        // config never reaches here. Degrading to `Detect` rather than `Enforce`
        // means a future construction path that skips validation cannot silently
        // gain enforcement it was never granted.
        Some(_) => Gate::Detect,
    }
}

impl RuleEngine {
    /// Evaluate a request. Total: no panic path, no allocation proportional to
    /// input size, and it always returns a verdict — including when the budget
    /// runs out.
    pub fn evaluate_request(
        &self,
        input: &RequestInput<'_>,
    ) -> Evaluation<RequestVerdict> {
        let cfg = &self.config;
        let (body, clamped) = clamp(input.body, cfg.body_inspect_limit);
        let scoped = RequestInput { body, ..*input };
        let mut budget = Budget::new(cfg.budget, cfg.on_budget_exhausted);
        let mut scorer = Scorer::new(cfg.anomaly_threshold);
        let mut exhausted = None;

        for rule in &self.request_rules {
            let gate = resolve_gate(
                cfg.request_mode(rule.category()).into(),
                rule.action_override(),
                false,
            );
            if gate == Gate::Skip || rule.paranoia() > cfg.paranoia {
                continue;
            }
            // Between rules, not only after the loop: one catastrophic pattern
            // must not be able to spend the whole budget unobserved.
            if let Err(e) = budget.check() {
                exhausted = Some(e);
                break;
            }
            if let Some(hit) = rule.evaluate(&scoped) {
                scorer.record(hit, gate == Gate::Enforce);
            }
        }

        let forced = forced_by_policy(exhausted.as_ref());
        Evaluation {
            rules_checked: budget.rules_checked(),
            truncated: clamped || input.body_truncated,
            elapsed: budget.elapsed(),
            enforcing_score: scorer.enforcing,
            verdict: finish_request(scorer, forced),
            exhausted,
        }
    }
}

impl RuleEngine {
    /// Evaluate an upstream response.
    ///
    /// Scores independently of the request: `input.request_score` is carried for
    /// correlation and is deliberately never added to the response subtotal. A
    /// request allowed inbound is not re-judged on the way out, and its response
    /// could not be denied even if it were.
    pub fn evaluate_response(
        &self,
        input: &ResponseInput<'_>,
    ) -> Evaluation<ResponseVerdict> {
        let cfg = &self.config;
        let (body_chunk, clamped) =
            clamp(input.body_chunk, cfg.response_prefix_limit);
        let scoped = ResponseInput {
            body_chunk,
            ..*input
        };
        let mut budget = Budget::new(cfg.budget, cfg.on_budget_exhausted);
        let mut scorer = Scorer::new(cfg.anomaly_threshold);
        let mut exhausted = None;

        for rule in &self.response_rules {
            let gate = resolve_gate(
                cfg.response_mode(rule.category()).into(),
                rule.action_override(),
                true,
            );
            if gate == Gate::Skip || rule.paranoia() > cfg.paranoia {
                continue;
            }
            if let Err(e) = budget.check() {
                exhausted = Some(e);
                break;
            }
            if let Some(hit) = rule.evaluate(&scoped) {
                scorer.record(hit, gate == Gate::Enforce);
            }
        }

        Evaluation {
            rules_checked: budget.rules_checked(),
            truncated: clamped || input.body_truncated,
            elapsed: budget.elapsed(),
            enforcing_score: scorer.enforcing,
            verdict: finish_response(scorer),
            exhausted,
        }
    }
}

/// Whether budget exhaustion itself forces enforcement.
///
/// `Allow` (the default) does **not** mean "return Allow": hits already collected
/// are real findings and still count. It means the *unevaluated remainder* does not
/// count against the request. `Block` is the opt-in for operators who would rather
/// reject than pass something they could not finish inspecting.
fn forced_by_policy(exhausted: Option<&Exhausted>) -> bool {
    matches!(
        exhausted.map(|e| e.policy),
        Some(crate::budget::ExhaustedPolicy::Block)
    )
}

fn finish_request(scorer: Scorer, forced: bool) -> RequestVerdict {
    if forced || scorer.reached() {
        RequestVerdict::Block {
            hits: scorer.hits,
            score: scorer.total,
        }
    } else if scorer.hits.is_empty() {
        RequestVerdict::Allow
    } else {
        RequestVerdict::Detected {
            hits: scorer.hits,
            score: scorer.total,
        }
    }
}

/// Assemble the response verdict.
///
/// Budget exhaustion deliberately has no `forced` path here. The `block` policy
/// has nothing to act on: a response cannot be withheld once its status line is
/// downstream, and synthesising `Redact` with an empty hit list would tell the
/// caller to rewrite a span that was never found — at worst blanking a legitimate
/// response because inspection ran slow. Exhaustion is recorded on the evaluation
/// instead, which is what makes it visible without making it destructive.
fn finish_response(scorer: Scorer) -> ResponseVerdict {
    if scorer.reached() {
        ResponseVerdict::Redact {
            hits: scorer.hits,
            score: scorer.total,
        }
    } else if scorer.hits.is_empty() {
        ResponseVerdict::Allow
    } else {
        ResponseVerdict::Detected {
            hits: scorer.hits,
            score: scorer.total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CustomRule;

    #[test]
    fn text_prefix_stops_at_the_first_invalid_byte_without_allocating() {
        assert_eq!(text_prefix(b"union select"), "union select");
        // 0xff is never valid UTF-8. Everything before it is still inspected.
        assert_eq!(text_prefix(b"select\xffdrop"), "select");
        assert_eq!(text_prefix(b"\xff"), "");
        assert_eq!(text_prefix(b""), "");
        // A truncated multi-byte sequence must not panic or split a code point.
        let euro = "€".as_bytes();
        assert_eq!(text_prefix(&euro[..1]), "");
        assert_eq!(text_prefix(euro), "€");
    }

    #[test]
    fn clamp_reports_whether_bytes_were_left_out() {
        assert_eq!(clamp(None, 10), (None, false));
        assert_eq!(
            clamp(Some(b"abc".as_slice()), 10),
            (Some(b"abc".as_slice()), false)
        );
        let (kept, cut) = clamp(Some(b"abcdef".as_slice()), 3);
        assert_eq!(kept, Some(b"abc".as_slice()));
        assert!(cut, "over-cap must be reported, never silently dropped");
        // Exactly at the cap is not truncation.
        assert_eq!(
            clamp(Some(b"abc".as_slice()), 3),
            (Some(b"abc".as_slice()), false)
        );
    }

    #[test]
    fn scorer_keeps_detect_only_hits_out_of_the_enforcing_subtotal() {
        // The whole reason for two subtotals: a category left in `detect` must not
        // be able to push a request over the threshold and cause the block the
        // operator turned it off to avoid.
        let mut s = Scorer::new(5);
        let hit = |score| Hit {
            rule_id: RuleId::custom_wrapping(1),
            category: Category::Xss,
            severity: Severity::Warning,
            score,
            matched_field: MatchedField::Uri,
        };
        s.record(hit(4), false);
        s.record(hit(4), false);
        assert_eq!(s.total, 8, "total counts every hit");
        assert_eq!(s.enforcing, 0);
        assert!(
            !s.reached(),
            "8 detect-only points must not reach a 5 threshold"
        );
        s.record(hit(5), true);
        assert!(s.reached());
        assert_eq!(s.total, 13);
    }

    #[test]
    fn threshold_comparison_is_inclusive() {
        let mut s = Scorer::new(5);
        s.record(
            Hit {
                rule_id: RuleId::custom_wrapping(2),
                category: Category::SqlInjection,
                severity: Severity::Critical,
                score: 5,
                matched_field: MatchedField::Uri,
            },
            true,
        );
        // A single `critical` (5) must reach the default threshold of 5, or the
        // documented default would be off by one rule.
        assert!(s.reached());
    }

    #[test]
    fn custom_ids_are_name_derived_and_stable() {
        let a = custom_id_for("block-legacy-admin");
        assert_eq!(a, custom_id_for("block-legacy-admin"), "must be stable");
        assert!(a.is_custom());
        assert_ne!(a, custom_id_for("block-legacy-admin2"));
        // Position-independence is the point: inserting a rule ahead of another
        // must not renumber it, or historical log lines change meaning.
        assert_ne!(custom_id_for("aaa"), custom_id_for("zzz"));
    }

    #[test]
    fn resolve_gate_honours_the_surface() {
        // Category mode passes through untouched when no override is declared.
        assert_eq!(resolve_gate(Gate::Enforce, None, false), Gate::Enforce);
        // A declared action wins over the category.
        assert_eq!(
            resolve_gate(Gate::Detect, Some(RawMode::Block), false),
            Gate::Enforce
        );
        assert_eq!(
            resolve_gate(Gate::Detect, Some(RawMode::Redact), true),
            Gate::Enforce
        );
        assert_eq!(
            resolve_gate(Gate::Enforce, Some(RawMode::Off), false),
            Gate::Skip
        );
        // Cross-surface actions are rejected at validation; if one ever reaches
        // here it must not grant enforcement.
        assert_eq!(
            resolve_gate(Gate::Detect, Some(RawMode::Redact), false),
            Gate::Detect
        );
        assert_eq!(
            resolve_gate(Gate::Detect, Some(RawMode::Block), true),
            Gate::Detect
        );
    }

    #[test]
    fn modes_map_onto_the_same_gate_from_both_surfaces() {
        assert_eq!(Gate::from(RequestMode::Off), Gate::Skip);
        assert_eq!(Gate::from(ResponseMode::Off), Gate::Skip);
        assert_eq!(Gate::from(RequestMode::Detect), Gate::Detect);
        assert_eq!(Gate::from(ResponseMode::Detect), Gate::Detect);
        // `block` request-side and `redact` response-side are the enforcing modes
        // of their respective surfaces.
        assert_eq!(Gate::from(RequestMode::Block), Gate::Enforce);
        assert_eq!(Gate::from(ResponseMode::Redact), Gate::Enforce);
    }

    #[test]
    fn two_names_deriving_the_same_id_are_rejected_at_build() {
        // The reserved range is large, so a collision has to be searched for rather
        // than written down. The search is deterministic — the same two names every
        // run — so this is a fixed test, not a probabilistic one. Without it the
        // collision guard would be unexercised code protecting the very property
        // that makes stable rule IDs worth having.
        use std::collections::HashMap;
        let mut seen: HashMap<u32, String> = HashMap::new();
        let mut pair = None;
        for i in 0..300_000u32 {
            let name = format!("c{i}");
            let id = custom_id_for(&name).get();
            if let Some(first) = seen.get(&id) {
                pair = Some((first.clone(), name));
                break;
            }
            seen.insert(id, name);
        }
        let (a, b) =
            pair.expect("a collision exists within the searched range");

        let mut cfg = crate::config::WafConfig::default();
        for name in [&a, &b] {
            cfg.custom_rules.insert(
                name.clone(),
                CustomRule {
                    category: Category::SqlInjection,
                    pattern: "x".into(),
                    severity: Severity::Notice,
                    paranoia: Paranoia::default(),
                    action: None,
                },
            );
        }
        let err = RuleEngine::build(
            cfg.validate().expect("config itself is valid"),
            Vec::new(),
            Vec::new(),
        )
        .expect_err("colliding rule IDs must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains(&a) && msg.contains(&b),
            "names both rules: {msg}"
        );
        assert!(msg.contains("rename"), "says what to do about it: {msg}");
    }
}
