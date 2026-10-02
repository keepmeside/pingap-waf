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
    /// Ask the challenge plugin to verify the client.
    Challenge { hits: Vec<Hit>, score: u32 },
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

impl RequestVerdict {
    pub fn hits(&self) -> &[Hit] {
        match self {
            Self::Allow => &[],
            Self::Detected { hits, .. }
            | Self::Block { hits, .. }
            | Self::Challenge { hits, .. } => hits,
        }
    }

    pub fn score(&self) -> u32 {
        match self {
            Self::Allow => 0,
            Self::Detected { score, .. }
            | Self::Block { score, .. }
            | Self::Challenge { score, .. } => *score,
        }
    }

    pub fn is_enforcing(&self) -> bool {
        matches!(self, Self::Block { .. } | Self::Challenge { .. })
    }

    pub fn is_challenge(&self) -> bool {
        matches!(self, Self::Challenge { .. })
    }
}

impl ResponseVerdict {
    pub fn hits(&self) -> &[Hit] {
        match self {
            Self::Allow => &[],
            Self::Detected { hits, .. } | Self::Redact { hits, .. } => hits,
        }
    }

    pub fn score(&self) -> u32 {
        match self {
            Self::Allow => 0,
            Self::Detected { score, .. } | Self::Redact { score, .. } => *score,
        }
    }

    pub fn is_enforcing(&self) -> bool {
        matches!(self, Self::Redact { .. })
    }
}

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
    challenge_only: bool,
    block_seen: bool,
    threshold: u32,
}

impl Scorer {
    fn new(threshold: u32) -> Self {
        Self {
            hits: Vec::new(),
            total: 0,
            enforcing: 0,
            challenge_only: true,
            block_seen: false,
            threshold,
        }
    }

    fn record(&mut self, hit: Hit, gate: Gate) {
        self.total = self.total.saturating_add(hit.score);
        if matches!(gate, Gate::Enforce | Gate::Challenge) {
            self.enforcing = self.enforcing.saturating_add(hit.score);
            if gate == Gate::Enforce {
                self.block_seen = true;
                self.challenge_only = false;
            }
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
/// Crate-visible for the prefilter, which must see the exact body prefix the
/// rules see — its own clamping logic would be a second definition of
/// "inspectable bytes" that can drift.
pub(crate) fn text_prefix(bytes: &[u8]) -> &str {
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

/// Visit every form of `value` that a rule could match in, in the order the
/// engine tries them. Three forms, not one: the raw bytes; the
/// percent-decoded bytes, only when decoding actually changed something
/// (because `%27` reaches the origin as `'`); and the form-urlencoded
/// reading where `+` is a space, only when the value contains one (because
/// that is what a query string and a form body are). Matching only the raw
/// form is bypassed by the cheapest possible trick, and matching only the
/// decoded form would miss a pattern written against an encoded sequence
/// such as `%2e%2e%2f`.
///
/// The visitor returns `true` to stop; forms after the stop are not even
/// computed, so the extra scans cost nothing on a path that has already
/// answered.
///
/// One definition of "the forms of a field", shared by the matching path
/// ([`find_both_forms`]) and the prefilter's prescan. Two copies would
/// drift, and drift is unsound in both directions: a form only the rules
/// scan is a needle the gate never sees, so an absent rule would be skipped
/// while it could match; a form only the prescan scans is wasted work.
pub(crate) fn each_form(value: &str, visit: &mut dyn FnMut(&str) -> bool) {
    if visit(value) {
        return;
    }
    if let Ok(std::borrow::Cow::Owned(decoded)) = urlencoding::decode(value)
        && visit(&decoded)
    {
        return;
    }
    // `+` is a space in `application/x-www-form-urlencoded`, which is what a
    // query string and a form body are. Percent-decoding alone leaves it
    // literal, so `?q=UNION+SELECT+pw` reads as one long token and every
    // pattern that requires whitespace between keywords misses it — while the
    // origin sees the spaces. This is the cheapest bypass after
    // percent-encoding, and it costs a third scan only for values that
    // actually contain a `+`.
    if value.contains('+') {
        let spaced = value.replace('+', " ");
        let decoded = urlencoding::decode(&spaced)
            .map(std::borrow::Cow::into_owned)
            .unwrap_or(spaced);
        visit(&decoded);
    }
}

/// Run `find` against a field value in every form it could reach the origin
/// as ([`each_form`]), reporting the first match.
///
/// The returned range is only meaningful when the match was on the raw form; a
/// decoded match reports the range within the decoded string, which does not map back
/// to the original bytes. That is why response bodies — the only place a range is
/// used to rewrite bytes — are matched raw, by [`find_in_response`].
fn find_both_forms(
    value: &str,
    find: &dyn Fn(&str) -> Option<std::ops::Range<usize>>,
) -> Option<std::ops::Range<usize>> {
    let mut at = None;
    each_form(value, &mut |form| {
        if at.is_none() {
            at = find(form);
        }
        at.is_some()
    });
    at
}

/// Walk every field of a request a rule may inspect, in evaluation order, and
/// report the first match.
///
/// One definition of "what a rule can see", shared by the native detectors and by
/// operator-authored custom rules. Two copies would drift, and the drift shows up
/// as a payload caught in one field and missed in another — which is exactly the
/// defect the inherited detectors shipped, four times over, as four private
/// skip-lists.
///
/// `inspect_header` decides which headers participate. It is a parameter rather
/// than a constant so the policy lives in one place that a test can point at,
/// not scattered across detector modules.
pub fn find_in_request(
    input: &RequestInput<'_>,
    inspect_header: &dyn Fn(&str) -> bool,
    find: &dyn Fn(&str) -> Option<std::ops::Range<usize>>,
) -> Option<MatchedField> {
    if find_both_forms(input.method, find).is_some() {
        return Some(MatchedField::Method);
    }
    if find_both_forms(input.uri, find).is_some() {
        return Some(MatchedField::Uri);
    }
    for (key, value) in input.query {
        if find_both_forms(value, find).is_some() {
            return Some(MatchedField::Query {
                key: (*key).to_string(),
            });
        }
    }
    for (name, value) in input.headers {
        if !inspect_header(name) {
            continue;
        }
        if find_both_forms(value, find).is_some() {
            return Some(MatchedField::Header {
                name: (*name).to_string(),
            });
        }
    }
    let at = find_both_forms(text_prefix(input.body?), find)?;
    Some(MatchedField::Body {
        offset: at.start,
        len: at.len(),
    })
}

/// The response-side counterpart. Headers, then the bounded body prefix.
///
/// **No percent-decoding here.** A response body is HTML or JSON, not a
/// percent-encoded field, so decoding buys nothing — and it would break redaction: a
/// match found in a decoded copy reports offsets into that copy, and masking the
/// original at those offsets would overwrite the wrong bytes. Matching raw keeps every
/// reported range valid against the bytes that will actually be rewritten.
pub fn find_in_response(
    input: &ResponseInput<'_>,
    inspect_header: &dyn Fn(&str) -> bool,
    find: &dyn Fn(&str) -> Option<std::ops::Range<usize>>,
) -> Option<MatchedField> {
    for (name, value) in input.headers {
        if !inspect_header(name) {
            continue;
        }
        if find(value).is_some() {
            return Some(MatchedField::ResponseHeader {
                name: (*name).to_string(),
            });
        }
    }
    let at = find(text_prefix(input.body_chunk?))?;
    Some(MatchedField::ResponseBody {
        offset: at.start,
        len: at.len(),
    })
}

/// Header policy for operator-authored custom rules: inspect everything.
///
/// A custom rule exists because the operator wanted something specific matched, so
/// silently excluding fields from it would be surprising in the worst direction.
fn every_header(_name: &str) -> bool {
    true
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
    /// The prefilter's needle set, extracted from the same pattern string
    /// that was compiled above. `None` leaves the rule ungated.
    needles: Option<Vec<String>>,
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
    fn required_literals(&self) -> Option<&[String]> {
        self.needles.as_deref()
    }
}

impl CompiledCustomRule {
    /// Match range within `text`, or `None`.
    ///
    /// A `fancy-regex` error — a hit backtrack limit, most plausibly — is treated
    /// as **no match**, not as a match and not as a panic. That is a deliberate
    /// fail-open at the single-rule level: the alternative is blocking traffic
    /// because a pattern was too expensive, which turns an operator's bad regex
    /// into an outage. The budget is what makes the cost visible.
    fn find_at(&self, text: &str) -> Option<std::ops::Range<usize>> {
        self.pattern.find(text).ok().flatten().map(|m| m.range())
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
        let field =
            find_in_request(input, &every_header, &|text| self.find_at(text))?;
        Some(self.hit(field))
    }
}

impl ResponseRule for CompiledCustomRule {
    fn evaluate(&self, input: &ResponseInput<'_>) -> Option<Hit> {
        let field =
            find_in_response(input, &every_header, &|text| self.find_at(text))?;
        Some(self.hit(field))
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
    /// One literal gate per surface, built from the same rule lists. A rule
    /// whose needles are absent from a request is skipped before its regex
    /// runs — see [`crate::prefilter`] for the soundness contract.
    request_prefilter: crate::prefilter::Prefilter,
    response_prefilter: crate::prefilter::Prefilter,
    /// Each rule's gate, resolved once at build rather than per evaluation:
    /// it depends only on the config and the rule, never on the input.
    /// `None` means the rule does not participate — its category is `off` or
    /// its own action is, or it sits above the configured paranoia level.
    /// The prescan's present-marking and the evaluation loop read the same
    /// answer here, so the two can never disagree about which rules run.
    request_gates: Vec<Option<Gate>>,
    response_gates: Vec<Option<Gate>>,
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
        // Built after the custom rules land in their lists, so the gate sees
        // the same rules evaluation will walk.
        let request_prefilter =
            crate::prefilter::Prefilter::build(&request_rules);
        let response_prefilter =
            crate::prefilter::Prefilter::build(&response_rules);
        // Resolved once, read per evaluation: the gate is config-and-rule
        // state, so resolving it per request would pay the same lookups
        // twice — once to mark non-participating rules present for the
        // prescan, once to skip them in the loop.
        let request_gates = resolve_gates(&config, &request_rules, false);
        let response_gates = resolve_gates(&config, &response_rules, true);
        Ok(Self {
            config,
            request_rules,
            response_rules,
            request_prefilter,
            response_prefilter,
            request_gates,
            response_gates,
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
        needles: crate::prefilter::required_needles(&spec.pattern),
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
    Challenge,
}

impl From<RequestMode> for Gate {
    fn from(m: RequestMode) -> Self {
        match m {
            RequestMode::Off => Self::Skip,
            RequestMode::Detect => Self::Detect,
            RequestMode::Block => Self::Enforce,
            RequestMode::Challenge => Self::Challenge,
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
        Some(RawMode::Challenge) if !response_side => Gate::Challenge,
        Some(RawMode::Redact) if response_side => Gate::Enforce,
        // Validation rejects an action its surface cannot perform, so a loaded
        // config never reaches here. Degrading to `Detect` rather than `Enforce`
        // means a future construction path that skips validation cannot silently
        // gain enforcement it was never granted.
        Some(_) => Gate::Detect,
    }
}

/// Every rule's gate for one surface, `None` for a rule that does not
/// participate.
///
/// Input-independent by construction — mode, action override and paranoia are
/// all config-and-rule state — so this is resolved once at build and both the
/// prescan and the evaluation loop read the same answer, one array read per
/// rule per evaluation instead of a mode lookup and a trait call.
fn resolve_gates<R: Rule + ?Sized>(
    config: &ValidatedConfig,
    rules: &[Box<R>],
    response_side: bool,
) -> Vec<Option<Gate>> {
    rules
        .iter()
        .map(|rule| {
            let gate = if response_side {
                resolve_gate(
                    config.response_mode(rule.category()).into(),
                    rule.action_override(),
                    true,
                )
            } else {
                resolve_gate(
                    config.request_mode(rule.category()).into(),
                    rule.action_override(),
                    false,
                )
            };
            (gate != Gate::Skip && rule.paranoia() <= config.paranoia)
                .then_some(gate)
        })
        .collect()
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
        let mut scorer = Scorer::new(cfg.anomaly_threshold);
        let mut exhausted = None;

        // One literal pass over the inspectable bytes decides which rules can
        // possibly match; the absent rest is skipped below, before the budget.
        // `rules_checked` will read lower than an unfiltered run — by design,
        // skipped rules checked nothing — and exhaustion can only lift, never
        // newly appear: a rule proven absent is a completed evaluation, not an
        // unfinished one, so evaluations finish more often than the
        // unfiltered engine's, and with `on_budget_exhausted = block` a body
        // whose absent rules would have spent the budget is allowed as
        // verified rather than blocked as unfinished. That direction is the
        // documented behaviour, not a regression to hide.
        //
        // Rules the loop below cannot run read as present here, so the walk
        // can early-exit once every rule it could run is accounted for, and a
        // config with every category off pays no scan at all. The gates were
        // resolved at build; marking them present changes no verdict because
        // the loop skips them before it consults the mask.
        let mut present = self.request_prefilter.present_mask();
        for (index, gate) in self.request_gates.iter().enumerate() {
            if gate.is_none() {
                present[index] = true;
            }
        }
        self.request_prefilter.mark_request(&scoped, &mut present);

        // The budget clock starts after the prescan: charging the scan to the
        // rule budget would spend it before the first rule runs, and an input
        // that marks most rules present — no skip savings, full scan cost —
        // could lose late rules that the unfiltered engine still reached. The
        // budget bounds rule evaluation, exactly as it did before the
        // prefilter; `elapsed` reports rule time, not prescan time.
        let mut budget = Budget::new(cfg.budget, cfg.on_budget_exhausted);

        for (index, rule) in self.request_rules.iter().enumerate() {
            let Some(gate) = self.request_gates[index] else {
                continue;
            };
            if !present[index] {
                continue;
            }
            // Between rules, not only after the loop: one catastrophic pattern
            // must not be able to spend the whole budget unobserved.
            if let Err(e) = budget.check() {
                exhausted = Some(e);
                break;
            }
            if let Some(hit) = rule.evaluate(&scoped) {
                scorer.record(hit, gate);
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
        let mut scorer = Scorer::new(cfg.anomaly_threshold);
        let mut exhausted = None;

        // Same shape as the request loop: one raw-only literal pass — header
        // values, then the body prefix, mirroring `find_in_response` — and
        // rules the loop below cannot run read as present so the walk can
        // early-exit. See the request-side prescan comment for the budget
        // interaction; it is the same here.
        let mut present = self.response_prefilter.present_mask();
        for (index, gate) in self.response_gates.iter().enumerate() {
            if gate.is_none() {
                present[index] = true;
            }
        }
        self.response_prefilter.mark_response(&scoped, &mut present);

        // Off the prescan, as on the request side.
        let mut budget = Budget::new(cfg.budget, cfg.on_budget_exhausted);

        for (index, rule) in self.response_rules.iter().enumerate() {
            let Some(gate) = self.response_gates[index] else {
                continue;
            };
            if !present[index] {
                continue;
            }
            if let Err(e) = budget.check() {
                exhausted = Some(e);
                break;
            }
            if let Some(hit) = rule.evaluate(&scoped) {
                scorer.record(hit, gate);
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
        if !forced && scorer.challenge_only && !scorer.block_seen {
            RequestVerdict::Challenge {
                hits: scorer.hits,
                score: scorer.total,
            }
        } else {
            RequestVerdict::Block {
                hits: scorer.hits,
                score: scorer.total,
            }
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
        s.record(hit(4), Gate::Detect);
        s.record(hit(4), Gate::Detect);
        assert_eq!(s.total, 8, "total counts every hit");
        assert_eq!(s.enforcing, 0);
        assert!(
            !s.reached(),
            "8 detect-only points must not reach a 5 threshold"
        );
        s.record(hit(5), Gate::Enforce);
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
            Gate::Enforce,
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

    #[test]
    fn the_prefilter_never_changes_a_verdict_on_the_frozen_corpus() {
        // The prefilter's promise is narrow and absolute: skipping a rule
        // whose literals are absent must never change what the engine
        // decides. A present rule marked absent is an attack walking
        // through, which is why this test exists rather than trusting the
        // extraction heuristics. It runs the frozen corpus — the same tree
        // and hash the regression gate in `tests/corpus.rs` freezes —
        // through the same engine twice, once with the real literal gate
        // and once with the gate forced open for every rule, and requires
        // the two runs to agree on everything an operator or a log can
        // see: verdict (which carries the hits), enforcing score,
        // exhaustion, truncation.
        //
        // `rules_checked` and `elapsed` are excluded by design. A skipped
        // rule checks nothing — that is the point — and timing is not a
        // behaviour. Everything else must be identical.
        use std::path::{Path, PathBuf};

        const FROZEN_TREE_HASH: &str =
            "ea65120d61d1b7b727944697c53df0ed9e6ae61975e8f3e6fc69d45fc88e1822";
        const FROZEN_FILE_COUNT: usize = 726;

        /// What one evaluation looked like, minus the two fields the
        /// prefilter is allowed to change.
        #[derive(Debug, Clone, PartialEq)]
        struct Snap<V> {
            verdict: V,
            enforcing_score: u32,
            exhausted: Option<Exhausted>,
            truncated: bool,
        }

        fn snap<V: Clone + PartialEq>(e: &Evaluation<V>) -> Snap<V> {
            Snap {
                verdict: e.verdict.clone(),
                enforcing_score: e.enforcing_score,
                exhausted: e.exhausted.clone(),
                truncated: e.truncated,
            }
        }

        /// Every corpus file, verified as the frozen tree first: an
        /// equivalence run over an edited corpus would still prove the
        /// property, but over fewer cases than anyone believed.
        fn corpus_cases(root: &Path) -> Vec<(String, String)> {
            use sha2::Digest;
            let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
            let mut stack = vec![root.to_path_buf()];
            while let Some(dir) = stack.pop() {
                let mut children: Vec<PathBuf> = std::fs::read_dir(&dir)
                    .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .collect();
                children.sort();
                for path in children {
                    if path.is_dir() {
                        stack.push(path);
                        continue;
                    }
                    let name =
                        path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if name == "MANIFEST.sha256" || name == "TREE_HASH" {
                        continue;
                    }
                    let rel = path
                        .strip_prefix(root)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    let body = std::fs::read(&path).unwrap_or_else(|e| {
                        panic!("read {}: {e}", path.display())
                    });
                    entries.push((rel, body));
                }
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut h = sha2::Sha256::new();
            for (rel, body) in &entries {
                h.update(rel.as_bytes());
                h.update([0u8]);
                h.update(body);
                h.update([0u8]);
            }
            let hash = hex::encode(h.finalize());
            assert_eq!(
                entries.len(),
                FROZEN_FILE_COUNT,
                "corpus file count changed; the equivalence run would not \
                 cover what it claims to"
            );
            assert_eq!(
                hash, FROZEN_TREE_HASH,
                "corpus contents changed; re-run against the frozen tree"
            );
            entries
                .into_iter()
                .map(|(rel, body)| {
                    let case = String::from_utf8(body)
                        .unwrap_or_else(|e| panic!("{rel} is not UTF-8: {e}"));
                    (rel, case)
                })
                .collect()
        }

        /// One corpus case through all three walks the gates perform:
        /// request-side as a query value (the regression gate's shape),
        /// request-side as a body (the clamped text prefix), and
        /// response-side as a header plus body prefix. The response arm is
        /// equivalence-only by nature: corpus text is request-shaped, so it
        /// walks real bytes but rarely fires a response rule. Firing
        /// coverage of every carrier — response ones included — is pinned
        /// by the probe test below.
        fn run_case(
            engine: &RuleEngine,
            case: &str,
        ) -> (
            Snap<RequestVerdict>,
            Snap<RequestVerdict>,
            Snap<ResponseVerdict>,
        ) {
            let query = [("q", case)];
            let as_query = RequestInput {
                method: "GET",
                uri: "/",
                headers: &[],
                query: &query,
                body: None,
                client_ip: None,
                body_truncated: false,
            };
            let as_body = RequestInput {
                method: "POST",
                uri: "/",
                headers: &[],
                query: &[],
                body: Some(case.as_bytes()),
                client_ip: None,
                body_truncated: false,
            };
            let headers = [("x-note", case)];
            let as_response = ResponseInput {
                status: 200,
                headers: &headers,
                body_chunk: Some(case.as_bytes()),
                request_score: 0,
                body_truncated: false,
            };
            (
                snap(&engine.evaluate_request(&as_query)),
                snap(&engine.evaluate_request(&as_body)),
                snap(&engine.evaluate_response(&as_response)),
            )
        }

        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../spikes/detector-baseline/corpus");
        assert!(
            root.is_dir(),
            "the frozen corpus is missing at {} — this test cannot run \
             without it",
            root.display()
        );
        let cases = corpus_cases(&root);

        let cfg = crate::config::WafConfig {
            categories: Category::ALL
                .iter()
                .map(|c| (c.key().to_string(), RawMode::Detect))
                .collect(),
            paranoia: Paranoia::MIN,
            // Generous, same as the regression gate: a corpus case
            // exhausting the budget would make the two runs differ for a
            // reason that is not the prefilter.
            budget_ms: 10_000,
            ..Default::default()
        };
        let mut engine = RuleEngine::build(
            cfg.validate().expect("corpus config is valid"),
            crate::detectors::request_rules(),
            crate::detectors::response_rules(),
        )
        .expect("native ruleset builds");

        // Pass one: the real gate.
        let real: Vec<_> = cases
            .iter()
            .map(|(_, case)| run_case(&engine, case))
            .collect();

        // The vacuity guard: an equivalence test where nothing ever fires,
        // or everything fires, proves nothing about the skip path. It counts
        // the request arms only — corpus text is request-shaped, and firing
        // coverage of the response carriers is pinned per carrier by the
        // probe test below, not by corpus text.
        let firing = real
            .iter()
            .filter(|(q, b, _)| {
                !q.verdict.hits().is_empty() || !b.verdict.hits().is_empty()
            })
            .count();
        let clean = real
            .iter()
            .filter(|(q, b, _)| {
                q.verdict.hits().is_empty() && b.verdict.hits().is_empty()
            })
            .count();
        assert!(firing > 0, "no corpus case fired; the gate is untested");
        assert!(
            clean > 0,
            "every corpus case fired; the skip path is untested"
        );

        // Pass two: both gates forced open for every rule, which is
        // byte-for-byte the engine as it ran before the prefilter existed.
        engine.request_prefilter =
            crate::prefilter::Prefilter::always(engine.request_rules.len());
        engine.response_prefilter =
            crate::prefilter::Prefilter::always(engine.response_rules.len());

        for (i, (rel, case)) in cases.iter().enumerate() {
            let (q, b, r) = &real[i];
            let (q2, b2, r2) = run_case(&engine, case);
            assert_eq!(
                &q2, q,
                "the gate changed the query-form verdict on {rel}"
            );
            assert_eq!(
                &b2, b,
                "the gate changed the body-form verdict on {rel}"
            );
            assert_eq!(
                &r2, r,
                "the gate changed the response verdict on {rel}"
            );
        }
    }

    #[test]
    fn a_rule_the_gate_proves_absent_checks_nothing() {
        // What the skip costs the budget: a rule the gate proves absent never
        // reaches `budget.check`, so an evaluation finishes more often than
        // the unfiltered engine's — `exhausted` can lift, never newly appear,
        // and `on_budget_exhausted = block` fires less because a body whose
        // rules are all provably absent is allowed as verified rather than
        // blocked as unfinished. `rules_checked` is the deterministic
        // witness; pinning exhaustion itself would need a wall-clock budget,
        // which is flaky by nature.
        let cfg = crate::config::WafConfig {
            categories: Category::ALL
                .iter()
                .map(|c| (c.key().to_string(), RawMode::Detect))
                .collect(),
            paranoia: Paranoia::MIN,
            budget_ms: 10_000,
            custom_rules: [
                (
                    "present".to_string(),
                    CustomRule {
                        category: Category::ProtocolEnforcement,
                        pattern: r"(?i)unionselectprobe".to_string(),
                        severity: Severity::Notice,
                        paranoia: Paranoia::MIN,
                        action: None,
                    },
                ),
                (
                    "absent".to_string(),
                    CustomRule {
                        category: Category::ProtocolEnforcement,
                        pattern: r"(?i)neverpresentprobe".to_string(),
                        severity: Severity::Notice,
                        paranoia: Paranoia::MIN,
                        action: None,
                    },
                ),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        let mut engine = RuleEngine::build(
            cfg.validate().expect("budget config is valid"),
            Vec::new(),
            Vec::new(),
        )
        .expect("two custom rules build");
        let input = RequestInput {
            method: "POST",
            uri: "/",
            headers: &[],
            query: &[],
            body: Some(b"unionselectprobe"),
            client_ip: None,
            body_truncated: false,
        };
        let gated = engine.evaluate_request(&input);
        assert_eq!(
            gated.rules_checked, 1,
            "the absent rule must not spend a check"
        );
        assert_eq!(gated.exhausted, None);
        assert!(
            !gated.verdict.hits().is_empty(),
            "the present rule must fire"
        );
        engine.request_prefilter =
            crate::prefilter::Prefilter::always(engine.request_rules.len());
        let unfiltered = engine.evaluate_request(&input);
        assert_eq!(
            unfiltered.rules_checked, 2,
            "forced open, both rules must check"
        );
        // Skipping a rule that matches nothing changes nothing an operator
        // or a log can see.
        assert_eq!(gated.verdict, unfiltered.verdict);
    }

    #[test]
    fn every_carrier_the_gate_walks_stays_pinned_by_a_firing_probe() {
        // The corpus run above proves the two gates agree on corpus text, but
        // agreement alone cannot catch a scan line missing from the walk: the
        // gated run would skip the rule and the forced-open run would reach
        // it, and they would disagree — loudly. What the corpus cannot pin is
        // firing content per carrier, because its text is request-shaped. So
        // every carrier the prescan walks — request method, URI, query,
        // header, body; response header, body — gets a probe that fires
        // through that carrier alone: the real gate must collect the hit, and
        // the forced-open run must agree. Delete a scan line and its probe
        // loses the hit the forced-open run still collects.
        let cfg = crate::config::WafConfig {
            categories: Category::ALL
                .iter()
                .map(|c| (c.key().to_string(), RawMode::Detect))
                .collect(),
            paranoia: Paranoia::MIN,
            budget_ms: 10_000,
            // The method carrier needs a rule authored for a method token;
            // the native ruleset is written for path, query, header and body
            // content.
            custom_rules: [(
                "webdav-method".to_string(),
                CustomRule {
                    category: Category::ProtocolEnforcement,
                    pattern: r"(?i)\bpropfind\b".to_string(),
                    severity: Severity::Error,
                    paranoia: Paranoia::MIN,
                    action: None,
                },
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        let mut engine = RuleEngine::build(
            cfg.validate().expect("carrier config is valid"),
            crate::detectors::request_rules(),
            crate::detectors::response_rules(),
        )
        .expect("native ruleset builds");

        // Payloads already verified to fire elsewhere in the suite: the
        // User-Agent SQL-injection regression fixture, and the two response
        // fixtures from the detector lineage test.
        let sqli = "Mozilla/5.0 ' UNION SELECT pw FROM users --";
        let leak = "Warning: mysql_connect(): Access denied for user 'root'@'localhost'";
        let shell = "<?php eval($_POST['cmd']); ?>";

        let uri = format!("/search {sqli}");
        let query = [("q", sqli)];
        let request_headers = [("user-agent", sqli)];
        let request_probes: Vec<(&str, RequestInput)> = vec![
            (
                "method",
                RequestInput {
                    method: "PROPFIND",
                    uri: "/",
                    headers: &[],
                    query: &[],
                    body: None,
                    client_ip: None,
                    body_truncated: false,
                },
            ),
            (
                "uri",
                RequestInput {
                    method: "GET",
                    uri: &uri,
                    headers: &[],
                    query: &[],
                    body: None,
                    client_ip: None,
                    body_truncated: false,
                },
            ),
            (
                "query",
                RequestInput {
                    method: "GET",
                    uri: "/",
                    headers: &[],
                    query: &query,
                    body: None,
                    client_ip: None,
                    body_truncated: false,
                },
            ),
            (
                "header",
                RequestInput {
                    method: "GET",
                    uri: "/",
                    headers: &request_headers,
                    query: &[],
                    body: None,
                    client_ip: None,
                    body_truncated: false,
                },
            ),
            (
                "body",
                RequestInput {
                    method: "POST",
                    uri: "/",
                    headers: &[],
                    query: &[],
                    body: Some(sqli.as_bytes()),
                    client_ip: None,
                    body_truncated: false,
                },
            ),
        ];
        let response_headers = [("x-error", leak)];
        let response_probes: Vec<(&str, ResponseInput)> = vec![
            (
                "response header",
                ResponseInput {
                    status: 200,
                    headers: &response_headers,
                    body_chunk: Some(b"ok"),
                    request_score: 0,
                    body_truncated: false,
                },
            ),
            (
                "response body",
                ResponseInput {
                    status: 200,
                    headers: &[("content-type", "text/html")],
                    body_chunk: Some(shell.as_bytes()),
                    request_score: 0,
                    body_truncated: false,
                },
            ),
        ];

        // Pass one: the real gate must collect a hit through every carrier —
        // a probe that fires nothing pins nothing.
        let gated_request: Vec<_> = request_probes
            .iter()
            .map(|(_, input)| engine.evaluate_request(input))
            .collect();
        let gated_response: Vec<_> = response_probes
            .iter()
            .map(|(_, input)| engine.evaluate_response(input))
            .collect();
        for ((label, _), e) in request_probes.iter().zip(&gated_request) {
            assert!(
                !e.verdict.hits().is_empty(),
                "the {label} probe fired nothing — a carrier without a \
                 firing probe cannot catch its scan line going missing"
            );
        }
        for ((label, _), e) in response_probes.iter().zip(&gated_response) {
            assert!(
                !e.verdict.hits().is_empty(),
                "the {label} probe fired nothing — a carrier without a \
                 firing probe cannot catch its scan line going missing"
            );
        }

        // Pass two: both gates forced open, byte-for-byte the unfiltered
        // engine. Every carrier's observable outcome must agree.
        engine.request_prefilter =
            crate::prefilter::Prefilter::always(engine.request_rules.len());
        engine.response_prefilter =
            crate::prefilter::Prefilter::always(engine.response_rules.len());
        for ((label, input), gated) in request_probes.iter().zip(&gated_request)
        {
            let open = engine.evaluate_request(input);
            assert_eq!(
                open.verdict, gated.verdict,
                "the gate changed the {label} verdict"
            );
            assert_eq!(
                open.enforcing_score, gated.enforcing_score,
                "the gate changed the {label} enforcing score"
            );
            assert_eq!(
                open.exhausted, gated.exhausted,
                "the gate changed the {label} exhaustion"
            );
            assert_eq!(
                open.truncated, gated.truncated,
                "the gate changed the {label} truncation"
            );
        }
        for ((label, input), gated) in
            response_probes.iter().zip(&gated_response)
        {
            let open = engine.evaluate_response(input);
            assert_eq!(
                open.verdict, gated.verdict,
                "the gate changed the {label} verdict"
            );
            assert_eq!(
                open.enforcing_score, gated.enforcing_score,
                "the gate changed the {label} enforcing score"
            );
            assert_eq!(
                open.exhausted, gated.exhausted,
                "the gate changed the {label} exhaustion"
            );
            assert_eq!(
                open.truncated, gated.truncated,
                "the gate changed the {label} truncation"
            );
        }
    }
}
