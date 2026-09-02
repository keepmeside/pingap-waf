//! Typed WAF configuration, and the validation that keeps an invalid ruleset off
//! the request path.
//!
//! Every rejection names the offending key. A config error that surfaces as a
//! failed request instead of a failed validation is a config error the operator
//! finds in production.

use crate::budget::ExhaustedPolicy;
use crate::categories::Category;
use crate::rule::Paranoia;
use std::collections::BTreeMap;
use std::time::Duration;

/// Enforcement mode for a request-side category.
///
/// Response-side categories use [`ResponseMode`] instead. They are separate types
/// on purpose: the response body hook returns a result with no `Respond` variant,
/// and status and headers are already downstream by the time it runs, so `Block`
/// is not expressible there. Sharing one enum would let a config express a mode
/// the runtime cannot honour, and the natural failure would be a `block` that
/// silently behaves as `redact` — an operator believing a leak is suppressed when
/// it is only rewritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestMode {
    /// Category does not participate. No hits, no score contribution.
    Off,
    /// Evaluate and record hits; never reject. The default, because a baseline run
    /// of the inherited patterns over 560 benign requests measured a 35.4%
    /// false-positive rate — blocking on those out of the box would break roughly
    /// one request in three.
    #[default]
    Detect,
    /// Evaluate and reject when the anomaly threshold is crossed.
    Block,
}

/// Enforcement mode for a response-side category.
///
/// There is no `Block`. See [`RequestMode`] for why, and
/// [`Category::is_response_side`](crate::categories::Category::is_response_side).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    Off,
    #[default]
    Detect,
    /// Rewrite the matched span out of the response body. Not a denial: the
    /// status line has already been sent, so the response still completes with
    /// its original status.
    Redact,
}

/// A mode value as it arrives from config, before it is known which surface the
/// category belongs to.
///
/// Parsing is deliberately permissive so validation can produce a good error
/// message. `block` on a response-side category must fail with the key named,
/// not silently degrade to `redact`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawMode {
    Off,
    Detect,
    Block,
    Redact,
}

/// Configuration errors. Each names the key at fault.
#[derive(Debug, PartialEq, Eq, snafu::Snafu)]
pub enum ConfigError {
    #[snafu(display(
        "waf: category `{key}` does not exist; valid categories: {valid}"
    ))]
    UnknownCategory { key: String, valid: String },

    #[snafu(display(
        "waf: category `{category}` is response-side and cannot be set to \
         `block` — the response body hook cannot reject a response, and its \
         status line is already sent. Use `redact` to rewrite the matched span, \
         or `detect` to record it only"
    ))]
    BlockOnResponseCategory { category: String },

    #[snafu(display(
        "waf: category `{category}` is request-side and cannot be set to \
         `redact` — request-side enforcement rejects the request rather than \
         rewriting it. Use `block`, or `detect` to record only"
    ))]
    RedactOnRequestCategory { category: String },

    #[snafu(display(
        "waf: `paranoia` is {value}, which is out of range; expected 1..=4"
    ))]
    ParanoiaOutOfRange { value: u8 },

    #[snafu(display(
        "waf: `anomaly_threshold` is 0, which would block every request that \
         matches any rule at all. Set it above the score of a single rule, or \
         use `mode = \"detect\"` to record without blocking"
    ))]
    ZeroThreshold,

    #[snafu(display(
        "waf: `budget_ms` is 0 — evaluation would always be \
                     immediately over budget and no rule would ever run"
    ))]
    ZeroBudget,

    #[snafu(display(
        "waf: custom rule `{name}` has an unparsable pattern: {reason}"
    ))]
    BadCustomPattern { name: String, reason: String },

    #[snafu(display(
        "waf: custom rule `{name}` pattern is too costly to evaluate safely \
         ({reason}). `fancy-regex` backtracks, so a catastrophic pattern is an \
         availability risk for every domain on this process"
    ))]
    CostlyCustomPattern { name: String, reason: String },

    #[snafu(display(
        "waf: custom rule `{name}` declares `action = \"{action}\"`, which is \
         not available on category `{category}`. Available there: {available}"
    ))]
    CustomRuleActionUnavailable {
        name: String,
        category: String,
        action: String,
        available: String,
    },

    #[snafu(display(
        "waf: `body_inspect_limit` is 0 — no body would ever be \
                     inspected, which silently disables body detection"
    ))]
    ZeroBodyLimit,

    #[snafu(display(
        "waf: custom rules `{name}` and `{other}` both derive rule ID {id}. \
         Rule IDs are derived from the rule name so they stay stable across \
         config edits; rename one of the two"
    ))]
    CustomRuleIdCollision {
        name: String,
        other: String,
        id: u32,
    },
}

/// An operator-authored rule.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CustomRule {
    /// Category this rule is attributed to. Determines its available actions.
    pub category: Category,
    /// `fancy-regex` pattern.
    pub pattern: String,
    #[serde(default = "default_custom_severity")]
    pub severity: crate::rule::Severity,
    #[serde(default)]
    pub paranoia: Paranoia,
    /// Optional explicit action. Defaults to the category's configured mode.
    #[serde(default)]
    pub action: Option<RawMode>,
}

fn default_custom_severity() -> crate::rule::Severity {
    crate::rule::Severity::Warning
}

/// A custom rule that has passed validation, carrying its compiled pattern.
///
/// Validation must compile the pattern anyway in order to reject an unparsable
/// one, so the compiled artifact travels onward instead of being discarded and
/// rebuilt. Compiling twice would double the regex work on every config load and
/// every reload, and would put a second pattern-failure point *after* the gate
/// that is supposed to be the only one.
#[derive(Debug, Clone)]
pub struct ValidatedCustomRule {
    spec: CustomRule,
    pattern: fancy_regex::Regex,
}

impl ValidatedCustomRule {
    /// The rule as written in config: category, severity, paranoia, action.
    pub fn spec(&self) -> &CustomRule {
        &self.spec
    }

    /// The compiled pattern. Cheap to clone — `fancy_regex::Regex` shares its
    /// program behind an `Arc`.
    pub fn pattern(&self) -> &fancy_regex::Regex {
        &self.pattern
    }
}

/// A named WAF profile, bindable per domain (`waf:strict`, `waf:audit-only`).
///
/// Profiles are the isolation unit. Two domains that need independently counted
/// policy get two named profiles, because plugin instances are process-global and
/// keyed by name — a single profile shared across domains shares its state.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WafConfig {
    /// Per-category enforcement mode, as written in config.
    #[serde(default)]
    pub categories: BTreeMap<String, RawMode>,

    /// Rules below this paranoia level do not participate.
    #[serde(default)]
    pub paranoia: Paranoia,

    /// Accumulated score at which a request is rejected, when its categories are
    /// in `block` mode.
    #[serde(default = "default_threshold")]
    pub anomaly_threshold: u32,

    /// Per-request evaluation budget in milliseconds.
    #[serde(default = "default_budget_ms")]
    pub budget_ms: u64,

    /// What to do when the budget is exhausted mid-evaluation.
    #[serde(default)]
    pub on_budget_exhausted: ExhaustedPolicy,

    /// Maximum request-body bytes to inspect. Capped independently of
    /// `client_max_body_size` so the two limits cannot silently disagree.
    #[serde(default = "default_body_limit")]
    pub body_inspect_limit: usize,

    /// Maximum response-body prefix to inspect. The response hook is synchronous
    /// and cannot await, so a whole body is never buffered.
    #[serde(default = "default_response_prefix")]
    pub response_prefix_limit: usize,

    #[serde(default)]
    pub custom_rules: BTreeMap<String, CustomRule>,
}

const fn default_threshold() -> u32 {
    5
}
const fn default_budget_ms() -> u64 {
    10
}
const fn default_body_limit() -> usize {
    128 * 1024
}
const fn default_response_prefix() -> usize {
    64 * 1024
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            categories: BTreeMap::new(),
            paranoia: Paranoia::default(),
            anomaly_threshold: default_threshold(),
            budget_ms: default_budget_ms(),
            on_budget_exhausted: ExhaustedPolicy::default(),
            body_inspect_limit: default_body_limit(),
            response_prefix_limit: default_response_prefix(),
            custom_rules: BTreeMap::new(),
        }
    }
}

/// A validated configuration. Construction is the only way to get one, so an
/// unvalidated config cannot reach the engine.
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    request_modes: BTreeMap<Category, RequestMode>,
    response_modes: BTreeMap<Category, ResponseMode>,
    pub paranoia: Paranoia,
    pub anomaly_threshold: u32,
    pub budget: Duration,
    pub on_budget_exhausted: ExhaustedPolicy,
    pub body_inspect_limit: usize,
    pub response_prefix_limit: usize,
    pub custom_rules: BTreeMap<String, ValidatedCustomRule>,
}

impl ValidatedConfig {
    /// Mode for a request-side category.
    ///
    /// A response-side category returns `Off` rather than the default mode: it
    /// does not participate in request evaluation at all, and returning `Detect`
    /// here would make a 950-lineage rule look eligible on the request path.
    /// A request-side category the operator never mentioned returns the default,
    /// which is `Detect` — categories are on unless turned off.
    pub fn request_mode(&self, c: Category) -> RequestMode {
        if c.is_response_side() {
            return RequestMode::Off;
        }
        self.request_modes.get(&c).copied().unwrap_or_default()
    }

    /// Mode for a response-side category. A request-side category returns `Off`,
    /// mirroring [`Self::request_mode`].
    pub fn response_mode(&self, c: Category) -> ResponseMode {
        if !c.is_response_side() {
            return ResponseMode::Off;
        }
        self.response_modes.get(&c).copied().unwrap_or_default()
    }
}

impl WafConfig {
    /// Validate, or fail with the offending key named.
    pub fn validate(self) -> Result<ValidatedConfig, ConfigError> {
        if self.anomaly_threshold == 0 {
            return Err(ConfigError::ZeroThreshold);
        }
        if self.budget_ms == 0 {
            return Err(ConfigError::ZeroBudget);
        }
        if self.body_inspect_limit == 0 {
            return Err(ConfigError::ZeroBodyLimit);
        }

        let mut request_modes = BTreeMap::new();
        let mut response_modes = BTreeMap::new();
        let mut custom_rules = BTreeMap::new();

        for (key, raw) in &self.categories {
            let category = Category::ALL
                .iter()
                .copied()
                .find(|c| c.key() == key.as_str())
                .ok_or_else(|| ConfigError::UnknownCategory {
                    key: key.clone(),
                    valid: Category::ALL
                        .iter()
                        .map(|c| c.key())
                        .collect::<Vec<_>>()
                        .join(", "),
                })?;

            if category.is_response_side() {
                let mode = match raw {
                    RawMode::Off => ResponseMode::Off,
                    RawMode::Detect => ResponseMode::Detect,
                    RawMode::Redact => ResponseMode::Redact,
                    RawMode::Block => {
                        return Err(ConfigError::BlockOnResponseCategory {
                            category: category.key().to_string(),
                        });
                    },
                };
                response_modes.insert(category, mode);
            } else {
                let mode = match raw {
                    RawMode::Off => RequestMode::Off,
                    RawMode::Detect => RequestMode::Detect,
                    RawMode::Block => RequestMode::Block,
                    RawMode::Redact => {
                        return Err(ConfigError::RedactOnRequestCategory {
                            category: category.key().to_string(),
                        });
                    },
                };
                request_modes.insert(category, mode);
            }
        }

        for (name, rule) in &self.custom_rules {
            // Operator-authored patterns get the same scrutiny as inherited ones.
            // A catastrophic regex from an operator is the same outage as one from
            // upstream.
            let compiled =
                fancy_regex::Regex::new(&rule.pattern).map_err(|e| {
                    ConfigError::BadCustomPattern {
                        name: name.clone(),
                        reason: e.to_string(),
                    }
                })?;
            if let Err(reason) = cost_check(&rule.pattern) {
                return Err(ConfigError::CostlyCustomPattern {
                    name: name.clone(),
                    reason,
                });
            }
            if rule.category.is_response_side()
                && matches!(rule.action, Some(RawMode::Block))
            {
                return Err(ConfigError::CustomRuleActionUnavailable {
                    name: name.clone(),
                    category: rule.category.key().to_string(),
                    action: "block".to_string(),
                    available: "off, detect, redact".to_string(),
                });
            }
            if !rule.category.is_response_side()
                && matches!(rule.action, Some(RawMode::Redact))
            {
                return Err(ConfigError::CustomRuleActionUnavailable {
                    name: name.clone(),
                    category: rule.category.key().to_string(),
                    action: "redact".to_string(),
                    available: "off, detect, block".to_string(),
                });
            }
            custom_rules.insert(
                name.clone(),
                ValidatedCustomRule {
                    spec: rule.clone(),
                    pattern: compiled,
                },
            );
        }

        Ok(ValidatedConfig {
            request_modes,
            response_modes,
            paranoia: self.paranoia,
            anomaly_threshold: self.anomaly_threshold,
            budget: Duration::from_millis(self.budget_ms),
            on_budget_exhausted: self.on_budget_exhausted,
            body_inspect_limit: self.body_inspect_limit,
            response_prefix_limit: self.response_prefix_limit,
            custom_rules,
        })
    }
}

/// Reject patterns whose shape invites catastrophic backtracking.
///
/// Public so the native detector set can be held to exactly the standard operator
/// rules are held to. An inherited pattern with a quadratic shape would be worse
/// than an operator's, because no config could disable it.
pub fn check_pattern_cost(pattern: &str) -> Result<(), String> {
    cost_check(pattern)
}

/// Reject patterns whose shape invites catastrophic backtracking.
///
/// A heuristic, not a decision procedure — proving a backtracking bound is
/// undecidable in general. It catches the shapes that actually show up: an
/// unbounded quantifier inside a lookaround, nested unbounded quantifiers, and
/// very long patterns that are usually generated rather than written.
///
/// Works on the pattern text, not the compiled program: `fancy-regex` exposes no
/// cost estimate, and the shapes worth rejecting are visible in the source.
fn cost_check(pattern: &str) -> Result<(), String> {
    const MAX_PATTERN_LEN: usize = 2_000;
    if pattern.len() > MAX_PATTERN_LEN {
        return Err(format!(
            "pattern is {} chars, over the {MAX_PATTERN_LEN} limit",
            pattern.len()
        ));
    }

    if let Some(body) = unbounded_lookaround(pattern) {
        return Err(format!(
            "the lookaround over `{body}` contains an unbounded quantifier, so it \
             rescans to end of input from every start position — quadratic in body \
             size. Measured on this engine: 1 KB = 1.0 ms, 4 KB = 16.2 ms, 16 KB = \
             243.6 ms, which extrapolates to ~15 s at the default 128 KiB \
             body_inspect_limit. Neither the time budget nor a backtrack limit can \
             stop a rule already running, so express it as separate rules whose \
             anomaly scores sum instead"
        ));
    }

    // Nested unbounded quantifier: `(a+)+`, `(a*)*`, `(...+)*`. This is the
    // classic exponential shape.
    let bytes = pattern.as_bytes();
    let mut depth_quant = 0usize;
    for i in 0..bytes.len() {
        if matches!(bytes[i], b'+' | b'*') {
            // A quantifier applied directly to a group close, where that group
            // already contained an unbounded quantifier.
            if i > 0 && bytes[i - 1] == b')' {
                depth_quant += 1;
            }
        }
    }
    if depth_quant > 0 && pattern.contains('+') {
        // Only flag when a group-level quantifier coexists with an inner one.
        let inner_unbounded = pattern
            .split(')')
            .any(|seg| seg.contains("+") || seg.contains("*"));
        if inner_unbounded && depth_quant >= 2 {
            return Err(
                "nested unbounded quantifiers (e.g. `(a+)+`) can backtrack \
                 exponentially"
                    .to_string(),
            );
        }
    }
    Ok(())
}

/// The body of the first lookaround group containing an unbounded quantifier.
///
/// Lookarounds are the one construct `fancy-regex` cannot delegate to
/// `regex-automata`, so each one is re-run by the backtracking VM at every start
/// position. A bounded body (`(?=\d{3})`, `(?![a-z])`) costs a fixed number of
/// steps and stays linear overall; an unbounded one (`(?=.*x)`) walks to end of
/// input each time, which is the quadratic case.
fn unbounded_lookaround(pattern: &str) -> Option<&str> {
    let bytes = pattern.as_bytes();
    // Byte index where each open group's body starts, and whether it is a
    // lookaround. Plain groups are tracked too, so nesting stays aligned.
    let mut stack: Vec<(bool, usize)> = Vec::new();
    let mut i = 0usize;
    let mut in_class = false;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                // Skip the escaped byte whole; `\(` is a literal paren.
                i += 2;
                continue;
            },
            b'[' if !in_class => in_class = true,
            b']' if in_class => in_class = false,
            b'(' if !in_class => {
                let kind = lookaround_body_start(bytes, i);
                stack.push((kind.is_some(), kind.unwrap_or(i + 1)));
                i = kind.unwrap_or(i + 1);
                continue;
            },
            b')' if !in_class => {
                if let Some((is_lookaround, start)) = stack.pop()
                    && is_lookaround
                    && let Some(body) = pattern.get(start..i)
                    && has_unbounded_quantifier(body)
                {
                    return Some(body);
                }
            },
            _ => {},
        }
        i += 1;
    }
    None
}

/// Where a lookaround's body starts, if `open` is the `(` of one.
///
/// Covers `(?=`, `(?!`, `(?<=`, `(?<!`. A flag group (`(?i)`), a non-capturing
/// group (`(?:`), and a named group (`(?<name>`) are not lookarounds — the last is
/// why `(?<` alone is not enough to decide.
fn lookaround_body_start(bytes: &[u8], open: usize) -> Option<usize> {
    if bytes.get(open + 1) != Some(&b'?') {
        return None;
    }
    match bytes.get(open + 2) {
        Some(b'=' | b'!') => Some(open + 3),
        Some(b'<') => match bytes.get(open + 3) {
            Some(b'=' | b'!') => Some(open + 4),
            _ => None,
        },
        _ => None,
    }
}

/// Whether `s` contains a quantifier with no upper bound, outside a character
/// class and not escaped.
fn has_unbounded_quantifier(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut in_class = false;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 2;
                continue;
            },
            b'[' if !in_class => in_class = true,
            b']' if in_class => in_class = false,
            b'*' | b'+' if !in_class => return true,
            b'{' if !in_class => {
                // `{2,}` is unbounded; `{2,5}` and `{3}` are not.
                if let Some(end) = s[i..].find('}') {
                    let inner = &s[i + 1..i + end];
                    if inner.ends_with(',')
                        && inner[..inner.len() - 1]
                            .chars()
                            .all(|c| c.is_ascii_digit())
                    {
                        return true;
                    }
                }
            },
            _ => {},
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(categories: &[(&str, RawMode)]) -> WafConfig {
        WafConfig {
            categories: categories
                .iter()
                .map(|(k, m)| ((*k).to_string(), *m))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn detect_is_the_default_mode_on_both_surfaces() {
        // A baseline run of the inherited patterns measured fp_rate = 0.3536, so
        // shipping `block` by default would break ~1 request in 3.
        assert_eq!(RequestMode::default(), RequestMode::Detect);
        assert_eq!(ResponseMode::default(), ResponseMode::Detect);
        let v = WafConfig::default().validate().expect("defaults valid");
        assert_eq!(v.request_mode(Category::SqlInjection), RequestMode::Detect);
        assert_eq!(
            v.response_mode(Category::DataLeakage),
            ResponseMode::Detect
        );
    }

    #[test]
    fn block_on_a_response_category_is_rejected_with_the_key_named() {
        // This is the contradiction the red-team review found: the phase's
        // success criterion asked for a `block` gate response-side while its
        // requirements explained why `block` cannot exist there. Rejecting the
        // value is how the impossibility gets enforced rather than documented.
        for c in [Category::DataLeakage, Category::WebShell] {
            let err = cfg_with(&[(c.key(), RawMode::Block)])
                .validate()
                .expect_err("block must be rejected response-side");
            match &err {
                ConfigError::BlockOnResponseCategory { category } => {
                    assert_eq!(category, c.key());
                },
                other => panic!("wrong error for {c}: {other:?}"),
            }
            let msg = err.to_string();
            assert!(msg.contains(c.key()), "message must name the key: {msg}");
            assert!(
                msg.contains("redact"),
                "message must point at the alternative: {msg}"
            );
        }
    }

    #[test]
    fn redact_on_a_request_category_is_rejected() {
        // The mirror case. Request-side rejects rather than rewrites, so `redact`
        // there is equally unimplementable and equally must not silently degrade.
        let err = cfg_with(&[("sql_injection", RawMode::Redact)])
            .validate()
            .expect_err("redact must be rejected request-side");
        assert!(matches!(err, ConfigError::RedactOnRequestCategory { .. }));
        assert!(err.to_string().contains("sql_injection"));
    }

    #[test]
    fn response_categories_accept_off_detect_redact() {
        let v = cfg_with(&[
            ("data_leakage", RawMode::Redact),
            ("web_shell", RawMode::Off),
        ])
        .validate()
        .expect("valid response-side modes");
        assert_eq!(
            v.response_mode(Category::DataLeakage),
            ResponseMode::Redact
        );
        assert_eq!(v.response_mode(Category::WebShell), ResponseMode::Off);
    }

    #[test]
    fn unknown_category_names_the_key_and_lists_valid_ones() {
        let err = cfg_with(&[("sqli_typo", RawMode::Block)])
            .validate()
            .expect_err("unknown category must fail");
        let msg = err.to_string();
        assert!(msg.contains("sqli_typo"), "names the offending key: {msg}");
        assert!(
            msg.contains("sql_injection"),
            "lists valid categories so the fix is obvious: {msg}"
        );
    }

    #[test]
    fn zero_threshold_is_rejected() {
        let cfg = WafConfig {
            anomaly_threshold: 0,
            ..Default::default()
        };
        let err = cfg.validate().expect_err("zero threshold must fail");
        assert!(matches!(err, ConfigError::ZeroThreshold));
        // The message has to explain the consequence, not just the rule.
        assert!(err.to_string().contains("every request"));
    }

    #[test]
    fn zero_budget_and_zero_body_limit_are_rejected() {
        let err = WafConfig {
            budget_ms: 0,
            ..Default::default()
        }
        .validate()
        .expect_err("zero budget must fail");
        assert!(matches!(err, ConfigError::ZeroBudget));

        let err = WafConfig {
            body_inspect_limit: 0,
            ..Default::default()
        }
        .validate()
        .expect_err("zero body limit must fail");
        assert!(matches!(err, ConfigError::ZeroBodyLimit));
        // A silent disable is worse than a loud rejection.
        assert!(err.to_string().contains("silently disables"));
    }

    #[test]
    fn unparsable_custom_pattern_is_rejected_with_the_rule_named() {
        let mut cfg = WafConfig::default();
        cfg.custom_rules.insert(
            "my_rule".into(),
            CustomRule {
                category: Category::SqlInjection,
                pattern: "([unclosed".into(),
                severity: crate::rule::Severity::Warning,
                paranoia: Paranoia::default(),
                action: None,
            },
        );
        let err = cfg.validate().expect_err("bad pattern must fail");
        assert!(matches!(err, ConfigError::BadCustomPattern { .. }));
        assert!(err.to_string().contains("my_rule"));
    }

    #[test]
    fn catastrophic_custom_pattern_is_rejected() {
        let mut cfg = WafConfig::default();
        cfg.custom_rules.insert(
            "nested".into(),
            CustomRule {
                category: Category::SqlInjection,
                pattern: "(a+)+(b*)*".into(),
                severity: crate::rule::Severity::Warning,
                paranoia: Paranoia::default(),
                action: None,
            },
        );
        let err = cfg.validate().expect_err("nested quantifiers must fail");
        assert!(matches!(err, ConfigError::CostlyCustomPattern { .. }));
        let msg = err.to_string();
        assert!(msg.contains("nested"), "names the rule: {msg}");
        assert!(
            msg.contains("backtrack"),
            "explains why it is dangerous: {msg}"
        );
    }

    #[test]
    fn overlong_custom_pattern_is_rejected() {
        let mut cfg = WafConfig::default();
        cfg.custom_rules.insert(
            "huge".into(),
            CustomRule {
                category: Category::Xss,
                pattern: "a".repeat(2_001),
                severity: crate::rule::Severity::Notice,
                paranoia: Paranoia::default(),
                action: None,
            },
        );
        let err = cfg.validate().expect_err("overlong pattern must fail");
        assert!(matches!(err, ConfigError::CostlyCustomPattern { .. }));
    }

    #[test]
    fn a_custom_rule_action_must_exist_on_its_surface() {
        // A per-rule action override is only useful if it cannot express something
        // the surface cannot do. Both directions are rejected: `block` on a
        // response-side rule, and `redact` on a request-side one.
        for (category, action, label) in [
            (Category::DataLeakage, RawMode::Block, "block"),
            (Category::SqlInjection, RawMode::Redact, "redact"),
        ] {
            let mut cfg = WafConfig::default();
            cfg.custom_rules.insert(
                "leak".into(),
                CustomRule {
                    category,
                    pattern: "secret".into(),
                    severity: crate::rule::Severity::Critical,
                    paranoia: Paranoia::default(),
                    action: Some(action),
                },
            );
            let err = cfg.validate().expect_err("must reject");
            assert!(matches!(
                err,
                ConfigError::CustomRuleActionUnavailable { .. }
            ));
            let msg = err.to_string();
            assert!(msg.contains("leak"), "names the rule: {msg}");
            assert!(msg.contains(label), "names the bad action: {msg}");
            assert!(msg.contains(category.key()), "names the category: {msg}");
        }
    }

    #[test]
    fn a_reasonable_custom_pattern_passes_the_cost_check() {
        let mut cfg = WafConfig::default();
        cfg.custom_rules.insert(
            "ok".into(),
            CustomRule {
                category: Category::SqlInjection,
                // Backreference: the reason fancy-regex was chosen over regex.
                pattern: r"(?i)(\w+)\s+\1\s+union".into(),
                severity: crate::rule::Severity::Error,
                paranoia: Paranoia::default(),
                action: None,
            },
        );
        let v = cfg.validate().expect("valid custom rule");
        assert_eq!(v.custom_rules.len(), 1);
    }

    #[test]
    fn an_unbounded_lookaround_is_rejected_as_quadratic() {
        // Measured, not assumed. `(?=.*etc)(?=.*passwd)` over the benchmark body:
        // 1 KB = 1.0 ms, 4 KB = 16.2 ms, 16 KB = 243.6 ms — a clean O(n²), because
        // the lookahead rescans to end-of-input at every start position. At the
        // default 128 KiB `body_inspect_limit` that extrapolates to ~15.6 s on one
        // request, which is a worker thread gone for every domain on the process.
        //
        // Nothing else in the engine bounds it. `backtrack_limit` does not: at
        // 10_000 it still returned no-match at 4 KB after 15.3 ms, and only errored
        // at 16 KB after 206 ms. Nor does the time budget, which is checked
        // *between* rules and cannot preempt one already running. So the only place
        // this can be stopped is config load.
        for pattern in [
            r"(?=.*etc)(?=.*passwd)",
            r"(?=.+admin)",
            r"foo(?!.*bar)",
            r"(?=[a-z]*x)",
        ] {
            let mut cfg = WafConfig::default();
            cfg.custom_rules.insert(
                "quad".into(),
                CustomRule {
                    category: Category::LocalFileInclusion,
                    pattern: pattern.to_string(),
                    severity: crate::rule::Severity::Warning,
                    paranoia: Paranoia::default(),
                    action: None,
                },
            );
            let err = cfg
                .validate()
                .expect_err(&format!("must reject `{pattern}`"));
            assert!(
                matches!(err, ConfigError::CostlyCustomPattern { .. }),
                "`{pattern}` must fail the cost check, got {err}"
            );
            let msg = err.to_string();
            assert!(msg.contains("quad"), "names the rule: {msg}");
            // The rewrite is cheap and the engine already supports it, so the error
            // has to say so — otherwise an operator just widens the limit.
            assert!(
                msg.contains("separate rules"),
                "points at the two-rule rewrite: {msg}"
            );
        }
    }

    #[test]
    fn a_bounded_lookaround_is_still_allowed() {
        // Over-rejection would be its own failure: lookaround is half of why
        // fancy-regex is a dependency at all. A lookaround with no unbounded
        // quantifier inside it scans a fixed distance, so it stays linear.
        for pattern in [
            r"(?i)/etc/(passwd|shadow)(?=[/?&\s]|$)",
            r"(?=\d{3})\d+",
            r"admin(?![a-z])",
            r"(?<=/)passwd",
        ] {
            let mut cfg = WafConfig::default();
            cfg.custom_rules.insert(
                "bounded".into(),
                CustomRule {
                    category: Category::LocalFileInclusion,
                    pattern: pattern.to_string(),
                    severity: crate::rule::Severity::Warning,
                    paranoia: Paranoia::default(),
                    action: None,
                },
            );
            cfg.validate()
                .unwrap_or_else(|e| panic!("`{pattern}` must pass: {e}"));
        }
    }

    #[test]
    fn validation_hands_the_compiled_pattern_on_rather_than_discarding_it() {
        // Validation has to compile the pattern anyway to reject a bad one, so the
        // compiled artifact travels with the validated config. Discarding it and
        // recompiling in `RuleEngine::build` doubles the regex work on every config
        // load and every reload, and it puts a second failure point behind a gate
        // that is supposed to be the only one.
        let mut cfg = WafConfig::default();
        cfg.custom_rules.insert(
            "leak".into(),
            CustomRule {
                category: Category::DataLeakage,
                pattern: r"(?i)mysql_(connect|error)\(".into(),
                severity: crate::rule::Severity::Error,
                paranoia: Paranoia::default(),
                action: None,
            },
        );
        let v = cfg.validate().expect("valid custom rule");
        let rule = v
            .custom_rules
            .get("leak")
            .expect("rule survives validation");
        assert!(
            rule.pattern()
                .is_match("Warning: mysql_connect(): access denied")
                .expect("a validated pattern evaluates"),
            "the compiled pattern reached the validated config"
        );
        // The spec is still reachable — the engine needs its category and severity.
        assert_eq!(rule.spec().category, Category::DataLeakage);
    }

    #[test]
    fn paranoia_deserialises_within_range_and_rejects_outside() {
        let ok: WafConfig =
            toml::from_str("paranoia = 3").expect("in-range paranoia parses");
        assert_eq!(ok.paranoia.get(), 3);
        let err = toml::from_str::<WafConfig>("paranoia = 7")
            .expect_err("out-of-range paranoia must fail at parse");
        assert!(
            err.to_string().contains("out of range"),
            "parse error should explain: {err}"
        );
    }

    #[test]
    fn a_category_never_leaks_across_surfaces() {
        // A response-side category must not look eligible on the request path,
        // and vice versa. Without the guard both would report the default
        // `Detect` and a 950-lineage rule would appear runnable inbound.
        let v = WafConfig::default().validate().expect("defaults valid");
        for c in Category::ALL {
            if c.is_response_side() {
                assert_eq!(
                    v.request_mode(c),
                    RequestMode::Off,
                    "{c} on request path"
                );
            } else {
                assert_eq!(
                    v.response_mode(c),
                    ResponseMode::Off,
                    "{c} on response path"
                );
            }
        }
    }

    #[test]
    fn modes_parse_from_config_text() {
        let cfg: WafConfig = toml::from_str(
            r#"
            paranoia = 2
            anomaly_threshold = 8
            [categories]
            sql_injection = "block"
            xss = "detect"
            data_leakage = "redact"
            "#,
        )
        .expect("parses");
        let v = cfg.validate().expect("valid");
        assert_eq!(v.request_mode(Category::SqlInjection), RequestMode::Block);
        assert_eq!(v.request_mode(Category::Xss), RequestMode::Detect);
        assert_eq!(
            v.response_mode(Category::DataLeakage),
            ResponseMode::Redact
        );
        assert_eq!(v.anomaly_threshold, 8);
        assert_eq!(v.paranoia.get(), 2);
    }
}
