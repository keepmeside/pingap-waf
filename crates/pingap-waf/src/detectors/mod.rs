//! Native detectors: the patterns, and the rule identity attached to each.
//!
//! Ported from the reference WAF's seven request-side detectors, with the five
//! measured false-positive sources narrowed and the header blindspot closed. The
//! two response-side detectors (950 data leakage, 955 web shells) are new — the
//! reference has no response-side detection at all.
//!
//! Every pattern here is a [`PatternRule`]: an ID from its category's reserved
//! range, a severity, a paranoia level, and one compiled pattern. Detection logic
//! that needs more than a pattern does not belong in a rule — the IP filter
//! ([`crate::ip_filter`]) and the body accumulator ([`crate::body`]) are separate
//! for that reason, since neither produces a score.
//!
//! **Paranoia is how a noisy-but-useful pattern still ships.** A pattern measured
//! as a false-positive source is not deleted; it is narrowed, and if it is still
//! broad it is raised to a higher paranoia level so it participates only where an
//! operator asked for more aggression.

pub mod command_injection;
pub mod data_leakage;
pub mod headers;
pub mod path_traversal;
pub mod scanner;
pub mod sql_injection;
pub mod web_shell;
pub mod xss;

use crate::categories::Category;
use crate::engine::{
    RequestInput, ResponseInput, find_in_request, find_in_response,
};
use crate::rule::{
    Hit, MatchedField, Paranoia, RequestRule, ResponseRule, Rule, RuleId,
    Severity,
};

/// Which fields a pattern is allowed to look at.
///
/// Most detectors want every field: a SQL payload is a SQL payload wherever it
/// arrives. A client-fingerprint pattern is different in kind — `sqlmap` appearing
/// in a User-Agent identifies the client, while the same word in a request body is
/// someone discussing tools. Scanning every field with those patterns manufactures
/// false positives by construction, which no amount of pattern tuning can fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    AnyField,
    /// One named header, matched case-insensitively.
    Header(&'static str),
}

/// A detector pattern as written in source: the ID offset within its category's
/// range, the pattern, its severity, the paranoia level it activates at, and the
/// fields it may inspect.
///
/// Offsets rather than absolute IDs so a detector module cannot accidentally
/// allocate into another category's range — the absolute ID is derived from the
/// category at build time and asserted by test.
pub struct Spec {
    pub offset: u32,
    pub pattern: String,
    pub severity: Severity,
    pub paranoia: Paranoia,
    pub scope: Scope,
}

/// A spec at the default paranoia level, over every field.
pub fn spec(offset: u32, pattern: &str, severity: Severity) -> Spec {
    Spec {
        offset,
        pattern: pattern.to_string(),
        severity,
        paranoia: Paranoia::MIN,
        scope: Scope::AnyField,
    }
}

/// A spec that participates only at raised paranoia.
///
/// This is how a pattern that carries real signal but cannot be made precise still
/// ships: narrowed as far as it goes, then held back from the default profile
/// rather than deleted.
pub fn spec_at(
    offset: u32,
    pattern: &str,
    severity: Severity,
    paranoia: u8,
) -> Spec {
    Spec {
        paranoia: Paranoia::new(paranoia)
            .unwrap_or_else(|| panic!("paranoia {paranoia} is out of range")),
        ..spec(offset, pattern, severity)
    }
}

/// A spec restricted to one header.
pub fn spec_in_header(
    offset: u32,
    header: &'static str,
    pattern: &str,
    severity: Severity,
    paranoia: u8,
) -> Spec {
    Spec {
        scope: Scope::Header(header),
        ..spec_at(offset, pattern, severity, paranoia)
    }
}

/// One compiled native pattern, bound to a category.
pub struct PatternRule {
    id: RuleId,
    category: Category,
    severity: Severity,
    paranoia: Paranoia,
    scope: Scope,
    pattern: fancy_regex::Regex,
}

impl PatternRule {
    /// Compile a spec against its category.
    ///
    /// Panics on an unparsable pattern or an out-of-range offset. Both are
    /// impossible for a shipped pattern — every one is written in this module tree
    /// and the `native_patterns_all_compile` test compiles all of them — so a
    /// failure here is a source defect caught at first construction, not a runtime
    /// condition. Returning `Result` would push a "detectors failed to load" branch
    /// into the plugin, which is the shape that ends in a WAF silently running with
    /// no rules.
    fn compile(category: Category, s: &Spec) -> Self {
        let (lo, _) = category.id_range();
        let id = RuleId::native(lo + s.offset).unwrap_or_else(|| {
            panic!(
                "{category} rule offset {} is outside its ID range",
                s.offset
            )
        });
        let pattern = fancy_regex::Regex::new(&s.pattern).unwrap_or_else(|e| {
            panic!("{category} pattern `{}` does not compile: {e}", s.pattern)
        });
        Self {
            id,
            category,
            severity: s.severity,
            paranoia: s.paranoia,
            scope: s.scope,
            pattern,
        }
    }

    /// Match position, or `None`.
    ///
    /// A `fancy-regex` error — a hit backtrack limit being the plausible one — is
    /// treated as no match rather than as a match or a panic. Blocking traffic
    /// because a pattern was expensive turns a cost problem into an outage; the
    /// time budget is what makes the cost visible instead.
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

impl Rule for PatternRule {
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

impl RequestRule for PatternRule {
    fn evaluate(&self, input: &RequestInput<'_>) -> Option<Hit> {
        let field = match self.scope {
            Scope::AnyField => {
                find_in_request(input, &headers::inspect_header, &|t| {
                    self.find_at(t)
                })?
            },
            Scope::Header(want) => {
                let (name, value) = input
                    .headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(want))?;
                self.find_at(value)?;
                MatchedField::Header {
                    name: (*name).to_string(),
                }
            },
        };
        Some(self.hit(field))
    }
}

impl ResponseRule for PatternRule {
    fn evaluate(&self, input: &ResponseInput<'_>) -> Option<Hit> {
        let field = find_in_response(input, &headers::inspect_header, &|t| {
            self.find_at(t)
        })?;
        Some(self.hit(field))
    }
}

/// Every request-side detector's specs, paired with the category that owns them.
pub fn request_specs() -> Vec<(Category, Vec<Spec>)> {
    vec![
        (Category::SqlInjection, sql_injection::specs()),
        (Category::Xss, xss::specs()),
        (Category::LocalFileInclusion, path_traversal::specs()),
        (Category::RemoteCodeExecution, command_injection::specs()),
        (Category::Generic, scanner::specs()),
    ]
}

/// Every response-side detector's specs.
pub fn response_specs() -> Vec<(Category, Vec<Spec>)> {
    vec![
        (Category::DataLeakage, data_leakage::specs()),
        (Category::WebShell, web_shell::specs()),
    ]
}

/// The native request-side ruleset, compiled.
pub fn request_rules() -> Vec<Box<dyn RequestRule>> {
    request_specs()
        .into_iter()
        .flat_map(|(category, specs)| {
            specs.into_iter().map(move |s| {
                Box::new(PatternRule::compile(category, &s))
                    as Box<dyn RequestRule>
            })
        })
        .collect()
}

/// The native response-side ruleset, compiled.
pub fn response_rules() -> Vec<Box<dyn ResponseRule>> {
    response_specs()
        .into_iter()
        .flat_map(|(category, specs)| {
            specs.into_iter().map(move |s| {
                Box::new(PatternRule::compile(category, &s))
                    as Box<dyn ResponseRule>
            })
        })
        .collect()
}

/// Every native rule's ID with the category that owns it.
///
/// Exists so a test can assert the ID scheme holds across both surfaces without
/// reaching through trait objects. An ID outside its category's range silently
/// mislabels every log line the rule produces.
pub fn native_rule_ids() -> Vec<(RuleId, Category)> {
    request_specs()
        .into_iter()
        .chain(response_specs())
        .flat_map(|(category, specs)| {
            let (lo, _) = category.id_range();
            specs.into_iter().map(move |s| {
                (
                    RuleId::native(lo + s.offset).unwrap_or_else(|| {
                        panic!("{category} offset {} out of range", s.offset)
                    }),
                    category,
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_patterns_all_compile() {
        // `PatternRule::compile` panics on a bad pattern by design, so this test is
        // what turns that into a build-time failure rather than a first-request
        // one.
        assert!(!request_rules().is_empty(), "no request-side detectors");
        assert!(!response_rules().is_empty(), "no response-side detectors");
    }

    #[test]
    fn every_native_pattern_passes_the_cost_check_operators_are_held_to() {
        // Inherited patterns get no exemption. An unbounded quantifier inside a
        // lookaround is quadratic in body size and neither the time budget nor a
        // backtrack limit can bound it, so a native rule with that shape would be
        // an availability hole that no config could disable — worse than an
        // operator's, which at least gets rejected at load.
        for (category, specs) in
            request_specs().into_iter().chain(response_specs())
        {
            for s in specs {
                if let Err(reason) =
                    crate::config::check_pattern_cost(&s.pattern)
                {
                    panic!(
                        "{category} offset {} (`{}`) fails the cost check \
                         applied to operator rules: {reason}",
                        s.offset, s.pattern
                    );
                }
            }
        }
    }

    #[test]
    fn offsets_are_unique_within_each_category() {
        for (category, specs) in
            request_specs().into_iter().chain(response_specs())
        {
            let mut offsets: Vec<u32> =
                specs.iter().map(|s| s.offset).collect();
            let before = offsets.len();
            offsets.sort_unstable();
            offsets.dedup();
            assert_eq!(
                before,
                offsets.len(),
                "{category} has two patterns at the same offset, so one hit \
                 would be attributed to the other's rule ID"
            );
        }
    }

    #[test]
    fn offsets_fit_the_thousand_wide_category_range() {
        for (category, specs) in
            request_specs().into_iter().chain(response_specs())
        {
            for s in specs {
                assert!(
                    s.offset < 1_000,
                    "{category} offset {} would spill into the next \
                     category's range",
                    s.offset
                );
            }
        }
    }

    #[test]
    fn a_response_side_detector_is_never_registered_request_side() {
        // The two surfaces have different enforcement actions, so a response-side
        // pattern on the request path would be able to deny a request — a class of
        // false positive the type split exists to prevent.
        for (category, _) in request_specs() {
            assert!(
                !category.is_response_side(),
                "{category} is response-side but is in the request ruleset"
            );
        }
        for (category, _) in response_specs() {
            assert!(
                category.is_response_side(),
                "{category} is request-side but is in the response ruleset"
            );
        }
    }
}
