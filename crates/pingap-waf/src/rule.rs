//! Rule identity: IDs, severities, categories, and what a match produces.
//!
//! The point of this module is that a WAF verdict has to be *attributable*. An
//! operator reading a log line needs to know which rule fired, how bad it is,
//! and which field carried the payload — without that, a block is unexplainable
//! and a false positive is untriageable.

use crate::categories::Category;
use std::fmt;

/// Stable numeric rule identifier.
///
/// The allocation scheme is deliberate and asserted by test, because a collision
/// silently changes which rule a historical log line refers to:
///
/// - `1_000..=999_999` — native rules, grouped by CRS-adjacent category range
///   (see [`Category::id_range`]). Assigned by us, stable across releases.
/// - `1_000_000..` — operator-authored custom rules. Reserved so a future native
///   category can never collide with a rule someone already deployed.
///
/// The gap between the two ranges is intentional headroom.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(u32);

/// First ID available to operator-authored rules.
pub const CUSTOM_RULE_ID_BASE: u32 = 1_000_000;

impl RuleId {
    /// Construct a native rule ID. Returns `None` if the value falls outside the
    /// native range, which would put it in custom territory.
    pub const fn native(id: u32) -> Option<Self> {
        if id >= 1_000 && id < CUSTOM_RULE_ID_BASE {
            Some(Self(id))
        } else {
            None
        }
    }

    /// Construct a custom rule ID from an offset into the reserved range.
    pub const fn custom(offset: u32) -> Option<Self> {
        match CUSTOM_RULE_ID_BASE.checked_add(offset) {
            Some(id) => Some(Self(id)),
            None => None,
        }
    }

    /// Construct a custom rule ID from an arbitrary offset, folding it into the
    /// reserved range so the operation is total.
    ///
    /// Exists for name-derived allocation, where the input is a hash and there is
    /// no meaningful error to return. It has to be total rather than fallible
    /// because the release profile is `panic = "abort"`: an `unwrap` on this path
    /// would trade a hash quirk for a gateway-wide outage.
    pub const fn custom_wrapping(offset: u32) -> Self {
        // `offset % span < span`, so the sum stays below `u32::MAX`.
        let span = u32::MAX - CUSTOM_RULE_ID_BASE;
        Self(CUSTOM_RULE_ID_BASE + offset % span)
    }

    pub const fn get(self) -> u32 {
        self.0
    }

    pub const fn is_custom(self) -> bool {
        self.0 >= CUSTOM_RULE_ID_BASE
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// How serious a match is. Maps to an anomaly score contribution, but kept
/// separate from the score so an operator can retune scores without relabelling
/// severities in every log dashboard they have built.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Notice,
    Warning,
    Error,
    Critical,
}

impl Severity {
    /// Default score contribution. CRS uses 2/3/4/5 for the equivalent tiers;
    /// the shape is inherited, the numbers are ours and are config-overridable.
    pub const fn default_score(self) -> u32 {
        match self {
            Self::Notice => 2,
            Self::Warning => 3,
            Self::Error => 4,
            Self::Critical => 5,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        };
        f.write_str(s)
    }
}

/// Which part of the request or response carried the match.
///
/// Carries the field *name*, never its value. Attack strings in logs become an
/// injection vector against whatever reads them, so the payload stays behind a
/// debug-level flag and never reaches an info-level record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchedField {
    Method,
    Uri,
    Query {
        key: String,
    },
    Header {
        name: String,
    },
    Cookie {
        name: String,
    },
    /// Byte range of the match within the inspected body prefix. The length is
    /// carried because a redactor has to know how much to mask, and masking a fixed
    /// guessed window would either leave part of a leak readable or destroy bytes
    /// around it.
    Body {
        offset: usize,
        len: usize,
    },
    Status,
    ResponseHeader {
        name: String,
    },
    ResponseBody {
        offset: usize,
        len: usize,
    },
}

impl fmt::Display for MatchedField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Method => f.write_str("method"),
            Self::Uri => f.write_str("uri"),
            Self::Query { key } => write!(f, "query:{key}"),
            Self::Header { name } => write!(f, "header:{name}"),
            Self::Cookie { name } => write!(f, "cookie:{name}"),
            Self::Body { offset, len } => write!(f, "body@{offset}+{len}"),
            Self::Status => f.write_str("status"),
            Self::ResponseHeader { name } => {
                write!(f, "response_header:{name}")
            },
            Self::ResponseBody { offset, len } => {
                write!(f, "response_body@{offset}+{len}")
            },
        }
    }
}

/// One rule matching once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub rule_id: RuleId,
    pub category: Category,
    pub severity: Severity,
    pub score: u32,
    pub matched_field: MatchedField,
}

/// Paranoia level, in CRS's sense: a dial from "only high-confidence rules" to
/// "everything, including rules that will fire on odd-but-legitimate traffic".
///
/// A rule declares the minimum level at which it participates. The reference
/// product ships every category at level 1, which is why level 1 is the default
/// here too.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize,
)]
#[serde(try_from = "u8")]
pub struct Paranoia(u8);

impl Paranoia {
    pub const MIN: Self = Self(1);
    pub const MAX: Self = Self(4);

    pub const fn new(level: u8) -> Option<Self> {
        if level >= 1 && level <= 4 {
            Some(Self(level))
        } else {
            None
        }
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

impl Default for Paranoia {
    fn default() -> Self {
        Self::MIN
    }
}

impl TryFrom<u8> for Paranoia {
    type Error = String;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Self::new(v).ok_or_else(|| {
            format!("paranoia level {v} out of range; expected 1..=4")
        })
    }
}

/// What a rule needs to answer: does this input match, and if so, how.
///
/// Two hard constraints, both load-bearing:
///
/// 1. **No panics.** The release profile is `panic = "abort"`, so a panic on
///    attacker input takes down the whole gateway — every tenant on the box, not
///    just the request. `unwrap_used` is denied workspace-wide; do not reach for
///    `expect` either.
/// 2. **No unbounded allocation.** A rule that allocates proportionally to input
///    size hands an attacker a memory amplifier.
///
/// Implementations receive only what is in the input type. If a detector needs
/// something absent, widen the input rather than passing a session — the engine
/// stays a pure function so it can be fuzzed in isolation.
pub trait Rule: Send + Sync {
    fn id(&self) -> RuleId;
    fn category(&self) -> Category;
    fn severity(&self) -> Severity;

    /// Minimum paranoia level at which this rule participates.
    fn paranoia(&self) -> Paranoia {
        Paranoia::MIN
    }

    /// Score contribution when this rule matches. Defaults to the severity's
    /// score so most rules need not think about it.
    fn score(&self) -> u32 {
        self.severity().default_score()
    }

    /// An enforcement mode declared by the rule itself, overriding the mode
    /// configured for its category.
    ///
    /// Only operator-authored rules set this; a native rule always follows its
    /// category, which is why the default is `None`. It lives on the trait rather
    /// than on the custom-rule type so the engine can run one uniform loop over
    /// trait objects instead of keeping custom rules in a parallel list.
    fn action_override(&self) -> Option<crate::config::RawMode> {
        None
    }
}

/// Request-side rule.
pub trait RequestRule: Rule {
    fn evaluate(&self, input: &crate::engine::RequestInput) -> Option<Hit>;
}

/// Response-side rule. Separate trait rather than one trait with two methods,
/// so a rule cannot accidentally be registered on the surface it was not written
/// for — the two inputs carry different fields and the enforcement actions
/// available differ (see `engine::Verdict`).
pub trait ResponseRule: Rule {
    fn evaluate(&self, input: &crate::engine::ResponseInput) -> Option<Hit>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_and_custom_id_ranges_cannot_overlap() {
        assert!(RuleId::native(999).is_none(), "below native floor");
        assert!(RuleId::native(1_000).is_some());
        assert!(RuleId::native(999_999).is_some());
        assert!(
            RuleId::native(CUSTOM_RULE_ID_BASE).is_none(),
            "native must not reach into the custom range"
        );

        let custom = RuleId::custom(0).expect("custom base");
        assert!(custom.is_custom());
        assert_eq!(custom.get(), CUSTOM_RULE_ID_BASE);

        // The whole point of the scheme: no native ID is ever custom.
        for id in [1_000, 942_100, 999_999] {
            let r = RuleId::native(id).expect("native");
            assert!(!r.is_custom(), "native {id} classified as custom");
        }
    }

    #[test]
    fn custom_id_offset_cannot_overflow_silently() {
        assert!(RuleId::custom(u32::MAX).is_none());
    }

    #[test]
    fn custom_wrapping_is_total_and_stays_in_the_reserved_range() {
        // The name-hash allocator feeds arbitrary u32s here, so every input must
        // land inside the custom range — a value that fell below the base would be
        // indistinguishable from a native ID in a log line.
        for offset in [0, 1, 12_345, u32::MAX / 2, u32::MAX - 1, u32::MAX] {
            let id = RuleId::custom_wrapping(offset);
            assert!(id.is_custom(), "offset {offset} escaped the custom range");
            assert!(RuleId::native(id.get()).is_none());
        }
        assert_eq!(RuleId::custom_wrapping(0).get(), CUSTOM_RULE_ID_BASE);
    }

    #[test]
    fn paranoia_rejects_out_of_range() {
        assert!(Paranoia::new(0).is_none());
        assert!(Paranoia::new(5).is_none());
        assert_eq!(Paranoia::default(), Paranoia::MIN);
        let err = Paranoia::try_from(9).expect_err("must reject");
        assert!(
            err.contains("out of range"),
            "message names the problem: {err}"
        );
    }

    #[test]
    fn severity_scores_are_ordered() {
        // A higher severity must never score lower, or threshold tuning becomes
        // incoherent.
        let ordered = [
            Severity::Notice,
            Severity::Warning,
            Severity::Error,
            Severity::Critical,
        ];
        for w in ordered.windows(2) {
            assert!(
                w[0].default_score() < w[1].default_score(),
                "{:?} must score below {:?}",
                w[0],
                w[1]
            );
        }
    }

    #[test]
    fn matched_field_never_renders_a_value() {
        // Field names only. If this test starts failing because someone added a
        // value to the Display impl, that is the bug, not the test.
        let f = MatchedField::Header {
            name: "user-agent".into(),
        };
        assert_eq!(f.to_string(), "header:user-agent");
        // A body match renders position and length, never the bytes. The length is
        // what a redactor needs; the bytes are what an attacker wants in your logs.
        let b = MatchedField::Body { offset: 42, len: 7 };
        assert_eq!(b.to_string(), "body@42+7");
        let r = MatchedField::ResponseBody { offset: 0, len: 19 };
        assert_eq!(r.to_string(), "response_body@0+19");
    }
}
