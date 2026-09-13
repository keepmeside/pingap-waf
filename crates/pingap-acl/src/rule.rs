//! The ACL rule model, and the validation that keeps an unenforceable rule out of the
//! request path.
//!
//! Field × operator × action, mirroring the reference product's `AclField` /
//! `AclOperator` / `AclAction` enums so the admin UI maps across without a translation
//! layer. What is *not* mirrored is the reference's storage-order dependence — see
//! [`RuleSet`](crate::evaluate::RuleSet) for how order is fixed here.
//!
//! Every rejection names the offending key. An ACL that loads with a rule the engine
//! cannot evaluate is worse than one that fails to load: the operator believes the rule
//! is enforcing.

use pingap_util::IpRules;
use serde::Deserialize;

/// The request attribute a rule tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    /// Client IP, resolved by the gateway's own trusted-proxy logic — never read
    /// straight off a forwarded header.
    Ip,
    /// Two-letter country code from the embedded GeoIP database. Requires the `geo`
    /// feature; without it, validation refuses the rule by name.
    GeoCountry,
    UserAgent,
    Referer,
    Method,
    /// An arbitrary request header, named by the rule's `header` key.
    Header,
}

impl Field {
    pub const fn key(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::GeoCountry => "geo_country",
            Self::UserAgent => "user_agent",
            Self::Referer => "referer",
            Self::Method => "method",
            Self::Header => "header",
        }
    }

    /// Operators this field can be tested with.
    ///
    /// A closed list rather than "try it and see": `in_cidr` on a `user_agent` is not a
    /// rule that never fires, it is a rule whose author misunderstood something, and
    /// silently accepting it means they find out from a security incident.
    pub const fn operators(self) -> &'static [Operator] {
        match self {
            Self::Ip => &[Operator::InCidr, Operator::Equals, Operator::InList],
            // A country code is an exact token. `contains` on "US" would match "AUS".
            Self::GeoCountry | Self::Method => {
                &[Operator::Equals, Operator::InList]
            },
            Self::UserAgent | Self::Referer | Self::Header => &[
                Operator::Equals,
                Operator::Contains,
                Operator::Regex,
                Operator::InList,
            ],
        }
    }
}

/// How the field's value is compared against the rule's values.
///
/// String comparison is case-insensitive for `equals`, `contains` and `in_list`.
/// HTTP methods and header values are conventionally compared that way, and an
/// operator who writes `GET` should not get a different answer than one who writes
/// `get`. `regex` is the escape hatch when case matters — write `(?-i)` or rely on the
/// default, which is case-sensitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    /// Exact match against exactly one value. Use `in_list` for several.
    Equals,
    Contains,
    Regex,
    /// IP or CIDR membership, via the workspace's single CIDR matcher.
    InCidr,
    /// Exact match against any of several values.
    InList,
}

impl Operator {
    pub const fn key(self) -> &'static str {
        match self {
            Self::Equals => "equals",
            Self::Contains => "contains",
            Self::Regex => "regex",
            Self::InCidr => "in_cidr",
            Self::InList => "in_list",
        }
    }
}

/// What a matching rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
    /// Record the match and keep evaluating.
    ///
    /// Deliberately **not** terminal. If `log` stopped evaluation it would be
    /// impossible to log a match and then deny it, and an operator adding a `log` rule
    /// for visibility would silently disable every rule below it — turning an
    /// observability change into a policy change.
    Log,
}

impl Action {
    pub const fn key(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Log => "log",
        }
    }

    /// Whether this action ends evaluation.
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Log)
    }
}

/// Configuration errors. Each names the key at fault.
#[derive(Debug, PartialEq, Eq, snafu::Snafu)]
pub enum RuleError {
    #[snafu(display(
        "acl: rule {index} tests `{field}` with `{operator}`, which is not \
         available on that field. Available there: {available}"
    ))]
    OperatorNotOnField {
        index: usize,
        field: String,
        operator: String,
        available: String,
    },

    #[snafu(display(
        "acl: rule {index} has no `values`, so it can never match. Remove the \
         rule, or give it something to compare against"
    ))]
    NoValues { index: usize },

    #[snafu(display(
        "acl: rule {index} uses `equals` with {count} values. `equals` compares \
         against exactly one; use `in_list` to match any of several"
    ))]
    EqualsWantsOneValue { index: usize, count: usize },

    #[snafu(display(
        "acl: rule {index} tests `header` but does not say which one. Set \
         `header = \"<name>\"`"
    ))]
    HeaderNotNamed { index: usize },

    #[snafu(display(
        "acl: rule {index} sets `header = \"{header}\"` while testing `{field}`. \
         The `header` key only applies to `field = \"header\"`"
    ))]
    HeaderOnOtherField {
        index: usize,
        field: String,
        header: String,
    },

    #[snafu(display("acl: rule {index} has an unparsable regex: {reason}"))]
    BadRegex { index: usize, reason: String },

    #[snafu(display(
        "acl: rule {index} lists `{value}`, which is not an IP address or CIDR \
         range"
    ))]
    BadCidr { index: usize, value: String },

    #[snafu(display(
        "acl: rule {index} tests `geo_country`, but this build has no GeoIP \
         database — the `geo` feature is off, so the rule could never match. \
         Rebuild with `--features geo`, or remove the rule"
    ))]
    GeoUnavailable { index: usize },
}

/// A rule as written in config.
#[derive(Debug, Clone, Deserialize)]
pub struct AclRule {
    pub field: Field,
    pub operator: Operator,
    /// Values to compare against. Any one matching makes the rule match.
    #[serde(default)]
    pub values: Vec<String>,
    /// Which header, when `field = "header"`.
    #[serde(default)]
    pub header: Option<String>,
    pub action: Action,
    /// Explicit ordering hint, for stores that do not preserve insertion order.
    ///
    /// Rules are written as a TOML array, so their written order already *is* the
    /// evaluation order and this defaults to 0 for every rule — meaning the default
    /// behaviour is exactly "top to bottom as written". It exists because the
    /// control-plane store puts rules in a database, where row order is not a promise,
    /// and the admin UI needs a field to reorder by. Sorting is stable, so `order`
    /// breaks ties between groups and written position breaks ties within one.
    #[serde(default)]
    pub order: i32,
    /// A disabled rule is skipped, not deleted. Operators turn rules off to test.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

const fn default_enabled() -> bool {
    true
}

/// A rule that has passed validation, carrying whatever it compiled.
///
/// Compiling here rather than at evaluation time for the same reason `pingap-waf`
/// does it: validation has to compile a regex anyway in order to reject a bad one, and
/// throwing the result away would put a second failure point *after* the gate that is
/// supposed to be the only one.
#[derive(Debug, Clone)]
pub struct ValidatedRule {
    spec: AclRule,
    /// Compiled once, for `Operator::Regex`.
    patterns: Vec<regex::Regex>,
    /// Parsed once, for `Operator::InCidr`.
    cidrs: Option<IpRules>,
    /// Lowercased values, for the case-insensitive operators.
    folded: Vec<String>,
}

impl ValidatedRule {
    /// Check one rule and compile what it needs.
    ///
    /// `index` is its position in the written list, so an error points at a line the
    /// operator can find rather than at a name they have to go looking for.
    pub fn new(spec: AclRule, index: usize) -> Result<Self, RuleError> {
        let field = spec.field;
        let operator = spec.operator;

        if !field.operators().contains(&operator) {
            return Err(RuleError::OperatorNotOnField {
                index,
                field: field.key().to_string(),
                operator: operator.key().to_string(),
                available: field
                    .operators()
                    .iter()
                    .map(|o| o.key())
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        }
        if spec.values.is_empty() {
            return Err(RuleError::NoValues { index });
        }
        if operator == Operator::Equals && spec.values.len() != 1 {
            return Err(RuleError::EqualsWantsOneValue {
                index,
                count: spec.values.len(),
            });
        }
        match (field, &spec.header) {
            (Field::Header, None) => {
                return Err(RuleError::HeaderNotNamed { index });
            },
            (other, Some(header)) if other != Field::Header => {
                return Err(RuleError::HeaderOnOtherField {
                    index,
                    field: other.key().to_string(),
                    header: header.clone(),
                });
            },
            _ => {},
        }
        if field == Field::GeoCountry && !cfg!(feature = "geo") {
            return Err(RuleError::GeoUnavailable { index });
        }

        let mut patterns = Vec::new();
        if operator == Operator::Regex {
            for value in &spec.values {
                patterns.push(regex::Regex::new(value).map_err(|e| {
                    RuleError::BadRegex {
                        index,
                        reason: e.to_string(),
                    }
                })?);
            }
        }

        // `IpRules` drops what it cannot parse, so the stored count is compared against
        // the input to catch a typo that would otherwise become a rule silently
        // covering less than its author wrote.
        let cidrs = if operator == Operator::InCidr {
            let rules = IpRules::new(&spec.values);
            if rules.len() != spec.values.len() {
                let value = spec
                    .values
                    .iter()
                    .find(|v| IpRules::new(std::slice::from_ref(*v)).is_empty())
                    .cloned()
                    .unwrap_or_default();
                return Err(RuleError::BadCidr { index, value });
            }
            Some(rules)
        } else {
            None
        };

        let folded = spec
            .values
            .iter()
            .map(|v| v.to_lowercase())
            .collect::<Vec<_>>();
        Ok(Self {
            spec,
            patterns,
            cidrs,
            folded,
        })
    }

    pub fn spec(&self) -> &AclRule {
        &self.spec
    }

    pub fn action(&self) -> Action {
        self.spec.action
    }

    /// Whether the rule matches an already-extracted field value.
    ///
    /// Extraction is the caller's job — see [`crate::evaluate::RequestFacts`] — so this
    /// stays a pure function over a string and is testable without a request.
    pub fn matches(&self, value: &str) -> bool {
        if !self.spec.enabled {
            return false;
        }
        match self.spec.operator {
            Operator::InCidr => self
                .cidrs
                .as_ref()
                // An address the resolver could not produce is not a member of
                // anything. `deny` therefore does not fire on it and `allow` does not
                // confirm it — the same reading `pingap-waf`'s IP filter takes.
                .and_then(|rules| rules.is_match(value).ok())
                .unwrap_or(false),
            Operator::Regex => {
                self.patterns.iter().any(|re| re.is_match(value))
            },
            Operator::Contains => {
                let folded = value.to_lowercase();
                self.folded.iter().any(|v| folded.contains(v))
            },
            Operator::Equals | Operator::InList => {
                let folded = value.to_lowercase();
                self.folded.contains(&folded)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(field: Field, operator: Operator, values: &[&str]) -> AclRule {
        AclRule {
            field,
            operator,
            values: values.iter().map(|v| v.to_string()).collect(),
            header: (field == Field::Header).then(|| "x-tenant".to_string()),
            action: Action::Deny,
            order: 0,
            enabled: true,
        }
    }

    fn validated(
        field: Field,
        operator: Operator,
        values: &[&str],
    ) -> ValidatedRule {
        ValidatedRule::new(rule(field, operator, values), 0)
            .expect("test rule is valid")
    }

    #[test]
    fn an_operator_the_field_does_not_support_is_refused_by_name() {
        // Not "a rule that never fires" — a rule whose author misunderstood the field.
        // Accepting it silently means they learn from an incident.
        let err = ValidatedRule::new(
            rule(Field::UserAgent, Operator::InCidr, &["10.0.0.0/8"]),
            3,
        )
        .expect_err("in_cidr on user_agent must fail");
        let msg = err.to_string();
        assert!(msg.contains("rule 3"), "points at the rule: {msg}");
        assert!(msg.contains("user_agent"), "names the field: {msg}");
        assert!(msg.contains("in_cidr"), "names the operator: {msg}");
        assert!(msg.contains("regex"), "lists what is available: {msg}");
    }

    #[test]
    fn equals_takes_one_value_and_in_list_takes_several() {
        let err = ValidatedRule::new(
            rule(Field::Method, Operator::Equals, &["GET", "POST"]),
            1,
        )
        .expect_err("equals with two values must fail");
        assert!(
            err.to_string().contains("in_list"),
            "the error must point at the operator that does this: {err}"
        );
        // And the same intent expressed correctly is accepted.
        let ok = validated(Field::Method, Operator::InList, &["GET", "POST"]);
        assert!(ok.matches("POST"));
        assert!(!ok.matches("DELETE"));
    }

    #[test]
    fn a_rule_with_nothing_to_compare_against_is_refused() {
        let err =
            ValidatedRule::new(rule(Field::Method, Operator::InList, &[]), 0)
                .expect_err("an empty value list must fail");
        assert!(matches!(err, RuleError::NoValues { .. }));
    }

    #[test]
    fn a_header_rule_must_say_which_header() {
        let mut spec = rule(Field::Header, Operator::Equals, &["acme"]);
        spec.header = None;
        let err = ValidatedRule::new(spec, 2)
            .expect_err("an unnamed header must fail");
        assert!(matches!(err, RuleError::HeaderNotNamed { .. }));

        // And the key is refused on a field it cannot apply to, rather than ignored.
        let mut spec = rule(Field::Method, Operator::Equals, &["GET"]);
        spec.header = Some("x-tenant".to_string());
        let err = ValidatedRule::new(spec, 4)
            .expect_err("header on a non-header field must fail");
        assert!(matches!(err, RuleError::HeaderOnOtherField { .. }));
    }

    #[test]
    fn an_unparsable_regex_or_cidr_is_refused_with_the_value_named() {
        let err = ValidatedRule::new(
            rule(Field::Referer, Operator::Regex, &["("]),
            0,
        )
        .expect_err("a broken regex must fail");
        assert!(matches!(err, RuleError::BadRegex { .. }));

        let err = ValidatedRule::new(
            rule(Field::Ip, Operator::InCidr, &["10.0.0.0/8", "not-an-ip"]),
            5,
        )
        .expect_err("a broken CIDR must fail");
        let msg = err.to_string();
        assert!(msg.contains("not-an-ip"), "names the value: {msg}");
    }

    #[test]
    fn string_comparison_is_case_insensitive_except_for_regex() {
        // An operator who writes `GET` should not get a different answer than one who
        // writes `get`; header values and methods are conventionally folded.
        assert!(
            validated(Field::Method, Operator::Equals, &["get"]).matches("GET")
        );
        assert!(
            validated(Field::UserAgent, Operator::Contains, &["CURL"])
                .matches("curl/8.5.0")
        );
        // Regex is the escape hatch, and it is case-sensitive as written.
        assert!(
            !validated(Field::UserAgent, Operator::Regex, &["^curl"])
                .matches("CURL/8.5.0")
        );
        assert!(
            validated(Field::UserAgent, Operator::Regex, &["(?i)^curl"])
                .matches("CURL/8.5.0")
        );
    }

    #[test]
    fn a_disabled_rule_matches_nothing() {
        // Disabled means skipped, not deleted: operators turn a rule off to test.
        let mut spec = rule(Field::Method, Operator::Equals, &["GET"]);
        spec.enabled = false;
        let off = ValidatedRule::new(spec, 0).expect("valid");
        assert!(!off.matches("GET"));
    }

    #[test]
    fn an_unresolvable_address_is_not_a_member_of_any_cidr_list() {
        // The client-IP resolver returns an empty string when it has no address to
        // attribute. Treating that as a member would make a `deny` rule fire on every
        // such request; treating it as a match for `allow` would let it past.
        let r = validated(Field::Ip, Operator::InCidr, &["10.0.0.0/8"]);
        assert!(r.matches("10.1.2.3"));
        assert!(!r.matches(""));
        assert!(!r.matches("203.0.113.9"));
    }

    #[test]
    fn log_is_the_only_non_terminal_action() {
        // If `log` stopped evaluation, adding one for visibility would silently
        // disable every rule below it — an observability change becoming a policy one.
        assert!(!Action::Log.is_terminal());
        assert!(Action::Allow.is_terminal());
        assert!(Action::Deny.is_terminal());
    }
}
