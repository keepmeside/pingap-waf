//! Rule-set evaluation: first terminal match wins, read top to bottom.
//!
//! The one property this file exists to guarantee is that an operator can predict the
//! outcome by reading their rule list in order. No "most specific wins", no implicit
//! reordering, no scoring. Overlapping allow and deny rules are a classic source of
//! accidental exposure, and every heuristic that tries to be clever about them makes
//! the list harder to reason about than the exposure was worth.

use crate::rule::{Action, Field, ValidatedRule};

/// What happens when no rule reached a terminal action.
///
/// `Allow` is the default, so an empty rule table is a no-op rather than an outage.
/// Deny-by-default is expressible — and it has to be, because "allow nothing unless
/// listed" is a policy operators legitimately want — but it is opt-in, because a
/// config that silently began refusing everything would be worse than one that
/// silently allowed everything on a table nobody had filled in yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    #[default]
    Allow,
    Deny,
}

/// The attributes a rule can be tested against.
///
/// A plain struct of borrowed strings rather than a session reference, for the same
/// reason `pingap-waf`'s engine takes one: it makes evaluation a pure function that can
/// be unit-tested exhaustively without a proxy. When a rule needs something this cannot
/// see, widen the struct — do not pass a session in.
#[derive(Debug, Default, Clone, Copy)]
pub struct RequestFacts<'a> {
    /// Resolved by the gateway's trusted-proxy logic. Empty when there is no address
    /// to attribute, which is not the same as "0.0.0.0".
    pub client_ip: &'a str,
    pub method: &'a str,
    /// All request headers. `user_agent` and `referer` are read from here rather than
    /// carried separately, so there is one source for a header value.
    pub headers: &'a [(&'a str, &'a str)],
}

impl<'a> RequestFacts<'a> {
    fn header(&self, name: &str) -> &'a str {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
            .unwrap_or_default()
    }
}

/// The country lookup, or an empty string on a build without the database.
///
/// The `not(geo)` arm is unreachable through config — validation refuses a
/// `geo_country` rule when the feature is off — and exists so the crate still compiles
/// in the default feature set.
#[cfg(feature = "geo")]
fn country_of(ip: &str) -> String {
    ip.parse()
        .ok()
        .and_then(pingap_plugin::lookup_country_code)
        .unwrap_or_default()
}

#[cfg(not(feature = "geo"))]
fn country_of(_ip: &str) -> String {
    String::new()
}

/// Which rule decided, and what was observed on the way there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub allowed: bool,
    /// Position of the rule that decided, or `None` when the default action did.
    pub decided_by: Option<usize>,
    /// Positions of every `log` rule that matched, in evaluation order. These are
    /// observations, so they accumulate rather than stopping the walk.
    pub logged: Vec<usize>,
}

/// A validated, ordered rule table plus its default action.
#[derive(Debug, Clone)]
pub struct RuleSet {
    rules: Vec<ValidatedRule>,
    default_action: DefaultAction,
}

impl RuleSet {
    /// Order the rules once, at construction.
    ///
    /// A **stable** sort by `order`, so rules sharing an `order` — which is all of them
    /// by default — keep their written positions. That is what makes "read it top to
    /// bottom" true for a hand-written TOML array while still giving the admin UI and
    /// the Phase 07 database a field to reorder by.
    pub fn new(
        mut rules: Vec<ValidatedRule>,
        default_action: DefaultAction,
    ) -> Self {
        rules.sort_by_key(|r| r.spec().order);
        Self {
            rules,
            default_action,
        }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn default_action(&self) -> DefaultAction {
        self.default_action
    }

    /// Walk the rules in order and return the first terminal decision.
    pub fn evaluate(&self, facts: &RequestFacts<'_>) -> Outcome {
        // Resolved at most once, and only if a rule asks for it: a GeoIP lookup is
        // the most expensive field here by a wide margin.
        let mut country: Option<String> = None;
        let mut logged = Vec::new();

        for (index, rule) in self.rules.iter().enumerate() {
            let value: &str = match rule.spec().field {
                Field::Ip => facts.client_ip,
                Field::Method => facts.method,
                Field::UserAgent => facts.header("user-agent"),
                Field::Referer => facts.header("referer"),
                Field::Header => rule
                    .spec()
                    .header
                    .as_deref()
                    .map(|name| facts.header(name))
                    .unwrap_or_default(),
                Field::GeoCountry => {
                    country.get_or_insert_with(|| country_of(facts.client_ip))
                },
            };
            if !rule.matches(value) {
                continue;
            }
            match rule.action() {
                Action::Log => logged.push(index),
                Action::Allow => {
                    return Outcome {
                        allowed: true,
                        decided_by: Some(index),
                        logged,
                    };
                },
                Action::Deny => {
                    return Outcome {
                        allowed: false,
                        decided_by: Some(index),
                        logged,
                    };
                },
            }
        }

        Outcome {
            allowed: self.default_action == DefaultAction::Allow,
            decided_by: None,
            logged,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{AclRule, Operator};

    fn rule(
        field: Field,
        operator: Operator,
        values: &[&str],
        action: Action,
    ) -> AclRule {
        AclRule {
            field,
            operator,
            values: values.iter().map(|v| v.to_string()).collect(),
            header: (field == Field::Header).then(|| "x-tenant".to_string()),
            action,
            order: 0,
            enabled: true,
        }
    }

    fn set(specs: Vec<AclRule>, default_action: DefaultAction) -> RuleSet {
        let rules = specs
            .into_iter()
            .enumerate()
            .map(|(i, spec)| {
                ValidatedRule::new(spec, i).expect("test rule is valid")
            })
            .collect();
        RuleSet::new(rules, default_action)
    }

    const HEADERS: &[(&str, &str)] = &[
        ("user-agent", "curl/8.5.0"),
        ("referer", "https://acme.test/x"),
    ];

    fn facts<'a>(ip: &'a str, method: &'a str) -> RequestFacts<'a> {
        RequestFacts {
            client_ip: ip,
            method,
            headers: HEADERS,
        }
    }

    #[test]
    fn the_first_matching_rule_decides_even_when_a_later_one_disagrees() {
        // The property the whole file exists for. Both rules match this request; the
        // one written first is the answer, and swapping them swaps the outcome.
        let allow_then_deny = set(
            vec![
                rule(
                    Field::Ip,
                    Operator::InCidr,
                    &["10.0.0.0/8"],
                    Action::Allow,
                ),
                rule(Field::Method, Operator::Equals, &["GET"], Action::Deny),
            ],
            DefaultAction::Allow,
        );
        let outcome = allow_then_deny.evaluate(&facts("10.1.2.3", "GET"));
        assert!(outcome.allowed);
        assert_eq!(outcome.decided_by, Some(0));

        let deny_then_allow = set(
            vec![
                rule(Field::Method, Operator::Equals, &["GET"], Action::Deny),
                rule(
                    Field::Ip,
                    Operator::InCidr,
                    &["10.0.0.0/8"],
                    Action::Allow,
                ),
            ],
            DefaultAction::Allow,
        );
        let outcome = deny_then_allow.evaluate(&facts("10.1.2.3", "GET"));
        assert!(!outcome.allowed);
        assert_eq!(outcome.decided_by, Some(0));
    }

    #[test]
    fn a_log_rule_records_and_does_not_stop_the_walk() {
        // Adding a `log` rule for visibility must not disable the rules below it.
        let rs = set(
            vec![
                rule(
                    Field::UserAgent,
                    Operator::Contains,
                    &["curl"],
                    Action::Log,
                ),
                rule(Field::Method, Operator::Equals, &["GET"], Action::Deny),
            ],
            DefaultAction::Allow,
        );
        let outcome = rs.evaluate(&facts("203.0.113.9", "GET"));
        assert!(!outcome.allowed, "the deny below the log rule never ran");
        assert_eq!(outcome.decided_by, Some(1));
        assert_eq!(outcome.logged, vec![0]);
    }

    #[test]
    fn nothing_matching_falls_through_to_the_default_action() {
        let specs = || {
            vec![rule(
                Field::Ip,
                Operator::InCidr,
                &["10.0.0.0/8"],
                Action::Allow,
            )]
        };
        let permissive = set(specs(), DefaultAction::Allow);
        assert!(permissive.evaluate(&facts("203.0.113.9", "GET")).allowed);

        // Deny-by-default: "allow nothing unless listed" is a policy operators want,
        // and it must be expressible rather than approximated with a trailing rule.
        let closed = set(specs(), DefaultAction::Deny);
        let outcome = closed.evaluate(&facts("203.0.113.9", "GET"));
        assert!(!outcome.allowed);
        assert_eq!(
            outcome.decided_by, None,
            "the default action is not a rule and must not claim to be one"
        );
        assert!(closed.evaluate(&facts("10.1.2.3", "GET")).allowed);
    }

    #[test]
    fn an_empty_table_is_a_no_op_rather_than_an_outage() {
        let rs = set(vec![], DefaultAction::default());
        assert!(rs.is_empty());
        assert!(rs.evaluate(&facts("203.0.113.9", "POST")).allowed);
    }

    #[test]
    fn order_regroups_rules_without_disturbing_what_shares_a_number() {
        // Written order is the default order, and `order` moves a rule between groups
        // while leaving relative position inside a group alone — which is what makes a
        // stable sort the right one here.
        let mut first =
            rule(Field::Method, Operator::Equals, &["GET"], Action::Deny);
        first.order = 10;
        let second =
            rule(Field::Ip, Operator::InCidr, &["10.0.0.0/8"], Action::Allow);
        let rs = set(vec![first, second], DefaultAction::Allow);
        // The allow now runs first despite being written second.
        let outcome = rs.evaluate(&facts("10.1.2.3", "GET"));
        assert!(outcome.allowed);
        assert_eq!(outcome.decided_by, Some(0));
    }

    #[test]
    fn a_header_rule_reads_the_header_it_names() {
        let headers = [("x-tenant", "acme"), ("user-agent", "curl/8.5.0")];
        let rs = set(
            vec![rule(
                Field::Header,
                Operator::Equals,
                &["acme"],
                Action::Deny,
            )],
            DefaultAction::Allow,
        );
        let outcome = rs.evaluate(&RequestFacts {
            client_ip: "203.0.113.9",
            method: "GET",
            headers: &headers,
        });
        assert!(!outcome.allowed);

        // A header the request does not carry is an empty value, not a match.
        let outcome = rs.evaluate(&facts("203.0.113.9", "GET"));
        assert!(outcome.allowed);
    }
}
