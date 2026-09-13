//! Bot profiles and rules, and the evaluation over them.
//!
//! Same precedence discipline as `pingap-acl`: the rules are an ordered list, the first
//! matching one with a terminal action decides, and `log` is an observation that does not
//! stop the walk. An operator reading the list top to bottom can predict the outcome.
//!
//! One deliberate asymmetry with the ACL: a profile has a **mode**. `detect` records
//! every verdict and denies nothing, which is how a fingerprint deny list gets rolled out
//! against real traffic before it is trusted to block. A fingerprint is a
//! client-behaviour signal, and the false-positive cost of blocking on one is a real user
//! who cannot reach the site.

use crate::ja4h;
use serde::Deserialize;

/// Which fingerprint a rule matches against.
///
/// One variant today. JA4 arrives only once the ClientHello spike's open gate items are
/// closed (`docs/spikes/ja4-finding.md`), and it arrives *here* — as another variant behind
/// the same rule model — rather than as a parallel mechanism. Values of different types must
/// never be compared against each other: a JA4H list entry has no meaning as a JA4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintType {
    Ja4h,
}

impl FingerprintType {
    pub const fn key(self) -> &'static str {
        match self {
            Self::Ja4h => "ja4h",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BotAction {
    Allow,
    Deny,
    /// Record and keep evaluating. Not terminal, for the same reason it is not in the
    /// ACL: adding one for visibility must not disable the rules below it.
    Log,
}

impl BotAction {
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Log)
    }
}

/// Whether the profile may deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    /// Record verdicts, deny nothing. The default, because a fingerprint deny list
    /// should be measured against real traffic before it is trusted.
    #[default]
    Detect,
    Block,
}

#[derive(Debug, PartialEq, Eq, snafu::Snafu)]
pub enum RuleError {
    #[snafu(display(
        "bot: rule {index} matches on nothing — give it a `fingerprint` or a \
         `user_agent` pattern"
    ))]
    NothingToMatch { index: usize },

    #[snafu(display(
        "bot: rule {index} has an unparsable `user_agent` regex: {reason}"
    ))]
    BadUserAgent { index: usize, reason: String },

    #[snafu(display(
        "bot: rule {index} sets `fingerprint` without `fingerprint_type`, so it is \
         not clear which fingerprint the value belongs to"
    ))]
    FingerprintTypeMissing { index: usize },

    #[snafu(display(
        "bot: rule {index} declares `fingerprint = \"{value}\"`, which is not a \
         JA4H. Expected `{{method}}{{version}}{{c|n}}{{r|n}}{{count}}{{lang}}_` \
         followed by one to three 12-character hashes"
    ))]
    NotAJa4h { index: usize, value: String },
}

/// A rule as written in config.
#[derive(Debug, Clone, Deserialize)]
pub struct BotRule {
    #[serde(default)]
    pub fingerprint_type: Option<FingerprintType>,
    /// An exact fingerprint to match. Compared as a prefix when it carries fewer than
    /// the full four components — see [`ValidatedBotRule::matches`].
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// A `regex` pattern over the `User-Agent`.
    #[serde(default)]
    pub user_agent: Option<String>,
    pub action: BotAction,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub remark: Option<String>,
}

const fn default_enabled() -> bool {
    true
}

/// A rule that has passed validation, carrying its compiled pattern.
#[derive(Debug, Clone)]
pub struct ValidatedBotRule {
    spec: BotRule,
    pattern: Option<regex::Regex>,
}

impl ValidatedBotRule {
    pub fn new(spec: BotRule, index: usize) -> Result<Self, RuleError> {
        if spec.fingerprint.is_none() && spec.user_agent.is_none() {
            return Err(RuleError::NothingToMatch { index });
        }
        if let Some(value) = &spec.fingerprint {
            if spec.fingerprint_type.is_none() {
                return Err(RuleError::FingerprintTypeMissing { index });
            }
            if !ja4h::looks_like_ja4h(value) {
                return Err(RuleError::NotAJa4h {
                    index,
                    value: value.clone(),
                });
            }
        }
        let pattern = match &spec.user_agent {
            Some(source) => Some(regex::Regex::new(source).map_err(|e| {
                RuleError::BadUserAgent {
                    index,
                    reason: e.to_string(),
                }
            })?),
            None => None,
        };
        Ok(Self { spec, pattern })
    }

    pub fn action(&self) -> BotAction {
        self.spec.action
    }

    pub fn spec(&self) -> &BotRule {
        &self.spec
    }

    /// Whether this rule matches.
    ///
    /// Both conditions must hold when both are written — a rule naming a fingerprint
    /// *and* a User-Agent means "this client, and only when it presents that UA", which
    /// is how a specific automation build is targeted without catching the whole family.
    ///
    /// A configured fingerprint matches as a **prefix** on `_` boundaries. Published
    /// lists carry only `a_b`, because the cookie components identify a session rather
    /// than a client; comparing those for equality against a full four-component value
    /// would make every library entry miss. Matching a bare prefix without the boundary
    /// check would let `ge11nn03…_ab` match `…_abcdef`, so the boundary is explicit.
    pub fn matches(&self, fingerprint: Option<&str>, user_agent: &str) -> bool {
        if !self.spec.enabled {
            return false;
        }
        if let Some(wanted) = &self.spec.fingerprint {
            let Some(actual) = fingerprint else {
                // No fingerprint was computed, so a fingerprint rule cannot match. This
                // is the fail-open path, and the miss is counted by the caller.
                return false;
            };
            let hit = actual == wanted
                || actual
                    .strip_prefix(wanted.as_str())
                    .is_some_and(|rest| rest.starts_with('_'));
            if !hit {
                return false;
            }
        }
        if let Some(pattern) = &self.pattern
            && !pattern.is_match(user_agent)
        {
            return false;
        }
        true
    }
}

/// A validated bot profile: an ordered rule table, a mode, and the crawler exemption.
#[derive(Debug, Clone)]
pub struct BotProfile {
    name: String,
    mode: PolicyMode,
    allow_known_bots: bool,
    rules: Vec<ValidatedBotRule>,
}

/// What a profile decided, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotOutcome {
    /// Whether the request is refused. Always false in `detect` mode.
    pub denied: bool,
    /// Whether a rule would have denied it. Set in `detect` mode too, which is the whole
    /// point of `detect`: the verdict is recorded without being enforced.
    pub would_deny: bool,
    pub decided_by: Option<usize>,
    pub logged: Vec<usize>,
    /// Whether the request was exempted as a known-good crawler.
    pub known_bot: bool,
}

impl BotProfile {
    pub fn new(
        name: &str,
        mode: PolicyMode,
        allow_known_bots: bool,
        rules: Vec<ValidatedBotRule>,
    ) -> Self {
        Self {
            name: name.to_string(),
            mode,
            allow_known_bots,
            rules,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mode(&self) -> PolicyMode {
        self.mode
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Evaluate the profile against a request.
    ///
    /// `allow_known_bots` is checked first and short-circuits everything. A broad deny
    /// written to stop scrapers will otherwise take Googlebot with it, and the operator
    /// finds out from their search ranking rather than from a log.
    pub fn evaluate(
        &self,
        fingerprint: Option<&str>,
        user_agent: &str,
    ) -> BotOutcome {
        if self.allow_known_bots && crate::library::is_known_good(user_agent) {
            return BotOutcome {
                denied: false,
                would_deny: false,
                decided_by: None,
                logged: Vec::new(),
                known_bot: true,
            };
        }

        let mut logged = Vec::new();
        for (index, rule) in self.rules.iter().enumerate() {
            if !rule.matches(fingerprint, user_agent) {
                continue;
            }
            match rule.action() {
                BotAction::Log => logged.push(index),
                BotAction::Allow => {
                    return BotOutcome {
                        denied: false,
                        would_deny: false,
                        decided_by: Some(index),
                        logged,
                        known_bot: false,
                    };
                },
                BotAction::Deny => {
                    return BotOutcome {
                        denied: self.mode == PolicyMode::Block,
                        would_deny: true,
                        decided_by: Some(index),
                        logged,
                        known_bot: false,
                    };
                },
            }
        }
        BotOutcome {
            denied: false,
            would_deny: false,
            decided_by: None,
            logged,
            known_bot: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A JA4H prefix a library entry would carry: the `a_b` part and nothing more.
    const URLLIB: &str = "ge11nn040000_5b1e8b5f4d2d";
    /// The same client's full four-component fingerprint, as computed per request.
    const URLLIB_FULL: &str =
        "ge11nn040000_5b1e8b5f4d2d_000000000000_000000000000";

    fn rule(fp: Option<&str>, ua: Option<&str>, action: BotAction) -> BotRule {
        BotRule {
            fingerprint_type: fp.map(|_| FingerprintType::Ja4h),
            fingerprint: fp.map(str::to_string),
            user_agent: ua.map(str::to_string),
            action,
            enabled: true,
            remark: None,
        }
    }

    fn profile(
        mode: PolicyMode,
        allow_known_bots: bool,
        specs: Vec<BotRule>,
    ) -> BotProfile {
        let rules = specs
            .into_iter()
            .enumerate()
            .map(|(i, spec)| {
                ValidatedBotRule::new(spec, i).expect("test rule is valid")
            })
            .collect();
        BotProfile::new("test", mode, allow_known_bots, rules)
    }

    #[test]
    fn a_library_prefix_matches_the_full_per_request_fingerprint() {
        // Published entries stop at `a_b` because the cookie components identify a
        // session, not a client. Comparing for equality would make every entry miss.
        let p = profile(
            PolicyMode::Block,
            false,
            vec![rule(Some(URLLIB), None, BotAction::Deny)],
        );
        assert!(p.evaluate(Some(URLLIB_FULL), "python-urllib/3.11").denied);
    }

    #[test]
    fn a_partial_hash_cannot_be_configured_and_a_near_miss_does_not_match() {
        // Prefix matching is what makes library entries usable, so the obvious worry is
        // that `…_5b1e8b5f` would match `…_5b1e8b5f4d2d`. It cannot, from two directions.
        //
        // First, a truncated hash is not a JA4H, so it is refused before it can ever be
        // compared:
        let err = ValidatedBotRule::new(
            rule(Some("ge11nn040000_5b1e8b5f"), None, BotAction::Deny),
            0,
        )
        .expect_err("a truncated hash must be refused");
        assert!(matches!(err, RuleError::NotAJa4h { .. }));

        // Second, a well-formed entry differing only in the final hex digit does not
        // match, so prefix matching has not been widened into "starts with".
        let p = profile(
            PolicyMode::Block,
            false,
            vec![rule(
                Some("ge11nn040000_5b1e8b5f4d2e"),
                None,
                BotAction::Deny,
            )],
        );
        assert!(!p.evaluate(Some(URLLIB_FULL), "python-urllib/3.11").denied);
    }

    #[test]
    fn detect_mode_records_the_verdict_without_refusing() {
        let p = profile(
            PolicyMode::Detect,
            false,
            vec![rule(Some(URLLIB), None, BotAction::Deny)],
        );
        let outcome = p.evaluate(Some(URLLIB_FULL), "python-urllib/3.11");
        assert!(!outcome.denied, "detect mode refused a request");
        assert!(
            outcome.would_deny,
            "detect mode must still record what it would have done, or it is just off"
        );
        assert_eq!(outcome.decided_by, Some(0));
    }

    #[test]
    fn a_known_good_crawler_escapes_a_broad_deny() {
        // A deny written to stop scrapers otherwise takes Googlebot with it, and the
        // operator finds out from their search ranking rather than from a log.
        let broad = vec![rule(None, Some("."), BotAction::Deny)];
        let exempt = profile(PolicyMode::Block, true, broad.clone());
        let outcome =
            exempt.evaluate(None, "Mozilla/5.0 (compatible; Googlebot/2.1)");
        assert!(!outcome.denied);
        assert!(outcome.known_bot);

        // And with the exemption off, the same request is refused — proving the
        // exemption is what spared it rather than the rule failing to match.
        let strict = profile(PolicyMode::Block, false, broad);
        assert!(
            strict
                .evaluate(None, "Mozilla/5.0 (compatible; Googlebot/2.1)")
                .denied
        );
    }

    #[test]
    fn a_request_with_no_fingerprint_fails_open_against_a_fingerprint_rule() {
        // The documented default. An h2 request has no computable JA4H, and a
        // fingerprint rule cannot match what does not exist.
        let p = profile(
            PolicyMode::Block,
            false,
            vec![rule(Some(URLLIB), None, BotAction::Deny)],
        );
        let outcome = p.evaluate(None, "python-urllib/3.11");
        assert!(!outcome.denied);
        assert_eq!(outcome.decided_by, None);
    }

    #[test]
    fn a_rule_naming_both_conditions_requires_both() {
        // "This client, and only when it presents that UA" — how a specific automation
        // build is targeted without catching the whole family.
        let p = profile(
            PolicyMode::Block,
            false,
            vec![rule(Some(URLLIB), Some("3\\.11"), BotAction::Deny)],
        );
        assert!(p.evaluate(Some(URLLIB_FULL), "python-urllib/3.11").denied);
        assert!(!p.evaluate(Some(URLLIB_FULL), "python-urllib/3.9").denied);
    }

    #[test]
    fn the_first_terminal_rule_decides_and_log_does_not_stop_the_walk() {
        let p = profile(
            PolicyMode::Block,
            false,
            vec![
                rule(None, Some("urllib"), BotAction::Log),
                rule(None, Some("python"), BotAction::Deny),
            ],
        );
        let outcome = p.evaluate(None, "python-urllib/3.11");
        assert!(outcome.denied, "the deny below the log rule never ran");
        assert_eq!(outcome.decided_by, Some(1));
        assert_eq!(outcome.logged, vec![0]);

        // Allow first wins over a later deny.
        let p = profile(
            PolicyMode::Block,
            false,
            vec![
                rule(None, Some("urllib"), BotAction::Allow),
                rule(None, Some("python"), BotAction::Deny),
            ],
        );
        assert!(!p.evaluate(None, "python-urllib/3.11").denied);
    }

    #[test]
    fn a_rule_that_matches_nothing_is_refused_at_config_load() {
        let err = ValidatedBotRule::new(rule(None, None, BotAction::Deny), 2)
            .expect_err("a rule with no conditions must fail");
        assert!(matches!(err, RuleError::NothingToMatch { index: 2 }));
    }

    #[test]
    fn a_fingerprint_without_its_type_is_refused() {
        let mut spec = rule(Some(URLLIB), None, BotAction::Deny);
        spec.fingerprint_type = None;
        let err = ValidatedBotRule::new(spec, 0)
            .expect_err("an untyped fingerprint must fail");
        assert!(matches!(err, RuleError::FingerprintTypeMissing { .. }));
    }

    #[test]
    fn a_value_that_is_not_a_ja4h_is_refused_with_the_value_named() {
        for bad in [
            "not-a-fingerprint",
            "ge11nn040000",
            "ge11xx040000_5b1e8b5f4d2d",
        ] {
            let err = ValidatedBotRule::new(
                rule(Some(bad), None, BotAction::Deny),
                1,
            )
            .expect_err("a malformed fingerprint must fail");
            assert!(
                err.to_string().contains(bad),
                "the error must name the value: {err}"
            );
        }
        // And a real one, in both the prefix and full forms, is accepted.
        for good in [URLLIB, URLLIB_FULL] {
            ValidatedBotRule::new(rule(Some(good), None, BotAction::Deny), 0)
                .expect("a well-formed JA4H is accepted");
        }
    }

    #[test]
    fn a_disabled_rule_matches_nothing() {
        let mut spec = rule(None, Some("python"), BotAction::Deny);
        spec.enabled = false;
        let p = profile(PolicyMode::Block, false, vec![spec]);
        assert!(!p.evaluate(None, "python-urllib/3.11").denied);
    }

    #[test]
    fn detect_is_the_default_mode() {
        // Blocking on a client-behaviour signal costs a real user who cannot reach the
        // site, so it is opt-in.
        assert_eq!(PolicyMode::default(), PolicyMode::Detect);
    }
}
