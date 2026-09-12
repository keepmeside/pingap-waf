//! IP allow and deny lists.
//!
//! Not a scored rule. An address is on a list or it is not; there is no anomaly
//! score to accumulate and nothing for a threshold to weigh, so folding this into the
//! rule engine would mean inventing a score for a decision that does not have one.
//! It also runs first, because rejecting a known-bad address before any pattern
//! evaluation is the cheapest work the WAF can do.
//!
//! **CIDR parsing and matching are delegated, not reimplemented.**
//! `pingap_util::IpRules` already does both, and the `ip_restriction` plugin already
//! uses it. A second matcher in this crate could disagree with the one the rest of the
//! gateway uses, and a WAF that blocks an address the access log attributes to a
//! different network produces findings nobody can act on.

use pingap_util::IpRules;

/// Which way the list reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListMode {
    /// Listed addresses are rejected; everything else passes. The default, because a
    /// deny list that is accidentally empty still serves traffic, whereas an empty
    /// allow list would reject every request including the operator's own.
    #[default]
    Deny,
    /// Only listed addresses pass.
    Allow,
}

/// A parsed allow or deny list.
#[derive(Debug)]
pub struct IpFilter {
    mode: ListMode,
    rules: IpRules,
    /// Kept so an empty list can be distinguished from no list at all. An empty
    /// `allow` list would otherwise reject everything, which is a configuration
    /// mistake rather than a policy.
    entries: usize,
}

impl IpFilter {
    /// Build from config entries, refusing any the CIDR parser did not understand.
    ///
    /// `IpRules` drops what it cannot parse, so a typo would otherwise produce a list
    /// that silently covers less than its author wrote — a deny list missing a range,
    /// or an allow list missing the operator's own network. The stored count is
    /// compared against the input to catch it, which is what `IpRules::len` exists for.
    pub fn new(mode: ListMode, entries: &[String]) -> Result<Self, String> {
        let rules = IpRules::new(entries);
        if rules.len() != entries.len() {
            let bad = entries
                .iter()
                .find(|e| IpRules::new(std::slice::from_ref(*e)).is_empty())
                .cloned()
                .unwrap_or_default();
            return Err(format!(
                "`ip_list` entry `{bad}` is not an IP address or CIDR range"
            ));
        }
        Ok(Self {
            mode,
            rules,
            entries: entries.len(),
        })
    }

    /// Whether the list has any entries. An `allow` filter with none is a config
    /// error the plugin must reject rather than honour.
    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }

    /// Whether this address is refused.
    ///
    /// An unparsable address is refused under `allow` and permitted under `deny`,
    /// which is the fail-closed reading of each: an allow list cannot confirm
    /// membership for something it cannot parse, and a deny list cannot confirm
    /// membership either — so neither is given the benefit of the doubt in the
    /// direction that would weaken the policy the operator wrote.
    pub fn rejects(&self, ip: &str) -> bool {
        // `unwrap_or(false)` reads as "membership unproven", and each mode then draws
        // the conservative conclusion for itself: `allow` refuses what it cannot
        // confirm is a member, `deny` permits what it cannot confirm is one.
        let matched = self.rules.is_match(ip).unwrap_or(false);
        match self.mode {
            ListMode::Deny => matched,
            ListMode::Allow => !matched,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deny_list_rejects_only_what_it_names() {
        let f = IpFilter::new(
            ListMode::Deny,
            &["192.168.1.1".to_string(), "10.0.0.0/8".to_string()],
        )
        .expect("valid entries");
        assert!(f.rejects("192.168.1.1"));
        assert!(f.rejects("10.4.5.6"), "a CIDR range must match its members");
        assert!(!f.rejects("203.0.113.9"));
    }

    #[test]
    fn an_allow_list_rejects_everything_it_does_not_name() {
        let f = IpFilter::new(ListMode::Allow, &["203.0.113.0/24".to_string()])
            .expect("valid entries");
        assert!(!f.rejects("203.0.113.9"));
        assert!(f.rejects("198.51.100.1"));
    }

    #[test]
    fn ipv6_is_matched_by_the_same_parser() {
        let f = IpFilter::new(ListMode::Deny, &["2001:db8::/32".to_string()])
            .expect("valid entries");
        assert!(f.rejects("2001:db8::1"));
        assert!(!f.rejects("2001:db9::1"));
    }

    #[test]
    fn deny_is_the_default_mode() {
        // An accidentally-empty deny list still serves traffic; an accidentally-empty
        // allow list would reject every request, including the operator's.
        assert_eq!(ListMode::default(), ListMode::Deny);
    }

    #[test]
    fn an_empty_list_is_detectable() {
        assert!(
            IpFilter::new(ListMode::Allow, &[])
                .expect("no entries is not a parse failure")
                .is_empty()
        );
        assert!(
            !IpFilter::new(ListMode::Deny, &["1.2.3.4".into()])
                .expect("valid entries")
                .is_empty()
        );
    }

    #[test]
    fn a_typo_is_refused_rather_than_silently_narrowing_the_list() {
        // `IpRules` drops what it cannot parse. Left undetected, a deny list would be
        // missing a range its author wrote, or an allow list would be missing the
        // operator's own network — in both directions a policy quietly weaker than the
        // config says.
        let err = IpFilter::new(
            ListMode::Deny,
            &["10.0.0.0/8".to_string(), "192.168.1.0/33".to_string()],
        )
        .expect_err("an unparsable entry must fail");
        assert!(err.contains("192.168.1.0/33"), "names the entry: {err}");
    }

    #[test]
    fn an_unresolvable_address_does_not_pass_an_allow_list() {
        // A client IP the resolver could not produce must not be treated as a member
        // of an allow list. Under `deny` there is nothing to match it against either,
        // so it passes — which is what `deny` means when a rule does not apply.
        let allow = IpFilter::new(ListMode::Allow, &["10.0.0.0/8".to_string()])
            .expect("valid entries");
        assert!(allow.rejects(""));
        assert!(allow.rejects("not-an-ip"));
        let deny = IpFilter::new(ListMode::Deny, &["10.0.0.0/8".to_string()])
            .expect("valid entries");
        assert!(!deny.rejects(""));
    }
}
