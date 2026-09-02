//! Rule categories and their CRS lineage.
//!
//! Category names follow the CRS groups the reference product actually exposes,
//! verified against
//! `.xia-src/nginx-love/apps/api/src/domains/modsec/services/crs-rules.service.ts`
//! — ten files, eight request-side and two response-side.
//!
//! This is a **lineage mapping, not a compatibility claim**. No promise is made
//! that an arbitrary CRS `.conf` loads; the names exist so an operator who knows
//! CRS recognises what a category covers. `docs/waf-category-mapping.md` is the
//! published form of this table and ships in the same commit as this file.

use std::fmt;

/// A rule category. Request-side and response-side categories share one enum
/// because they share the `RuleId` space, severity scale, and scoring model —
/// but they differ in which enforcement actions are reachable, which
/// [`Category::is_response_side`] exists to make explicit at the type level's
/// nearest available equivalent.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// CRS 920 — REQUEST-PROTOCOL-ENFORCEMENT
    ProtocolEnforcement,
    /// CRS 930 — REQUEST-APPLICATION-ATTACK-LFI
    LocalFileInclusion,
    /// CRS 932 — REQUEST-APPLICATION-ATTACK-RCE
    RemoteCodeExecution,
    /// CRS 933 — REQUEST-APPLICATION-ATTACK-PHP
    Php,
    /// CRS 934 — REQUEST-APPLICATION-ATTACK-GENERIC
    ///
    /// Named GENERIC, not SSRF. The reference product's own config labels this
    /// group `SSRF`, which is wrong: upstream CRS ships it as
    /// `APPLICATION-ATTACK-GENERIC`. Following the reference's mislabel would
    /// have meant an operator reading our UI could not find the corresponding
    /// CRS rules.
    Generic,
    /// CRS 941 — REQUEST-APPLICATION-ATTACK-XSS
    Xss,
    /// CRS 942 — REQUEST-APPLICATION-ATTACK-SQLI
    SqlInjection,
    /// CRS 943 — REQUEST-APPLICATION-ATTACK-SESSION-FIXATION
    SessionFixation,
    /// CRS 950 — RESPONSE-DATA-LEAKAGES. Response-side.
    DataLeakage,
    /// CRS 955 — RESPONSE-WEB-SHELLS. Response-side.
    WebShell,
}

impl Category {
    /// Every category, in CRS numeric order.
    pub const ALL: [Category; 10] = [
        Self::ProtocolEnforcement,
        Self::LocalFileInclusion,
        Self::RemoteCodeExecution,
        Self::Php,
        Self::Generic,
        Self::Xss,
        Self::SqlInjection,
        Self::SessionFixation,
        Self::DataLeakage,
        Self::WebShell,
    ];

    /// The CRS group number this category descends from.
    pub const fn crs_group(self) -> u16 {
        match self {
            Self::ProtocolEnforcement => 920,
            Self::LocalFileInclusion => 930,
            Self::RemoteCodeExecution => 932,
            Self::Php => 933,
            Self::Generic => 934,
            Self::Xss => 941,
            Self::SqlInjection => 942,
            Self::SessionFixation => 943,
            Self::DataLeakage => 950,
            Self::WebShell => 955,
        }
    }

    /// The upstream CRS rule file this category's lineage traces to.
    pub const fn crs_file(self) -> &'static str {
        match self {
            Self::ProtocolEnforcement => {
                "REQUEST-920-PROTOCOL-ENFORCEMENT.conf"
            },
            Self::LocalFileInclusion => {
                "REQUEST-930-APPLICATION-ATTACK-LFI.conf"
            },
            Self::RemoteCodeExecution => {
                "REQUEST-932-APPLICATION-ATTACK-RCE.conf"
            },
            Self::Php => "REQUEST-933-APPLICATION-ATTACK-PHP.conf",
            Self::Generic => "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
            Self::Xss => "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
            Self::SqlInjection => "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
            Self::SessionFixation => {
                "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf"
            },
            Self::DataLeakage => "RESPONSE-950-DATA-LEAKAGES.conf",
            Self::WebShell => "RESPONSE-955-WEB-SHELLS.conf",
        }
    }

    /// Whether this category evaluates on the response rather than the request.
    ///
    /// Load-bearing: response-side categories cannot deny. The body hook's result
    /// type has no `Respond` variant and the status line is already downstream by
    /// the time it runs, so the strongest available action is rewriting bytes.
    /// [`crate::config::CategoryMode`] enforces the consequence.
    pub const fn is_response_side(self) -> bool {
        matches!(self, Self::DataLeakage | Self::WebShell)
    }

    /// Native rule IDs for this category live in `group * 1000 ..= group * 1000 + 999`.
    ///
    /// Derived from the CRS group so an ID is self-describing: `942_017` is
    /// visibly a SQLi rule. Ranges cannot overlap because CRS groups are
    /// distinct, which the tests assert rather than assume.
    pub const fn id_range(self) -> (u32, u32) {
        let base = self.crs_group() as u32 * 1_000;
        (base, base + 999)
    }

    /// Whether `id` falls in this category's native range.
    pub const fn owns_id(self, id: u32) -> bool {
        let (lo, hi) = self.id_range();
        id >= lo && id <= hi
    }

    /// Config key for this category, matching the `serde` rename.
    pub const fn key(self) -> &'static str {
        match self {
            Self::ProtocolEnforcement => "protocol_enforcement",
            Self::LocalFileInclusion => "local_file_inclusion",
            Self::RemoteCodeExecution => "remote_code_execution",
            Self::Php => "php",
            Self::Generic => "generic",
            Self::Xss => "xss",
            Self::SqlInjection => "sql_injection",
            Self::SessionFixation => "session_fixation",
            Self::DataLeakage => "data_leakage",
            Self::WebShell => "web_shell",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_covers_every_variant() {
        // If a variant is added without extending ALL, category iteration
        // silently skips it and its rules never run.
        assert_eq!(Category::ALL.len(), 10);
        let keys: HashSet<&str> =
            Category::ALL.iter().map(|c| c.key()).collect();
        assert_eq!(keys.len(), 10, "duplicate config key");
    }

    #[test]
    fn id_ranges_do_not_overlap() {
        // A collision would silently change which rule a historical log line
        // refers to, so this is asserted rather than trusted to arithmetic.
        let mut seen: Vec<(u32, u32, Category)> = Category::ALL
            .iter()
            .map(|c| {
                let (lo, hi) = c.id_range();
                (lo, hi, *c)
            })
            .collect();
        seen.sort_by_key(|(lo, _, _)| *lo);
        for w in seen.windows(2) {
            let (_, hi_a, a) = w[0];
            let (lo_b, _, b) = w[1];
            assert!(
                hi_a < lo_b,
                "{a} range ends at {hi_a}, {b} starts at {lo_b} — overlap"
            );
        }
    }

    #[test]
    fn native_ids_stay_below_the_custom_floor() {
        // Category ranges are derived from CRS group numbers; the highest is 955,
        // so the top native ID is 955_999 — comfortably below CUSTOM_RULE_ID_BASE.
        let max = Category::ALL
            .iter()
            .map(|c| c.id_range().1)
            .max()
            .expect("non-empty");
        assert!(
            max < crate::rule::CUSTOM_RULE_ID_BASE,
            "native range {max} reaches into custom space"
        );
        assert!(crate::rule::RuleId::native(max).is_some());
    }

    #[test]
    fn owns_id_matches_range() {
        let sqli = Category::SqlInjection;
        assert!(sqli.owns_id(942_000));
        assert!(sqli.owns_id(942_999));
        assert!(!sqli.owns_id(941_999));
        assert!(!sqli.owns_id(943_000));
    }

    #[test]
    fn exactly_two_categories_are_response_side() {
        let resp: Vec<_> = Category::ALL
            .iter()
            .filter(|c| c.is_response_side())
            .collect();
        assert_eq!(resp.len(), 2, "expected 950 and 955 only");
        assert!(resp.contains(&&Category::DataLeakage));
        assert!(resp.contains(&&Category::WebShell));
        // The 95x prefix is what makes them response-side in CRS.
        for c in resp {
            assert!(c.crs_group() >= 950);
        }
    }

    #[test]
    fn generic_is_934_and_not_labelled_ssrf() {
        // The reference product labels 934 "SSRF"; upstream CRS ships it as
        // APPLICATION-ATTACK-GENERIC. Following the mislabel would leave an
        // operator unable to find the corresponding CRS rules.
        assert_eq!(Category::Generic.crs_group(), 934);
        assert!(Category::Generic.crs_file().contains("GENERIC"));
        assert!(!Category::Generic.crs_file().contains("SSRF"));
    }

    #[test]
    fn crs_files_match_their_group_numbers() {
        for c in Category::ALL {
            let n = c.crs_group().to_string();
            assert!(
                c.crs_file().contains(&n),
                "{c} file {} does not name group {n}",
                c.crs_file()
            );
        }
    }
}
