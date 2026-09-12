//! Bot analytics: counts per fingerprint, per verdict, per domain.
//!
//! Aggregated in Rust rather than in SQL, and not as a style preference. Phase 07's store
//! is Turso, whose window-function support lacks `lag`/`lead` and custom frames — the
//! shape a "top fingerprints over the last hour, ranked" query wants. Computing here keeps
//! the store to inserts and simple selects, which is the subset it is reliable at.
//!
//! **Aggregate only.** A fingerprint is a weak tracking identifier, so this deliberately
//! offers no per-visitor history: there is nowhere to record "this fingerprint, from this
//! address, at these times". Counts by fingerprint answer the operational question ("what
//! is hitting me, and is my rule working") without building a profile of anyone.

use std::collections::BTreeMap;

/// What a profile decided about a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Allowed,
    /// A rule matched and the profile is in `block` mode.
    Denied,
    /// A rule matched but the profile is in `detect` mode, so nothing was refused.
    WouldDeny,
    /// Exempted as a known-good crawler.
    KnownBot,
    /// No fingerprint could be computed. Fail-open — the request was allowed.
    Missed,
}

impl Verdict {
    pub const fn key(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::WouldDeny => "would_deny",
            Self::KnownBot => "known_bot",
            Self::Missed => "missed",
        }
    }
}

/// One observation. Deliberately carries no address and no timestamp.
#[derive(Debug, Clone)]
pub struct Observation {
    pub domain: String,
    pub fingerprint: Option<String>,
    pub verdict: Verdict,
    /// The protocol the request arrived on, e.g. `HTTP/1.1`.
    pub protocol: String,
}

/// Rolling counts.
///
/// `BTreeMap` rather than a hash map so every report is emitted in a stable order — a
/// dashboard whose rows reshuffle between refreshes is read as data changing.
#[derive(Debug, Default, Clone)]
pub struct Analytics {
    by_fingerprint: BTreeMap<String, u64>,
    by_verdict: BTreeMap<Verdict, u64>,
    by_domain: BTreeMap<String, u64>,
    /// Misses broken out by protocol. An all-h2 miss population is *expected*, because
    /// h2 does not preserve header order; without the breakdown it is indistinguishable
    /// from an attacker forcing misses, which is the one thing fail-open must not hide.
    misses_by_protocol: BTreeMap<String, u64>,
    total: u64,
}

impl Analytics {
    pub fn record(&mut self, observation: &Observation) {
        self.total += 1;
        *self.by_verdict.entry(observation.verdict).or_default() += 1;
        *self
            .by_domain
            .entry(observation.domain.clone())
            .or_default() += 1;
        if let Some(fingerprint) = &observation.fingerprint {
            *self.by_fingerprint.entry(fingerprint.clone()).or_default() += 1;
        }
        if observation.verdict == Verdict::Missed {
            *self
                .misses_by_protocol
                .entry(observation.protocol.clone())
                .or_default() += 1;
        }
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    /// Fingerprints by descending count, ties broken by fingerprint so the order is
    /// deterministic. This is the "ranked top-N" a window function would otherwise do.
    pub fn top_fingerprints(&self, limit: usize) -> Vec<(&str, u64)> {
        let mut rows: Vec<(&str, u64)> = self
            .by_fingerprint
            .iter()
            .map(|(k, v)| (k.as_str(), *v))
            .collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        rows.truncate(limit);
        rows
    }

    pub fn verdict_counts(&self) -> Vec<(Verdict, u64)> {
        self.by_verdict.iter().map(|(k, v)| (*k, *v)).collect()
    }

    pub fn domain_counts(&self) -> Vec<(&str, u64)> {
        self.by_domain
            .iter()
            .map(|(k, v)| (k.as_str(), *v))
            .collect()
    }

    pub fn misses_by_protocol(&self) -> Vec<(&str, u64)> {
        self.misses_by_protocol
            .iter()
            .map(|(k, v)| (k.as_str(), *v))
            .collect()
    }

    /// Fraction of observations with no computable fingerprint.
    ///
    /// Exposed because fail-open is only defensible if it is measurable: an operator has
    /// to be able to see the rate to know whether their policy covers their traffic.
    pub fn miss_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let missed =
            self.by_verdict.get(&Verdict::Missed).copied().unwrap_or(0);
        missed as f64 / self.total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(
        domain: &str,
        fp: Option<&str>,
        verdict: Verdict,
        proto: &str,
    ) -> Observation {
        Observation {
            domain: domain.to_string(),
            fingerprint: fp.map(str::to_string),
            verdict,
            protocol: proto.to_string(),
        }
    }

    #[test]
    fn counts_rank_without_a_window_function() {
        let mut a = Analytics::default();
        for _ in 0..3 {
            a.record(&obs(
                "a.test",
                Some("ge11nn03"),
                Verdict::Denied,
                "HTTP/1.1",
            ));
        }
        a.record(&obs(
            "a.test",
            Some("ge11nn04"),
            Verdict::Allowed,
            "HTTP/1.1",
        ));
        a.record(&obs(
            "b.test",
            Some("ge11nn04"),
            Verdict::Allowed,
            "HTTP/1.1",
        ));

        assert_eq!(
            a.top_fingerprints(2),
            vec![("ge11nn03", 3), ("ge11nn04", 2)]
        );
        assert_eq!(a.domain_counts(), vec![("a.test", 4), ("b.test", 1)]);
        assert_eq!(a.total(), 5);
    }

    #[test]
    fn ties_break_deterministically() {
        // A dashboard whose rows reshuffle between refreshes reads as data changing.
        let mut a = Analytics::default();
        a.record(&obs("d", Some("zzz"), Verdict::Allowed, "HTTP/1.1"));
        a.record(&obs("d", Some("aaa"), Verdict::Allowed, "HTTP/1.1"));
        assert_eq!(a.top_fingerprints(2), vec![("aaa", 1), ("zzz", 1)]);
    }

    #[test]
    fn the_miss_rate_is_measurable_and_broken_out_by_protocol() {
        // Fail-open is only defensible if the rate is visible, and an all-h2 miss
        // population has to be distinguishable from an attacker forcing misses.
        let mut a = Analytics::default();
        a.record(&obs("d", Some("ge11nn03"), Verdict::Allowed, "HTTP/1.1"));
        a.record(&obs("d", None, Verdict::Missed, "HTTP/2.0"));
        a.record(&obs("d", None, Verdict::Missed, "HTTP/2.0"));
        a.record(&obs("d", None, Verdict::Missed, "HTTP/1.1"));

        assert_eq!(a.miss_rate(), 0.75);
        assert_eq!(
            a.misses_by_protocol(),
            vec![("HTTP/1.1", 1), ("HTTP/2.0", 2)]
        );
    }

    #[test]
    fn an_empty_report_has_a_zero_miss_rate_rather_than_a_division_by_zero() {
        assert_eq!(Analytics::default().miss_rate(), 0.0);
        assert!(Analytics::default().top_fingerprints(10).is_empty());
    }

    #[test]
    fn a_missed_request_contributes_no_fingerprint_row() {
        // There is no fingerprint to attribute it to, and inventing a placeholder row
        // would put an unbounded "unknown" bucket at the top of every ranking.
        let mut a = Analytics::default();
        a.record(&obs("d", None, Verdict::Missed, "HTTP/2.0"));
        assert!(a.top_fingerprints(5).is_empty());
        assert_eq!(a.verdict_counts(), vec![(Verdict::Missed, 1)]);
    }
}
