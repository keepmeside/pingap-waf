//! Per-request evaluation time budget.
//!
//! `fancy-regex` backtracks. That is why it was chosen — some CRS-derived
//! patterns need backreferences and lookaround that `regex` rejects — but it
//! means a pathological input can make a single pattern cost far more than the
//! rest of the ruleset combined.
//!
//! The budget is **enforced between rules, not only at the end**. Checking only
//! after the loop would let one catastrophic pattern consume the whole budget
//! unobserved, which is the failure this exists to make visible.

use std::time::{Duration, Instant};

/// What to do when a request exhausts its evaluation budget.
///
/// This is a security-relevant default, so it is an operator decision rather than
/// a constant. `Allow` trades detection for availability: a request that could not
/// be fully evaluated is passed through. `Block` trades the reverse.
///
/// `Allow` is the default because a WAF that starts rejecting traffic under load
/// — exactly when evaluation is slowest — turns a latency problem into an outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExhaustedPolicy {
    #[default]
    Allow,
    Block,
}

/// Tracks elapsed evaluation time for one request.
///
/// Deliberately not `Copy`: a budget is per-request state, and copying one would
/// silently reset the clock.
#[derive(Debug)]
pub struct Budget {
    started: Instant,
    limit: Duration,
    policy: ExhaustedPolicy,
    /// Rules evaluated before exhaustion, for the log record. An operator needs
    /// to know whether the budget blew at rule 3 or rule 300.
    checked: u32,
}

/// Why evaluation stopped early.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exhausted {
    /// How long evaluation actually took before the budget was noticed.
    pub elapsed: Duration,
    /// Configured limit, for context in the log line.
    pub limit: Duration,
    /// Rules completed before the budget ran out.
    pub rules_checked: u32,
    pub policy: ExhaustedPolicy,
}

impl Budget {
    pub fn new(limit: Duration, policy: ExhaustedPolicy) -> Self {
        Self {
            started: Instant::now(),
            limit,
            policy,
            checked: 0,
        }
    }

    pub const fn policy(&self) -> ExhaustedPolicy {
        self.policy
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    pub const fn rules_checked(&self) -> u32 {
        self.checked
    }

    /// Call once per rule, before evaluating it. Returns `Err` when the budget is
    /// spent, carrying enough context for a non-silent log record.
    ///
    /// Counting happens on the success path so `rules_checked` means "rules
    /// actually evaluated", not "checks attempted".
    pub fn check(&mut self) -> Result<(), Exhausted> {
        let elapsed = self.started.elapsed();
        if elapsed >= self.limit {
            return Err(Exhausted {
                elapsed,
                limit: self.limit,
                rules_checked: self.checked,
                policy: self.policy,
            });
        }
        self.checked = self.checked.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_permits_work_within_the_limit() {
        let mut b =
            Budget::new(Duration::from_secs(30), ExhaustedPolicy::Allow);
        for _ in 0..100 {
            assert!(b.check().is_ok());
        }
        assert_eq!(b.rules_checked(), 100);
    }

    #[test]
    fn budget_fires_once_exhausted_and_reports_context() {
        // Zero limit: the first check is already over budget.
        let mut b = Budget::new(Duration::ZERO, ExhaustedPolicy::Block);
        let err = b.check().expect_err("zero budget must be exhausted");
        assert_eq!(err.policy, ExhaustedPolicy::Block);
        assert_eq!(err.limit, Duration::ZERO);
        // Nothing was evaluated, and the record says so rather than being silent.
        assert_eq!(err.rules_checked, 0);
    }

    #[test]
    fn exhaustion_is_sticky_across_subsequent_checks() {
        // Once over budget, every later check must also fail — otherwise a caller
        // that ignores one error keeps evaluating on borrowed time.
        let mut b = Budget::new(Duration::ZERO, ExhaustedPolicy::Allow);
        assert!(b.check().is_err());
        assert!(b.check().is_err());
        assert_eq!(b.rules_checked(), 0);
    }

    #[test]
    fn rules_checked_counts_only_successful_checks() {
        let mut b =
            Budget::new(Duration::from_millis(50), ExhaustedPolicy::Allow);
        assert!(b.check().is_ok());
        assert!(b.check().is_ok());
        assert_eq!(b.rules_checked(), 2);
        std::thread::sleep(Duration::from_millis(60));
        let err = b.check().expect_err("budget should be spent");
        assert_eq!(
            err.rules_checked, 2,
            "the failing check must not inflate the count"
        );
        assert!(err.elapsed >= Duration::from_millis(50));
    }

    #[test]
    fn allow_is_the_default_policy() {
        // Documented as the availability-preserving default; asserted so a future
        // refactor cannot flip it silently.
        assert_eq!(ExhaustedPolicy::default(), ExhaustedPolicy::Allow);
    }
}
