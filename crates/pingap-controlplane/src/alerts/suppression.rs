use super::evaluator::Evaluation;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionDecision {
    Suppress,
    Fire,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuppressionState {
    pub evaluation: Evaluation,
    pub changed_at: i64,
    pub last_sent_at: Option<i64>,
}
#[derive(Debug, Default)]
pub struct Suppression {
    states: HashMap<String, SuppressionState>,
    window_secs: i64,
}
impl Suppression {
    pub fn new(window_secs: i64) -> Self {
        Self {
            states: HashMap::new(),
            window_secs: window_secs.max(0),
        }
    }
    pub fn decide(
        &mut self,
        rule_id: &str,
        evaluation: Evaluation,
        now: i64,
    ) -> SuppressionDecision {
        let prior = self.states.get(rule_id).copied();
        let changed = prior.is_none_or(|s| s.evaluation != evaluation);
        let allowed = changed
            || prior
                .and_then(|s| s.last_sent_at)
                .is_none_or(|at| now.saturating_sub(at) >= self.window_secs);
        self.states.insert(
            rule_id.to_string(),
            SuppressionState {
                evaluation,
                // `changed` is false only when `prior` exists and its evaluation matched —
                // so reaching the `else` means the timestamp is there to keep.
                changed_at: if changed {
                    now
                } else {
                    prior.map(|s| s.changed_at).unwrap_or(now)
                },
                last_sent_at: if allowed {
                    Some(now)
                } else {
                    prior.and_then(|s| s.last_sent_at)
                },
            },
        );
        if allowed {
            SuppressionDecision::Fire
        } else {
            SuppressionDecision::Suppress
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transitions_and_window() {
        let mut s = Suppression::new(60);
        assert_eq!(
            s.decide("r", Evaluation::Firing, 0),
            SuppressionDecision::Fire
        );
        assert_eq!(
            s.decide("r", Evaluation::Firing, 1),
            SuppressionDecision::Suppress
        );
        assert_eq!(s.decide("r", Evaluation::Ok, 2), SuppressionDecision::Fire);
    }
}
