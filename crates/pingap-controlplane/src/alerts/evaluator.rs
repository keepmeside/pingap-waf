use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Comparison {
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
    Equal,
}

impl Comparison {
    pub fn matches(self, observed: f64, threshold: f64) -> bool {
        match self {
            Self::Greater => observed > threshold,
            Self::GreaterOrEqual => observed >= threshold,
            Self::Less => observed < threshold,
            Self::LessOrEqual => observed <= threshold,
            Self::Equal => (observed - threshold).abs() < f64::EPSILON,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub metric: String,
    pub comparator: Comparison,
    pub threshold: f64,
    pub window_secs: i64,
    pub severity: String,
    pub enabled: bool,
    pub channel_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MetricSample {
    pub value: f64,
    pub bucket_start: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evaluation {
    Firing,
    Ok,
}

pub fn evaluate(
    rule: &AlertRule,
    samples: &[MetricSample],
    now: i64,
) -> Option<(Evaluation, f64)> {
    if !rule.enabled || rule.window_secs <= 0 || !rule.threshold.is_finite() {
        return None;
    }
    let since = now.saturating_sub(rule.window_secs);
    let observed = samples
        .iter()
        .filter(|s| s.bucket_start >= since && s.bucket_start <= now)
        .map(|s| s.value)
        .sum::<f64>();
    if !observed.is_finite() {
        return None;
    }
    Some((
        if rule.comparator.matches(observed, rule.threshold) {
            Evaluation::Firing
        } else {
            Evaluation::Ok
        },
        observed,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rule(c: Comparison) -> AlertRule {
        AlertRule {
            id: "r".into(),
            name: "r".into(),
            metric: "m".into(),
            comparator: c,
            threshold: 3.0,
            window_secs: 60,
            severity: "warn".into(),
            enabled: true,
            channel_ids: vec![],
        }
    }
    #[test]
    fn sums_only_window() {
        let r = rule(Comparison::GreaterOrEqual);
        assert_eq!(
            evaluate(
                &r,
                &[
                    MetricSample {
                        value: 2.0,
                        bucket_start: 100
                    },
                    MetricSample {
                        value: 9.0,
                        bucket_start: 20
                    }
                ],
                100
            ),
            Some((Evaluation::Ok, 2.0))
        );
    }
    #[test]
    fn comparisons_are_explicit() {
        assert_eq!(
            evaluate(
                &rule(Comparison::Greater),
                &[MetricSample {
                    value: 3.0,
                    bucket_start: 100
                }],
                100
            )
            .unwrap()
            .0,
            Evaluation::Ok
        );
    }
}
