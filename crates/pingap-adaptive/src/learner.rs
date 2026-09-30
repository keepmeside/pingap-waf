use crate::config::AdaptiveConfig;
use crate::decision::{self, Decision};
use crate::profile::HourlyProfile;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleDisposition {
    Normal,
    Denied,
    Challenged,
    Bot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub profiles: Vec<HourlyProfile>,
    pub learned_at_secs: u64,
}

#[derive(Debug, Clone)]
pub struct AdaptiveLearner {
    pub profiles: Vec<HourlyProfile>,
    pub samples: u64,
    pub calibrated: bool,
    pub confidence: f64,
    pub discarded_baselines: u64,
    config: AdaptiveConfig,
    learned_at: Option<SystemTime>,
    /// Rolling request counter used to derive the domain's current RPS. The
    /// window is a short fixed span, so `current_rps` reflects the live rate
    /// rather than an all-time average.
    rate: RateWindow,
}

/// Requests counted over a fixed second-aligned window. Produces a current
/// requests-per-second reading for the learner's ratio — the value the
/// `adaptive_current_rps` ctx variable was a placeholder for before any
/// producer wrote it.
#[derive(Debug, Clone)]
struct RateWindow {
    /// Length of one window in whole seconds.
    span_secs: u64,
    /// Second-aligned window start, seconds since the Unix epoch.
    start_secs: u64,
    /// Requests observed since `start_secs`.
    count: u64,
    /// The previous completed window's rate, so the reading does not reset to
    /// zero at each boundary.
    last_rate: f64,
}

impl RateWindow {
    fn new(span_secs: u64) -> Self {
        Self {
            span_secs: span_secs.max(1),
            start_secs: 0,
            count: 0,
            last_rate: 0.0,
        }
    }

    /// Record one request at `now` and return the current requests-per-second.
    fn observe(&mut self, now_secs: u64) -> f64 {
        if self.start_secs == 0 {
            self.start_secs = now_secs;
        }
        self.count = self.count.saturating_add(1);
        let elapsed = now_secs.saturating_sub(self.start_secs);
        if elapsed < self.span_secs {
            // Inside the window: estimate the live rate from elapsed time.
            let live = self.count as f64 / (elapsed.max(1) as f64);
            // Blend with the last completed window so a fresh boundary does not
            // read as a traffic spike or collapse.
            return live.max(self.last_rate);
        }
        // Window closed: roll the completed rate forward and start a new one.
        self.last_rate = self.count as f64 / elapsed as f64;
        self.count = 0;
        self.start_secs = now_secs;
        self.last_rate
    }
}

impl AdaptiveLearner {
    pub fn new(config: AdaptiveConfig) -> Self {
        Self {
            profiles: (0..24)
                .map(|_| HourlyProfile::new(config.max_samples_per_hour))
                .collect(),
            samples: 0,
            calibrated: false,
            confidence: 0.0,
            discarded_baselines: 0,
            config,
            learned_at: None,
            rate: RateWindow::new(10),
        }
    }
    /// Record one request and return the domain's current requests-per-second.
    /// The learner measures the rate itself; nothing external supplies it.
    pub fn observe(&mut self, now: SystemTime) -> f64 {
        let now_secs =
            now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        self.rate.observe(now_secs)
    }
    pub fn record(
        &mut self,
        hour: usize,
        rps: f64,
        bot_rate: f64,
        disposition: SampleDisposition,
    ) {
        if !matches!(disposition, SampleDisposition::Normal) {
            return;
        }
        self.profiles[hour % 24].record(rps, bot_rate);
        self.samples = self.samples.saturating_add(1);
        self.recalibrate();
    }
    pub fn recalibrate(&mut self) {
        let populated = self
            .profiles
            .iter()
            .filter(|profile| {
                profile.len() >= self.config.max_samples_per_hour.min(4)
            })
            .count() as f64;
        self.confidence = (populated / 24.0).sqrt().min(1.0);
        self.calibrated = self.samples
            >= u64::from(self.config.min_days_to_calibrate) * 24
            && self.confidence >= self.config.min_confidence;
    }
    pub fn decision(&self, hour: usize, current_rps: f64) -> Decision {
        if !self.calibrated {
            return Decision::normal();
        }
        let profile = &self.profiles[hour % 24];
        decision::decide(
            &self.config,
            profile.avg_rps,
            current_rps,
            profile.avg_bot_rate,
        )
    }
    pub fn baseline(&self) -> Baseline {
        Baseline {
            profiles: self.profiles.clone(),
            learned_at_secs: self
                .learned_at
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs())
                .unwrap_or_else(|| {
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                }),
        }
    }
    pub fn restore(&mut self, baseline: Baseline, now: SystemTime) -> bool {
        if baseline.profiles.len() != 24 {
            self.discarded_baselines =
                self.discarded_baselines.saturating_add(1);
            return false;
        }
        let age = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(baseline.learned_at_secs);
        if age > self.config.max_baseline_age_days.saturating_mul(86_400) {
            self.discarded_baselines =
                self.discarded_baselines.saturating_add(1);
            return false;
        }
        self.profiles = baseline
            .profiles
            .into_iter()
            .map(|mut profile| {
                profile.max_samples = self.config.max_samples_per_hour;
                while profile.samples.len() > self.config.max_samples_per_hour {
                    profile.samples.pop_front();
                }
                profile
            })
            .collect();
        self.learned_at = Some(now);
        self.samples = 0;
        self.calibrated = false;
        self.confidence = 0.0;
        true
    }
    pub fn effective_factor(
        &self,
        configured: f64,
        decision: &Decision,
    ) -> f64 {
        if !decision.calibrated {
            1.0
        } else {
            decision::clamp_factor(
                configured,
                decision.rate_limit_factor,
                self.config.min_factor,
                self.config.allow_loosening,
            )
        }
    }
    pub fn config(&self) -> &AdaptiveConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn learner() -> AdaptiveLearner {
        AdaptiveLearner::new(AdaptiveConfig::default())
    }

    #[test]
    fn observe_reports_the_measured_rate_not_a_constant() {
        // Before the learner owned the counter, `current_rps` was a phantom
        // ctx variable nothing wrote, so every sample was 1.0. Now a burst
        // inside one window reads high and an idle gap reads lower.
        let mut l = learner();
        let base = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut last = 0.0;
        for i in 0..20 {
            last = l.observe(base + Duration::from_millis(i * 100));
        }
        // 20 requests across ~2 s inside a 10 s window ≈ 10 rps, not 1.0.
        assert!(last > 5.0, "live rate should track the burst, got {last}");
        // An idle window rolls the rate forward rather than pegging it.
        let after_idle = l.observe(base + Duration::from_secs(120));
        assert!(
            after_idle <= last,
            "idle must not read higher than the burst"
        );
    }

    #[test]
    fn the_rate_window_is_deterministic_for_the_same_sequence() {
        let run = || {
            let mut l = learner();
            let base = UNIX_EPOCH + Duration::from_secs(5_000);
            (0..10u64)
                .map(|i| l.observe(base + Duration::from_secs(i)))
                .last()
                .unwrap_or_default()
        };
        assert_eq!(run(), run());
    }
}
