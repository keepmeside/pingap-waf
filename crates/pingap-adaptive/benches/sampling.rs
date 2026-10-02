//! Per-request sampling overhead for the adaptive learner, as percentiles.
//!
//! Like the detector latency bench in `pingap-waf`, this times each call
//! individually and reads the quantiles off the sorted samples: the decision
//! this measurement owes — does recording stay on every request, or does it
//! need sampling down to every Nth? — is read off the p99, and a batch mean
//! is not a p99. No framework, `harness = false`.
//!
//! **What this measures.** The learner sequence the plugin runs for every
//! request: `observe` (the rate window), `record` (the profile push plus the
//! recalibration pass over all 24 hourly profiles), `decision` (the ratio
//! ladder, including the reason `String` it allocates), and
//! `effective_factor` (the clamp against the configured limit). The learner
//! is calibrated and its hourly profile is at the sample cap, which is the
//! steady state a production domain holds — and the upper bound: an
//! uncalibrated learner returns early from `decision` and costs less.
//!
//! **What it excludes.** The per-domain learner lookup and the lock around
//! it, the modulation counter, and the ctx variable writes. Those are the
//! plugin surface every plugin shares; the sampling cost the decision is
//! about is the learner itself.
//!
//! Run with `cargo bench -p pingap-adaptive --bench sampling`.

use pingap_adaptive::{AdaptiveConfig, AdaptiveLearner, SampleDisposition};
use std::hint::black_box;
use std::time::{Duration, Instant, UNIX_EPOCH};

/// Enough samples that the p99 is read off ~20 observations rather than one.
const ITERATIONS: usize = 2000;
/// Discarded before measuring, and past the calibration point (24 samples at
/// `min_days_to_calibrate = 1`), so the measurement is of the calibrated
/// steady state rather than the learning edge.
const WARMUP: usize = 200;

/// The tuning that reaches the calibrated steady state within the warmup:
/// one day of samples and a confidence floor a single populated hour clears.
/// Everything else is the shipped default, including the 240-sample hourly
/// cap the profile settles at.
fn learner() -> AdaptiveLearner {
    let config = AdaptiveConfig {
        min_days_to_calibrate: 1,
        min_confidence: 0.01,
        ..Default::default()
    };
    AdaptiveLearner::new(config)
}

/// Sort the samples and report the quantiles this benchmark owes, plus the
/// maximum: the worst single request is the number that decides whether a
/// worker stalls, and it is invisible in a p99.
fn report(label: &str, mut samples: Vec<u128>) {
    samples.sort_unstable();
    let at = |q: f64| {
        let idx = ((samples.len() - 1) as f64 * q).round() as usize;
        samples[idx] as f64 / 1000.0
    };
    println!(
        "{label:<38} p50 {:>8.2} µs  p99 {:>8.2} µs  max {:>9.2} µs",
        at(0.50),
        at(0.99),
        samples[samples.len() - 1] as f64 / 1000.0,
    );
}

fn main() {
    let mut learner = learner();
    let base = UNIX_EPOCH + Duration::from_secs(1_000_000);
    let mut tick = 0u64;

    for _ in 0..WARMUP {
        let now = base + Duration::from_millis(tick);
        tick += 1;
        let current = learner.observe(now);
        learner.record(12, current, 0.0, SampleDisposition::Normal);
        let decision = learner.decision(12, current);
        black_box(learner.effective_factor(1.0, &decision));
    }

    let mut samples = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let started = Instant::now();
        let now = base + Duration::from_millis(tick);
        tick += 1;
        let current = learner.observe(now);
        learner.record(12, current, 0.0, SampleDisposition::Normal);
        let decision = learner.decision(12, current);
        black_box(learner.effective_factor(1.0, &decision));
        samples.push(started.elapsed().as_nanos());
    }
    report("observe+record+decision", samples);
}
