//! Per-request scoring cost for the behavioural plugin, as percentiles.
//!
//! The plan owes three per-request numbers recorded separately, so none hides
//! inside another: the detector set (measured in `pingap-waf`'s latency
//! bench), the Phase 2 container (measured in `pingap-domainstate`'s store
//! bench), and the behavioural scoring itself — this file. Like those, it
//! times each call individually and reads the quantiles off the sorted
//! samples, because the number that decides whether scoring stays on every
//! request is a p99, and a batch mean is not a p99. No framework,
//! `harness = false`.
//!
//! **What this measures.** The behaviour-specific per-request work: landing
//! one observation in a profile (`record`, which at the sample cap also pops
//! the oldest and rebuilds the URL and user-agent aggregates) and scoring the
//! profile (`score`, all six signals over the bounded window, the weighted
//! average and the classification). The profile is at every cap, which is the
//! steady state a busy client holds — the upper bound; a younger profile
//! scores fewer samples and costs less.
//!
//! **What it excludes.** The store lookup and the profile snapshot it clones
//! (the Phase 2 container's own per-operation cost, benched in
//! `pingap-domainstate`), the session header reads, and the ctx variable
//! writes — the plugin surface every plugin shares.
//!
//! Run with `cargo bench -p pingap-behaviour --bench scoring`.

use pingap_behaviour::{Observation, Profile, SignalWeights, Thresholds};
use std::hint::black_box;
use std::time::{Duration, Instant};

/// Enough samples that the p99 is read off ~20 observations rather than one.
const ITERATIONS: usize = 2000;
/// Discarded before measuring, and past the 32-sample cap, so the
/// measurement is of the steady state rather than the growing edge.
const WARMUP: usize = 200;

/// The paths a returning visitor cycles through. A fixed small set, so the
/// URL aggregate settles at its window-bounded steady state and every signal
/// runs its full path every iteration.
const PATHS: [&str; 8] = [
    "/",
    "/products",
    "/products/1",
    "/products/2",
    "/cart",
    "/checkout",
    "/account",
    "/search",
];

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
    // The documented defaults: 32 interval samples, 64 URL keys, 8 user
    // agents, a 5-minute window, the shipped weights and thresholds.
    let mut profile = Profile::new(32, 64, 8, Duration::from_secs(300));
    let weights = SignalWeights::default();
    let thresholds = Thresholds::default();
    let min_samples = 6;

    let start = Instant::now();
    let mut tick = 0u64;
    // One observation: varied intervals so the timing signal runs its full
    // path, the cycling path set above, and two user agents.
    let observation = |tick: u64| Observation {
        at: start + Duration::from_millis(tick),
        uri: PATHS[(tick / 700) as usize % PATHS.len()].into(),
        user_agent: if (tick / 3_500).is_multiple_of(2) {
            "browser-a".into()
        } else {
            "browser-b".into()
        },
        status: 200,
        denied: false,
        challenged: false,
        bot: false,
    };

    for _ in 0..WARMUP {
        tick += 400 + (tick % 7) * 300;
        profile.record(observation(tick));
        black_box(pingap_behaviour::score::score(
            &profile,
            weights,
            thresholds,
            min_samples,
        ));
    }

    let mut samples = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let started = Instant::now();
        tick += 400 + (tick % 7) * 300;
        profile.record(observation(tick));
        black_box(pingap_behaviour::score::score(
            &profile,
            weights,
            thresholds,
            min_samples,
        ));
        samples.push(started.elapsed().as_nanos());
    }
    report("record+score", samples);
}
