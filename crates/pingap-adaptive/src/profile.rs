//! One hour's bounded sample window: the learned expectation a ratio is taken
//! against.
//!
//! Ported from mango-waf `detection/adaptive.go` at commit 7f2c30c (MIT); see ./NOTICE.
//! The bounded sample window is the one memory property the donor gets right here
//! and is preserved exactly; serde is added so the aggregate persists.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourlyProfile {
    pub samples: VecDeque<f64>,
    pub avg_rps: f64,
    pub max_rps: f64,
    pub min_rps: f64,
    pub stddev_rps: f64,
    pub avg_bot_rate: f64,
    pub max_samples: usize,
}

impl HourlyProfile {
    pub fn new(max_samples: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(max_samples.max(1)),
            avg_rps: 0.0,
            max_rps: 0.0,
            min_rps: f64::MAX,
            stddev_rps: 0.0,
            avg_bot_rate: 0.0,
            max_samples: max_samples.max(1),
        }
    }
    pub fn record(&mut self, rps: f64, bot_rate: f64) {
        if self.samples.len() == self.max_samples {
            self.samples.pop_front();
        }
        self.samples.push_back(rps.max(0.0));
        let n = self.samples.len() as f64;
        self.avg_rps = self.samples.iter().sum::<f64>() / n;
        self.max_rps = self.samples.iter().copied().fold(0.0, f64::max);
        self.min_rps = self.samples.iter().copied().fold(f64::MAX, f64::min);
        self.stddev_rps = (self
            .samples
            .iter()
            .map(|value| (*value - self.avg_rps).powi(2))
            .sum::<f64>()
            / n)
            .sqrt();
        self.avg_bot_rate =
            (self.avg_bot_rate * (n - 1.0) + bot_rate.clamp(0.0, 1.0)) / n;
    }
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}
