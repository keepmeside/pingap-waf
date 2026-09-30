// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Findings, aggregated into buckets.
//!
//! Computed in Rust and not in SQL, which is a constraint rather than a preference: the
//! store's window functions have no `lag` or `lead` and no custom frames, so a rate or a delta
//! over buckets is not expressible as one query. Reading a window of rows and differencing them
//! here is slower and honest about it.
//!
//! What this aggregates is WAF findings, and only those. Request rate, latency percentiles and
//! upstream health are already collected on the request path by `pingap-performance` and
//! exported as Prometheus counters and histograms; recomputing them from a findings table
//! would produce a second, worse answer to a question that is already answered. The
//! WAF-specific breakdown — how many findings, how many were enforced, which rules and
//! categories produced them — is what nothing else holds.
//!
//! A pure function over a slice, with no store and no clock, so the aggregation is testable
//! against a fixed input and the caller decides what window to feed it and where the result
//! goes.

use crate::repository::{NewPerformanceMetric, WafEventRecord};

/// Default bucket width, in seconds.
///
/// One minute. Fine enough that an operator watching a dashboard sees an attack start within a
/// minute of it starting, coarse enough that a day of traffic is 1,440 buckets per metric
/// rather than 86,400.
pub const DEFAULT_BUCKET_SECS: i64 = 60;

/// The bucket a timestamp falls in.
///
/// Floor-aligned to the epoch rather than to the first event, so two nodes rolling up
/// independently produce rows that line up, and so a bucket's start is the same number
/// whichever node computed it.
pub fn bucket_start(created_at: i64, bucket_secs: i64) -> i64 {
    if bucket_secs <= 0 {
        return created_at;
    }
    // Flooring rather than truncating division: a negative timestamp would otherwise round
    // toward zero and land in the bucket after the one it belongs in. Nothing writes a
    // negative `created_at`, and the arithmetic should not depend on that.
    created_at.div_euclid(bucket_secs) * bucket_secs
}

/// Aggregates findings into metric rows, one set per bucket they fall in.
///
/// Metric names are a small closed vocabulary plus two derived families:
///
/// - `waf.findings` — how many findings landed in the bucket
/// - `waf.blocks` — how many of them were enforced
/// - `waf.rule.<id>` — how many a given rule produced
/// - `waf.category.<key>` — how many a given category produced
///
/// The derived families are sparse by construction: a row exists only for a rule or category
/// that actually fired, so cardinality tracks activity rather than the size of the ruleset.
/// That is what makes per-rule breakdown affordable at one-minute buckets, and it is also why
/// an absent row means "nothing fired" and not "not measured".
///
/// `node` is stamped on every row because peers share a store, and a total that silently
/// mixes two nodes is a number nobody can act on.
pub fn rollup(
    events: &[WafEventRecord],
    bucket_secs: i64,
    node: &str,
) -> Vec<NewPerformanceMetric> {
    if events.is_empty() {
        return Vec::new();
    }
    let bucket_secs = if bucket_secs > 0 {
        bucket_secs
    } else {
        DEFAULT_BUCKET_SECS
    };

    // One accumulator per bucket, in first-seen order. The input arrives newest-first, so a
    // linear scan over buckets is short — a window of findings spans a handful of minutes —
    // and keeping insertion order means the output is deterministic without a sort.
    let mut buckets: Vec<(i64, Bucket)> = Vec::new();
    for event in events {
        let start = bucket_start(event.created_at, bucket_secs);
        // Index rather than a borrowed entry: finding the bucket and, failing that, pushing
        // one cannot both hold a mutable borrow of the vector.
        let index = match buckets.iter().position(|(key, _)| *key == start) {
            Some(index) => index,
            None => {
                buckets.push((start, Bucket::default()));
                buckets.len() - 1
            },
        };
        buckets[index].1.absorb(event);
    }

    let mut out = Vec::new();
    for (start, bucket) in buckets {
        let metric = |name: String, value: f64| NewPerformanceMetric {
            node: node.to_string(),
            metric: name,
            value,
            bucket_start: start,
            bucket_secs,
        };
        out.push(metric("waf.findings".to_string(), bucket.findings as f64));
        out.push(metric("waf.blocks".to_string(), bucket.blocks as f64));
        for (rule, count) in &bucket.rules {
            out.push(metric(format!("waf.rule.{rule}"), *count as f64));
        }
        for (category, count) in &bucket.categories {
            out.push(metric(format!("waf.category.{category}"), *count as f64));
        }
    }
    out
}

/// One bucket's running totals.
#[derive(Debug, Default)]
struct Bucket {
    findings: u64,
    blocks: u64,
    /// Keyed by rule ID, so a finding with no single rule behind it is counted in the totals
    /// and in neither derived family. Inventing an ID for it would put a number in a metric
    /// name that means nothing.
    rules: std::collections::BTreeMap<u32, u64>,
    categories: std::collections::BTreeMap<String, u64>,
}

impl Bucket {
    fn absorb(&mut self, event: &WafEventRecord) {
        self.findings += 1;
        if event.blocked {
            self.blocks += 1;
        }
        if let Some(rule) = event.rule_id {
            *self.rules.entry(rule).or_default() += 1;
        }
        if let Some(category) = &event.category {
            *self.categories.entry(category.clone()).or_default() += 1;
        }
    }
}
