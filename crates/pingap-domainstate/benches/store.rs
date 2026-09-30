//! Per-operation cost of the keyed container.
//!
//! Measured rather than assumed, because the open latency decision needs a number: the
//! detectors already add 815 µs–5.6 ms per request, so a container that costs microseconds is
//! noise and one that costs tens of microseconds is a reason to shard. Every benchmark here is
//! steady-state — a bench that grows a map without limit measures its own eviction.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use pingap_domainstate::{Domain, HostPolicy, Limits, ScopedStore};
// `std::hint` rather than `criterion::black_box`, which 0.7 deprecates.
use std::hint::black_box;
use std::time::Duration;

const TTL: Duration = Duration::from_secs(300);

fn hosts(count: usize) -> Vec<String> {
    (0..count)
        .map(|round| format!("h{round}.example"))
        .collect()
}

fn store(
    domain_count: usize,
    entries_per_domain: usize,
) -> (ScopedStore<u64>, Vec<Domain>) {
    let names = hosts(domain_count);
    let scoped = ScopedStore::new(
        HostPolicy::new(names.iter().map(String::as_str)),
        Limits {
            max_domains: domain_count,
            max_entries_per_domain: entries_per_domain,
        },
    );
    let keys = names
        .iter()
        .map(|name| scoped.hosts().classify(name))
        .collect();
    (scoped, keys)
}

/// The per-request host classification, before any locking.
fn classify(c: &mut Criterion) {
    let mut group = c.benchmark_group("classify");
    for count in [1usize, 64, 1000] {
        let names = hosts(count);
        let policy = HostPolicy::new(names.iter().map(String::as_str));
        let registered = names[count / 2].clone();
        group.bench_with_input(
            BenchmarkId::new("registered-host", count),
            &registered,
            |b, host| b.iter(|| black_box(policy.classify(black_box(host)))),
        );
        group.bench_with_input(
            BenchmarkId::new("unregistered-host", count),
            &"not-configured.example",
            |b, host| b.iter(|| black_box(policy.classify(black_box(host)))),
        );
    }
    group.finish();
}

/// Reads, which are the common case: most requests hit state that already exists.
fn read(c: &mut Criterion) {
    let mut group = c.benchmark_group("read");
    for (domain_count, entries) in
        [(1usize, 64usize), (64, 1_000), (256, 5_000)]
    {
        let (scoped, keys) = store(domain_count, entries);
        for (round, key) in keys.iter().enumerate() {
            for entry in 0..entries {
                let _ = scoped.insert(
                    *key,
                    &format!("client-{round}-{entry}"),
                    entry as u64,
                    TTL,
                );
            }
        }
        group.bench_with_input(
            BenchmarkId::new("hit", format!("{domain_count}x{entries}")),
            &entries,
            |b, _| {
                let mut round = 0usize;
                b.iter(|| {
                    let key = keys[round % keys.len()];
                    let identity = format!(
                        "client-{}-{}",
                        round % keys.len(),
                        round % entries
                    );
                    round = round.wrapping_add(1);
                    black_box(scoped.get(black_box(key), black_box(&identity)))
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("miss", format!("{domain_count}x{entries}")),
            &entries,
            |b, _| {
                let mut round = 0usize;
                b.iter(|| {
                    let key = keys[round % keys.len()];
                    round = round.wrapping_add(1);
                    black_box(
                        scoped.get(black_box(key), black_box("never-present")),
                    )
                });
            },
        );
    }
    group.finish();
}

/// Writes: the refresh path, which is what an incrementing counter takes per request.
fn write(c: &mut Criterion) {
    let mut group = c.benchmark_group("write");
    for (domain_count, entries) in
        [(1usize, 64usize), (64, 1_000), (256, 5_000)]
    {
        let (scoped, keys) = store(domain_count, entries);
        for (round, key) in keys.iter().enumerate() {
            for entry in 0..entries {
                let _ = scoped.insert(
                    *key,
                    &format!("client-{round}-{entry}"),
                    entry as u64,
                    TTL,
                );
            }
        }
        let label = format!("{domain_count}x{entries}");
        group.bench_with_input(
            BenchmarkId::new("refresh", &label),
            &entries,
            |b, _| {
                let mut round = 0usize;
                b.iter(|| {
                    let index = round % keys.len();
                    let identity =
                        format!("client-{index}-{}", round % entries);
                    round = round.wrapping_add(1);
                    black_box(
                        scoped
                            .insert(
                                black_box(keys[index]),
                                black_box(&identity),
                                round as u64,
                                TTL,
                            )
                            .is_ok(),
                    )
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("update", &label),
            &entries,
            |b, _| {
                let mut round = 0usize;
                b.iter(|| {
                    let index = round % keys.len();
                    let identity =
                        format!("client-{index}-{}", round % entries);
                    round = round.wrapping_add(1);
                    black_box(scoped.update(
                        black_box(keys[index]),
                        black_box(&identity),
                        |value| *value = value.wrapping_add(1),
                    ))
                });
            },
        );
    }
    group.finish();
}

/// The saturated path: a full bucket, so every new identity pays a reclaim scan and a refusal.
///
/// This is the cost an attacker can force, which is why it is measured separately rather than
/// averaged into the write figures.
fn saturated(c: &mut Criterion) {
    let entries = 5_000usize;
    let (scoped, keys) = store(1, entries);
    let key = keys[0];
    for round in 0..entries {
        let _ =
            scoped.insert(key, &format!("client-{round}"), round as u64, TTL);
    }

    c.bench_function("write/saturated-new-identity", |b| {
        let mut round = 0usize;
        b.iter(|| {
            let identity = format!("attacker-{round}");
            round = round.wrapping_add(1);
            black_box(
                scoped
                    .insert(black_box(key), black_box(&identity), 0, TTL)
                    .is_err(),
            )
        })
    });
}

criterion_group!(benches, classify, read, write, saturated);
criterion_main!(benches);
