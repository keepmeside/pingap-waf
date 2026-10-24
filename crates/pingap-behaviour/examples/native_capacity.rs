use pingap_behaviour::decisions::{
    Admission, MonotonicClock, Registry, ScenarioProfile,
};
use pingap_behaviour::scenario::{AbuseConfig, Mode, Rule};
use pingap_domainstate::{HostPolicy, Limits, ManualClock};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

const DOMAINS: usize = 256;
const ENTRIES: usize = 5_000;
const PROFILES: usize = 2;
const PER_PROFILE: usize = ENTRIES / PROFILES;

fn profile(namespace: &str) -> ScenarioProfile {
    ScenarioProfile::new(
        namespace,
        AbuseConfig {
            enabled: true,
            failed_login: None,
            scan: Some(Rule {
                mode: Mode::Detect,
                window: Duration::from_secs(3600),
                threshold: 64,
                ban_ttl: Duration::from_secs(3600),
            }),
        },
        PER_PROFILE,
        16,
        64,
    )
    .expect("capacity profile")
}

fn ip(domain: usize, entry: usize) -> String {
    format!("10.{}.{}.{}", domain, entry / 256, entry % 256)
}

fn p99_nanos(latencies: &[u128]) -> u128 {
    assert!(!latencies.is_empty(), "latency sample must not be empty");
    let mut sorted = latencies.to_vec();
    sorted.sort_unstable();
    sorted[(sorted.len() * 99 / 100).min(sorted.len() - 1)]
}

fn main() {
    let limits = Limits::default();
    assert_eq!(limits.max_domains, DOMAINS);
    assert_eq!(limits.max_entries_per_domain, ENTRIES);
    let hosts: Vec<String> = (0..DOMAINS)
        .map(|domain| format!("site-{domain}.test"))
        .collect();
    let profiles = vec![
        profile("behaviour:capacity-a"),
        profile("behaviour:capacity-b"),
    ];
    let registry =
        Arc::new(Registry::with_clock(limits, MonotonicClock::default()));
    registry.retain_hosts(HostPolicy::new(hosts.iter().map(String::as_str)));
    registry.activate(profiles.clone());

    let started = Instant::now();
    let mut admitted = 0usize;
    let mut population_latencies = Vec::with_capacity(4096);
    for (domain, host) in hosts.iter().enumerate() {
        for (profile_index, scenario) in profiles.iter().enumerate() {
            for entry in 0..PER_PROFILE {
                let identity = ip(domain, entry);
                let call_started = Instant::now();
                let result = registry
                    .admit_profile(scenario, host, &identity, "GET", "/", true);
                if !matches!(result, Admission::Allowed(Some(_))) {
                    panic!(
                        "unexpected admission at domain={domain} profile={profile_index} entry={entry}: {result:?}"
                    );
                }
                admitted += 1;
                if entry % 256 == 0 {
                    population_latencies.push(call_started.elapsed().as_nanos());
                }
            }
        }
    }
    let reload_registry = Arc::clone(&registry);
    let reload_hosts = hosts.clone();
    let reload_profiles = profiles.clone();
    let concurrent_start = Arc::new(Barrier::new(2));
    let reload_start = Arc::clone(&concurrent_start);
    let reloads = thread::spawn(move || {
        reload_start.wait();
        for cycle in 0..8 {
            if cycle > 0 {
                thread::sleep(Duration::from_millis(25));
            }
            reload_registry.retain_hosts(HostPolicy::new(
                reload_hosts.iter().map(String::as_str),
            ));
            reload_registry.activate(reload_profiles.clone());
        }
        8usize
    });
    let traffic_registry = Arc::clone(&registry);
    let traffic_hosts = hosts.clone();
    let traffic_profiles = profiles.clone();
    let traffic_start = Arc::clone(&concurrent_start);
    let traffic = thread::spawn(move || {
        let mut latencies = Vec::with_capacity(2_048);
        traffic_start.wait();
        for n in 0..2_048 {
            let domain = n % DOMAINS;
            let profile = &traffic_profiles[n % PROFILES];
            let call_started = Instant::now();
            let _ = traffic_registry.admit_profile(
                profile,
                &traffic_hosts[domain],
                "192.0.2.254",
                "GET",
                "/",
                true,
            );
            latencies.push(call_started.elapsed().as_nanos());
        }
        latencies
    });
    let reload_count = reloads.join().expect("reload thread");
    let concurrent_reload_latencies = traffic.join().expect("traffic thread");
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;

    let mut saturated = 0usize;
    let mut post_reload_latencies = Vec::with_capacity(DOMAINS * PROFILES);
    for host in &hosts {
        for scenario in &profiles {
            let call_started = Instant::now();
            if matches!(
                registry.admit_profile(
                    scenario,
                    host,
                    "192.0.2.254",
                    "GET",
                    "/",
                    true
                ),
                Admission::Saturated
            ) {
                saturated += 1;
            }
            post_reload_latencies.push(call_started.elapsed().as_nanos());
        }
    }
    assert_eq!(saturated, DOMAINS * PROFILES, "entry bound must be visible");

    let expiry_clock = ManualClock::at(0);
    let expiry_registry = Registry::with_clock(
        Limits {
            max_domains: 1,
            max_entries_per_domain: 1,
        },
        expiry_clock.clone(),
    );
    let expiry_profile = ScenarioProfile::new(
        "behaviour:expiry",
        AbuseConfig {
            enabled: true,
            failed_login: None,
            scan: Some(Rule {
                mode: Mode::Block,
                window: Duration::from_secs(1),
                threshold: 1,
                ban_ttl: Duration::from_millis(10),
            }),
        },
        1,
        1,
        1,
    )
    .expect("expiry profile");
    expiry_registry.retain_hosts(HostPolicy::new(["expiry.test"]));
    expiry_registry.activate(vec![expiry_profile.clone()]);
    let ticket = match expiry_registry.admit_profile(
        &expiry_profile,
        "expiry.test",
        "198.51.100.1",
        "GET",
        "/missing",
        true,
    ) {
        Admission::Allowed(Some(ticket)) => ticket,
        other => panic!("expiry admission failed: {other:?}"),
    };
    assert!(expiry_registry.observe(&ticket, 404, false).ban_created);
    expiry_clock.advance(Duration::from_secs(2));
    assert!(matches!(
        expiry_registry.admit_profile(
            &expiry_profile,
            "expiry.test",
            "198.51.100.2",
            "GET",
            "/missing-2",
            true,
        ),
        Admission::Allowed(Some(_))
    ));

    let p99_population = p99_nanos(&population_latencies);
    let p99_concurrent_reload = p99_nanos(&concurrent_reload_latencies);
    let p99_post_reload = p99_nanos(&post_reload_latencies);
    let mut all_latencies = population_latencies;
    all_latencies.extend_from_slice(&concurrent_reload_latencies);
    all_latencies.extend_from_slice(&post_reload_latencies);
    let p99 = p99_nanos(&all_latencies);
    let counters = registry.counters();
    println!(
        "NATIVE_CAPACITY_METRICS domains={} entries_per_domain={} profiles={} admitted={} expected={} saturated={} reloads={} expiry_reused=true elapsed_ms={:.2} p99_us={:.2} p99_population_us={:.2} p99_concurrent_reload_us={:.2} p99_post_reload_us={:.2} detected={} dropped_lifecycle={}",
        DOMAINS,
        ENTRIES,
        PROFILES,
        admitted,
        DOMAINS * ENTRIES,
        saturated,
        reload_count,
        elapsed_ms,
        p99 as f64 / 1000.0,
        p99_population as f64 / 1000.0,
        p99_concurrent_reload as f64 / 1000.0,
        p99_post_reload as f64 / 1000.0,
        counters.detected,
        counters.dropped_lifecycle,
    );
    println!("NATIVE_CAPACITY_PASS");
}
