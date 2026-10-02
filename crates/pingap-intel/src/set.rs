//! Atomic, attributable publication of feed contributions.
//!
//! Ported from mango-waf `intelligence/feeds.go` at commit 7f2c30c (MIT); see ./NOTICE.
//! Rewritten for build-then-swap publication with per-feed attribution, because the
//! donor accumulated into a map nothing evicted from, so an address that left a
//! feed stayed blocked forever.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::SystemTime;

use arc_swap::ArcSwap;
use pingap_util::IpRules;
use serde::Serialize;

use crate::config::{Definition, Plan};
use crate::feed::{FeedError, FeedResult, fetch};

#[derive(Debug, Clone)]
pub struct FeedMatch {
    pub feed: Option<String>,
    pub category: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RefreshStats {
    pub fetch_errors: u64,
    pub stale_drops: u64,
    pub truncated: u64,
    pub malformed: u64,
    pub allow_private_targets: u64,
}

#[derive(Debug, Clone)]
pub struct FeedSnapshot {
    pub generation: u64,
    pub refreshed_at: Option<SystemTime>,
    pub manual: IpRules,
    pub feeds: BTreeMap<String, FeedContribution>,
    pub stats: RefreshStats,
}

#[derive(Debug, Clone)]
pub struct FeedContribution {
    pub category: String,
    pub rules: IpRules,
    pub entries: usize,
    pub fetched_at: SystemTime,
}

/// One feed's published stats: the category, the entry count and when it was
/// last fetched. The rules themselves are the request-path artefact — not
/// serialisable, and not a metric.
#[derive(Debug, Clone, Serialize)]
pub struct FeedEntryStats {
    pub category: String,
    pub entries: usize,
    pub fetched_at: u64,
}

/// The serialisable projection of a [`FeedSnapshot`] for the metrics surface:
/// generation, refresh stats, and per-feed stats. The rule maps are dropped —
/// what is published is aggregate counts, never the rules.
#[derive(Debug, Clone, Serialize)]
pub struct FeedStatsSnapshot {
    pub generation: u64,
    /// Unix seconds; `None` until the first refresh completes.
    pub refreshed_at: Option<u64>,
    pub stats: RefreshStats,
    pub feeds: BTreeMap<String, FeedEntryStats>,
}

impl FeedSnapshot {
    /// The serialisable projection of this snapshot for the metrics surface.
    /// The feed names are the configured, fixed enumeration — never a value
    /// read from a request — and the BTreeMap ordering makes the projection
    /// deterministic for the same snapshot.
    pub fn stats_projection(&self) -> FeedStatsSnapshot {
        FeedStatsSnapshot {
            generation: self.generation,
            refreshed_at: self.refreshed_at.map(unix_secs),
            stats: self.stats.clone(),
            feeds: self
                .feeds
                .iter()
                .map(|(name, contribution)| {
                    (
                        name.clone(),
                        FeedEntryStats {
                            category: contribution.category.clone(),
                            entries: contribution.entries,
                            fetched_at: unix_secs(contribution.fetched_at),
                        },
                    )
                })
                .collect(),
        }
    }
}

fn unix_secs(at: SystemTime) -> u64 {
    at.duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug)]
struct FeedState {
    definition: Definition,
    last_good: Option<FeedContribution>,
    last_error: Option<String>,
}

#[derive(Debug)]
struct Inner {
    definitions: Mutex<BTreeMap<String, FeedState>>,
    manual: IpRules,
    limits: crate::config::Limits,
    state: Mutex<RefreshState>,
}

#[derive(Debug, Default)]
struct RefreshState {
    generation: u64,
    stats: RefreshStats,
    stale: BTreeSet<String>,
}

/// Process-global registry. The pointer-swap is the request-path boundary: readers observe
/// either the complete previous set or the complete next set, never a partially rebuilt map.
#[derive(Debug)]
pub struct FeedRegistry {
    inner: Inner,
    snapshot: ArcSwap<FeedSnapshot>,
}

impl FeedRegistry {
    pub fn new(plan: Plan) -> Self {
        let manual = IpRules::new(&plan.manual);
        let definitions = plan
            .definitions
            .into_iter()
            .map(|definition| {
                let name = definition.name.clone();
                (
                    name,
                    FeedState {
                        definition,
                        last_good: None,
                        last_error: None,
                    },
                )
            })
            .collect();
        let empty = Arc::new(FeedSnapshot {
            generation: 0,
            refreshed_at: None,
            manual: manual.clone(),
            feeds: BTreeMap::new(),
            stats: RefreshStats::default(),
        });
        Self {
            inner: Inner {
                definitions: Mutex::new(definitions),
                manual,
                limits: plan.limits,
                state: Mutex::new(RefreshState::default()),
            },
            snapshot: ArcSwap::from(empty),
        }
    }

    pub fn snapshot(&self) -> Arc<FeedSnapshot> {
        self.snapshot.load_full()
    }

    pub fn generation(&self) -> u64 {
        self.snapshot.load().generation
    }

    pub fn matches(&self, ip: &IpAddr) -> Option<FeedMatch> {
        let snapshot = self.snapshot.load();
        if snapshot.manual.is_match_addr(ip) {
            return Some(FeedMatch {
                feed: None,
                category: Some("manual".to_string()),
            });
        }
        snapshot.feeds.iter().find_map(|(name, contribution)| {
            contribution.rules.is_match_addr(ip).then(|| FeedMatch {
                feed: Some(name.clone()),
                category: Some(contribution.category.clone()),
            })
        })
    }

    pub fn apply(
        &self,
        result: Result<FeedResult, FeedError>,
        opt_outs: u64,
        now: SystemTime,
    ) {
        let mut state = match self.inner.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Accumulated before the outcome is inspected: the opt-out count is the
        // audit signal for `allow_private_targets`, and a fetch that reached a
        // private mirror before failing permitted the same decision a successful
        // one did.
        state.stats.allow_private_targets =
            state.stats.allow_private_targets.saturating_add(opt_outs);
        let (name, fetched) = match result {
            Ok(result) => {
                if let Some(feed) = self
                    .inner
                    .definitions
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get_mut(&result.name)
                {
                    feed.last_good = Some(FeedContribution {
                        category: feed.definition.category.clone(),
                        rules: result.parsed.rules().clone(),
                        entries: result.parsed.len(),
                        fetched_at: result.fetched_at,
                    });
                    state.stale.remove(&result.name);
                }
                let contribution = self
                    .inner
                    .definitions
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get(&result.name)
                    .and_then(|feed| feed.last_good.clone());
                state.stats.malformed = state
                    .stats
                    .malformed
                    .saturating_add(result.parsed.dropped() as u64);
                state.stats.truncated += u64::from(result.parsed.truncated());
                (result.name, contribution)
            },
            Err(error) => {
                let name = error_name(&error);
                if let Some(feed) = self
                    .inner
                    .definitions
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get_mut(&name)
                {
                    feed.last_error = Some(error.to_string());
                }
                state.stats.fetch_errors =
                    state.stats.fetch_errors.saturating_add(1);
                (name, None)
            },
        };
        let _ = (name, fetched, now);
        self.publish_locked(&mut state, now);
    }

    fn publish_locked(&self, state: &mut RefreshState, now: SystemTime) {
        let mut feeds = BTreeMap::new();
        let definitions = self
            .inner
            .definitions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (name, feed) in definitions.iter() {
            if let Some(contribution) = &feed.last_good {
                let age = now
                    .duration_since(contribution.fetched_at)
                    .unwrap_or_default();
                if age <= self.inner.limits.staleness {
                    feeds.insert(name.clone(), contribution.clone());
                } else {
                    if state.stale.insert(name.clone()) {
                        state.stats.stale_drops =
                            state.stats.stale_drops.saturating_add(1);
                    }
                }
            }
        }
        state.generation = state.generation.saturating_add(1);
        self.snapshot.store(Arc::new(FeedSnapshot {
            generation: state.generation,
            refreshed_at: Some(now),
            manual: self.inner.manual.clone(),
            feeds,
            stats: state.stats.clone(),
        }));
    }

    pub async fn refresh_once(&self) -> bool {
        let now = SystemTime::now();
        let definitions: Vec<Definition> = self
            .inner
            .definitions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(|state| state.definition.clone())
            .collect();
        if definitions.is_empty() {
            return false;
        }
        for definition in definitions {
            let (result, opt_outs) =
                fetch(&definition, self.inner.limits, now).await;
            self.apply(result, opt_outs, now);
        }
        true
    }
}

fn error_name(error: &FeedError) -> String {
    let text = error.to_string();
    text.strip_prefix("intel feed `")
        .and_then(|rest| rest.split('`').next())
        .unwrap_or_default()
        .to_string()
}

static GLOBAL: OnceLock<Mutex<Vec<Weak<FeedRegistry>>>> = OnceLock::new();

pub fn install_global_registry(
    registry: Arc<FeedRegistry>,
) -> Result<(), Arc<FeedRegistry>> {
    let registries = GLOBAL.get_or_init(|| Mutex::new(Vec::new()));
    let mut guard = registries
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.retain(|entry| entry.strong_count() > 0);
    if !guard
        .iter()
        .any(|entry| entry.ptr_eq(&Arc::downgrade(&registry)))
    {
        guard.push(Arc::downgrade(&registry));
    }
    Ok(())
}

pub fn global_registry() -> Option<Arc<FeedRegistry>> {
    GLOBAL.get().and_then(|registries| {
        registries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .find_map(Weak::upgrade)
    })
}

/// The process-global feed stats, for the metrics surface to publish. `None`
/// when no registry is installed, which is the honest reading of a deployment
/// with no intel feeds configured: there is nothing to publish.
pub fn feed_stats_snapshot() -> Option<FeedStatsSnapshot> {
    global_registry().map(|registry| registry.snapshot().stats_projection())
}

pub async fn refresh_all() -> bool {
    let registries = GLOBAL
        .get()
        .map(|registries| {
            registries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut refreshed = false;
    for registry in registries {
        refreshed |= registry.refresh_once().await;
    }
    refreshed
}
