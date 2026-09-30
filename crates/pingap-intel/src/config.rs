//! What an operator writes to turn threat intelligence on, and every way that can be wrong.
//!
//! Two things live here that are easy to conflate and are deliberately kept apart.
//!
//! **Selection** is per-policy. Each `[intel]` table belongs to one WAF plugin entry, and
//! which feeds apply to which domain is a routing decision, not a node property. That is why
//! [`IntelConf`] is deserialised by the plugin that carries it and why the same feed can
//! appear in several entries.
//!
//! **Content** is node-global. A feed is fetched once per node and consulted by every policy
//! that selected it, because fetching it per-policy would multiply the request rate against
//! the publisher for no benefit and would let two policies' copies of the same list disagree
//! during a refresh. That is why [`plan`] takes *every* entry at once: the limits a feed is
//! fetched under are merged across them rather than picked from one.
//!
//! # Why validation happens here and not at fetch time
//!
//! A feed that is refused when it is fetched is refused every cycle, forever, and the only
//! evidence is a log line that scrolls past. A feed refused here stops the process from
//! starting and tells the operator which key to change. Since this runs at plugin
//! construction — that is, at config load, and again on every hot reload — nothing here can
//! be deferred to the first refresh without trading a startup error for a silent gap in
//! coverage. Every message names the plugin entry it came from, because on a node with a
//! dozen WAF profiles "a feed URL is malformed" is not actionable.
//!
//! # Merging, and why the strictest declaration wins
//!
//! The limits are merged with `min` across the entries that declare them, and the compiled-in
//! default applies only to a limit nobody mentioned. Merging against the default instead
//! would clamp every knob from above, so an operator with a slow publisher could never ask
//! for a longer timeout than the one shipped. `min` across declarations means one entry
//! asking for a tighter bound gets it, no entry can loosen what another tightened, and the
//! effective bound never depends on plugin iteration order — which last-wins would make it
//! do, so that adding an unrelated profile could widen what every other profile fetches.
//!
//! # What is deliberately not validated
//!
//! `category` is an operator label, surfaced in statistics and in the attribution attached to
//! a block. It is not checked against the WAF rule categories: the two vocabularies have
//! nothing to do with each other, and coupling them would break every operator who groups
//! feeds their own way while buying no safety, since a category only ever describes a refusal
//! and never decides one.

use std::time::Duration;

use serde::Deserialize;
use url::Url;

use crate::parse::parses_as_an_address;

/// The default fetch timeout.
///
/// A feed fetch is a bulk download from a third party that may be slow, rate-limited, or
/// partitioned. Long enough to complete a large list over a modest link, short enough that a
/// hung publisher cannot hold the refresh cycle — which it would, because a cycle waits for
/// every feed in it.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The default staleness window: how long a failed fetch may keep serving the last good set.
///
/// 24 hours, and configurable. A threat list an hour old is worth far more than no list at
/// all, and most publishers update no more than daily — so a window shorter than their
/// publication period would drop contributions that are merely due rather than broken. Past a
/// day the node starts enforcing a list whose publisher may have delisted an address since,
/// which is a false-positive risk against real traffic.
pub const DEFAULT_STALENESS: Duration = Duration::from_secs(24 * 60 * 60);

/// The default cap on one feed response body, in bytes.
///
/// Chosen so the largest lists in common use fit with room to spare, while a publisher that
/// starts serving something enormous — an HTML error page repeated by a captive portal, a
/// redirect into a tarball — cannot exhaust the node. The body is held in memory only for the
/// duration of one fetch, and feeds are fetched sequentially, so this bounds the transient
/// cost of a refresh cycle rather than multiplying by the feed count.
pub const DEFAULT_MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// The default cap on accepted entries from one feed.
///
/// Unlike the body cap this one is persistent: every accepted entry becomes a `String` and a
/// matcher node that live until the next successful refresh. Bounding it per feed means total
/// memory is `max_entries` times the number of feeds the *operator* configured — a quantity
/// under operator control — rather than anything a publisher controls. It also stops one
/// runaway feed from starving the others.
pub const DEFAULT_MAX_ENTRIES: usize = 250_000;

/// The default redirect budget: follow nothing.
///
/// Every hop is a fresh connection to a host nobody reviewed, and a redirect is exactly how a
/// feed URL that looks public ends up pointed at an internal address. Publishers of blocklists
/// serve them from a stable URL, so a default of zero costs nothing; an operator whose feed
/// legitimately redirects raises it explicitly, and each hop is then policed by the egress
/// guard rather than trusted.
pub const DEFAULT_REDIRECT_HOPS: usize = 0;

/// The largest redirect budget this config accepts.
///
/// Above this the bound stops being a bound: a chain long enough to matter is either a
/// misconfigured publisher or something trying to hold the refresh cycle open.
pub const MAX_REDIRECT_HOPS: usize = 10;

/// The category attached to a feed whose config does not give one.
///
/// A label rather than an empty string, so a statistic or an access-log field carrying it is
/// always readable and never looks like a missing value.
pub const UNSPECIFIED_CATEGORY: &str = "unspecified";

/// One `[intel]` table, as written inside one WAF plugin entry.
///
/// Every key here is optional, so an empty table is a valid configuration meaning "consult
/// the threat intelligence, but nothing is configured to fetch". Unknown keys are refused: on
/// a security control, a typo that silently does nothing is worse than one that fails to load.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntelConf {
    /// The feeds this policy selects.
    #[serde(default)]
    pub feed: Vec<FeedConf>,

    /// Addresses and ranges the operator wants refused without a feed.
    ///
    /// These reach the same matcher as feed entries and are rebuilt on every refresh cycle, so
    /// they take effect on reload without waiting for a fetch. They are not a substitute for
    /// the static `ip_list` on the WAF entry, which is in force from the very first request;
    /// these are for entries an operator wants managed alongside the feeds.
    #[serde(default)]
    pub manual: Vec<String>,

    /// Per-fetch timeout. Node-global; the strictest declaration wins.
    #[serde(default, with = "humantime_serde::option")]
    pub timeout: Option<Duration>,

    /// How long a failed fetch keeps serving the last good set. Node-global; strictest wins.
    #[serde(default, with = "humantime_serde::option")]
    pub staleness: Option<Duration>,

    /// Cap on one feed response body, in bytes. Node-global; strictest wins.
    #[serde(default)]
    pub max_body_bytes: Option<usize>,

    /// Cap on accepted entries per feed. Node-global; strictest wins.
    #[serde(default)]
    pub max_entries: Option<usize>,

    /// Redirect budget. Node-global; strictest wins. Zero follows nothing.
    #[serde(default)]
    pub redirect_hops: Option<usize>,
}

/// One `[[intel.feed]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedConf {
    /// The identity of this feed, used for statistics, attribution, and deduplication across
    /// plugin entries. Required and non-blank: a refusal that cannot say which list caused it
    /// cannot be investigated.
    #[serde(default)]
    pub name: String,

    /// Where to fetch it. Must be an `http` or `https` URL — the only two schemes the egress
    /// guard can police, because it polices connections.
    #[serde(default)]
    pub url: String,

    /// An operator label for what this feed lists. Defaults to [`UNSPECIFIED_CATEGORY`].
    #[serde(default)]
    pub category: Option<String>,

    /// Whether to fetch it at all. Defaults to true, so a declared feed is a live feed.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,

    /// Whether this feed may be fetched from a private or reserved address range.
    ///
    /// Defaults to false, and the refusals the opt-out permits are counted, so an operator can
    /// see that it is in use. It exists for the legitimate case — an internal mirror of a
    /// public list, which is how a node behind an egress firewall consumes feeds at all — and
    /// is per-feed rather than global so that widening it for one mirror does not widen it for
    /// the dozen public URLs beside it.
    #[serde(default)]
    pub allow_private_targets: bool,
}

fn enabled_by_default() -> bool {
    true
}

/// The bounds one fetch runs under.
///
/// Node-global: a feed is fetched once per node, so it cannot be fetched under two different
/// sets of limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Per-fetch timeout.
    pub timeout: Duration,
    /// How long a failed fetch keeps serving the last good set.
    pub staleness: Duration,
    /// Cap on one response body, in bytes.
    pub max_body_bytes: usize,
    /// Cap on accepted entries.
    pub max_entries: usize,
    /// Redirect budget. Zero follows nothing.
    pub redirect_hops: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            staleness: DEFAULT_STALENESS,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_entries: DEFAULT_MAX_ENTRIES,
            redirect_hops: DEFAULT_REDIRECT_HOPS,
        }
    }
}

/// A feed the node will fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    /// The feed's name. Unique across the node.
    pub name: String,
    /// The parsed URL.
    pub url: Url,
    /// The operator's label for it.
    pub category: String,
    /// Whether it may be fetched from a private or reserved range.
    pub allow_private_targets: bool,
}

/// What the node should fetch, what it should refuse manually, and under what bounds.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    /// The feeds to fetch, in declaration order with duplicates collapsed.
    pub definitions: Vec<Definition>,
    /// The operator's own entries, deduplicated, in declaration order.
    pub manual: Vec<String>,
    /// The bounds every fetch runs under.
    pub limits: Limits,
}

/// Configuration errors. Each names the key at fault and the plugin entry it came from.
#[derive(Debug, PartialEq, Eq, snafu::Snafu)]
pub enum ConfigError {
    /// One feed declaration cannot be used.
    #[snafu(display(
        "intel: plugin \"{entry}\" declares a feed that cannot be fetched: {reason}"
    ))]
    BadFeed {
        /// The plugin entry carrying the `[intel]` table.
        entry: String,
        /// The feed's `name`, empty if that is what is wrong.
        name: String,
        /// What is wrong, naming the key.
        reason: String,
    },

    /// One manual entry is not an address or a range.
    #[snafu(display(
        "intel: plugin \"{entry}\" lists `manual[{index}]` = \"{value}\", which is not an IP \
         address or CIDR range"
    ))]
    BadManual {
        /// The plugin entry carrying the `[intel]` table.
        entry: String,
        /// The position in `manual`.
        index: usize,
        /// The offending value.
        value: String,
    },

    /// A node-global limit was set to something that cannot work.
    #[snafu(display("intel: plugin \"{entry}\" sets {reason}"))]
    BadLimits {
        /// The plugin entry carrying the `[intel]` table.
        entry: String,
        /// What is wrong, naming the key.
        reason: String,
    },

    /// Two plugin entries declared the same feed name with different content.
    #[snafu(display(
        "intel: plugins \"{first}\" and \"{second}\" both declare the feed \"{name}\" but \
         disagree about `{key}`: {detail}"
    ))]
    ConflictingFeed {
        /// The entry that declared it first.
        first: String,
        /// The entry that disagreed.
        second: String,
        /// The shared feed name.
        name: String,
        /// The key they disagree about.
        key: &'static str,
        /// Both values, so the disagreement is visible without opening two files.
        detail: String,
    },
}

/// Validates every entry and merges them into one node-wide plan.
///
/// `entries` yields `(plugin entry name, its [intel] table)`. The whole set has to be visible
/// at once, because a feed declared by two policies is fetched once and the two declarations
/// must agree — a check no single plugin constructor can perform on its own.
///
/// Disabled feeds are still validated and still take part in the agreement check; they are
/// only left out of the returned plan. Validating what the operator wrote rather than what
/// they currently switched on means flipping `enabled` cannot turn a latent typo into a live
/// failure, and means a disabled declaration cannot silently disagree with an enabled one.
pub fn plan<'a, I>(entries: I) -> Result<Plan, ConfigError>
where
    I: IntoIterator<Item = (&'a str, &'a IntelConf)>,
{
    let mut declared: Vec<Declaration> = Vec::new();
    let mut manual: Vec<String> = Vec::new();
    let mut opinions = Opinions::default();

    for (entry, conf) in entries {
        conf.check_limits(entry, &mut opinions)?;
        conf.check_manual(entry, &mut manual)?;
        conf.check_feeds(entry, &mut declared)?;
    }

    Ok(Plan {
        definitions: collapse(declared)?,
        manual,
        limits: opinions.resolve(),
    })
}

/// A feed declaration, before duplicates across plugin entries are collapsed.
#[derive(Debug)]
struct Declaration {
    /// The plugin entry that declared it.
    entry: String,
    /// What it resolved to.
    definition: Definition,
    /// Whether that entry asked for it to be fetched.
    enabled: bool,
}

/// The limits the entries actually mentioned, before defaults are applied.
///
/// Kept apart from [`Limits`] so that "nobody said" stays distinguishable from "somebody said
/// the default", which is what makes a knob raisable above the default.
#[derive(Debug, Default)]
struct Opinions {
    timeout: Option<Duration>,
    staleness: Option<Duration>,
    max_body_bytes: Option<usize>,
    max_entries: Option<usize>,
    redirect_hops: Option<usize>,
}

impl Opinions {
    /// Folds one entry's declarations in, keeping the strictest of each.
    fn fold(&mut self, conf: &IntelConf) {
        self.timeout = strictest(self.timeout, conf.timeout);
        self.staleness = strictest(self.staleness, conf.staleness);
        self.max_body_bytes =
            strictest(self.max_body_bytes, conf.max_body_bytes);
        self.max_entries = strictest(self.max_entries, conf.max_entries);
        self.redirect_hops = strictest(self.redirect_hops, conf.redirect_hops);
    }

    /// Applies the compiled-in default to every limit nobody mentioned.
    fn resolve(self) -> Limits {
        let fallback = Limits::default();
        Limits {
            timeout: self.timeout.unwrap_or(fallback.timeout),
            staleness: self.staleness.unwrap_or(fallback.staleness),
            max_body_bytes: self
                .max_body_bytes
                .unwrap_or(fallback.max_body_bytes),
            max_entries: self.max_entries.unwrap_or(fallback.max_entries),
            redirect_hops: self.redirect_hops.unwrap_or(fallback.redirect_hops),
        }
    }
}

/// The stricter of two bounds, treating an absent one as no opinion.
fn strictest<T: Ord>(current: Option<T>, candidate: Option<T>) -> Option<T> {
    match candidate {
        None => current,
        Some(candidate) => Some(match current {
            Some(current) => current.min(candidate),
            None => candidate,
        }),
    }
}

/// The reason one entry's limits cannot work, if they cannot.
///
/// Separated from the folding so the two jobs stay individually simple, and so a bad limit is
/// caught before it can be merged into the node's answer.
fn limit_fault(conf: &IntelConf) -> Option<String> {
    if conf.timeout == Some(Duration::ZERO) {
        return Some(
            "`timeout` = 0, which would abandon every fetch before it started. Remove it for \
             the default, or give the feed a real window"
                .to_string(),
        );
    }
    if conf.staleness == Some(Duration::ZERO) {
        return Some(
            "`staleness` = 0, which would discard the last good set the cycle after any single \
             failed fetch. Remove it for the default, or give a real window"
                .to_string(),
        );
    }
    if conf.max_body_bytes == Some(0) {
        return Some(
            "`max_body_bytes` = 0, which would refuse every response from every feed"
                .to_string(),
        );
    }
    if conf.max_entries == Some(0) {
        return Some(
            "`max_entries` = 0, which would accept nothing from every feed"
                .to_string(),
        );
    }
    if conf.redirect_hops.is_some_and(|h| h > MAX_REDIRECT_HOPS) {
        return Some(format!(
            "`redirect_hops` above the ceiling of {MAX_REDIRECT_HOPS}, past which the bound is \
             not a bound — every hop is a connection to a host nobody reviewed"
        ));
    }
    None
}

impl IntelConf {
    /// Folds this entry's node-global limits into `opinions`, keeping the strictest of each.
    fn check_limits(
        &self,
        entry: &str,
        opinions: &mut Opinions,
    ) -> Result<(), ConfigError> {
        if let Some(reason) = limit_fault(self) {
            return Err(ConfigError::BadLimits {
                entry: entry.to_string(),
                reason,
            });
        }
        opinions.fold(self);
        Ok(())
    }

    /// Validates this entry's manual entries and appends the ones not already listed.
    fn check_manual(
        &self,
        entry: &str,
        manual: &mut Vec<String>,
    ) -> Result<(), ConfigError> {
        for (index, value) in self.manual.iter().enumerate() {
            if !parses_as_an_address(value) {
                return Err(ConfigError::BadManual {
                    entry: entry.to_string(),
                    index,
                    value: value.clone(),
                });
            }
            if !manual.contains(value) {
                manual.push(value.clone());
            }
        }
        Ok(())
    }

    /// Validates this entry's feeds and appends them.
    ///
    /// A name repeated *inside one table* is refused here, because within one `[intel]` there
    /// is no reading in which the operator meant two feeds with one identity. The same name
    /// arriving from two different plugin entries is not an error — that is per-policy
    /// selection working — and is handled by [`collapse`], which merges them or refuses the
    /// disagreement.
    fn check_feeds(
        &self,
        entry: &str,
        declared: &mut Vec<Declaration>,
    ) -> Result<(), ConfigError> {
        let from = declared.len();
        for feed in &self.feed {
            let definition = definition(entry, feed)?;
            if declared[from..]
                .iter()
                .any(|d| d.definition.name == definition.name)
            {
                return Err(ConfigError::BadFeed {
                    entry: entry.to_string(),
                    name: definition.name,
                    reason: "that `name` is declared twice in this one `[intel]` table, so \
                             there is no way to tell which URL the policy meant"
                        .to_string(),
                });
            }
            declared.push(Declaration {
                entry: entry.to_string(),
                definition,
                enabled: feed.enabled,
            });
        }
        Ok(())
    }
}

/// Resolves one feed declaration into what the node would fetch.
fn definition(entry: &str, feed: &FeedConf) -> Result<Definition, ConfigError> {
    let bad = |reason: String| ConfigError::BadFeed {
        entry: entry.to_string(),
        name: feed.name.clone(),
        reason,
    };

    if feed.name.trim().is_empty() {
        return Err(bad(
            "its `name` is blank. Every feed needs one, so a refusal can say which list caused \
             it and so two policies selecting it share one fetch"
                .to_string(),
        ));
    }
    if feed.url.trim().is_empty() {
        return Err(bad("it has no `url`".to_string()));
    }

    let url = Url::parse(&feed.url).map_err(|e| {
        bad(format!("`url` \"{}\" does not parse: {e}", feed.url))
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(bad(format!(
            "`url` \"{}\" is a `{}` URL. Only `http` and `https` can be fetched, because those \
             are the only schemes the egress guard has a connection to police",
            feed.url,
            url.scheme()
        )));
    }

    Ok(Definition {
        name: feed.name.clone(),
        url,
        category: feed
            .category
            .clone()
            .filter(|category| !category.trim().is_empty())
            .unwrap_or_else(|| UNSPECIFIED_CATEGORY.to_string()),
        allow_private_targets: feed.allow_private_targets,
    })
}

/// Collapses one feed name declared by several plugin entries into a single definition,
/// refusing any disagreement, then drops the ones nobody enabled.
fn collapse(
    declared: Vec<Declaration>,
) -> Result<Vec<Definition>, ConfigError> {
    let mut merged: Vec<(Definition, String, bool)> = Vec::new();

    for declaration in declared {
        merge(&mut merged, declaration)?;
    }

    Ok(merged
        .into_iter()
        .filter(|(_, _, enabled)| *enabled)
        .map(|(definition, _, _)| definition)
        .collect())
}

/// Folds one declaration into the merged list.
///
/// One entry enabling a feed the others left off enables it: the union of what anyone asked
/// for is what the node fetches, which is the only reading consistent with selection being
/// per-policy and content being node-global.
fn merge(
    merged: &mut Vec<(Definition, String, bool)>,
    declaration: Declaration,
) -> Result<(), ConfigError> {
    let Declaration {
        entry,
        definition,
        enabled,
    } = declaration;

    let Some((existing, first_entry, already_enabled)) = merged
        .iter_mut()
        .find(|(existing, _, _)| existing.name == definition.name)
    else {
        merged.push((definition, entry, enabled));
        return Ok(());
    };

    if let Some((key, detail)) = disagreement(existing, &definition) {
        return Err(ConfigError::ConflictingFeed {
            first: first_entry.clone(),
            second: entry,
            name: definition.name,
            key,
            detail,
        });
    }
    *already_enabled |= enabled;
    Ok(())
}

/// The first key on which two declarations of one feed name disagree.
fn disagreement(
    a: &Definition,
    b: &Definition,
) -> Option<(&'static str, String)> {
    if a.url != b.url {
        return Some(("url", format!("\"{}\" and \"{}\"", a.url, b.url)));
    }
    if a.category != b.category {
        return Some((
            "category",
            format!("\"{}\" and \"{}\"", a.category, b.category),
        ));
    }
    if a.allow_private_targets != b.allow_private_targets {
        return Some((
            "allow_private_targets",
            format!(
                "{} and {}",
                a.allow_private_targets, b.allow_private_targets
            ),
        ));
    }
    None
}
