//! The Tier-1 egress guard: what this node is allowed to connect to in order to fetch a
//! feed, decided at connection time.
//!
//! # Why not a check at config load
//!
//! A syntactic check on the configured URL string, performed once when the config is read,
//! is the wrong layer and the wrong time. It is the wrong time because the address a
//! hostname resolves to is not a property of the config; it is a property of DNS at the
//! moment of the fetch, and an operator who configures `https://feeds.example.com/…` has
//! configured a name they do not control. It is the wrong layer because the URL in the
//! config is not the URL that gets fetched — a `302` replaces it.
//!
//! The permitted failure mode is concrete. A public, innocuous-looking feed host answers
//! `302 → http://169.254.169.254/latest/meta-data/iam/security-credentials/`, or
//! `→ http://127.0.0.1:3018/`, which is this product's own admin listener. Downstream that
//! is either a working SSRF read primitive — whose timing and error text leak back through
//! feed-error counters and projection failure messages — or attacker-influenced content
//! loaded as **deny entries**, which is worse than a read because it needs no
//! exfiltration channel. The TOCTOU variant needs no redirect at all: a name that resolves
//! publicly at check time and to `127.0.0.1` at fetch time.
//!
//! # Three layers, because no single hook covers all three URL shapes
//!
//! 1. **URL-host validation**, [`Guard::check_url`]. If the host is an IP literal there is
//!    nothing to resolve, so this is the only layer that can see it. Not optional, and the
//!    layer a resolver-based design silently omits.
//! 2. **A custom [`reqwest::dns::Resolve`]**, [`EgressResolver`]. Every address a name
//!    resolves to is decided before it is handed to the connector, on redirect hops as
//!    well as on the first request.
//! 3. **The redirect policy**, [`Guard::redirect_policy`]. A hop is re-validated by layer 1
//!    before it is followed, and the chain length is bounded.
//!
//! The layers are not redundant; each covers a case the other two cannot. Layer 1 cannot
//! see a name's addresses. Layer 2 never sees an IP literal, because reqwest does not
//! consult a resolver for one. Layer 3 never sees the initial URL, because a redirect
//! policy is only invoked on a `30x`. **reqwest offers no hook for the initial URL at
//! all**, which is why layer 1 is the caller's responsibility: [`Guard::client`] alone
//! cannot refuse an IP-literal target, and the fetch in `feed.rs` calls `check_url` before
//! `send`.
//!
//! # What is refused
//!
//! Every family in [`REFUSED_FAMILIES`], matched through `pingap_util::IpRules` so that
//! this crate and the WAF cannot disagree about which network an address belongs to. Two
//! families are additions to the list this design was specified with, both for the same
//! reason: on Linux a `connect()` to the unspecified address reaches the loopback one, so
//! `http://0.0.0.0:3018/` is this product's own admin listener. Without `0.0.0.0/8` and
//! `::/128` the named `127.0.0.0/8` family would not actually hold.
//!
//! `::ffff:`-mapped forms are unwrapped with `Ipv6Addr::to_ipv4_mapped` and re-decided
//! against the IPv4 families, so `::ffff:127.0.0.1` is refused as loopback and *named* as
//! loopback. Not `to_ipv4`, which would also turn `::1` into `0.0.0.1` and attribute a
//! loopback address to the wrong family. The mapped *block* is deliberately not refused
//! wholesale: `::ffff:8.8.8.8` is a legitimate public address written in mapped form, and
//! refusing it would refuse real feeds.
//!
//! Known residuals, refused by nobody: `100.64.0.0/10` (RFC 6598 CGNAT — a real SSRF
//! target on some clouds and a real feed origin on others, so it belongs to an operator
//! decision rather than to a default) and the documentation ranges.
//!
//! # Pinning is not an operator knob
//!
//! `ClientBuilder::resolve` short-circuits: `DnsResolverWithOverrides::resolve` returns the
//! override without consulting the wrapped resolver. A name pinned by an operator would be
//! enforced by layer 1 alone and never by layer 2. This crate exposes no pinning
//! configuration for exactly that reason, and `tests/egress.rs` asserts the short-circuit
//! so the fact stays recorded if reqwest changes.
//!
//! # Counters
//!
//! `refusals` and `opt_outs` count *decisions*, at address granularity, and only in the
//! layers that actually gate a connection. [`Guard::permits`] does not count, because a
//! caller asking a classification question is not performing an egress decision. The
//! per-feed `allow_private_targets` opt-out is counted rather than merely permitted: the
//! opt-out is itself the audit signal, explicit rather than ambient.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use pingap_util::IpRules;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect::Policy;
use snafu::Snafu;
use url::{Host, Url};

/// The refused families, as `(prefix, why it is refused)`. One entry per family, and the
/// label is what an operator reads in a refusal, so it says what the range is rather than
/// restating the prefix.
const REFUSED_FAMILIES: &[(&str, &str)] = &[
    (
        "0.0.0.0/8",
        "the unspecified address, which Linux connects as loopback",
    ),
    ("10.0.0.0/8", "private"),
    ("127.0.0.0/8", "loopback"),
    (
        "169.254.0.0/16",
        "link-local, which is where cloud metadata lives",
    ),
    ("172.16.0.0/12", "private"),
    ("192.168.0.0/16", "private"),
    (
        "::/128",
        "the unspecified address, which Linux connects as loopback",
    ),
    ("::1/128", "loopback"),
    ("fc00::/7", "unique-local"),
    ("fe80::/10", "link-local"),
];

/// One compiled refused family.
///
/// Built once process-wide, because the list is a constant and parsing ten CIDR strings per
/// decision would put an allocation on a path that is otherwise a hash lookup and a linear
/// scan of ten networks.
#[derive(Debug)]
pub struct Family {
    prefix: &'static str,
    label: &'static str,
    rules: IpRules,
}

impl Family {
    /// The text a refusal names this family by.
    pub fn reason(&self) -> String {
        format!("{}, {}", self.prefix, self.label)
    }

    /// Whether `addr` is inside this family.
    ///
    /// A `::ffff:`-mapped address is unwrapped and re-decided, because the IPv4 rules
    /// cannot see it in mapped form and the IPv6 rules would only match it as an address
    /// nobody wrote down.
    fn matches(&self, addr: &IpAddr) -> bool {
        if self.rules.is_match_addr(addr) {
            return true;
        }
        match addr {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => self.rules.is_match_addr(&IpAddr::V4(v4)),
                None => false,
            },
            IpAddr::V4(_) => false,
        }
    }
}

/// The compiled family list.
///
/// `IpRules::new` silently drops what it cannot parse, so a typo in a prefix here would
/// leave a family that never matches — a guard that looks complete and is not. The unit
/// test `every_family_compiles_to_exactly_one_network` is the length check that turns such
/// a typo into a named failure.
fn families() -> &'static [Family] {
    static FAMILIES: OnceLock<Vec<Family>> = OnceLock::new();
    FAMILIES.get_or_init(|| {
        REFUSED_FAMILIES
            .iter()
            .map(|(prefix, label)| Family {
                prefix,
                label,
                rules: IpRules::new(&[*prefix]),
            })
            .collect()
    })
}

/// Which refused family `addr` falls in, or `None` if it is reachable.
///
/// One function, shared by all three layers. That sharing is what makes it sound to test
/// every family against `check_url`, every family against `permits`, and then test the
/// resolver and the redirect policy for *reaching* the decision — rather than re-testing
/// ten families at three layers.
fn classify(addr: &IpAddr) -> Option<&'static Family> {
    families().iter().find(|family| family.matches(addr))
}

/// Why the guard would not build a client, would not reach a target, or would not follow a
/// hop.
///
/// Every variant's text begins with the crate prefix and names the offending value, so a
/// refusal that surfaces three `source()` links deep inside a reqwest error is still
/// readable as ours and still says what was refused.
#[derive(Debug, Snafu)]
pub enum EgressError {
    /// A target, a hop, or a resolved address fell in a refused family, or a hop budget ran
    /// out.
    #[snafu(display("intel: refused to reach {target}: {reason}"))]
    Refused {
        /// The URL or hostname that was refused.
        target: String,
        /// The family and its label, or the budget that ran out.
        reason: String,
    },

    /// The feed's own resolver could not turn a name into addresses.
    #[snafu(display("intel: could not resolve {host}: {source}"))]
    Lookup {
        /// The name that failed.
        host: String,
        /// The underlying resolver error.
        source: std::io::Error,
    },

    /// `reqwest` would not build the guarded client.
    #[snafu(display("intel: the feed client could not be built: {source}"))]
    Client {
        /// The builder error.
        source: reqwest::Error,
    },
}

/// What this node may connect to in order to fetch feeds.
///
/// Cheap to clone and shared by every layer: the counters live behind the `Arc`, so a
/// resolver, a redirect policy and a client built from one `Guard` all report into the same
/// pair of numbers.
#[derive(Clone, Debug)]
pub struct Guard {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    allow_private_targets: bool,
    max_hops: usize,
    refusals: AtomicU64,
    opt_outs: AtomicU64,
}

impl Default for Guard {
    /// Strict, and that is the default rather than a choice a caller has to remember to
    /// make: no private targets, no redirects.
    fn default() -> Self {
        Self::strict()
    }
}

impl Guard {
    /// Deny private targets, follow no redirect.
    pub fn strict() -> Self {
        Self::new(false, 0)
    }

    /// A guard with an explicit opt-out and an explicit hop budget.
    ///
    /// `max_hops` of `0` means a `30x` is *refused* rather than returned, which is not the
    /// same thing as `reqwest::redirect::Policy::none()`: that one hands the `30x` back as
    /// `Ok`, so the redirect response's own body would be parsed as a blocklist and the feed
    /// would look merely empty. A threat feed that redirects is suspicious by definition,
    /// and the response to suspicion is a named refusal.
    pub fn new(allow_private_targets: bool, max_hops: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                allow_private_targets,
                max_hops,
                refusals: AtomicU64::new(0),
                opt_outs: AtomicU64::new(0),
            }),
        }
    }

    /// Whether this guard permits private targets, for the stats it feeds into.
    pub fn allow_private_targets(&self) -> bool {
        self.inner.allow_private_targets
    }

    /// How many redirects a fetch may follow.
    pub fn max_hops(&self) -> usize {
        self.inner.max_hops
    }

    /// How many addresses this guard refused.
    pub fn refusals(&self) -> u64 {
        self.inner.refusals.load(Ordering::Relaxed)
    }

    /// How many times the `allow_private_targets` opt-out rescued an address that would
    /// otherwise have been refused. Counted, because the opt-out is the audit signal.
    pub fn opt_outs(&self) -> u64 {
        self.inner.opt_outs.load(Ordering::Relaxed)
    }

    /// Whether `addr` is reachable under this guard.
    ///
    /// A classification, not a decision: it does not touch the counters. The layers that
    /// gate a connection go through [`Guard::decide`] instead.
    pub fn permits(&self, addr: &IpAddr) -> bool {
        self.inner.allow_private_targets || classify(addr).is_none()
    }

    /// One decision, counted once.
    fn decide(&self, addr: &IpAddr) -> Result<(), &'static Family> {
        let Some(family) = classify(addr) else {
            return Ok(());
        };
        if self.inner.allow_private_targets {
            self.inner.opt_outs.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        self.inner.refusals.fetch_add(1, Ordering::Relaxed);
        Err(family)
    }

    /// Layer 1: decide the URL's own host.
    ///
    /// This is the layer that sees an IP literal, and an IP literal is the shape that
    /// reaches no resolver. It also runs on every redirect hop, from inside the policy.
    ///
    /// A hostname passes this layer unconditionally. Refusing a name here would mean
    /// guessing at its addresses, and layer 2 does not guess.
    pub fn check_url(&self, url: &Url) -> Result<(), EgressError> {
        match url.scheme() {
            "http" | "https" => {},
            other => {
                return Err(EgressError::Refused {
                    target: url.to_string(),
                    reason: format!(
                        "{other} is not a feed transport; only http and https are"
                    ),
                });
            },
        }
        match url.host() {
            Some(Host::Ipv4(v4)) => self.check_addr(&IpAddr::V4(v4), url),
            Some(Host::Ipv6(v6)) => self.check_addr(&IpAddr::V6(v6), url),
            Some(Host::Domain(_)) | None => Ok(()),
        }
    }

    fn check_addr(&self, addr: &IpAddr, url: &Url) -> Result<(), EgressError> {
        self.decide(addr).map_err(|family| EgressError::Refused {
            target: url.to_string(),
            reason: family.reason(),
        })
    }

    /// Layer 2, as a resolver to hand to `reqwest::ClientBuilder::dns_resolver`.
    pub fn resolver(&self) -> EgressResolver {
        EgressResolver {
            guard: self.clone(),
        }
    }

    /// Layer 3: re-validate each hop with layer 1, then bound the chain.
    pub fn redirect_policy(&self) -> Policy {
        let guard = self.clone();
        Policy::custom(move |attempt| {
            // The host check runs before the budget check. Which address a feed tried to
            // reach is the security-relevant fact; that it was the fourth hop is not, and
            // reporting the budget first would hide it.
            if let Err(error) = guard.check_url(attempt.url()) {
                return attempt.error(error);
            }
            let target = attempt.url().to_string();
            let max_hops = guard.max_hops();
            // `previous()` already includes the URL that emitted this `30x`, so the first
            // hop arrives with a length of one and `>` permits exactly `max_hops` hops.
            // That is reqwest's own `Policy::limited` arithmetic, not a guess at it.
            if attempt.previous().len() > max_hops {
                return attempt.error(EgressError::Refused {
                    target,
                    reason: format!(
                        "redirect hop budget exceeded: this feed allows {max_hops}"
                    ),
                });
            }
            attempt.follow()
        })
    }

    /// A client with all three layers wired, for one fetch.
    ///
    /// `no_proxy` is not a preference. reqwest honours `HTTP_PROXY` and `HTTPS_PROXY` by
    /// default, and an HTTP proxy resolves the target name itself — which takes layer 2 out
    /// of the request path entirely and leaves the guard deciding a hostname whose addresses
    /// it never sees.
    pub fn client(
        &self,
        timeout: Duration,
    ) -> Result<reqwest::Client, EgressError> {
        reqwest::Client::builder()
            .no_proxy()
            .dns_resolver(self.resolver())
            .redirect(self.redirect_policy())
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()
            .map_err(|source| EgressError::Client { source })
    }
}

/// Layer 2: a [`Resolve`] that decides every address a name resolves to.
///
/// Returned by [`Guard::resolver`]. It counts into the same `Guard`, so a refusal here and a
/// refusal at layer 1 land in the same number.
#[derive(Clone, Debug)]
pub struct EgressResolver {
    guard: Guard,
}

impl Resolve for EgressResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let guard = self.guard.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|source| EgressError::Lookup {
                    host: host.clone(),
                    source,
                })?
                .collect::<Vec<_>>();
            permitted(&guard, &host, addrs)
                .map(|allowed| Box::new(allowed.into_iter()) as Addrs)
                // `Resolving`'s error half is `reqwest`'s own boxed-error alias, which is
                // `pub(crate)` there, so the type is spelled out rather than named.
                .map_err(|error| {
                    Box::new(error) as Box<dyn std::error::Error + Send + Sync>
                })
        })
    }
}

/// Split a resolved address list into what may be connected to and a refusal naming what
/// may not.
///
/// Only the permitted addresses are returned, and a name with no permitted address is an
/// error rather than an empty list. Both halves matter. hyper tries the addresses a
/// resolver returns in order, so returning a refused address alongside a permitted one
/// hands the connector a path into a private range the guard already decided against; and
/// an empty list is not a refusal an operator can read.
fn permitted(
    guard: &Guard,
    host: &str,
    addrs: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>, EgressError> {
    let mut allowed = Vec::with_capacity(addrs.len());
    let mut refusal: Option<String> = None;
    for addr in addrs {
        if let Err(family) = guard.decide(&addr.ip()) {
            refusal.get_or_insert_with(|| {
                format!(
                    "{} resolved to {}, {}",
                    host,
                    addr.ip(),
                    family.reason()
                )
            });
            continue;
        }
        allowed.push(addr);
    }
    if !allowed.is_empty() {
        return Ok(allowed);
    }
    let reason = refusal.unwrap_or_else(|| {
        format!(
            "{host} resolved to no address, so there is nothing permitted to connect to"
        )
    });
    Err(EgressError::Refused {
        target: host.to_string(),
        reason,
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn every_family_compiles_to_exactly_one_network() {
        let compiled = families();
        assert_eq!(
            compiled.len(),
            REFUSED_FAMILIES.len(),
            "a family went missing from the compiled list"
        );
        for family in compiled {
            // `IpRules::new` drops what it cannot parse and says nothing, so a typo in a
            // prefix would leave a family that never matches. This is the length check that
            // makes such a typo a named failure instead of a silently narrower guard.
            assert_eq!(
                family.rules.len(),
                1,
                "the prefix {} did not compile to one network",
                family.prefix
            );
            assert!(
                !family.rules.is_empty(),
                "the prefix {} compiled to nothing",
                family.prefix
            );
        }
    }

    #[test]
    fn no_prefix_is_listed_twice() {
        let mut prefixes: Vec<&str> =
            REFUSED_FAMILIES.iter().map(|(prefix, _)| *prefix).collect();
        let listed = prefixes.len();
        prefixes.sort_unstable();
        prefixes.dedup();
        assert_eq!(prefixes.len(), listed);
    }

    #[test]
    fn an_ipv4_mapped_literal_keeps_its_address_through_url_parsing() {
        // WHATWG serialization would render this host `[::ffff:7f00:1]`, but that is the
        // same 128 bits and `to_ipv4_mapped` reads the value rather than the text. What must
        // not happen is the parser losing the address, which would let a mapped loopback
        // literal past layer 1 as an unrecognised host.
        let parsed = Url::parse("http://[::ffff:127.0.0.1]/x")
            .expect("a valid test URL");
        match parsed.host() {
            Some(Host::Ipv6(v6)) => {
                assert_eq!(
                    v6.to_ipv4_mapped(),
                    Some(Ipv4Addr::new(127, 0, 0, 1))
                );
            },
            Some(Host::Ipv4(v4)) => assert_eq!(v4, Ipv4Addr::new(127, 0, 0, 1)),
            other => {
                panic!("a mapped literal parsed to {other:?}, not an address")
            },
        }
    }

    #[test]
    fn a_mapped_form_is_named_by_the_family_it_belongs_to() {
        let mapped: IpAddr =
            "::ffff:127.0.0.1".parse().expect("a valid test address");
        assert_eq!(
            classify(&mapped).map(|family| family.prefix),
            Some("127.0.0.0/8"),
            "a mapped loopback literal must be refused as loopback"
        );
        // `to_ipv4` would turn `::1` into `0.0.0.1` and name the unspecified family for an
        // address that is loopback. The unwrap has to be the narrower one.
        let loopback: IpAddr = "::1".parse().expect("a valid test address");
        assert_eq!(
            classify(&loopback).map(|family| family.prefix),
            Some("::1/128")
        );
        let unspecified: IpAddr = "::".parse().expect("a valid test address");
        assert_eq!(
            classify(&unspecified).map(|family| family.prefix),
            Some("::/128")
        );
    }

    #[test]
    fn permits_does_not_count() {
        let guard = Guard::strict();
        let refused: IpAddr = "10.0.0.1".parse().expect("a valid test address");
        assert!(!guard.permits(&refused));
        assert_eq!(
            guard.refusals(),
            0,
            "`permits` classifies and does not decide"
        );
        assert_eq!(guard.opt_outs(), 0);
    }

    #[test]
    fn a_guard_clone_shares_its_counters() {
        // The resolver and the redirect policy are built by cloning, so a refusal reached
        // through either has to land in the number the stats read.
        let guard = Guard::strict();
        let cloned = guard.clone();
        let refused =
            Url::parse("http://10.0.0.1/x").expect("a valid test URL");
        assert!(cloned.check_url(&refused).is_err());
        assert_eq!(guard.refusals(), 1);
    }
}
