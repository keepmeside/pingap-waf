//! Which address a request's state is keyed on.
//!
//! Resolved once, at construction, and never re-derived per request. That is the point: a
//! decision taken on every request is a decision that can be taken differently on some
//! requests, and the failure here is not a wrong answer but an attacker-chosen one.
//!
//! # Why a trust anchor is required at all
//!
//! The workspace's single client-address resolver is not itself a trust anchor. It checks
//! whether a trusted-proxy list is configured, and only then verifies the TCP peer is on that
//! list before honouring forwarded headers (`pingap-core/src/http_header.rs:379-411`). The
//! flag defaults to unset (`:316`), so **in a default deployment the resolver returns
//! `X-Forwarded-For` verbatim**, then `X-Real-IP`, then the peer. The vendored rate limiter's
//! own comment says as much: *"Use client IP (from X-Forwarded-For or direct connection)"*.
//!
//! Keying state on that value means the client picks its own key. Three consequences, all
//! reachable with one header:
//!
//! 1. entries are minted under spoofed identities without limit, so a per-domain bound never
//!    engages against a real attacker;
//! 2. a binding pinned at issue time to a chosen address proves nothing;
//! 3. counters never accrue against the attacker — rotate the header per request — while they
//!    do accrue against the spoofed victim, who is then refused on every domain. That is
//!    unauthenticated, targeted denial of service against an arbitrary address, using no deny
//!    rule anyone wrote.
//!
//! Every one of those passes a test that builds a session with a peer address and no forwarded
//! header, which is why the gate is asserted with the header present.
//!
//! # The three branches
//!
//! | Configuration | Identity used | Why it is safe |
//! |---|---|---|
//! | `trusted_proxies` configured | the existing resolver | Already spoof-resistant: a peer not on the list gets its own address back and its forwarded headers dropped |
//! | `client_ip_from_peer = true` | the TCP peer address | The node is directly exposed, so the peer *is* the client, and a TCP source address cannot be forged by the party sending the request |
//! | neither | **refuse to construct** | The resolver would return `X-Forwarded-For` verbatim, so there is no identity to key on |
//!
//! The middle branch is an explicit operator assertion, not an inference. Nothing inside the
//! process can detect "directly exposed", and guessing wrong in the permissive direction is
//! the vulnerability this closes. A *false* assertion fails loudly rather than silently: every
//! client behind the proxy collapses onto one address, so counters, ladders and rate buckets
//! all fire globally at once. That is why this branch is acceptable and the quiet
//! `X-Forwarded-For` fallback is not — and why the store publishes a distinct-identity count,
//! so "one identity for the whole site" is a number rather than an incident.
//!
//! A directly-exposed node is a first-class deployment, not an unsupported one: a small VPS
//! terminating its own TLS has no proxy list and needs none. Refusing it would make every
//! stateful control unusable in exactly the shape both reference products target.

use pingap_core::{get_client_ip, get_remote_addr, trusted_proxies_enabled};
use pingora::proxy::Session;

/// Which trust anchor resolved at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySource {
    /// A trusted-proxy list is configured, so forwarded headers are honoured only from a peer
    /// on it and every other peer is identified by its own address.
    TrustedProxies,
    /// The operator asserted the node is directly exposed, so the TCP peer is the client and
    /// forwarded headers are never read.
    PeerAddress,
}

/// Why construction was refused.
#[derive(Debug, Clone, PartialEq, Eq, snafu::Snafu)]
pub enum IdentityError {
    /// Neither trust anchor is configured, so the only client address available is one the
    /// request itself supplied.
    ///
    /// Names both remedies and the reason, because an error that says only "misconfigured"
    /// gets answered by deleting the control that refused.
    #[snafu(display(
        "this control keys state on the client address, but `basic.trusted_proxies` is not \
         configured and `client_ip_from_peer` is not asserted. With neither, \
         `X-Forwarded-For` is honoured from any peer, so the client chooses its own identity: \
         every binding keyed on it proves nothing, and state can be accrued against an \
         address the request merely named. Set `basic.trusted_proxies` to the addresses of \
         your own proxies; or, if this node terminates client connections directly with \
         nothing in front of it, set `client_ip_from_peer = true`"
    ))]
    NoTrustAnchor,
}

/// A resolved client-identity contract.
///
/// Cheap to copy and safe to share: it holds only which branch was taken, decided once.
#[derive(Debug, Clone, Copy)]
pub struct ClientIdentity {
    source: IdentitySource,
}

impl ClientIdentity {
    /// Resolves the contract, or refuses to build.
    ///
    /// A configured trusted-proxy list wins over a peer assertion. That order is a decision
    /// rather than an accident of the match: the list names the client, where the assertion
    /// can only name the last hop. Setting both is not an error, because an operator moving a
    /// node from directly-exposed to behind-a-proxy adds the second before removing the first.
    ///
    /// The refusal is at construction, not on the request path, so it is loud and pre-startup.
    pub fn new(client_ip_from_peer: bool) -> Result<Self, IdentityError> {
        if trusted_proxies_enabled() {
            return Ok(Self {
                source: IdentitySource::TrustedProxies,
            });
        }
        if client_ip_from_peer {
            return Ok(Self {
                source: IdentitySource::PeerAddress,
            });
        }
        Err(IdentityError::NoTrustAnchor)
    }

    /// Which branch resolved.
    pub fn source(&self) -> IdentitySource {
        self.source
    }

    /// The identity this request's state is keyed on.
    ///
    /// Delegates to the workspace's single resolver on the first branch rather than
    /// reimplementing it, and reads the TCP peer directly on the second — never a forwarded
    /// header, which is the whole content of that branch. An unattributable connection yields
    /// the empty string on both paths, so such traffic collapses onto one key instead of
    /// spreading across keys the request chose.
    pub fn of(&self, session: &Session) -> String {
        match self.source {
            IdentitySource::TrustedProxies => get_client_ip(session),
            IdentitySource::PeerAddress => get_remote_addr(session)
                .map(|(addr, _)| addr)
                .unwrap_or_default(),
        }
    }
}
