//! The construction gate, in the process where no trusted-proxy list is configured.
//!
//! Its own binary because `basic.trusted_proxies` is process-global: the cases that need it
//! set live in `identity_trusted.rs`, and two test binaries are two processes, which is the
//! only way both states can hold at once. The same reason the gateway's client-IP test is
//! separate from its domain-isolation test.
//!
//! This is the load-bearing file of the phase. Every control built on top of it keys state on
//! a client identity, and with no trust anchor that identity is a header the client wrote —
//! so a token binding proves nothing, a store entry is minted under an address the attacker
//! chose, and an escalation ladder advances against a victim instead of an attacker.

mod common;

use common::{session, session_without_peer, unset_trusted_proxies};
use pingap_domainstate::IdentitySource;
use pingap_domainstate::identity::ClientIdentity;

/// A request from `198.51.100.7` claiming, three different ways, to be from `203.0.113.9`.
const SPOOF_XFF: &str =
    "GET / HTTP/1.1\r\nHost: a.example\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n";
const SPOOF_XFF_CHAIN: &str = "GET / HTTP/1.1\r\nHost: a.example\r\n\
     X-Forwarded-For: 203.0.113.9, 198.51.100.7, 10.0.0.1\r\n\r\n";
const SPOOF_REAL_IP: &str =
    "GET / HTTP/1.1\r\nHost: a.example\r\nX-Real-IP: 203.0.113.9\r\n\r\n";
const PEER: &str = "198.51.100.7:41000";

#[test]
fn construction_refuses_when_there_is_no_trust_anchor() {
    unset_trusted_proxies();

    let err = ClientIdentity::new(false)
        .expect_err("no anchor means no identity to key on");
    let text = err.to_string();

    // Both remedies, named. An error that says only "misconfigured" sends the operator into
    // the source; one that names both keys lets them fix it from the message alone.
    assert!(
        text.contains("trusted_proxies"),
        "the error must name the proxy remedy: {text}"
    );
    assert!(
        text.contains("client_ip_from_peer"),
        "the error must name the peer-assertion remedy: {text}"
    );
    // And the reason, or the "fix" is to delete the control that refused.
    assert!(
        text.contains("X-Forwarded-For"),
        "the error must name the header that is spoofable without an anchor: {text}"
    );
}

#[test]
fn an_explicit_peer_assertion_constructs_without_a_proxy_list() {
    unset_trusted_proxies();

    // A node that terminates client connections itself has no proxy list and needs none: its
    // TCP peer *is* the client. Refusing that deployment would make every stateful control
    // unusable on a plain VPS, which is the shape both reference products target.
    let identity = ClientIdentity::new(true)
        .expect("a directly exposed node is supported");
    assert_eq!(identity.source(), IdentitySource::PeerAddress);
}

#[tokio::test]
async fn a_spoofed_forwarded_for_never_becomes_the_identity() {
    unset_trusted_proxies();

    // Asserted with the header present. With it absent the test would pass on the peer
    // fallback and prove nothing about the header being ignored.
    let sess = session(SPOOF_XFF, PEER).await;
    let identity = ClientIdentity::new(true).expect("peer asserted");
    assert_eq!(identity.of(&sess), "198.51.100.7");
}

#[tokio::test]
async fn a_spoofed_forwarded_for_chain_never_becomes_the_identity() {
    unset_trusted_proxies();

    // The resolver's first branch takes the left-most entry of a chain, so this is the form
    // that would yield the attacker's chosen address if the branch were ever reached.
    let sess = session(SPOOF_XFF_CHAIN, PEER).await;
    let identity = ClientIdentity::new(true).expect("peer asserted");
    assert_eq!(identity.of(&sess), "198.51.100.7");
}

#[tokio::test]
async fn a_spoofed_real_ip_never_becomes_the_identity() {
    unset_trusted_proxies();

    let sess = session(SPOOF_REAL_IP, PEER).await;
    let identity = ClientIdentity::new(true).expect("peer asserted");
    assert_eq!(identity.of(&sess), "198.51.100.7");
}

#[tokio::test]
async fn the_identity_is_stable_across_requests_from_one_peer() {
    unset_trusted_proxies();

    // A binding is only worth anything if the same client resolves to the same key twice.
    // Rotating the spoofed header must not move it, which is the attack the branch exists
    // to stop: one request per address, no state ever accruing against the attacker.
    let identity = ClientIdentity::new(true).expect("peer asserted");
    let first = identity.of(&session(SPOOF_XFF, PEER).await);
    let second = identity.of(&session(SPOOF_REAL_IP, PEER).await);
    let third = identity.of(&session(SPOOF_XFF_CHAIN, PEER).await);
    assert_eq!(
        (first.as_str(), second.as_str()),
        (third.as_str(), "198.51.100.7")
    );
}

#[tokio::test]
async fn a_connection_with_no_peer_address_has_no_identity_rather_than_a_chosen_one()
 {
    unset_trusted_proxies();

    // The fail-safe direction. An unattributable connection resolves to the empty string,
    // never to a header the request carried, so such traffic collapses onto one key instead
    // of spreading across keys an attacker picked.
    let sess = session_without_peer(SPOOF_XFF).await;
    let identity = ClientIdentity::new(true).expect("peer asserted");
    assert_eq!(identity.of(&sess), "");
}
