//! The construction gate, in the process where a trusted-proxy list *is* configured.
//!
//! Separate from `identity.rs` for the reason given there: the flag is process-global, and
//! every test in this binary needs it set. With the anchor present the resolver is already
//! spoof-resistant — a peer that is not on the list gets its own address back and its
//! forwarded headers dropped — so the contract here is that this crate delegates to it
//! unchanged rather than reimplementing a weaker version.

mod common;

use common::{
    TRUSTED_PROXY, session, set_trusted_proxies, trusted_proxy_lock,
};
use pingap_domainstate::IdentitySource;
use pingap_domainstate::identity::ClientIdentity;

const SPOOF_XFF: &str =
    "GET / HTTP/1.1\r\nHost: a.example\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n";
/// A client behind the proxy, so the address the proxy forwards is the real client.
const REAL_CLIENT: &str = "203.0.113.9";

#[tokio::test]
async fn an_untrusted_peer_s_forwarded_headers_are_ignored() {
    let _g = trusted_proxy_lock().await;
    set_trusted_proxies();

    // The peer is a client connecting directly, not the configured proxy, so its claim to be
    // `203.0.113.9` is dropped and its own address is used. Without this, configuring a
    // proxy list would still leave every directly-connecting client able to pick its key.
    let sess = session(SPOOF_XFF, "198.51.100.7:41000").await;
    let identity =
        ClientIdentity::new(false).expect("a proxy list is an anchor");
    assert_eq!(identity.source(), IdentitySource::TrustedProxies);
    assert_eq!(identity.of(&sess), "198.51.100.7");
}

#[tokio::test]
async fn a_configured_proxy_s_forwarded_header_is_honoured() {
    let _g = trusted_proxy_lock().await;
    set_trusted_proxies();

    // The other half. Refusing every forwarded header would collapse a whole CDN onto one
    // identity, which is the false-assertion failure mode and just as useless.
    let sess = session(SPOOF_XFF, &format!("{TRUSTED_PROXY}:41000")).await;
    let identity =
        ClientIdentity::new(false).expect("a proxy list is an anchor");
    assert_eq!(identity.of(&sess), REAL_CLIENT);
}

#[tokio::test]
async fn a_proxy_inside_a_configured_range_is_honoured() {
    // A CIDR entry, not just a single address: a proxy tier is a subnet in any real
    // deployment, and a gate that only matched exact addresses would silently downgrade
    // every node behind it to its own hop address. The lock holds the whole set → assert →
    // restore sequence atomic against siblings reading the shared list.
    let _g = trusted_proxy_lock().await;
    pingap_core::set_trusted_proxies(&Some(vec!["192.0.2.0/24".to_string()]));

    let sess = session(SPOOF_XFF, "192.0.2.77:41000").await;
    let identity =
        ClientIdentity::new(false).expect("a proxy list is an anchor");
    assert_eq!(identity.of(&sess), REAL_CLIENT);

    // Restore, so the other tests in this binary see the state they were written against.
    set_trusted_proxies();
    pingap_core::set_trusted_proxies(&Some(vec![TRUSTED_PROXY.to_string()]));
}

#[tokio::test]
async fn a_proxy_list_takes_precedence_over_a_peer_assertion() {
    let _g = trusted_proxy_lock().await;
    set_trusted_proxies();

    // Both configured at once. The list wins, and the order is a documented decision rather
    // than an accident of the match: it names the client, where the assertion can only name
    // the last hop. Asserting both is not an error, because an operator migrating a node
    // from directly-exposed to behind-a-proxy sets the second before removing the first.
    let identity = ClientIdentity::new(true).expect("an anchor is present");
    assert_eq!(identity.source(), IdentitySource::TrustedProxies);
}
