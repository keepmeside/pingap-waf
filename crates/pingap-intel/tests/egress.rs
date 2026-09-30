//! The Tier-1 egress guard, one test per refused range family per layer.
//!
//! Two kinds of case live here and the difference matters:
//!
//! - **Classification** cases go through [`Guard::permits`] and [`Guard::check_url`],
//!   which need no network. They are written one assertion per family rather than as
//!   one loop over a list, so that a family that stops being refused is a named
//!   failure instead of one red line in a table.
//! - **Wiring** cases stand up a real listener on 127.0.0.1 and drive a real
//!   `reqwest::Client`, because the property under test is what the client does at
//!   connection time and a mock cannot answer that. A stubbed resolver would prove
//!   only that the stub refuses.
//!
//! Every wiring case reaches the listener through a *pinned* hostname rather than
//! through `http://127.0.0.1:PORT`, because the guard refuses `127.0.0.0/8` — that
//! is the whole point of it, and it means the test cannot point the guarded client at
//! its own server directly. [`pinned_client`] does the pinning, and
//! [`the_pinned_name_never_reaches_the_resolver`] records what that costs.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pingap_intel::egress::{EgressResolver, Guard};
use reqwest::dns::{Name, Resolve, Resolving};
use reqwest::redirect::Policy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

/// The hostname the wiring cases pin to the local listener. Not a real name: if the
/// pin ever stopped being applied, resolution would fail rather than silently
/// reaching somewhere else.
const PINNED: &str = "feed.test";

/// A name that resolves into `127.0.0.0/8` on every machine this can run on, which
/// is why the hop tests use it: the refused-range case for a *hostname* needs a name
/// that really does resolve into a refused range, and inventing one would need DNS.
const LOOPBACK_NAME: &str = "localhost";

fn ip(text: &str) -> IpAddr {
    text.parse().expect("a valid test address")
}

fn url(text: &str) -> Url {
    Url::parse(text).expect("a valid test URL")
}

/// Every name a resolver was asked about, in order.
type Seen = Arc<Mutex<Vec<String>>>;

/// Records the names it is asked about, then delegates the answer to the guard's own
/// resolver. Wrapping rather than replacing is what makes "the resolver was
/// consulted for this hop" observable without changing what it decides.
struct Recording {
    seen: Seen,
    inner: EgressResolver,
}

impl Resolve for Recording {
    fn resolve(&self, name: Name) -> Resolving {
        self.seen
            .lock()
            .expect("test lock")
            .push(name.as_str().to_string());
        self.inner.resolve(name)
    }
}

/// The whole cause chain flattened into one string. The criterion is that a refusal
/// *surfaces its inner cause*, so an assertion on `err.to_string()` alone would pass
/// on reqwest's outer "error sending request for url" and prove nothing.
fn chain(err: &reqwest::Error) -> String {
    let mut out = Vec::new();
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(current) = source {
        out.push(current.to_string());
        source = current.source();
    }
    out.join(" | ")
}

fn route(path: &str, port: u16) -> String {
    let found = |location: String| {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
    };
    match path {
        // The SSRF read primitive the guard exists to close.
        "/redirect-metadata" => found(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/".to_string(),
        ),
        // A *hostname* hop, so the resolver has to be consulted again.
        "/redirect-localhost" => found(format!("http://{LOOPBACK_NAME}:9/x")),
        // A hop nothing here would refuse, for the budget and follow-through cases.
        "/redirect-elsewhere" => found("http://upstream.test/x".to_string()),
        "/redirect-to-feed" => found(format!("http://{PINNED}:{port}/feed")),
        "/loop" => found(format!("http://{PINNED}:{port}/loop")),
        _ => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string(),
    }
}

/// Starts a one-response-per-connection server on an ephemeral 127.0.0.1 port and
/// returns the port. The task dies with the test's runtime.
async fn spawn_feed_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a free port");
    let port = listener.local_addr().expect("a local address").port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let read = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..read]).to_string();
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                let response = route(&path, port);
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    port
}

/// The guarded client the wiring cases need. `feed.test` is pinned to the listener so
/// the *initial* URL has a hostname the guard has nothing to object to, which leaves
/// the layers under test free to fire on the hop instead.
fn pinned_client(
    guard: &Guard,
    port: u16,
    seen: Option<Seen>,
) -> reqwest::Client {
    let builder = reqwest::Client::builder().redirect(guard.redirect_policy());
    let builder = match seen {
        Some(seen) => builder.dns_resolver(Recording {
            seen,
            inner: guard.resolver(),
        }),
        None => builder.dns_resolver(guard.resolver()),
    };
    builder
        .resolve(
            PINNED,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        )
        .build()
        .expect("a client")
}

async fn send(
    client: &reqwest::Client,
    target: &str,
) -> reqwest::Result<reqwest::Response> {
    // A guard that refuses by hanging rather than by erroring would otherwise make
    // these tests time out at the harness limit and report the wrong failure.
    tokio::time::timeout(Duration::from_secs(10), client.get(target).send())
        .await
        .expect("no hang")
}

/// Asserts the refusal text, so a family that is refused *without being named* fails
/// here rather than showing up as an unexplained 403 in production.
fn refused(target: &str) -> pingap_intel::egress::EgressError {
    Guard::strict()
        .check_url(&url(target))
        .expect_err("a refused target")
}

// --- layer 1: the host in the URL, which is the layer a resolver-based design omits

#[test]
fn layer_one_refuses_the_loopback_family() {
    assert!(
        Guard::strict()
            .check_url(&url("http://127.0.0.1/x"))
            .is_err()
    );
    assert!(
        Guard::strict()
            .check_url(&url("http://127.9.9.9:8080/x"))
            .is_err()
    );
}

#[test]
fn layer_one_refuses_the_ten_family() {
    assert!(
        Guard::strict()
            .check_url(&url("http://10.0.0.1/x"))
            .is_err()
    );
    assert!(
        Guard::strict()
            .check_url(&url("http://10.255.255.254/x"))
            .is_err()
    );
}

#[test]
fn layer_one_refuses_the_seventeen_family() {
    assert!(
        Guard::strict()
            .check_url(&url("http://172.16.0.1/x"))
            .is_err()
    );
    assert!(
        Guard::strict()
            .check_url(&url("http://172.31.255.254/x"))
            .is_err()
    );
}

#[test]
fn layer_one_refuses_the_nineteen_family() {
    assert!(
        Guard::strict()
            .check_url(&url("http://192.168.0.1/x"))
            .is_err()
    );
    assert!(
        Guard::strict()
            .check_url(&url("http://192.168.255.254/x"))
            .is_err()
    );
}

#[test]
fn layer_one_refuses_the_link_local_family() {
    assert!(
        Guard::strict()
            .check_url(&url("http://169.254.169.254/latest/meta-data/"))
            .is_err()
    );
}

#[test]
fn layer_one_refuses_the_unspecified_family() {
    // On Linux a connect to the unspecified address reaches the loopback one, so
    // `http://0.0.0.0:3018/` is this product's own admin listener.
    assert!(
        Guard::strict()
            .check_url(&url("http://0.0.0.0:3018/x"))
            .is_err()
    );
}

#[test]
fn layer_one_refuses_the_ipv6_loopback_family() {
    assert!(Guard::strict().check_url(&url("http://[::1]/x")).is_err());
}

#[test]
fn layer_one_refuses_the_ipv6_unique_local_family() {
    assert!(
        Guard::strict()
            .check_url(&url("http://[fc00::1]/x"))
            .is_err()
    );
    assert!(
        Guard::strict()
            .check_url(&url("http://[fd12:3456::1]/x"))
            .is_err()
    );
}

#[test]
fn layer_one_refuses_the_ipv6_link_local_family() {
    assert!(
        Guard::strict()
            .check_url(&url("http://[fe80::1]/x"))
            .is_err()
    );
}

#[test]
fn layer_one_refuses_the_ipv6_unspecified_family() {
    assert!(
        Guard::strict()
            .check_url(&url("http://[::]:3018/x"))
            .is_err()
    );
}

#[test]
fn layer_one_refuses_an_ipv4_mapped_loopback_form() {
    assert!(
        Guard::strict()
            .check_url(&url("http://[::ffff:127.0.0.1]/x"))
            .is_err()
    );
}

#[test]
fn layer_one_refuses_an_ipv4_mapped_link_local_form() {
    assert!(
        Guard::strict()
            .check_url(&url("http://[::ffff:169.254.169.254]/x"))
            .is_err()
    );
}

#[test]
fn layer_one_permits_public_space() {
    assert!(Guard::strict().check_url(&url("http://8.8.8.8/x")).is_ok());
    assert!(
        Guard::strict()
            .check_url(&url("https://[2606:4700:4700::1111]/x"))
            .is_ok()
    );
    assert!(
        Guard::strict()
            .check_url(&url("https://feeds.example.com/blocklist.txt"))
            .is_ok()
    );
}

#[test]
fn layer_one_names_the_family_it_refused() {
    let text = refused("http://127.0.0.1/x").to_string();
    assert!(text.contains("127.0.0.0/8"), "{text}");
    assert!(text.contains("intel: refused"), "{text}");

    let text = refused("http://169.254.169.254/x").to_string();
    assert!(text.contains("169.254.0.0/16"), "{text}");

    let text = refused("http://[fd00::1]/x").to_string();
    assert!(text.contains("fc00::/7"), "{text}");
}

#[test]
fn layer_one_refuses_a_scheme_that_is_not_a_feed_transport() {
    assert!(
        Guard::strict()
            .check_url(&url("file:///etc/passwd"))
            .is_err()
    );
    assert!(Guard::strict().check_url(&url("ftp://8.8.8.8/x")).is_err());
}

#[test]
fn the_private_target_opt_out_permits_one_guard_and_is_counted() {
    let opted_out = Guard::new(true, 0);
    assert!(
        opted_out
            .check_url(&url("http://169.254.169.254/x"))
            .is_ok()
    );
    assert_eq!(opted_out.opt_outs(), 1, "the opt-out is the audit signal");
    assert_eq!(opted_out.refusals(), 0);

    // ...and it changes nothing for any other guard.
    assert!(
        Guard::strict()
            .check_url(&url("http://169.254.169.254/x"))
            .is_err()
    );
    assert_eq!(Guard::strict().opt_outs(), 0);
}

#[test]
fn a_refusal_is_counted() {
    let guard = Guard::strict();
    assert_eq!(guard.refusals(), 0);
    assert!(guard.check_url(&url("http://10.1.2.3/x")).is_err());
    assert_eq!(guard.refusals(), 1);
}

// --- layer 2: the addresses a name resolves to

#[test]
fn the_resolver_refuses_the_loopback_family() {
    assert!(!Guard::strict().permits(&ip("127.0.0.1")));
    assert!(!Guard::strict().permits(&ip("127.255.255.254")));
}

#[test]
fn the_resolver_refuses_the_ten_family() {
    assert!(!Guard::strict().permits(&ip("10.0.0.1")));
    assert!(!Guard::strict().permits(&ip("10.255.255.254")));
}

#[test]
fn the_resolver_refuses_the_seventeen_family() {
    assert!(!Guard::strict().permits(&ip("172.16.0.1")));
    assert!(!Guard::strict().permits(&ip("172.31.255.254")));
    // Just outside, so the /12 is not being read as a /8.
    assert!(Guard::strict().permits(&ip("172.32.0.1")));
    assert!(Guard::strict().permits(&ip("172.15.255.254")));
}

#[test]
fn the_resolver_refuses_the_nineteen_family() {
    assert!(!Guard::strict().permits(&ip("192.168.0.1")));
    assert!(!Guard::strict().permits(&ip("192.168.255.254")));
}

#[test]
fn the_resolver_refuses_the_link_local_family() {
    assert!(!Guard::strict().permits(&ip("169.254.169.254")));
}

#[test]
fn the_resolver_refuses_the_unspecified_family() {
    assert!(!Guard::strict().permits(&ip("0.0.0.0")));
    assert!(!Guard::strict().permits(&ip("::")));
}

#[test]
fn the_resolver_refuses_the_ipv6_loopback_family() {
    assert!(!Guard::strict().permits(&ip("::1")));
}

#[test]
fn the_resolver_refuses_the_ipv6_unique_local_family() {
    assert!(!Guard::strict().permits(&ip("fc00::1")));
    assert!(!Guard::strict().permits(&ip("fdff:ffff::1")));
}

#[test]
fn the_resolver_refuses_the_ipv6_link_local_family() {
    assert!(!Guard::strict().permits(&ip("fe80::1")));
    assert!(!Guard::strict().permits(&ip("febf::1")));
}

#[test]
fn the_resolver_refuses_ipv4_mapped_forms() {
    assert!(!Guard::strict().permits(&ip("::ffff:127.0.0.1")));
    assert!(!Guard::strict().permits(&ip("::ffff:10.0.0.1")));
    assert!(!Guard::strict().permits(&ip("::ffff:169.254.169.254")));
    // A mapped form of a *public* address stays permitted: refusing the whole
    // `::ffff:0:0/96` block would refuse legitimate targets expressed that way.
    assert!(Guard::strict().permits(&ip("::ffff:8.8.8.8")));
}

#[test]
fn the_resolver_permits_public_space() {
    assert!(Guard::strict().permits(&ip("8.8.8.8")));
    assert!(Guard::strict().permits(&ip("1.1.1.1")));
    assert!(Guard::strict().permits(&ip("2606:4700:4700::1111")));
}

#[test]
fn the_opt_out_permits_a_refused_address_and_is_counted_once() {
    let guard = Guard::new(true, 0);
    assert!(guard.permits(&ip("192.168.1.1")));
    assert_eq!(
        guard.opt_outs(),
        0,
        "`permits` classifies and does not decide"
    );
    assert!(guard.check_url(&url("http://192.168.1.1/x")).is_ok());
    assert_eq!(guard.opt_outs(), 1);
}

#[tokio::test]
async fn a_hostname_that_resolves_into_a_refused_range_is_refused_at_connect() {
    // `localhost` resolves into 127.0.0.0/8 from /etc/hosts, so this exercises the
    // resolver for real. Port 9 is the discard port and nothing is listening there;
    // the refusal has to arrive before that could matter.
    let client = Guard::strict()
        .client(Duration::from_secs(5))
        .expect("a client");
    let err = send(&client, &format!("http://{LOOPBACK_NAME}:9/x"))
        .await
        .expect_err("a refusal");
    let text = chain(&err);
    assert!(text.contains(LOOPBACK_NAME), "{text}");
    assert!(text.contains("127.0.0.0/8"), "{text}");
    // The inner cause reaches the caller as this crate's own message rather than being
    // flattened into an opaque connect error. hyper-util labels the layer it failed at
    // "dns error", but that string belongs to a transitive dependency, so the assertion
    // is on our prefix instead of on it.
    assert!(text.contains("intel: refused"), "{text}");
}

// --- layer 3: the redirect policy

#[tokio::test]
async fn a_redirect_to_a_refused_ip_literal_is_refused_at_the_hop() {
    let port = spawn_feed_server().await;
    // A budget of five, so what refuses the hop is the host check and not the budget.
    let client = pinned_client(&Guard::new(false, 5), port, None);
    let err = send(
        &client,
        &format!("http://{PINNED}:{port}/redirect-metadata"),
    )
    .await
    .expect_err("a refusal");
    let text = chain(&err);
    assert!(text.contains("169.254.169.254"), "{text}");
    assert!(text.contains("169.254.0.0/16"), "{text}");
    // The outer error names the original URL; the inner cause names the hop. Both
    // have to be there or the operator cannot tell which feed redirected where.
    assert!(text.contains(PINNED), "{text}");
}

#[tokio::test]
async fn a_redirect_to_a_refused_hostname_is_refused_and_the_resolver_saw_the_hop()
 {
    let port = spawn_feed_server().await;
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let client =
        pinned_client(&Guard::new(false, 5), port, Some(Arc::clone(&seen)));
    let err = send(
        &client,
        &format!("http://{PINNED}:{port}/redirect-localhost"),
    )
    .await
    .expect_err("a refusal");

    let text = chain(&err);
    assert!(text.contains(LOOPBACK_NAME), "{text}");
    assert!(text.contains("127.0.0.0/8"), "{text}");

    // The assertion that makes the one above mean something: the resolver was
    // consulted for the *hop*, and the pinned initial name never reached it.
    assert_eq!(*seen.lock().expect("test lock"), vec![LOOPBACK_NAME]);
}

#[tokio::test]
async fn the_default_guard_follows_no_redirect_and_says_so() {
    let port = spawn_feed_server().await;
    let target = format!("http://{PINNED}:{port}/redirect-elsewhere");

    // `Policy::none()` is what "do not follow" looks like in reqwest, and it is not
    // what a feed fetch may use: `stop` returns the 30x as the `Ok` result, so the
    // redirect *response* becomes the body and is parsed as a blocklist.
    let stopping = pinned_client_with(Guard::strict(), port, Policy::none());
    let stopped = send(&stopping, &target).await.expect("the 30x as Ok");
    assert_eq!(stopped.status(), 302);

    // The guard errors instead, which is the difference between an empty feed and a
    // feed that quietly stopped being what the operator configured.
    let erroring = pinned_client(&Guard::strict(), port, None);
    let err = send(&erroring, &target).await.expect_err("a refusal");
    assert!(chain(&err).contains("redirect"), "{err}");
}

#[tokio::test]
async fn a_redirect_chain_longer_than_the_budget_is_refused() {
    let port = spawn_feed_server().await;
    let client = pinned_client(&Guard::new(false, 2), port, None);
    let err = send(&client, &format!("http://{PINNED}:{port}/loop"))
        .await
        .expect_err("a refusal");
    let text = chain(&err);
    assert!(text.contains("budget"), "{text}");
    assert!(text.contains('2'), "{text}");
}

#[tokio::test]
async fn a_redirect_inside_the_budget_to_a_permitted_host_is_followed() {
    let port = spawn_feed_server().await;
    let client = pinned_client(&Guard::new(false, 5), port, None);
    let response =
        send(&client, &format!("http://{PINNED}:{port}/redirect-to-feed"))
            .await
            .expect("a permitted hop is followed");
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.expect("a body"), "ok");
}

/// The companion to [`the_default_guard_follows_no_redirect_and_says_so`] that takes
/// an arbitrary policy, so the two clients differ in exactly one thing.
fn pinned_client_with(
    guard: Guard,
    port: u16,
    policy: Policy,
) -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(policy)
        .dns_resolver(guard.resolver())
        .resolve(
            PINNED,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        )
        .build()
        .expect("a client")
}

// --- the pinned-name caveat, recorded as a test rather than as a comment

#[tokio::test]
async fn the_pinned_name_never_reaches_the_resolver() {
    // `ClientBuilder::resolve` installs a `DnsResolverWithOverrides`, whose `resolve`
    // returns the override without consulting the wrapped resolver. Recorded here
    // because it is load-bearing for the design: a pinned name is enforced by layer 1
    // alone, so layer 1 has to run before anything is pinned. It also means this
    // crate must never expose pinning as an operator knob.
    let port = spawn_feed_server().await;
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let client =
        pinned_client(&Guard::new(false, 5), port, Some(Arc::clone(&seen)));
    let response = send(&client, &format!("http://{PINNED}:{port}/feed"))
        .await
        .expect("the pinned request succeeds");
    assert_eq!(response.status(), 200);
    assert!(seen.lock().expect("test lock").is_empty());
}

// --- the same refusals over TLS
//
// Two separate cases, because the two URL shapes are refused by different layers and
// one of them is not refused by a `reqwest::Client` at all.
//
// The spike's load-bearing negative result is that an IP literal never reaches a custom
// resolver. reqwest's redirect policy is the only other hook, and it fires on a 30x, not
// on the initial URL. So for `https://169.254.169.254/...` there is nothing inside a
// built client that can refuse it: layer 1, applied by the caller before `send()`, is
// the only enforcement, which is why `feed.rs` calls `check_url` and this asserts on it
// directly. It is a pure function of the URL, so it runs before a socket exists and
// therefore before a handshake can start. No test here connects to that address — the
// spike established the route goes out through the host gateway and the metadata path
// answered 200, and reaching a cloud metadata endpoint is exactly what the guard exists
// to prevent.

#[test]
fn an_https_literal_in_a_refused_range_is_refused_by_the_url_check_alone() {
    let err = Guard::strict()
        .check_url(&url("https://169.254.169.254/latest/meta-data/"))
        .expect_err("a refusal");
    let text = err.to_string();
    assert!(text.contains("169.254.169.254"), "{text}");
    assert!(text.contains("169.254.0.0/16"), "{text}");
    // `https` is a feed transport, so what refuses this is the address and not the
    // scheme. If a future change narrows the scheme list, this fails for the wrong
    // reason and the message above still names the family.
    assert!(
        Guard::strict()
            .check_url(&url("https://feeds.example.com/blocklist.txt"))
            .is_ok()
    );
}

#[tokio::test]
async fn an_https_hostname_in_a_refused_range_is_refused_before_any_handshake()
{
    // The hostname case does go through a real client over `https://`: hyper-util
    // resolves the name before it opens the TLS socket, so layer 2 refuses first and no
    // handshake is attempted. This is the case the plaintext spike did not cover, and it
    // is the one where the plaintext result could plausibly not have transferred.
    let client = Guard::strict()
        .client(Duration::from_secs(5))
        .expect("a client");
    let err = send(&client, &format!("https://{LOOPBACK_NAME}:9/x"))
        .await
        .expect_err("a refusal");
    let text = chain(&err);
    assert!(text.contains(LOOPBACK_NAME), "{text}");
    assert!(text.contains("127.0.0.0/8"), "{text}");
    assert!(text.contains("intel: refused"), "{text}");
}
