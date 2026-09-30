//! Shared fixtures.
//!
//! A module rather than copies in each test binary: a session builder that installs a TCP
//! peer address is fiddly enough that four divergent copies would eventually disagree about
//! what "the client" means, and that disagreement is exactly what these tests exist to
//! prevent.
// Each test binary includes this module and uses only part of it — the identity binaries need
// the trusted-proxy helpers and not the peer-less session, the store binaries need neither.
// Dead code here is the shape of a shared fixture, not an unused function.
#![allow(dead_code)]

use pingora::protocols::SocketDigest;
use pingora::protocols::l4::socket::SocketAddr as PeerAddr;
use pingora::proxy::Session;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use tokio::sync::{Mutex, MutexGuard};
use tokio_test::io::Builder;

/// A session carrying `request` as its bytes, whose TCP peer is `peer`.
///
/// The peer is installed through the connection digest because that is where pingora reads
/// it from: `client_addr()` resolves to `digest.socket_digest.peer_addr`. A mock stream has
/// no socket, so without this step the peer is `None`, every identity resolves to the empty
/// string, and a test asserting "not the spoofed header" passes for the wrong reason.
pub async fn session(request: &str, peer: &str) -> Session {
    let io = Builder::new().read(request.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(io));
    session.read_request().await.expect("mock request reads");

    let addr: SocketAddr = peer.parse().expect("test peer address parses");
    // The descriptor is never used: `peer_addr` is a `OnceCell`, and reading it returns the
    // value set below rather than querying the socket — so no `mut` binding is needed either.
    // Pingora wraps the standard address in its own enum so a Unix socket can travel the same
    // path.
    #[cfg(unix)]
    let digest = SocketDigest::from_raw_fd(-1);
    #[cfg(windows)]
    let digest = SocketDigest::from_raw_socket(u64::MAX);
    digest
        .peer_addr
        .set(Some(PeerAddr::Inet(addr)))
        .expect("a fresh digest has no peer yet");

    let installed = session
        .downstream_session
        .digest_mut()
        .map(|digest_ref| {
            digest_ref.socket_digest = Some(Arc::new(digest));
        })
        .is_some();
    assert!(
        installed,
        "an h1 session read from a mock always has a digest"
    );
    session
}

/// A session with no peer address at all, as an unattributable connection presents.
pub async fn session_without_peer(request: &str) -> Session {
    let io = Builder::new().read(request.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(io));
    session.read_request().await.expect("mock request reads");
    session
}

/// The address configured as the one trusted proxy, so a test can be the peer or not be it.
pub const TRUSTED_PROXY: &str = "192.0.2.10";

/// Serializes access to the process-global trusted-proxy list.
///
/// `TRUSTED_PROXIES` is one `RwLock`-protected static for the whole process, and
/// `set_trusted_proxies` writes it. A test that installs a *different* list — the CIDR
/// case, which writes `192.0.2.0/24` over the default `192.0.2.10` — races every sibling
/// that reads the list through `get_client_ip`: whichever wrote last decides what the
/// other test's peer resolves to. Holding this guard for the whole test body makes the
/// set → assert → restore sequence atomic against those reads, so the CIDR test cannot
/// bleed its range into a sibling, and a sibling cannot restore the exact-IP list while
/// the CIDR test is mid-assertion. It is a `tokio::sync::Mutex` rather than `std::sync`
/// precisely because the guard is held across `.await` on the mock session, so the lock
/// must yield to the executor rather than block a worker thread. Every test that calls
/// `set_trusted_proxies` or `set_trusted_proxies(&Some(...))` holds this for its duration.
pub async fn trusted_proxy_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().await
}

/// Clears the process-global trusted-proxy list.
///
/// Called at the top of every test in a binary that needs it clear. The flag is a static, so
/// a test that merely assumes the default is a test that breaks the moment another one in the
/// same process changes it — and tests in one binary run on parallel threads.
pub fn unset_trusted_proxies() {
    pingap_core::set_trusted_proxies(&None);
}

/// Installs `TRUSTED_PROXY` as the only trusted proxy, once per process.
///
/// `OnceLock` rather than a bare call: with tests on parallel threads, whichever ran first
/// would otherwise decide whether the others saw the flag set.
pub fn set_trusted_proxies() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        pingap_core::set_trusted_proxies(&Some(vec![
            TRUSTED_PROXY.to_string(),
        ]));
    });
}
