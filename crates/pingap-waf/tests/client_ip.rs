//! Client-IP resolution and IP-list enforcement.
//!
//! Two properties, and they are related. The WAF must enforce on the address the rest
//! of the gateway attributes the request to — a WAF that blocks an address the access
//! log records differently produces findings nobody can act on. And with no
//! trusted-proxy list configured, the address is one the *client* chose, because
//! forwarded headers are then honoured unconditionally.
//!
//! Its own file rather than an inline module because `basic.trusted_proxies` is process
//! global. The tests below need it configured; the construction test that proves an IP
//! list is refused *without* it needs it unset. Separate test binaries are separate
//! processes, which is the only way both can hold.
#![cfg(feature = "plugin")]

use pingap_config::PluginConf;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingap_waf::plugin::{Waf, WafState};
use pingora::proxy::Session;
use std::path::Path;
use tokio_test::io::Builder;

/// A proxy address that is *not* the peer of any session built here, so every request
/// in this file arrives from an untrusted peer.
const TRUSTED: &str = "192.0.2.10";

fn enable_trusted_proxies() {
    pingap_core::set_trusted_proxies(&Some(vec![TRUSTED.to_string()]));
}

fn plugin(conf: &str) -> Waf {
    Waf::try_from(
        &toml::from_str::<PluginConf>(conf).expect("test config parses"),
    )
    .expect("test config builds")
}

async fn session_for(request: &str) -> Session {
    let io = Builder::new().read(request.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(io));
    session.read_request().await.expect("mock request reads");
    session
}

#[tokio::test]
async fn a_spoofed_forwarded_header_does_not_change_the_enforced_ip() {
    enable_trusted_proxies();
    // The header claims an address that is on the deny list. If forwarded headers were
    // honoured for an untrusted peer, this request would be refused — and, worse, any
    // client could equally claim an address that is *not* on the list.
    let waf = plugin(
        "category = \"waf\"\nip_list = [\"10.0.0.0/8\"]\nip_list_mode = \
         \"deny\"\n",
    );
    let mut ctx = Ctx::default();
    let mut session = session_for(
        "GET /health HTTP/1.1\r\nX-Forwarded-For: 10.0.0.5\r\n\r\n",
    )
    .await;

    let result = waf
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("evaluation is total");
    assert!(
        matches!(result, RequestPluginResult::Continue),
        "the spoofed address was used for the access decision"
    );
    assert_ne!(
        ctx.conn.client_ip.as_deref(),
        Some("10.0.0.5"),
        "the enforced client IP came from a header the client controls"
    );
}

#[tokio::test]
async fn a_refused_address_is_judged_before_any_pattern_runs() {
    enable_trusted_proxies();
    // An allow list, so the mock session's unresolvable peer is refused: an allow list
    // cannot confirm membership for an address it does not have, and that is the
    // fail-closed reading.
    let waf = plugin(
        "category = \"waf\"\nanomaly_threshold = 1\ncategories = { \
         sql_injection = \"block\" }\nip_list = [\"203.0.113.0/24\"]\n\
         ip_list_mode = \"allow\"\n",
    );
    let mut ctx = Ctx::default();
    // Carries a SQL injection the engine would certainly hit on. If the list ran after
    // the engine, the state would name those rules.
    let mut session = session_for(
        "GET /s?q=%27+UNION+SELECT+pw+FROM+users+--+ HTTP/1.1\r\n\r\n",
    )
    .await;

    let RequestPluginResult::Respond(resp) = waf
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("evaluation is total")
    else {
        panic!("an address outside the allow list was not refused");
    };
    assert_eq!(resp.status.as_u16(), 403);
    let state = ctx.extensions.get::<WafState>().expect("state recorded");
    assert!(state.blocked);
    assert!(
        state.hits.is_empty(),
        "the engine ran anyway, so the list is not the cheap reject it is meant to be"
    );
}

/// Every `.rs` file under the workspace's own source roots, as (path, contents).
///
/// Explicit roots rather than a whole-tree walk: `.xia-src/` holds the read-only
/// reference checkouts this fork ported *from*, and they legitimately contain the
/// duplicate resolvers the fork exists to not have.
fn workspace_sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/pingap-waf sits two levels below the workspace root")
        .to_path_buf();

    let mut roots = vec![root.join("src")];
    for group in ["", "crates"] {
        let dir = if group.is_empty() {
            root.clone()
        } else {
            root.join(group)
        };
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let src = entry.path().join("src");
            if src.is_dir() {
                roots.push(src);
            }
        }
    }

    let mut out = Vec::new();
    let mut stack = roots;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                out.push((path.display().to_string(), text));
            }
        }
    }
    assert!(out.len() > 50, "the source walk found almost nothing");
    out
}

#[test]
fn the_workspace_has_one_client_ip_resolver_and_one_cidr_parser() {
    // A second resolver would let the WAF and the access log disagree about who the
    // client is, which makes a block impossible to correlate with the traffic that
    // caused it. A second CIDR matcher would let the WAF and `ip_restriction` disagree
    // about which network an address belongs to. Both are cheap to reintroduce by
    // accident — someone needing a client IP in a new crate writes ten obvious lines —
    // so the constraint is asserted rather than trusted to review.
    let mut resolvers = Vec::new();
    let mut cidr_parsers = Vec::new();
    for (path, text) in workspace_sources() {
        if text.contains("fn get_client_ip")
            || text.contains("fn ensure_client_ip")
        {
            resolvers.push(path.clone());
        }
        // The one type that turns text into networks. Everything else must reach CIDR
        // matching through it.
        if text.contains("struct IpRules") || text.contains("IpCidr") {
            cidr_parsers.push(path);
        }
    }

    assert_eq!(
        resolvers.len(),
        1,
        "client-IP resolution must live in exactly one place, found: {resolvers:?}"
    );
    assert!(
        resolvers[0].ends_with("pingap-core/src/http_header.rs"),
        "the resolver moved: {}",
        resolvers[0]
    );
    assert_eq!(
        cidr_parsers.len(),
        1,
        "CIDR parsing must live in exactly one place, found: {cidr_parsers:?}"
    );
    assert!(
        cidr_parsers[0].ends_with("pingap-util/src/ip.rs"),
        "the CIDR parser moved: {}",
        cidr_parsers[0]
    );
}
