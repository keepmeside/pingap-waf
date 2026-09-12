//! The bot plugin as pingap loads and runs it.
//!
//! JA4H canonicalisation is checked in `tests/ja4h.rs` against FoxIO's own vectors, and
//! the rule table in `src/rule.rs`. What is left for this file is what only exists once
//! the plugin is real: registration, the header-order guard, the fingerprint reaching the
//! access log, and the headline case — an automation client refused while a browser
//! request to the same path is not.
#![cfg(feature = "plugin")]

use pingap_bot::analytics::Verdict;
use pingap_bot::plugin::{Bot, BotState, JA4H_VARIABLE, ordered_header_names};
use pingap_config::PluginConf;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingap_plugin::get_plugin_factory;
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use tokio_test::io::Builder;

/// python-urllib's captured fingerprint, `a_b` prefix only — the form a library entry
/// takes. Derived in `src/library.rs` from a real capture.
const URLLIB_JA4H: &str = "ge11nn040000_5b1e8b5f4d2d";

/// The request python-urllib actually sends: `Accept-Encoding` first, which is what makes
/// it distinctive.
const URLLIB_REQUEST: &str = "GET /x HTTP/1.1\r\nAccept-Encoding: identity\r\nHost: \
                              app.test\r\nUser-Agent: Python-urllib/3.11\r\n\
                              Connection: close\r\n\r\n";

/// A browser request to the same path. Different header set, different fingerprint.
const BROWSER_REQUEST: &str = "GET /x HTTP/1.1\r\nHost: app.test\r\nUser-Agent: Mozilla/5.0 (X11; Linux \
     x86_64) Gecko/20100101 Firefox/128.0\r\nAccept: text/html\r\n\
     Accept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\n\
     Connection: keep-alive\r\n\r\n";

fn conf(mode: &str) -> String {
    format!(
        "category = \"bot\"\nprofile = \"edge\"\nmode = \"{mode}\"\nrules = [ \
         {{ fingerprint_type = \"ja4h\", fingerprint = \"{URLLIB_JA4H}\", action = \
         \"deny\" }} ]\n"
    )
}

fn plugin(text: &str) -> Bot {
    Bot::try_from(
        &toml::from_str::<PluginConf>(text).expect("test config parses"),
    )
    .expect("test config builds")
}

fn error(text: &str) -> String {
    match Bot::try_from(
        &toml::from_str::<PluginConf>(text).expect("test config parses"),
    ) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("this config should not have built"),
    }
}

async fn run(bot: &Bot, request: &str) -> (Option<u16>, Ctx) {
    let io = Builder::new().read(request.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(io));
    session.read_request().await.expect("mock request reads");
    let mut ctx = Ctx::default();
    let result = bot
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("evaluation is total");
    let status = match result {
        RequestPluginResult::Respond(resp) => Some(resp.status.as_u16()),
        _ => None,
    };
    (status, ctx)
}

#[tokio::test]
async fn the_category_is_registered_with_the_plugin_factory() {
    assert!(
        get_plugin_factory()
            .supported_plugins()
            .contains(&"bot".to_string()),
        "the bot category did not reach the factory"
    );
}

#[tokio::test]
async fn an_automation_client_is_refused_while_a_browser_is_not() {
    // The headline case. Both requests hit the same path through the same profile; only
    // the fingerprint differs.
    let bot = plugin(&conf("block"));

    let (status, ctx) = run(&bot, URLLIB_REQUEST).await;
    assert_eq!(status, Some(403), "the automation client was not refused");
    let state = ctx.extensions.get::<BotState>().expect("state recorded");
    assert!(state.denied);
    assert_eq!(state.decided_by, Some(0));
    assert_eq!(state.ja4h.as_deref().map(|v| &v[..25]), Some(URLLIB_JA4H));

    let (status, ctx) = run(&bot, BROWSER_REQUEST).await;
    assert_eq!(status, None, "a browser request was refused");
    assert!(
        ctx.extensions.get::<BotState>().is_none(),
        "a request that matched nothing should leave no state behind"
    );
}

#[tokio::test]
async fn detect_mode_records_the_verdict_without_refusing() {
    let bot = plugin(&conf("detect"));
    let (status, ctx) = run(&bot, URLLIB_REQUEST).await;
    assert_eq!(status, None, "detect mode refused a request");
    let state = ctx.extensions.get::<BotState>().expect("state recorded");
    assert!(!state.denied);
    assert!(
        state.would_deny,
        "detect must record what it would have done, or it is indistinguishable from off"
    );
}

#[tokio::test]
async fn the_fingerprint_is_published_for_the_access_log() {
    // Published on every request, including allowed ones — that population is what an
    // operator builds a deny list from in the first place.
    let bot = plugin(&conf("detect"));
    let (_, ctx) = run(&bot, BROWSER_REQUEST).await;
    let value = ctx
        .features
        .as_ref()
        .and_then(|f| f.variables.as_ref())
        .and_then(|v| v.get(JA4H_VARIABLE))
        .cloned()
        .expect("the fingerprint did not reach the context variables");
    assert!(
        value.starts_with("ge11nn"),
        "unexpected fingerprint shape: {value}"
    );
}

#[tokio::test]
async fn plain_http_produces_a_fingerprint_and_never_errors() {
    // JA4H needs no TLS. The mock sessions here are all plain HTTP, so every other test
    // in this file is also evidence for this — asserted explicitly because the
    // requirement is easy to lose when JA4 arrives later.
    let bot = plugin(&conf("detect"));
    for request in [URLLIB_REQUEST, BROWSER_REQUEST] {
        let (_, ctx) = run(&bot, request).await;
        assert!(
            ctx.features
                .as_ref()
                .and_then(|f| f.variables.as_ref())
                .and_then(|v| v.get(JA4H_VARIABLE))
                .is_some()
        );
    }
}

#[test]
fn a_header_set_with_no_preserved_order_yields_no_fingerprint() {
    // The HTTP/2 shape. `build_no_case` produces exactly what pingora's h2 path does —
    // `header_name_map: None` — and the guard has to refuse it rather than fall back to
    // `HeaderMap` iteration, whose order is documented as arbitrary.
    let mut h2_like = RequestHeader::build_no_case("GET", b"/x", None)
        .expect("header builds");
    h2_like
        .append_header("host", "app.test")
        .expect("header appends");
    h2_like
        .append_header("user-agent", "Python-urllib/3.11")
        .expect("header appends");
    assert!(!h2_like.has_case());
    assert!(
        ordered_header_names(&h2_like).is_none(),
        "a fingerprint derived from unordered iteration would match no published list \
         while looking perfectly stable"
    );

    // And the h1 shape does yield an order, so the guard is not simply always refusing.
    let mut h1 =
        RequestHeader::build("GET", b"/x", None).expect("header builds");
    h1.append_header("Host", "app.test")
        .expect("header appends");
    assert!(h1.has_case());
    assert_eq!(ordered_header_names(&h1).as_deref(), Some(&["Host"][..]));
}

#[tokio::test]
async fn a_profile_that_enforces_nothing_is_refused() {
    let msg = error("category = \"bot\"\n");
    assert!(
        msg.contains("enforces nothing"),
        "the error must say what is wrong: {msg}"
    );
    // `allow_known_bots` on its own is a real policy: exempt crawlers, touch nothing else.
    plugin("category = \"bot\"\nallow_known_bots = true\n");
}

#[tokio::test]
async fn an_unsupported_step_is_rejected_rather_than_silently_ignored() {
    let msg = error("category = \"bot\"\nstep = \"upstream_response\"\n");
    assert!(msg.contains("step"), "the error must name the key: {msg}");
}

#[tokio::test]
async fn the_miss_rate_and_verdict_counts_are_queryable() {
    // Fail-open is only defensible if it is measurable.
    let bot = plugin(&conf("block"));
    run(&bot, URLLIB_REQUEST).await;
    run(&bot, BROWSER_REQUEST).await;
    let analytics = bot.analytics();
    assert_eq!(analytics.total(), 2);
    assert_eq!(analytics.miss_rate(), 0.0, "an h1 request should not miss");
    let verdicts = analytics.verdict_counts();
    assert!(verdicts.contains(&(Verdict::Denied, 1)), "{verdicts:?}");
    assert!(verdicts.contains(&(Verdict::Allowed, 1)), "{verdicts:?}");
    assert_eq!(analytics.top_fingerprints(1).len(), 1);
    // Counts are keyed by the domain each request named, not merged across domains.
    assert_eq!(analytics.domain_counts(), vec![("app.test", 2)]);
}

#[tokio::test]
async fn a_known_good_crawler_survives_a_broad_deny() {
    let bot = plugin(
        "category = \"bot\"\nmode = \"block\"\nallow_known_bots = true\nrules = [ \
         { user_agent = \".\", action = \"deny\" } ]\n",
    );
    let crawler = "GET /x HTTP/1.1\r\nHost: app.test\r\nUser-Agent: Mozilla/5.0 \
                   (compatible; Googlebot/2.1; +http://www.google.com/bot.html)\r\n\r\n";
    let (status, ctx) = run(&bot, crawler).await;
    assert_eq!(status, None, "a broad deny took Googlebot with it");
    assert!(
        ctx.extensions
            .get::<BotState>()
            .expect("recorded")
            .known_bot
    );

    // The same rule still refuses anything not on the known-good list, so the exemption
    // is what spared the crawler rather than the rule failing to match.
    let (status, _) = run(&bot, URLLIB_REQUEST).await;
    assert_eq!(status, Some(403));
}
