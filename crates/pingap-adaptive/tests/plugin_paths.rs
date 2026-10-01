//! Request-path assertions for the adaptive plugin: modulation is published as
//! access-log variables on the request it measured, never a refusal.

use pingap_adaptive::Adaptive;
use pingap_config::PluginConf;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use tokio_test::io::Builder;

fn plugin() -> Adaptive {
    let conf: PluginConf = toml::from_str(
        r#"category = "adaptive"
           enabled = true
           client_ip_from_peer = true
        "#,
    )
    .expect("config parses");
    Adaptive::try_from(&conf).expect("builds")
}

async fn session_for(request: &str) -> Session {
    let io = Builder::new().read(request.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(io));
    session.read_request().await.expect("mock request reads");
    session
}

#[tokio::test]
async fn a_request_is_never_refused_by_adaptive_modulation() {
    // The learner only ever modulates limits the policy already set — `handle_request`
    // always continues, even on a request it would throttle.
    let plugin = plugin();
    let mut ctx = Ctx::default();
    let mut session =
        session_for("GET /asset HTTP/1.1\r\nHost: a.test\r\n\r\n").await;
    let result = plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total");
    assert!(
        matches!(result, RequestPluginResult::Continue),
        "adaptive modulation must never refuse a request"
    );
}

#[tokio::test]
async fn the_reason_and_ratio_render_into_an_access_log_line() {
    // `{:adaptive_reason}` and `{:adaptive_ratio}` must reach a rendered log line, not
    // only sit in the variables map — asserted on the bytes `Parser::format` produces,
    // mirroring the WAF's rendered-line test.
    use pingap_logger::Parser;

    let plugin = plugin();
    let mut ctx = Ctx::default();
    let mut session =
        session_for("GET /asset HTTP/1.1\r\nHost: a.test\r\n\r\n").await;
    plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total");

    let parser: Parser = "{:adaptive_reason}|{:adaptive_ratio}".into();
    let rendered = parser.format(&session, &ctx);
    let line = String::from_utf8_lossy(&rendered).to_string();
    let fields: Vec<&str> = line.split('|').collect();
    assert_eq!(fields.len(), 2, "expected two fields: {line}");
    assert!(
        !fields[0].is_empty(),
        "adaptive_reason rendered empty: {line}"
    );
    assert!(
        !fields[1].is_empty() && fields[1].chars().all(|c| c.is_ascii_digit() || c == '.'),
        "adaptive_ratio did not render a number: {line}"
    );
}
