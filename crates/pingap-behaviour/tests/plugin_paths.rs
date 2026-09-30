//! Request-path assertions for the behaviour plugin: a behavioural score is an
//! input to policy, never a policy — `handle_request` must always `Continue`.

use pingap_behaviour::Behaviour;
use pingap_config::PluginConf;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use tokio_test::io::Builder;

fn plugin() -> Behaviour {
    let conf: PluginConf = toml::from_str(
        r#"category = "behaviour"
           enabled = true
           client_ip_from_peer = true
           budget_ms = 60000
        "#,
    )
    .expect("config parses");
    Behaviour::try_from(&conf).expect("builds")
}

async fn session_for(request: &str) -> Session {
    let io = Builder::new().read(request.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(io));
    session.read_request().await.expect("mock request reads");
    session
}

#[tokio::test]
async fn a_request_is_never_refused_by_behavioural_scoring() {
    // Even an enabled scorer on a path that produces no challenge and no deny
    // must let the request through — the score only ever feeds the challenge
    // tier, it cannot refuse on its own.
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
        "a behavioural score must never refuse a request"
    );
}

#[tokio::test]
async fn the_score_and_profile_are_published_on_an_allowed_request() {
    // The score is published for the access log on the *allow* path too — if it
    // only appeared on a challenged or blocked request, an operator could not
    // see what the detector thought of the traffic it let through.
    let plugin = plugin();
    let mut ctx = Ctx::default();
    let mut session =
        session_for("GET /asset HTTP/1.1\r\nHost: a.test\r\n\r\n").await;
    let result = plugin
        .handle_request(PluginStep::Request, &mut session, &mut ctx)
        .await
        .expect("handle_request is total");
    assert!(matches!(result, RequestPluginResult::Continue));
    assert!(
        ctx.get_variable("behaviour_score").is_some(),
        "behaviour_score must be published on the allow path"
    );
    assert!(
        ctx.get_variable("behaviour_profile").is_some(),
        "behaviour_profile must be published on the allow path"
    );
    assert!(ctx.get_variable("behaviour_cost_ms").is_some());
}
