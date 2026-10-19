use pingap_behaviour::{Behaviour, activate_profiles};
use pingap_config::PluginConf;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::{http::ResponseHeader, proxy::Session};
use std::collections::HashMap;
use tokio_test::io::Builder;
async fn session(path: &str, method: &str) -> Session {
    let raw = format!(
        "{method} {path} HTTP/1.1\r\nHost: a.test\r\nX-Forwarded-For: 9.9.9.9\r\n\r\n"
    );
    let io = Builder::new().read(raw.as_bytes()).build();
    let mut s = Session::new_h1(Box::new(io));
    s.read_request().await.expect("test fixture");
    s
}
fn profile(ns: &str, scenario: &str) -> PluginConf {
    let extra = if scenario == "failed_login" {
        "path=\"/login\"\nmethod=\"POST\"\nstatuses=[401]"
    } else {
        ""
    };
    toml::from_str(&format!(
        r#"category="behaviour"
enabled=true
abuse_namespace="{ns}"
budget_ms=60000
[abuse]
enabled=true
[abuse.{scenario}]
mode="block"
threshold=2
window="1m"
ban_ttl="1m"
{extra}
"#
    ))
    .expect("test fixture")
}
#[tokio::test]
async fn same_domain_profiles_preserve_each_pending_observation_in_both_orders()
{
    pingap_core::set_trusted_proxies(&Some(vec!["127.0.0.1".into()]));
    pingap_domainstate::set_registered_hosts(["a.test", "b.test"]);
    for reverse in [false, true] {
        let configs: HashMap<String, PluginConf> = [
            (
                "behaviour:login".into(),
                profile("behaviour:login", "failed_login"),
            ),
            ("behaviour:scan".into(), profile("behaviour:scan", "scan")),
        ]
        .into();
        activate_profiles(&HashMap::new());
        activate_profiles(&configs);
        let login = pingap_core::with_construction_trusted_proxies(
            &Some(vec!["127.0.0.1".into()]),
            || {
                Behaviour::try_from(&configs["behaviour:login"])
                    .expect("test fixture")
            },
        );
        let scan = pingap_core::with_construction_trusted_proxies(
            &Some(vec!["127.0.0.1".into()]),
            || {
                Behaviour::try_from(&configs["behaviour:scan"])
                    .expect("test fixture")
            },
        );
        let plugins = if reverse {
            vec![&scan, &login]
        } else {
            vec![&login, &scan]
        };
        for (path, method, status) in [
            ("/login", "POST", 401),
            ("/one", "GET", 404),
            ("/two", "GET", 404),
        ] {
            let mut s = session(path, method).await;
            let mut ctx = Ctx::default();
            ctx.conn.client_ip = Some("1.2.3.4".into());
            for p in &plugins {
                assert!(matches!(
                    p.handle_request(PluginStep::Request, &mut s, &mut ctx)
                        .await
                        .expect("test fixture"),
                    RequestPluginResult::Continue
                ));
            }
            let mut response =
                ResponseHeader::build(status, None).expect("test fixture");
            for p in &plugins {
                p.handle_response(&mut s, &mut ctx, &mut response)
                    .await
                    .expect("test fixture");
            }
        }
        let mut s = session("/", "GET").await;
        let mut ctx = Ctx::default();
        ctx.conn.client_ip = Some("1.2.3.4".into());
        assert!(matches!(
            scan.handle_request(PluginStep::Request, &mut s, &mut ctx)
                .await
                .expect("test fixture"),
            RequestPluginResult::Respond(_)
        ));
        assert!(matches!(
            login
                .handle_request(PluginStep::Request, &mut s, &mut ctx)
                .await
                .expect("test fixture"),
            RequestPluginResult::Continue
        ));
        let mut s = session("/login", "POST").await;
        let mut ctx = Ctx::default();
        ctx.conn.client_ip = Some("1.2.3.4".into());
        login
            .handle_request(PluginStep::Request, &mut s, &mut ctx)
            .await
            .expect("test fixture");
        login
            .handle_response(
                &mut s,
                &mut ctx,
                &mut ResponseHeader::build(401, None).expect("test fixture"),
            )
            .await
            .expect("test fixture");
        let mut ctx = Ctx::default();
        ctx.conn.client_ip = Some("1.2.3.4".into());
        assert!(matches!(
            login
                .handle_request(PluginStep::Request, &mut s, &mut ctx)
                .await
                .expect("test fixture"),
            RequestPluginResult::Respond(_)
        ));
        // Other domain and identities remain outside both bans.
        assert!(matches!(
            pingap_behaviour::decisions::registry().admit(
                "behaviour:login",
                "b.test",
                "1.2.3.4",
                "POST",
                "/login",
                true
            ),
            pingap_behaviour::decisions::Admission::Allowed(_)
        ));
        assert!(matches!(
            pingap_behaviour::decisions::registry().admit(
                "behaviour:login",
                "a.test",
                "5.6.7.8",
                "POST",
                "/login",
                true
            ),
            pingap_behaviour::decisions::Admission::Allowed(_)
        ));
    }
    activate_profiles(&HashMap::new());
    pingap_core::set_trusted_proxies(&None);
}
