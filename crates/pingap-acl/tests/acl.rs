//! The ACL plugin as pingap loads and runs it.
//!
//! The pure rule-table properties are asserted in `src/evaluate.rs` and `src/rule.rs`.
//! What is left for this file is everything that only exists once the plugin is real:
//! registration, config rejection, the 401-versus-403 choice, and an access list shared
//! across domains.
#![cfg(feature = "plugin")]

use pingap_acl::plugin::{Acl, AclState};
use pingap_config::PluginConf;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingap_plugin::get_plugin_factory;
use pingora::proxy::Session;
use tokio_test::io::Builder;

/// Deny-by-default with one allow rule: the shape an operator reaches for when a domain
/// should be reachable from the office and nowhere else.
const OFFICE_ONLY: &str = r#"
category = "acl"
default_action = "deny"
rules = [
  { field = "ip", operator = "in_cidr", values = ["10.0.0.0/8"], action = "allow" },
]
"#;

fn plugin(conf: &str) -> Acl {
    Acl::try_from(
        &toml::from_str::<PluginConf>(conf).expect("test config parses"),
    )
    .expect("test config builds")
}

fn error(conf: &str) -> String {
    match Acl::try_from(
        &toml::from_str::<PluginConf>(conf).expect("test config parses"),
    ) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("this config should not have built"),
    }
}

async fn session_for(request: &str) -> Session {
    let io = Builder::new().read(request.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(io));
    session.read_request().await.expect("mock request reads");
    session
}

/// Run one request through a plugin and return the status it answered with, if any.
async fn status_of(acl: &Acl, request: &str) -> (Option<u16>, Ctx) {
    let mut ctx = Ctx::default();
    let mut session = session_for(request).await;
    let result = acl
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
    // The `#[ctor]` runs at load, so by the time a test body executes registration has
    // either happened or silently not happened — the latter leaving `category = "acl"`
    // unknown at config load.
    assert!(
        get_plugin_factory()
            .supported_plugins()
            .contains(&"acl".to_string()),
        "the acl category did not reach the factory"
    );
}

#[tokio::test]
async fn an_unsupported_step_is_rejected_rather_than_silently_ignored() {
    // `get_step_conf` would fall back to the default, producing an access control that
    // never runs. For a security control that is the worst available outcome.
    let msg = error("category = \"acl\"\nstep = \"upstream_response\"\n");
    assert!(msg.contains("step"), "the error must name the key: {msg}");
}

#[tokio::test]
async fn an_unknown_field_or_operator_fails_config_load_by_name() {
    // What `pingap -t` surfaces. A rule the engine cannot evaluate must not load: the
    // operator would believe it is enforcing.
    let msg = error(
        "category = \"acl\"\nrules = [ { field = \"country\", operator = \
         \"equals\", values = [\"US\"], action = \"deny\" } ]\n",
    );
    assert!(msg.contains("country"), "names the bad field: {msg}");

    let msg = error(
        "category = \"acl\"\nrules = [ { field = \"method\", operator = \
         \"starts_with\", values = [\"GET\"], action = \"deny\" } ]\n",
    );
    assert!(msg.contains("starts_with"), "names the bad operator: {msg}");

    // And a combination that parses but cannot be evaluated on that field.
    let msg = error(
        "category = \"acl\"\nrules = [ { field = \"user_agent\", operator = \
         \"in_cidr\", values = [\"10.0.0.0/8\"], action = \"deny\" } ]\n",
    );
    assert!(msg.contains("user_agent"), "names the field: {msg}");
    assert!(msg.contains("in_cidr"), "names the operator: {msg}");
}

#[tokio::test]
async fn an_entry_that_enforces_nothing_is_refused() {
    // A table with no rules and no access list is an entry somebody forgot to fill in.
    let msg = error("category = \"acl\"\n");
    assert!(
        msg.contains("enforces nothing"),
        "the error must say what is wrong: {msg}"
    );
    // Except when refusing everything is the stated intent, which is a real policy.
    let closed = plugin("category = \"acl\"\ndefault_action = \"deny\"\n");
    let (status, _) = status_of(&closed, "GET /x HTTP/1.1\r\n\r\n").await;
    assert_eq!(status, Some(403));
}

#[tokio::test]
async fn a_rule_denial_answers_403_and_records_which_rule_decided() {
    let acl = plugin(
        "category = \"acl\"\nrules = [ { field = \"user_agent\", operator = \
         \"contains\", values = [\"curl\"], action = \"deny\" } ]\n",
    );
    let (status, ctx) =
        status_of(&acl, "GET /x HTTP/1.1\r\nUser-Agent: curl/8.5.0\r\n\r\n")
            .await;
    assert_eq!(status, Some(403));
    let state = ctx.extensions.get::<AclState>().expect("state recorded");
    assert!(state.denied);
    assert_eq!(
        state.decided_by,
        Some(0),
        "a denial must name the rule that caused it or it cannot be triaged"
    );

    // A request the rule does not match passes, and records nothing.
    let (status, ctx) =
        status_of(&acl, "GET /x HTTP/1.1\r\nUser-Agent: Firefox\r\n\r\n").await;
    assert_eq!(status, None);
    assert!(ctx.extensions.get::<AclState>().is_none());
}

#[tokio::test]
async fn deny_by_default_refuses_an_address_no_rule_allows() {
    let acl = plugin(OFFICE_ONLY);
    // The mock session has no peer address, so the resolved client IP is empty and no
    // allow rule can match it. That is the fail-closed reading and the reason
    // deny-by-default is worth having.
    let (status, ctx) = status_of(&acl, "GET /x HTTP/1.1\r\n\r\n").await;
    assert_eq!(status, Some(403));
    let state = ctx.extensions.get::<AclState>().expect("state recorded");
    assert!(state.denied);
    assert_eq!(
        state.decided_by, None,
        "the default action decided, and it is not a rule"
    );
}

#[tokio::test]
async fn a_log_rule_records_without_refusing() {
    let acl = plugin(
        "category = \"acl\"\nrules = [ { field = \"user_agent\", operator = \
         \"contains\", values = [\"curl\"], action = \"log\" }, { field = \
         \"method\", operator = \"equals\", values = [\"TRACE\"], action = \
         \"deny\" } ]\n",
    );
    let (status, ctx) =
        status_of(&acl, "GET /x HTTP/1.1\r\nUser-Agent: curl/8.5.0\r\n\r\n")
            .await;
    assert_eq!(status, None, "a log rule must not refuse the request");
    let state = ctx.extensions.get::<AclState>().expect("state recorded");
    assert!(!state.denied);
    assert_eq!(state.logged, vec![0]);
}

/// SHA-256 of `hunter2`, which is what the access-list config stores instead of the
/// password itself.
const HUNTER2: &str =
    "f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7";

fn access_list_conf(satisfy: &str) -> String {
    format!(
        "category = \"acl\"\ndefault_action = \"allow\"\nrules = [ {{ field = \
         \"method\", operator = \"equals\", values = [\"TRACE\"], action = \
         \"deny\" }} ]\nrealm = \"Staging\"\n\n[access_list]\nip_allowlist = \
         [\"10.0.0.0/8\"]\nusers = [\"alice:{HUNTER2}\"]\nsatisfy = \
         \"{satisfy}\"\n"
    )
}

#[tokio::test]
async fn an_access_list_with_users_challenges_rather_than_refusing_outright() {
    let acl = plugin(&access_list_conf("any"));
    let (status, ctx) = status_of(&acl, "GET /x HTTP/1.1\r\n\r\n").await;
    assert_eq!(
        status,
        Some(401),
        "a list a password could satisfy must challenge for one"
    );
    let state = ctx.extensions.get::<AclState>().expect("state recorded");
    assert!(state.denied);
    assert!(
        state.access_list_refused,
        "the refusal must be distinguishable from a rule denial, or a dashboard \
         cannot tell a gated domain from a policy hit"
    );

    // Correct credentials get through. `alice:hunter2` base64-encoded.
    let (status, _) = status_of(
        &acl,
        "GET /x HTTP/1.1\r\nAuthorization: Basic YWxpY2U6aHVudGVyMg==\r\n\r\n",
    )
    .await;
    assert_eq!(status, None, "valid credentials were refused");

    // Wrong password is refused, and still with a challenge.
    let (status, _) = status_of(
        &acl,
        "GET /x HTTP/1.1\r\nAuthorization: Basic YWxpY2U6d3Jvbmc=\r\n\r\n",
    )
    .await;
    assert_eq!(status, Some(401));
}

#[tokio::test]
async fn an_ip_only_access_list_refuses_without_a_challenge() {
    // Challenging for a password that does not exist invites a client to retry forever
    // against a gate no credential can open.
    let acl = plugin(
        "category = \"acl\"\ndefault_action = \"allow\"\n\n[access_list]\n\
         ip_allowlist = [\"10.0.0.0/8\"]\n",
    );
    let (status, _) = status_of(&acl, "GET /x HTTP/1.1\r\n\r\n").await;
    assert_eq!(status, Some(403));
}

#[tokio::test]
async fn the_access_list_gates_before_the_rule_table() {
    // An `allow` rule must not let past an address the access list refused. Ordering it
    // the other way would make attaching an access list meaningless as soon as any
    // allow rule existed.
    let acl = plugin(
        "category = \"acl\"\ndefault_action = \"deny\"\nrules = [ { field = \
         \"method\", operator = \"in_list\", values = [\"GET\", \"HEAD\"], \
         action = \"allow\" } ]\n\n[access_list]\nip_allowlist = \
         [\"10.0.0.0/8\"]\n",
    );
    let (status, ctx) = status_of(&acl, "GET /x HTTP/1.1\r\n\r\n").await;
    assert_eq!(status, Some(403));
    let state = ctx.extensions.get::<AclState>().expect("state recorded");
    assert!(
        state.access_list_refused,
        "the rule table decided, so the access list was not the gate"
    );
}

#[tokio::test]
async fn one_access_list_gates_every_domain_that_attaches_it_and_no_others() {
    // Two domains attaching the same list: both gated. A third that does not attach it:
    // not gated. Attachment is what enforces — the criterion Phase 05 exists to prove,
    // expressed at the level a plugin can be observed at.
    let shared = access_list_conf("any");
    let tenant_a = plugin(&shared);
    let tenant_b = plugin(&shared);
    let unattached = plugin(
        "category = \"acl\"\nrules = [ { field = \"method\", operator = \
         \"equals\", values = [\"TRACE\"], action = \"deny\" } ]\n",
    );

    for (label, acl) in [("a", &tenant_a), ("b", &tenant_b)] {
        let (status, _) = status_of(acl, "GET /x HTTP/1.1\r\n\r\n").await;
        assert_eq!(
            status,
            Some(401),
            "domain {label} attached the list and was not gated"
        );
    }
    let (status, _) = status_of(&unattached, "GET /x HTTP/1.1\r\n\r\n").await;
    assert_eq!(
        status, None,
        "a domain that never attached the list was gated anyway"
    );
}

#[tokio::test]
async fn a_geo_rule_is_refused_when_the_build_has_no_database() {
    let conf = "category = \"acl\"\nrules = [ { field = \"geo_country\", \
                operator = \"in_list\", values = [\"CN\", \"RU\"], action = \
                \"deny\" } ]\n";
    if cfg!(feature = "geo") {
        // With the database present the rule builds; whether it fires depends on the
        // address, and the mock session has none.
        let acl = plugin(conf);
        let (status, _) = status_of(&acl, "GET /x HTTP/1.1\r\n\r\n").await;
        assert_eq!(status, None);
    } else {
        // Without it, the rule could never match. Failing by name beats a rule the
        // operator believes is blocking two countries.
        let msg = error(conf);
        assert!(
            msg.contains("geo"),
            "the error must name the feature: {msg}"
        );
        assert!(
            msg.contains("geo_country"),
            "the error must name the field: {msg}"
        );
    }
}
