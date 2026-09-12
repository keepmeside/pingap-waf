// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The RBAC gate, enumerated over the real route table.
//!
//! Not a sample and not an assertion about a middleware. Every test here walks
//! `pingap_admin_api::table()` and drives each entry, so a route added without a guard, or
//! with the wrong one, fails here rather than shipping. That is the whole point of the table
//! being data: a chain of `if path.starts_with(..)` cannot be enumerated, so the equivalent
//! test could only ever check the routes its author remembered.
//!
//! These run against a real `TursoStore` and a real `Applier`. The handlers are therefore
//! really called — a route whose access check passed but whose handler panicked would show up
//! here — and the assertion is on the *status*, because what the gate promises is a 403 and
//! not a particular body.

use bytes::Bytes;
use http::{Method, StatusCode};
use pingap_admin_api::{Access, ApiRequest, AppState, Caller, dispatch, table};
use pingap_controlplane::projection::{
    Applier, ConfigSink, DataPlane, NoPluginCheck, Validator,
};
use pingap_controlplane::{
    AuthLevel, Capability, ControlPlaneStore, Role, TursoStore,
};
use std::sync::Arc;
use std::time::Duration;

/// A sink that accepts everything and remembers nothing.
///
/// These tests never assert on committed config — that is `tests/apply.rs` and the gateway
/// tests. Here the applier exists so the rollback route is really reachable.
struct NullSink;

#[async_trait::async_trait]
impl ConfigSink for NullSink {
    async fn commit(&self, _canonical_toml: &str) -> Result<(), String> {
        Ok(())
    }
}

struct NothingRunning;

impl DataPlane for NothingRunning {
    fn running_config_key(&self, _name: &str) -> Option<String> {
        None
    }
}

/// A migrated store with one real user per role, and an applier over it.
///
/// The users are real rows because a `Caller` naming a user that does not exist is not a
/// state the gate should be measured against: `/account` answers 401 to it, correctly, and a
/// fixture that produced that would make "the gate refused me" and "my account is gone"
/// indistinguishable in every assertion below.
struct Fixture {
    state: AppState,
    /// Role key → the id the store assigned.
    ids: std::collections::HashMap<&'static str, String>,
    _dir: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = TursoStore::open(
        dir.path().join("cp.db").to_str().expect("utf-8 path"),
    )
    .await
    .expect("the store opens");
    store.migrate().await.expect("migrations apply");
    let store: Arc<dyn ControlPlaneStore> = Arc::new(store);

    let mut ids = std::collections::HashMap::new();
    for role in Role::ALL {
        let user = store
            .create_user(
                pingap_controlplane::NewUser {
                    username: format!("{}-user", role.key()),
                    email: format!("{}@example.test", role.key()),
                    // Shaped like a PHC string, never produced by the KDF: nothing here
                    // verifies a password, and hashing for real costs 19 MiB per user.
                    password_hash: "$argon2id$v=19$m=19456,t=2,p=1$salt$hash"
                        .to_string(),
                    role,
                },
                1_000,
            )
            .await
            .expect("the user is created");
        ids.insert(role.key(), user.id);
    }

    let applier = Applier::new(
        store.clone(),
        // `/bin/true` exits 0: these tests are about who may reach a route, and pointing the
        // validator at a real gateway binary would make every one of them depend on a build.
        Validator::new("/bin/true"),
        Arc::new(NoPluginCheck),
        Arc::new(NullSink),
        Arc::new(NothingRunning),
        Duration::from_millis(0),
    );
    Fixture {
        state: AppState::new(store, Arc::new(applier)),
        ids,
        _dir: dir,
    }
}

fn caller(fixture: &Fixture, role: Role, level: AuthLevel) -> Caller {
    Caller {
        session_id: "s1".to_string(),
        user_id: fixture
            .ids
            .get(role.key())
            .expect("the fixture created this role")
            .clone(),
        username: format!("{}-user", role.key()),
        role,
        auth_level: level,
    }
}

/// A request for `route`, with every `:capture` filled in by something plausible.
///
/// The value does not matter — a 404 for a user that does not exist is a pass here, because
/// the question is whether the caller got *past the gate*. What matters is that the path
/// matches the pattern, or the route under test would never be reached and the test would
/// pass by routing to nothing.
fn request_for(
    route: &pingap_admin_api::Route,
    caller: Option<Caller>,
) -> ApiRequest {
    let path = route
        .path
        .split('/')
        .map(|segment| {
            if segment.starts_with(':') {
                "does-not-exist"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    ApiRequest {
        method: route.method.clone(),
        path,
        query: String::new(),
        // Valid JSON for the DTOs that parse a body, so a mutating route reaches its handler
        // rather than stopping at a 400 that would mask an access decision.
        body: Bytes::from_static(b"{}"),
        caller,
    }
}

/// Structural, and it runs without a store: a write route must name a mutating capability.
///
/// `Public` and `Authenticated` carry no capability at all, so a `POST` marked either would
/// be a write nobody's role was consulted about. Checked on the table rather than by driving
/// requests, because this is a property of the declaration and should fail at the same moment
/// the declaration is wrong.
#[test]
fn every_write_route_names_a_mutating_capability() {
    for route in table() {
        if route.method == Method::GET {
            continue;
        }
        assert!(
            route.access.is_mutating(),
            "{} {} changes state but its access is {:?}, which asks nobody's role",
            route.method,
            route.path,
            route.access
        );
    }
}

/// The unauthenticated surface is exactly one route.
///
/// Pinned by name, not counted: a test asserting "at most two public routes" would happily
/// accept a *different* second one. Login is the other unauthenticated endpoint and is
/// answered by the admin plugin ahead of the router, because it is the one request with no
/// session to read.
#[test]
fn only_health_is_public() {
    let public: Vec<String> = table()
        .iter()
        .filter(|route| route.access == Access::Public)
        .map(|route| format!("{} {}", route.method, route.path))
        .collect();
    assert_eq!(
        public,
        vec!["GET /health".to_string()],
        "the unauthenticated surface changed"
    );
}

#[tokio::test]
async fn a_route_that_is_not_public_is_401_without_a_session() {
    let f = fixture().await;
    for route in table() {
        if route.access == Access::Public {
            continue;
        }
        let response = dispatch(&f.state, &request_for(route, None)).await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "{} {} answered {} to a caller with no session",
            route.method,
            route.path,
            response.status
        );
    }
}

/// The plan-level criterion: a viewer is refused every mutating route, per route.
#[tokio::test]
async fn a_viewer_is_403_on_every_mutating_route() {
    let f = fixture().await;
    let mut checked = 0;
    for route in table() {
        if !route.access.is_mutating() {
            continue;
        }
        let request = request_for(
            route,
            Some(caller(&f, Role::Viewer, AuthLevel::TwoFactor)),
        );
        let response = dispatch(&f.state, &request).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "a viewer reached {} {} and got {}",
            route.method,
            route.path,
            response.status
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "no mutating route was found, so this test proved nothing"
    );
}

/// A password-only session may look but not touch, on every mutating route.
///
/// Separate from the viewer case because it is a different denial with a different meaning:
/// the role would allow this, and completing the second factor would grant it. A UI that
/// cannot tell the two apart either prompts a viewer for a TOTP code they can never use, or
/// tells an admin they lack permission they have.
#[tokio::test]
async fn a_password_only_session_is_403_on_every_mutating_route() {
    let f = fixture().await;
    for route in table() {
        if !route.access.is_mutating() {
            continue;
        }
        let request = request_for(
            route,
            Some(caller(&f, Role::Admin, AuthLevel::PasswordOnly)),
        );
        let response = dispatch(&f.state, &request).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "an unconfirmed session reached {} {}",
            route.method,
            route.path
        );
        let body = String::from_utf8_lossy(response.body.as_ref()).to_string();
        assert!(
            body.contains("complete_second_factor"),
            "{} {} refused without telling the caller the refusal is recoverable: {body}",
            route.method,
            route.path
        );
    }
}

/// The other direction, and the one a gate that simply refuses everything would fail: for
/// every route, a role the matrix says *does* hold the capability gets past the gate.
///
/// "Past the gate" is `!= 403`, not `== 200`: the fixtures name a user that does not exist and
/// a version that was never applied, so 404 and 409 are the honest answers. Asserting 200
/// would force the test to construct valid state for every route and would then be testing
/// the handlers, which is `tests/routes.rs`'s job.
#[tokio::test]
async fn a_role_that_holds_the_capability_reaches_every_route() {
    let f = fixture().await;
    for route in table() {
        let role = match route.access {
            Access::Public => continue,
            Access::Authenticated => Role::Viewer,
            Access::Needs(capability) => Role::ALL
                .into_iter()
                .find(|role| role.allows(capability))
                .unwrap_or_else(|| {
                    panic!(
                        "{} {} needs {capability:?}, which no role holds — the route is \
                         unreachable by anyone",
                        route.method, route.path
                    )
                }),
        };
        let request =
            request_for(route, Some(caller(&f, role, AuthLevel::TwoFactor)));
        let response = dispatch(&f.state, &request).await;
        assert_ne!(
            response.status,
            StatusCode::FORBIDDEN,
            "{} {} refused {:?}, which the matrix says holds its capability",
            route.method,
            route.path,
            role
        );
        assert_ne!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "{} {} treated an authenticated caller as anonymous",
            route.method,
            route.path
        );
    }
}

/// An operator may edit traffic and policy, and may not manage users or restart the process.
///
/// Named capabilities rather than named routes: the route table will grow, and a test written
/// against paths would drift from the matrix it is supposed to be checking.
#[test]
fn an_operator_may_edit_policy_and_may_not_manage_users() {
    for capability in [
        Capability::EditDomain,
        Capability::EditUpstream,
        Capability::EditPolicy,
        Capability::EditCertificate,
    ] {
        assert!(
            Role::Operator.allows(capability),
            "an operator cannot {capability:?}"
        );
    }
    for capability in [
        Capability::ManageUsers,
        Capability::EnrolNode,
        Capability::RestartProcess,
        Capability::RestoreBackup,
    ] {
        assert!(
            !Role::Operator.allows(capability),
            "an operator can {capability:?}"
        );
    }
}
