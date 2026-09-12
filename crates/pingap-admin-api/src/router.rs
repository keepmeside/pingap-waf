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

//! The route table, and the one place authorisation happens.
//!
//! Two properties matter more than the routing itself, and both come from the table being
//! *data* rather than a chain of `if path.starts_with(..)`:
//!
//! - **A route cannot exist without an access decision.** [`Access`] has no default and no
//!   `Option`: every entry either names a [`Capability`] or says `Public`, in a field the
//!   compiler requires. There is no shape for "I forgot".
//! - **The table is enumerable.** `tests/rbac_enumeration.rs` walks [`table`] and drives
//!   every entry as all three roles. A test that sampled routes, or trusted a middleware
//!   to have been applied, would pass for a route added without a guard — which is the
//!   normal way RBAC leaks.
//!
//! Dispatch is a linear scan over a table of this size, matched most-specific-first. A
//! tree would be faster and this is the admin listener: one operator, not request traffic.

use crate::{ApiError, ApiRequest, ApiResponse, AppState, Result};
use http::Method;
use pingap_controlplane::{Capability, Denial, authorize};
use std::future::Future;
use std::pin::Pin;

/// What a caller must have to reach a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Reachable with no session at all. Exactly two routes are, and the enumeration test
    /// pins the list so a third cannot be added quietly.
    Public,
    /// Any authenticated session, whatever its role. For routes that act only on the
    /// caller's own account — a viewer must be able to change their own password.
    Authenticated,
    /// Decided by [`authorize`], which answers role and second factor together.
    Needs(Capability),
}

impl Access {
    /// Whether reaching this route changes state.
    ///
    /// Read off the capability rather than off the HTTP method: `POST /auth/logout`
    /// mutates a session and `GET /backup/export` does not, and a method-based guess would
    /// be wrong about both. `Public` and `Authenticated` routes carry no capability, so
    /// they are read-only by construction — enforced by the enumeration test, which
    /// refuses a non-GET route that names neither.
    pub fn is_mutating(self) -> bool {
        matches!(self, Self::Needs(capability) if capability.is_mutating())
    }
}

/// A handler: the state, the request, and whatever the path pattern captured.
///
/// A boxed future behind a plain `fn` pointer rather than a trait object, so [`Route`] stays
/// a value that can live in a `static` table and be walked by a test.
pub type Handler = for<'a> fn(
    &'a AppState,
    &'a ApiRequest,
    &'a [String],
) -> Pin<
    Box<dyn Future<Output = Result<ApiResponse>> + Send + 'a>,
>;

/// Wrap an `async fn(&AppState, &ApiRequest, &[String])` as a [`Handler`].
macro_rules! handler {
    ($f:path) => {
        (|state, request, params| Box::pin($f(state, request, params)))
            as Handler
    };
}

pub struct Route {
    pub method: Method,
    /// Segments beginning `:` capture; everything else matches literally. No globs and no
    /// regex: a pattern language rich enough to overlap is a pattern language in which two
    /// routes can silently shadow each other.
    pub path: &'static str,
    pub access: Access,
    pub handler: Handler,
}

impl Route {
    /// The captured segments, or `None` if `path` is not this route.
    fn captures(&self, path: &str) -> Option<Vec<String>> {
        let mut captured = Vec::new();
        let mut pattern = self.path.split('/');
        let mut actual = path.split('/');
        loop {
            match (pattern.next(), actual.next()) {
                (None, None) => return Some(captured),
                (Some(p), Some(a)) if p.starts_with(':') => {
                    if a.is_empty() {
                        return None;
                    }
                    captured.push(
                        urlencoding::decode(a)
                            .map(|v| v.to_string())
                            .unwrap_or_else(|_| a.to_string()),
                    );
                },
                (Some(p), Some(a)) if p == a => {},
                _ => return None,
            }
        }
    }
}

/// Every registered route.
///
/// Built once. The order is irrelevant to correctness — patterns cannot overlap, because a
/// literal segment never equals a `:capture` and two entries differing only in method are
/// distinguished before access is decided.
pub fn table() -> &'static [Route] {
    static TABLE: std::sync::LazyLock<Vec<Route>> =
        std::sync::LazyLock::new(build);
    &TABLE
}

fn build() -> Vec<Route> {
    use crate::routes;
    vec![
        // ---- unauthenticated ---------------------------------------------------------
        //
        // The only route in this table a caller reaches without a session. Login is the
        // other unauthenticated endpoint and is answered by the admin plugin before the
        // router is consulted, because it is the one request that has no session to read.
        Route {
            method: Method::GET,
            path: "/health",
            access: Access::Public,
            handler: handler!(routes::system::health),
        },
        // ---- the caller's own account ------------------------------------------------
        Route {
            method: Method::GET,
            path: "/account",
            access: Access::Authenticated,
            handler: handler!(routes::account::profile),
        },
        Route {
            method: Method::GET,
            path: "/account/sessions",
            access: Access::Needs(Capability::ViewOwnSessions),
            handler: handler!(routes::account::own_sessions),
        },
        // ---- users -------------------------------------------------------------------
        Route {
            method: Method::GET,
            path: "/users",
            access: Access::Needs(Capability::ViewUsers),
            handler: handler!(routes::users::list),
        },
        Route {
            method: Method::POST,
            path: "/users",
            access: Access::Needs(Capability::ManageUsers),
            handler: handler!(routes::users::create),
        },
        Route {
            method: Method::PATCH,
            path: "/users/:id",
            access: Access::Needs(Capability::ManageUsers),
            handler: handler!(routes::users::update),
        },
        // ---- config versions, drift, rollback ----------------------------------------
        Route {
            method: Method::GET,
            path: "/config-versions",
            access: Access::Needs(Capability::ViewConfig),
            handler: handler!(routes::config_versions::list),
        },
        Route {
            method: Method::POST,
            path: "/config-versions/:id/rollback",
            access: Access::Needs(Capability::EditDomain),
            handler: handler!(routes::config_versions::rollback),
        },
        // ---- activity ----------------------------------------------------------------
        Route {
            method: Method::GET,
            path: "/activity",
            access: Access::Needs(Capability::ViewEvents),
            handler: handler!(routes::activity::list),
        },
        // ---- config-shaped resources, written through the projection ------------------
        //
        // Four operations each, and the same four for every category, because they are the
        // same map in `Intent`. A write here regenerates the whole config and runs the
        // apply; none of these handlers touches config storage.
        //
        // A listener carries `EditDomain` rather than a capability of its own: the matrix
        // has none for it, and inventing one here would put the answer to "who may change
        // traffic shape" in two places that could disagree.
        Route {
            method: Method::GET,
            path: "/domains",
            access: Access::Needs(Capability::ViewConfig),
            handler: handler!(routes::domains::list),
        },
        Route {
            method: Method::GET,
            path: "/domains/:name",
            access: Access::Needs(Capability::ViewConfig),
            handler: handler!(routes::domains::get),
        },
        Route {
            method: Method::PUT,
            path: "/domains/:name",
            access: Access::Needs(Capability::EditDomain),
            handler: handler!(routes::domains::put),
        },
        Route {
            method: Method::DELETE,
            path: "/domains/:name",
            access: Access::Needs(Capability::EditDomain),
            handler: handler!(routes::domains::delete),
        },
        Route {
            method: Method::GET,
            path: "/upstreams",
            access: Access::Needs(Capability::ViewConfig),
            handler: handler!(routes::upstreams::list),
        },
        Route {
            method: Method::GET,
            path: "/upstreams/:name",
            access: Access::Needs(Capability::ViewConfig),
            handler: handler!(routes::upstreams::get),
        },
        Route {
            method: Method::PUT,
            path: "/upstreams/:name",
            access: Access::Needs(Capability::EditUpstream),
            handler: handler!(routes::upstreams::put),
        },
        Route {
            method: Method::DELETE,
            path: "/upstreams/:name",
            access: Access::Needs(Capability::EditUpstream),
            handler: handler!(routes::upstreams::delete),
        },
        Route {
            method: Method::GET,
            path: "/listeners",
            access: Access::Needs(Capability::ViewConfig),
            handler: handler!(routes::listeners::list),
        },
        Route {
            method: Method::GET,
            path: "/listeners/:name",
            access: Access::Needs(Capability::ViewConfig),
            handler: handler!(routes::listeners::get),
        },
        Route {
            method: Method::PUT,
            path: "/listeners/:name",
            access: Access::Needs(Capability::EditDomain),
            handler: handler!(routes::listeners::put),
        },
        Route {
            method: Method::DELETE,
            path: "/listeners/:name",
            access: Access::Needs(Capability::EditDomain),
            handler: handler!(routes::listeners::delete),
        },
        Route {
            method: Method::GET,
            path: "/policies",
            access: Access::Needs(Capability::ViewConfig),
            handler: handler!(routes::policies::list),
        },
        Route {
            method: Method::GET,
            path: "/policies/:name",
            access: Access::Needs(Capability::ViewConfig),
            handler: handler!(routes::policies::get),
        },
        Route {
            method: Method::PUT,
            path: "/policies/:name",
            access: Access::Needs(Capability::EditPolicy),
            handler: handler!(routes::policies::put),
        },
        Route {
            method: Method::DELETE,
            path: "/policies/:name",
            access: Access::Needs(Capability::EditPolicy),
            handler: handler!(routes::policies::delete),
        },
    ]
}

/// Route a request, decide access, and run the handler.
///
/// Access is decided *here*, once, for every route — not in the handlers, and not in a
/// middleware a new route could be registered outside of. A handler is only ever called
/// after this function has said yes.
pub async fn dispatch(state: &AppState, request: &ApiRequest) -> ApiResponse {
    match route(state, request).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn route(state: &AppState, request: &ApiRequest) -> Result<ApiResponse> {
    let path = request.path.trim_end_matches('/');
    let path = if path.is_empty() { "/" } else { path };

    let mut path_exists = false;
    for entry in table() {
        let Some(params) = entry.captures(path) else {
            continue;
        };
        path_exists = true;
        if entry.method != request.method {
            continue;
        }
        check_access(entry.access, request)?;
        return (entry.handler)(state, request, &params).await;
    }

    // 405 rather than 404 when the path exists under another method: a client that gets
    // 404 for a `DELETE` on a real resource goes looking for the wrong bug.
    Err(if path_exists {
        ApiError::BadRequest {
            reason: format!("{} is not allowed on {path}", request.method),
        }
    } else {
        ApiError::NotFound {
            kind: "route".to_string(),
            id: path.to_string(),
        }
    })
}

/// The single access decision.
fn check_access(access: Access, request: &ApiRequest) -> Result<()> {
    let Access::Public = access else {
        let caller =
            request.caller.as_ref().ok_or(ApiError::Unauthenticated)?;
        return match access {
            // Unreachable: handled by the `let else` above. Written out rather than
            // `unreachable!()` because a panic in an authorisation path is a denial of
            // service, and the safe answer here is the restrictive one.
            Access::Public => Err(ApiError::Forbidden {
                denial: Denial::Role,
            }),
            Access::Authenticated => Ok(()),
            Access::Needs(capability) => {
                authorize(caller.role, caller.auth_level, capability)
                    .map_err(|denial| ApiError::Forbidden { denial })
            },
        };
    };
    Ok(())
}
