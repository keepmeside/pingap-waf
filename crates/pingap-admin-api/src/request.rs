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

//! One request and one response, in terms the router can be tested against.
//!
//! Deliberately not pingora's `Session`. The phase's load-bearing test walks every
//! registered route and drives each one as three different roles, and a test that needed a
//! listener and a socket per route would either be skipped or reduced to sampling. So the
//! binary reads the `Session` and hands over these; the router never sees pingora at all.

use bytes::Bytes;
use http::{Method, StatusCode};
use pingap_controlplane::{AuthLevel, Role};

/// Who is calling, once authentication has already happened.
///
/// The binary owns authentication and builds this from its `Principal`. The router's job
/// starts here: it decides *authorisation*, and it cannot be handed a caller whose role or
/// second-factor state is unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub session_id: String,
    pub user_id: String,
    pub username: String,
    pub role: Role,
    pub auth_level: AuthLevel,
}

/// A request as the router sees it.
///
/// `path` is already stripped of the admin plugin's mount prefix and of `/api`, so a route
/// pattern in this crate reads the way it is documented.
#[derive(Debug, Clone)]
pub struct ApiRequest {
    pub method: Method,
    pub path: String,
    /// Raw query string, no leading `?`. Parsed per route rather than eagerly, because
    /// each route's filter shape differs and a shared bag would drift from all of them.
    pub query: String,
    pub body: Bytes,
    /// `None` only for the routes declared public. Every other route is unreachable
    /// without one, which is enforced in `router.rs` rather than trusted per handler.
    pub caller: Option<Caller>,
}

impl ApiRequest {
    /// Deserialise the body, refusing anything the DTO does not name.
    ///
    /// `serde_json` ignores unknown fields by default, which on a config API means a
    /// typo'd key is accepted and silently does nothing — the same class of failure as a
    /// setting that never projects. Every DTO in this crate carries
    /// `#[serde(deny_unknown_fields)]`; this is the call site that makes the refusal
    /// visible to the caller instead of a 500.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> crate::Result<T> {
        serde_json::from_slice(self.body.as_ref()).map_err(|e| {
            crate::ApiError::BadRequest {
                reason: e.to_string(),
            }
        })
    }

    /// One query parameter, percent-decoded.
    pub fn param(&self, name: &str) -> Option<String> {
        self.query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then(|| {
                urlencoding::decode(value)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|_| value.to_string())
            })
        })
    }
}

/// A response, in the same terms.
///
/// The binary converts this into `pingap_core::HttpResponse`. Kept separate so a handler
/// cannot reach for a pingora-flavoured helper and make the router untestable again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiResponse {
    pub status: StatusCode,
    pub body: Bytes,
    /// `None` for an empty body, so a 204 does not claim to be JSON.
    pub content_type: Option<&'static str>,
}

impl ApiResponse {
    pub fn json<T: serde::Serialize>(value: &T) -> crate::Result<Self> {
        let body = serde_json::to_vec(value).map_err(|e| {
            crate::ApiError::Internal {
                reason: format!("response does not serialise: {e}"),
            }
        })?;
        Ok(Self {
            status: StatusCode::OK,
            body: Bytes::from(body),
            content_type: Some("application/json; charset=utf-8"),
        })
    }

    pub fn no_content() -> Self {
        Self {
            status: StatusCode::NO_CONTENT,
            body: Bytes::new(),
            content_type: None,
        }
    }
}
