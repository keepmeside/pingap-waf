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

//! What a handler can refuse with, and what the caller is told.
//!
//! Every variant maps to exactly one status, because the UI acts on the status: 401 sends
//! the operator to the login page, 403 does not, and 503 means "the store is down, this is
//! not your fault". Collapsing any two of those into a generic error turns a recoverable
//! state into a dead end.
//!
//! The bodies are deliberately thin. `reason` is written by this codebase, never
//! interpolated from a config file, a parser, or a filesystem path — an admin API that
//! echoes internals is how a 403 leaks the thing it was protecting.

use crate::ApiResponse;
use bytes::Bytes;
use http::StatusCode;
use pingap_controlplane::rbac::Denial;
use serde::Serialize;

#[derive(Debug, snafu::Snafu)]
pub enum ApiError {
    #[snafu(display("{reason}"))]
    BadRequest { reason: String },

    /// No session, or one the store no longer recognises.
    #[snafu(display("unauthenticated"))]
    Unauthenticated,

    /// The role does not have the capability, or the capability mutates and the session
    /// has not completed its second factor. Carried as the `Denial` rather than a string
    /// so the two cannot be conflated: one is final, the other is a challenge.
    #[snafu(display("forbidden"))]
    Forbidden { denial: Denial },

    #[snafu(display("{kind} `{id}` does not exist"))]
    NotFound { kind: String, id: String },

    #[snafu(display("{reason}"))]
    Conflict { reason: String },

    /// The control-plane store cannot be reached. A *state*, not a crash.
    #[snafu(display("control-plane store unavailable: {reason}"))]
    Unavailable { reason: String },

    #[snafu(display("{reason}"))]
    Internal { reason: String },
}

pub type Result<T> = std::result::Result<T, ApiError>;

/// The wire shape of a refusal. One field, always present, so a client never has to guess
/// whether an error body is JSON.
#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    /// Set only for a second-factor denial, because that is the one refusal the UI can
    /// act on without an operator changing anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<&'static str>,
}

impl ApiError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden { .. } => StatusCode::FORBIDDEN,
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::Unavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn into_response(self) -> ApiResponse {
        let status = self.status();
        let action = match &self {
            Self::Forbidden {
                denial: Denial::SecondFactorRequired,
            } => Some("complete_second_factor"),
            _ => None,
        };
        let message = self.to_string();
        let body = ErrorBody {
            error: &message,
            action,
        };
        // A serialisation failure here would replace the real refusal with a 500, so the
        // fallback keeps the status and gives up only on the shape.
        let body = serde_json::to_vec(&body)
            .unwrap_or_else(|_| b"{\"error\":\"unknown\"}".to_vec());
        ApiResponse {
            status,
            body: Bytes::from(body),
            content_type: Some("application/json; charset=utf-8"),
        }
    }
}

impl From<pingap_controlplane::repository::StoreError> for ApiError {
    /// The store's own vocabulary, mapped once.
    ///
    /// Per-handler mapping is how a `Conflict` ends up as a 500 in one route and a 409 in
    /// another, and the UI then cannot tell "that username is taken" from "the database
    /// broke".
    fn from(source: pingap_controlplane::repository::StoreError) -> Self {
        use pingap_controlplane::repository::StoreError;
        match source {
            StoreError::NotFound { kind, id } => Self::NotFound { kind, id },
            StoreError::Conflict { kind, value } => Self::Conflict {
                reason: format!("{kind} `{value}` already exists"),
            },
            other => Self::Unavailable {
                reason: other.to_string(),
            },
        }
    }
}
