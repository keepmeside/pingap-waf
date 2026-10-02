//! Fetch one feed under the Tier-1 egress guard.
//!
//! Ported from mango-waf `intelligence/feeds.go` at commit 7f2c30c (MIT); see ./NOTICE.
//! Rewritten for a fetch that must refuse where it connects, cap what it reads and
//! count every failure, because the donor's bare `httpClient.Get` shipped none of
//! the three.

use std::time::SystemTime;

use reqwest::StatusCode;
use snafu::Snafu;

use crate::config::{Definition, Limits};
use crate::egress::{EgressError, Guard};
use crate::parse::Parsed;

#[derive(Debug, Snafu)]
pub enum FeedError {
    #[snafu(display("intel feed `{feed}` returned HTTP {status}"))]
    Status { feed: String, status: StatusCode },
    #[snafu(display("intel feed `{feed}` could not be fetched: {source}"))]
    Request {
        feed: String,
        source: reqwest::Error,
    },
    #[snafu(display("intel feed `{feed}` exceeded the {limit}-byte body cap"))]
    BodyTooLarge { feed: String, limit: usize },
    #[snafu(display("intel feed `{feed}` egress was refused: {source}"))]
    Egress { feed: String, source: EgressError },
    #[snafu(display("intel feed `{feed}` body was not UTF-8: {source}"))]
    Utf8 {
        feed: String,
        source: std::str::Utf8Error,
    },
}

#[derive(Debug)]
pub struct FeedResult {
    pub name: String,
    pub parsed: Parsed,
    pub fetched_at: SystemTime,
}

/// Fetch and parse one configured feed. The URL is checked before the request because
/// reqwest never calls a resolver for an IP literal.
///
/// Returns the outcome beside the guard's opt-out count, so the caller can record
/// how many reserved-address decisions the `allow_private_targets` opt-out permitted.
/// The count rides on both arms: a fetch that reached a private mirror and then
/// failed still made the permitted decision, and the audit signal is the connection,
/// not the parse.
pub async fn fetch(
    definition: &Definition,
    limits: Limits,
    fetched_at: SystemTime,
) -> (Result<FeedResult, FeedError>, u64) {
    let guard =
        Guard::new(definition.allow_private_targets, limits.redirect_hops);
    let outcome = fetch_under(&guard, definition, limits, fetched_at).await;
    (outcome, guard.opt_outs())
}

async fn fetch_under(
    guard: &Guard,
    definition: &Definition,
    limits: Limits,
    fetched_at: SystemTime,
) -> Result<FeedResult, FeedError> {
    guard
        .check_url(&definition.url)
        .map_err(|source| FeedError::Egress {
            feed: definition.name.clone(),
            source,
        })?;
    let client =
        guard
            .client(limits.timeout)
            .map_err(|source| FeedError::Egress {
                feed: definition.name.clone(),
                source,
            })?;
    let response =
        client
            .get(definition.url.clone())
            .send()
            .await
            .map_err(|source| FeedError::Request {
                feed: definition.name.clone(),
                source,
            })?;
    let status = response.status();
    if !status.is_success() {
        return Err(FeedError::Status {
            feed: definition.name.clone(),
            status,
        });
    }
    let mut body = Vec::new();
    let mut response = response;
    while let Some(chunk) =
        response
            .chunk()
            .await
            .map_err(|source| FeedError::Request {
                feed: definition.name.clone(),
                source,
            })?
    {
        if body.len().saturating_add(chunk.len()) > limits.max_body_bytes {
            return Err(FeedError::BodyTooLarge {
                feed: definition.name.clone(),
                limit: limits.max_body_bytes,
            });
        }
        body.extend_from_slice(&chunk);
    }
    let text =
        std::str::from_utf8(&body).map_err(|source| FeedError::Utf8 {
            feed: definition.name.clone(),
            source,
        })?;
    Ok(FeedResult {
        name: definition.name.clone(),
        parsed: Parsed::parse(text, limits.max_entries),
        fetched_at,
    })
}
