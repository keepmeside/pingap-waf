//! Read runtime state and release exactly one decision; no desired-config write.
use crate::{ApiError, ApiRequest, ApiResponse, AppState, Result};
use pingap_controlplane::events::{NativeAbuse, NativeActor};
use serde::Deserialize;
fn runtime(state: &AppState) -> Result<&dyn NativeAbuse> {
    state
        .native_abuse
        .as_deref()
        .ok_or_else(|| ApiError::Unavailable {
            reason: "native abuse runtime is not connected".into(),
        })
}
fn bad(reason: &str) -> ApiError {
    ApiError::BadRequest {
        reason: reason.into(),
    }
}
pub async fn list(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let runtime = runtime(state)?;
    let after = match request.param("cursor") {
        None => 0,
        Some(cursor) => {
            let (epoch, sequence) = cursor
                .rsplit_once(':')
                .ok_or_else(|| bad("invalid ban cursor"))?;
            if epoch != runtime.epoch() {
                return Err(bad(
                    "ban cursor belongs to a previous runtime; refresh the first page",
                ));
            }
            sequence
                .parse::<u64>()
                .map_err(|_| bad("invalid ban cursor"))?
        },
    };
    let profile = request.param("profile");
    let domain = request.param("domain");
    ApiResponse::json(&runtime.list(
        profile.as_deref(),
        domain.as_deref(),
        after,
        100,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    profile: String,
    domain: String,
    client_ip: String,
}
pub async fn release(
    state: &AppState,
    request: &ApiRequest,
    params: &[String],
) -> Result<ApiResponse> {
    let id = super::name(params)?;
    if !id.contains('-')
        || id.split('-').any(|part| {
            part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return Err(bad("invalid ban decision id"));
    }
    let owner: Owner = request.json()?;
    if owner.profile.trim().is_empty() || owner.domain.trim().is_empty() {
        return Err(bad("profile and domain are required"));
    }
    let ip = owner
        .client_ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| bad("client_ip must be an IP address"))?
        .to_string();
    let caller = super::caller(request)?;
    let result = runtime(state)?.release(
        &owner.profile,
        &owner.domain,
        &ip,
        id,
        NativeActor {
            id: Some(caller.user_id.clone()),
            username: caller.username.clone(),
        },
    );
    ApiResponse::json(&result)
}
