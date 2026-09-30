use crate::{ApiRequest, ApiResponse, AppState, Result};
use pingap_controlplane::alerts::Comparison;
use pingap_controlplane::alerts::channels::telegram::TelegramDispatchSender;
use pingap_controlplane::alerts::{Dispatch, DispatchSender};
use pingap_controlplane::repository::NotificationChannel;
use pingap_controlplane::repository::{
    NewAlertRule, NewNotificationChannel, TimeRange,
};
use pingap_core::{NotificationData, NotificationLevel};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

static TEST_SENDS: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
fn test_send_allowed(id: &str) -> bool {
    let clock = TEST_SENDS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut entries = clock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if entries
        .get(id)
        .is_some_and(|at| at.elapsed() < Duration::from_secs(60))
    {
        return false;
    }
    entries.insert(id.to_string(), Instant::now());
    true
}

fn sender(channel: &NotificationChannel) -> Box<dyn DispatchSender> {
    if channel.kind == "telegram"
        && let Ok(config) =
            serde_json::from_str::<serde_json::Value>(&channel.config)
        && let (Some(token), Some(chat_id)) = (
            config.get("token").and_then(|v| v.as_str()),
            config.get("chat_id").and_then(|v| v.as_str()),
        )
        && let Ok(sender) =
            TelegramDispatchSender::new(token.to_string(), chat_id.to_string())
    {
        return Box::new(sender);
    }
    Box::new(pingap_controlplane::alerts::dispatch::UnavailableSender {
        reason: "unavailable:test-send transport".into(),
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewChannel {
    name: String,
    kind: String,
    config: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewRule {
    name: String,
    metric: String,
    comparator: Comparison,
    threshold: f64,
    window_secs: i64,
    severity: String,
    enabled: bool,
    channel_ids: Vec<String>,
}

fn range(request: &ApiRequest) -> TimeRange {
    let parse = |name| request.param(name).and_then(|v| v.parse::<i64>().ok());
    TimeRange {
        since: parse("since"),
        until: parse("until"),
        limit: parse("limit").and_then(|v| u32::try_from(v).ok()),
    }
}

fn public_channel(channel: NotificationChannel) -> serde_json::Value {
    json!({"id": channel.id, "name": channel.name, "kind": channel.kind,
        "config": "[redacted]", "enabled": channel.enabled, "created_at": channel.created_at})
}

pub async fn list_channels(
    state: &AppState,
    _request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let channels = state.store.list_notification_channels().await?;
    ApiResponse::json(
        &channels.into_iter().map(public_channel).collect::<Vec<_>>(),
    )
}

pub async fn create_channel(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let input: NewChannel = request.json()?;
    let channel = state
        .store
        .create_notification_channel(
            NewNotificationChannel {
                name: input.name,
                kind: input.kind,
                config: input.config,
                enabled: input.enabled,
            },
            super::now_sec(),
        )
        .await?;
    ApiResponse::json(&public_channel(channel))
}

pub async fn list_rules(
    state: &AppState,
    _request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    ApiResponse::json(&state.store.list_alert_rules().await?)
}

pub async fn create_rule(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let input: NewRule = request.json()?;
    let rule = state
        .store
        .create_alert_rule(
            NewAlertRule {
                name: input.name,
                metric: input.metric,
                comparator: input.comparator,
                threshold: input.threshold,
                window_secs: input.window_secs,
                severity: input.severity,
                enabled: input.enabled,
                channel_ids: input.channel_ids,
            },
            super::now_sec(),
        )
        .await?;
    ApiResponse::json(&rule)
}

pub async fn history(
    state: &AppState,
    request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    ApiResponse::json(&state.store.read_alert_history(range(request)).await?)
}

pub async fn test_send(
    state: &AppState,
    _request: &ApiRequest,
    params: &[String],
) -> Result<ApiResponse> {
    let id = params.first().ok_or_else(|| crate::ApiError::BadRequest {
        reason: "channel id is required".into(),
    })?;
    let channel = state
        .store
        .list_notification_channels()
        .await?
        .into_iter()
        .find(|channel| channel.id == *id)
        .ok_or_else(|| crate::ApiError::NotFound {
            kind: "notification channel".into(),
            id: id.clone(),
        })?;
    if !test_send_allowed(id) {
        return Err(crate::ApiError::Conflict {
            reason: "test-send is rate limited".into(),
        });
    }
    let data = NotificationData {
        category: "alert_test".into(),
        level: NotificationLevel::Info,
        title: "Pingap alert test".into(),
        message: "This is a delivery test. No request or stored credential is included.".into(),
    };
    let result = Dispatch::new(1, Duration::ZERO)
        .send(&[(channel.id.clone(), sender(&channel))], data)
        .await;
    let Some(delivery) = result.deliveries.into_iter().next() else {
        return Err(crate::ApiError::Unavailable {
            reason: "test-send produced no delivery result".into(),
        });
    };
    match delivery.outcome {
        pingap_controlplane::alerts::AttemptOutcome::Delivered => {
            ApiResponse::json(&json!({"delivered": true}))
        },
        pingap_controlplane::alerts::AttemptOutcome::Failed { error_class } => {
            Err(crate::ApiError::Unavailable {
                reason: error_class,
            })
        },
    }
}
