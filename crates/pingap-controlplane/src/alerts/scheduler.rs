use super::channels::email::EmailDispatchSender;
use super::channels::telegram::TelegramDispatchSender;
use serde_json::Value;

fn sender_for_channel(
    channel: &crate::repository::NotificationChannel,
) -> Box<dyn DispatchSender> {
    let config = serde_json::from_str::<Value>(&channel.config).ok();
    match channel.kind.as_str() {
        "telegram" => config
            .and_then(|c| {
                Some(TelegramDispatchSender::new(
                    c.get("token")?.as_str()?.to_owned(),
                    c.get("chat_id")?.as_str()?.to_owned(),
                ))
            })
            .and_then(Result::ok)
            .map(|s| Box::new(s) as Box<dyn DispatchSender>)
            .unwrap_or_else(|| {
                Box::new(super::dispatch::UnavailableSender {
                    reason: "unavailable:invalid telegram configuration".into(),
                })
            }),
        "email" => config
            .and_then(|c| {
                Some(EmailDispatchSender::new(
                    c.get("host")?.as_str()?.to_owned(),
                    u16::try_from(c.get("port")?.as_u64()?).ok()?,
                    c.get("username")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    c.get("password")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    c.get("from")?.as_str()?.to_owned(),
                    c.get("to")?.as_str()?.to_owned(),
                ))
            })
            .and_then(Result::ok)
            .map(|s| Box::new(s) as Box<dyn DispatchSender>)
            .unwrap_or_else(|| {
                Box::new(super::dispatch::UnavailableSender {
                    reason: "unavailable:invalid smtp configuration".into(),
                })
            }),
        _ => Box::new(super::dispatch::UnavailableSender {
            reason: format!(
                "unavailable:{} transport is not configured",
                channel.kind
            ),
        }),
    }
}

use super::{
    AlertRuleRecord, Dispatch, DispatchSender, MetricSample, Suppression,
    SuppressionDecision, evaluate,
};
use crate::repository::{ControlPlaneStore, NewAlertHistory, TimeRange};
use pingap_core::{NotificationData, NotificationLevel};
use std::time::Duration;

pub async fn dispatch_persisted_channels(
    store: &dyn ControlPlaneStore,
    data: NotificationData,
    now: i64,
) -> crate::repository::Result<usize> {
    let channels = store.list_notification_channels().await?;
    let selected = channels
        .iter()
        .filter(|c| c.enabled)
        .map(|channel| (channel.id.clone(), sender_for_channel(channel)))
        .collect::<Vec<_>>();
    let result = Dispatch::new(1, Duration::ZERO).send(&selected, data).await;
    for delivery in &result.deliveries {
        let (delivered, error) = match &delivery.outcome {
            super::AttemptOutcome::Delivered => (true, None),
            super::AttemptOutcome::Failed { error_class } => {
                (false, Some(error_class.clone()))
            },
        };
        store
            .record_alert_history(
                NewAlertHistory {
                    rule_id: None,
                    rule_name: "config drift".into(),
                    severity: "warn".into(),
                    observed: 1.0,
                    threshold: 1.0,
                    delivered,
                    delivery_error: error,
                },
                now,
            )
            .await?;
    }
    Ok(result.deliveries.len())
}

/// Evaluate persisted rules, suppress unchanged states, dispatch, and append one history row
/// per channel outcome. The caller owns the suppression state so it survives scheduler ticks.
pub async fn evaluate_once(
    store: &dyn ControlPlaneStore,
    suppression: &mut Suppression,
    now: i64,
) -> crate::repository::Result<usize> {
    let rules = store.list_alert_rules().await?;
    let channels = store.list_notification_channels().await?;
    let dispatcher = Dispatch::new(1, Duration::ZERO);
    let mut attempts = 0;
    for AlertRuleRecord { rule, .. } in rules {
        let rows = store
            .read_performance_metrics(
                Some(&rule.metric),
                TimeRange {
                    since: Some(now.saturating_sub(rule.window_secs)),
                    until: Some(now),
                    limit: Some(10_000),
                },
            )
            .await?;
        let samples = rows
            .into_iter()
            .map(|row| MetricSample {
                value: row.value,
                bucket_start: row.bucket_start,
            })
            .collect::<Vec<_>>();
        let Some((evaluation, observed)) = evaluate(&rule, &samples, now)
        else {
            continue;
        };
        if suppression.decide(&rule.id, evaluation, now)
            == SuppressionDecision::Suppress
        {
            continue;
        }
        let level = match rule.severity.as_str() {
            "error" => NotificationLevel::Error,
            "warn" => NotificationLevel::Warn,
            _ => NotificationLevel::Info,
        };
        let data = NotificationData {
            category: "alert".into(),
            level,
            title: rule.name.clone(),
            message: format!(
                "{} observed {observed}, threshold {}",
                rule.metric, rule.threshold
            ),
        };
        let selected = channels
            .iter()
            .filter(|channel| {
                channel.enabled
                    && rule.channel_ids.iter().any(|id| id == &channel.id)
            })
            .map(|channel| (channel.id.clone(), sender_for_channel(channel)))
            .collect::<Vec<_>>();
        let result = dispatcher.send(&selected, data).await;
        if result.deliveries.is_empty() {
            store
                .record_alert_history(
                    NewAlertHistory {
                        rule_id: Some(rule.id.clone()),
                        rule_name: rule.name.clone(),
                        severity: rule.severity.clone(),
                        observed,
                        threshold: rule.threshold,
                        delivered: false,
                        delivery_error: Some(
                            "unavailable:no enabled channels".into(),
                        ),
                    },
                    now,
                )
                .await?;
            attempts += 1;
        } else {
            for delivery in result.deliveries {
                let (delivered, error) = match delivery.outcome {
                    super::AttemptOutcome::Delivered => (true, None),
                    super::AttemptOutcome::Failed { error_class } => {
                        (false, Some(error_class))
                    },
                };
                store
                    .record_alert_history(
                        NewAlertHistory {
                            rule_id: Some(rule.id.clone()),
                            rule_name: rule.name.clone(),
                            severity: rule.severity.clone(),
                            observed,
                            threshold: rule.threshold,
                            delivered,
                            delivery_error: error,
                        },
                        now,
                    )
                    .await?;
                attempts += 1;
            }
        }
    }
    Ok(attempts)
}
