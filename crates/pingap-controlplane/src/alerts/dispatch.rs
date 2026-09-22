use std::future::Future;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptOutcome {
    Delivered,
    Failed { error_class: String },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub channel_id: String,
    pub outcome: AttemptOutcome,
    pub attempt: u8,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DispatchResult {
    pub deliveries: Vec<Delivery>,
}

/// The dispatch boundary is injectable: production adapters can wrap `Notification`, while tests
/// can deterministically return failures without making external requests.
pub trait DispatchSender: Send + Sync {
    fn send<'a>(
        &'a self,
        data: &'a pingap_core::NotificationData,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}
impl<T: pingap_core::Notification + Send + Sync> DispatchSender for T {
    fn send<'a>(
        &'a self,
        data: &'a pingap_core::NotificationData,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>
    {
        Box::pin(async move {
            self.notify(pingap_core::NotificationData {
                category: data.category.clone(),
                level: match data.level {
                    pingap_core::NotificationLevel::Error => {
                        pingap_core::NotificationLevel::Error
                    },
                    pingap_core::NotificationLevel::Warn => {
                        pingap_core::NotificationLevel::Warn
                    },
                    pingap_core::NotificationLevel::Info => {
                        pingap_core::NotificationLevel::Info
                    },
                },
                title: data.title.clone(),
                message: data.message.clone(),
            })
            .await;
            Ok(())
        })
    }
}
pub struct Dispatch {
    max_attempts: u8,
    base_backoff: Duration,
}
impl Dispatch {
    pub fn new(max_attempts: u8, base_backoff: Duration) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            base_backoff,
        }
    }
    pub async fn send(
        &self,
        channels: &[(String, Box<dyn DispatchSender>)],
        data: pingap_core::NotificationData,
    ) -> DispatchResult {
        let mut out = DispatchResult::default();
        for (id, channel) in channels {
            let mut result = Err("not attempted".to_string());
            for attempt in 1..=self.max_attempts {
                result = channel.send(&data).await;
                if result.is_ok() {
                    out.deliveries.push(Delivery {
                        channel_id: id.clone(),
                        outcome: AttemptOutcome::Delivered,
                        attempt,
                    });
                    break;
                }
                if attempt < self.max_attempts {
                    tokio::time::sleep(
                        self.base_backoff.saturating_mul(u32::from(attempt)),
                    )
                    .await;
                }
            }
            if let Err(error) = result {
                out.deliveries.push(Delivery {
                    channel_id: id.clone(),
                    outcome: AttemptOutcome::Failed {
                        error_class: error_class(&error),
                    },
                    attempt: self.max_attempts,
                });
            }
        }
        out
    }
}
fn error_class(error: &str) -> String {
    error
        .split(':')
        .next()
        .unwrap_or("delivery_error")
        .chars()
        .take(64)
        .collect()
}
