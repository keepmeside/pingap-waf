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
/// Explicit failure for channels whose transport is unavailable or cannot report a result.
pub struct UnavailableSender {
    pub reason: String,
}

impl DispatchSender for UnavailableSender {
    fn send<'a>(
        &'a self,
        _data: &'a pingap_core::NotificationData,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>
    {
        let reason = self.reason.clone();
        Box::pin(async move { Err(reason) })
    }
}

// Do not blanket-implement this trait for Notification: notify() cannot report delivery errors.
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

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_core::{NotificationData, NotificationLevel};

    struct FakeSender(Result<(), String>);
    impl DispatchSender for FakeSender {
        fn send<'a>(
            &'a self,
            _data: &'a NotificationData,
        ) -> std::pin::Pin<
            Box<dyn Future<Output = Result<(), String>> + Send + 'a>,
        > {
            let result = self.0.clone();
            Box::pin(async move { result })
        }
    }

    #[tokio::test]
    async fn fanout_preserves_sibling_delivery_when_one_channel_fails() {
        let data = NotificationData {
            category: "alert".into(),
            level: NotificationLevel::Warn,
            title: "threshold".into(),
            message: "bounded test".into(),
        };
        let result = Dispatch::new(1, Duration::ZERO)
            .send(
                &[
                    (
                        "broken".into(),
                        Box::new(FakeSender(Err("smtp:down".into())))
                            as Box<dyn DispatchSender>,
                    ),
                    (
                        "healthy".into(),
                        Box::new(FakeSender(Ok(()))) as Box<dyn DispatchSender>,
                    ),
                ],
                data,
            )
            .await;
        assert_eq!(result.deliveries.len(), 2);
        assert!(matches!(
            result.deliveries[0].outcome,
            AttemptOutcome::Failed { .. }
        ));
        assert_eq!(result.deliveries[1].outcome, AttemptOutcome::Delivered);
    }
}
