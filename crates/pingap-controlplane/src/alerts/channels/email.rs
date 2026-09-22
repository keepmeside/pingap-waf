use async_trait::async_trait;
use pingap_core::{Notification, NotificationData};

/// Injectable email transport. The control plane never logs or serializes `password`.
#[async_trait]
pub trait EmailTransport: Send + Sync {
    async fn send(
        &self,
        from: &str,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<(), String>;
}
pub struct EmailNotification<T> {
    pub transport: T,
    pub from: String,
    pub to: String,
}
#[async_trait]
impl<T: EmailTransport> Notification for EmailNotification<T> {
    async fn notify(&self, data: NotificationData) {
        let _ = self
            .transport
            .send(
                &self.from,
                &self.to,
                &data.title,
                &format!("[{}] {}", data.category, data.message),
            )
            .await;
    }
}
