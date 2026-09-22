use async_trait::async_trait;
use pingap_core::{Notification, NotificationData};

#[async_trait]
pub trait TelegramTransport: Send + Sync {
    async fn send(&self, chat_id: &str, text: &str) -> Result<(), String>;
}
pub struct TelegramNotification<T> {
    pub transport: T,
    pub chat_id: String,
}
#[async_trait]
impl<T: TelegramTransport> Notification for TelegramNotification<T> {
    async fn notify(&self, data: NotificationData) {
        let _ = self
            .transport
            .send(&self.chat_id, &format!("{}\n{}", data.title, data.message))
            .await;
    }
}
