use crate::alerts::DispatchSender;
use async_trait::async_trait;
use pingap_core::{Notification, NotificationData};
use serde::Deserialize;
use std::time::Duration;

#[async_trait]
pub trait TelegramTransport: Send + Sync {
    async fn send(&self, chat_id: &str, text: &str) -> Result<(), String>;
}

/// Result-bearing Telegram Bot API transport. The token is retained only in this private
/// value and is never included in errors or serialized output.
pub struct TelegramApiTransport {
    client: reqwest::Client,
    token: String,
}

impl TelegramApiTransport {
    pub fn new(token: String) -> Result<Self, String> {
        if token.is_empty()
            || token.len() > 256
            || token.chars().any(char::is_whitespace)
        {
            return Err("telegram token is malformed".into());
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| "telegram client unavailable".to_string())?;
        Ok(Self { client, token })
    }
}

#[derive(Deserialize)]
struct TelegramResponse {
    ok: bool,
}

impl TelegramApiTransport {
    pub async fn send_result(
        &self,
        chat_id: &str,
        text: &str,
    ) -> Result<(), String> {
        let url =
            format!("https://api.telegram.org/bot{}/sendMessage", self.token);
        let response = self
            .client
            .post(url)
            .json(&serde_json::json!({
                "chat_id": chat_id,
                "text": text,
                "disable_web_page_preview": true
            }))
            .send()
            .await
            .map_err(|_| "telegram:transport".to_string())?;
        if !response.status().is_success() {
            return Err(format!(
                "telegram:http_{}",
                response.status().as_u16()
            ));
        }
        let body = response
            .json::<TelegramResponse>()
            .await
            .map_err(|_| "telegram:invalid_response".to_string())?;
        if !body.ok {
            return Err("telegram:api_rejected".to_string());
        }
        Ok(())
    }
}

#[async_trait]
impl TelegramTransport for TelegramApiTransport {
    async fn send(&self, chat_id: &str, text: &str) -> Result<(), String> {
        self.send_result(chat_id, text).await
    }
}

pub struct TelegramDispatchSender {
    transport: TelegramApiTransport,
    chat_id: String,
}

impl TelegramDispatchSender {
    pub fn new(token: String, chat_id: String) -> Result<Self, String> {
        Ok(Self {
            transport: TelegramApiTransport::new(token)?,
            chat_id,
        })
    }
}

impl DispatchSender for TelegramDispatchSender {
    fn send<'a>(
        &'a self,
        data: &'a NotificationData,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.transport
                .send_result(
                    &self.chat_id,
                    &format!("{}\n{}", data.title, data.message),
                )
                .await
        })
    }
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

#[cfg(test)]
mod tests {
    use super::TelegramApiTransport;

    #[test]
    fn token_validation_does_not_accept_whitespace() {
        assert!(TelegramApiTransport::new("bad token".into()).is_err());
        assert!(TelegramApiTransport::new("token".into()).is_ok());
    }
}
