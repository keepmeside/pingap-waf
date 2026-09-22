use crate::alerts::DispatchSender;
use async_trait::async_trait;
use lettre::message::{Mailbox, Message, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use pingap_core::{Notification, NotificationData};
use std::time::Duration;

pub struct SmtpEmailTransport {
    transport: AsyncSmtpTransport<Tokio1Executor>,
}
impl SmtpEmailTransport {
    pub fn new(
        host: &str,
        port: u16,
        user: Option<&str>,
        password: Option<&str>,
    ) -> Result<Self, String> {
        if host.is_empty() || host.chars().any(char::is_whitespace) {
            return Err("smtp:invalid_host".into());
        }
        let builder =
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
                .map_err(|_| "smtp:invalid_host".to_string())?
                .port(port)
                .timeout(Some(Duration::from_secs(10)));
        let transport = match (user, password) {
            (Some(u), Some(p)) if !u.is_empty() => builder
                .credentials(Credentials::new(u.to_owned(), p.to_owned()))
                .build(),
            (None, None) => builder.build(),
            _ => return Err("smtp:incomplete_credentials".into()),
        };
        Ok(Self { transport })
    }
    pub async fn send_result(
        &self,
        from: &str,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<(), String> {
        let message = Message::builder()
            .from(from.parse::<Mailbox>().map_err(|_| "smtp:invalid_from")?)
            .to(to.parse::<Mailbox>().map_err(|_| "smtp:invalid_to")?)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body.to_owned())
            .map_err(|_| "smtp:invalid_message".to_string())?;
        self.transport
            .send(message)
            .await
            .map(|_| ())
            .map_err(|_| "smtp:transport".into())
    }
}

pub struct EmailDispatchSender {
    transport: SmtpEmailTransport,
    from: String,
    to: String,
}
impl EmailDispatchSender {
    pub fn new(
        host: String,
        port: u16,
        user: Option<String>,
        password: Option<String>,
        from: String,
        to: String,
    ) -> Result<Self, String> {
        Ok(Self {
            transport: SmtpEmailTransport::new(
                &host,
                port,
                user.as_deref(),
                password.as_deref(),
            )?,
            from,
            to,
        })
    }
}
impl DispatchSender for EmailDispatchSender {
    fn send<'a>(
        &'a self,
        data: &'a NotificationData,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.transport
                .send_result(
                    &self.from,
                    &self.to,
                    &data.title,
                    &format!("[{}] {}", data.category, data.message),
                )
                .await
        })
    }
}

pub struct EmailNotification<T> {
    pub transport: T,
    pub from: String,
    pub to: String,
}
#[async_trait]
impl<T: Send + Sync + 'static> Notification for EmailNotification<T> {
    async fn notify(&self, _data: NotificationData) {}
}

#[cfg(test)]
mod tests {
    use super::SmtpEmailTransport;
    #[test]
    fn rejects_bad_smtp_config() {
        assert!(SmtpEmailTransport::new("bad host", 587, None, None).is_err());
    }
}
