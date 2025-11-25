use aws_sdk_ses::Client as SesClient;
use aws_sdk_ses::types::{Body, Content, Destination, Message};

use crate::error::{AppError, Result};
use crate::routes::auth::LoginMetadata;

/// Email service for sending emails via AWS SES
#[derive(Clone)]
pub struct EmailService {
    client: SesClient,
    from_email: String,
    reply_to_email: String,
}

impl EmailService {
    /// Create a new email service instance
    pub async fn new(from_email: String, reply_to_email: String) -> Result<Self> {
        let config = aws_config::load_from_env().await;
        let client = SesClient::new(&config);

        Ok(Self { client, from_email, reply_to_email })
    }

    /// Send verification code email
    pub async fn send_verification_code(&self, to_email: &str, code: &str) -> Result<()> {
        let subject = format!("lay.run - {} is your verification code", code);
        let body = format!(
            "Your verification code is: {}\n\nThis code will expire in 10 minutes.\n\nIf you didn't request this code, please ignore this email.",
            code
        );

        self.send_email(to_email, &subject, &body).await
    }

    /// Send password reset email
    pub async fn send_password_reset(&self, to_email: &str, code: &str) -> Result<()> {
        let subject = format!("lay.run - {} is your password reset code", code);
        let body = format!(
            "Your password reset code is: {}\n\nThis code will expire in 10 minutes.\n\nIf you didn't request this code, please ignore this email.",
            code
        );

        self.send_email(to_email, &subject, &body).await
    }

    /// Send login verification code
    pub async fn send_login_code(
        &self,
        to_email: &str,
        code: &str,
        metadata: &LoginMetadata,
    ) -> Result<()> {
        let subject = format!("lay.run - {} is your verification code", code);

        // Format timestamp
        let timestamp = metadata.timestamp.format("%B %d, %Y at %H:%M:%S UTC");

        // Format location
        let location = if let Some(loc) = &metadata.location {
            format!("{} (IP: {})", loc, metadata.ip)
        } else {
            format!("IP: {}", metadata.ip)
        };

        let body = format!(
            r#"Your login code is: {}

This code will expire in 10 minutes.

Login Details:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Date & Time:  {}
Device:       {}
Browser:      {}
OS:           {}
Location:     {}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

If you didn't request this code or don't recognize this activity,
please secure your account immediately by enabling Two-Factor
Authentication (2FA).

This is an automated security notification to keep your account safe."#,
            code, timestamp, metadata.device, metadata.browser, metadata.os, location
        );

        self.send_email(to_email, &subject, &body).await
    }

    /// Generic email sending function
    async fn send_email(&self, to_email: &str, subject: &str, body: &str) -> Result<()> {
        let dest = Destination::builder().to_addresses(to_email).build();

        let subject_content = Content::builder().data(subject).charset("UTF-8").build()?;

        let body_content = Content::builder().data(body).charset("UTF-8").build()?;

        let body_obj = Body::builder().text(body_content).build();

        let msg = Message::builder().subject(subject_content).body(body_obj).build();

        self.client
            .send_email()
            .source(&self.from_email)
            .destination(dest)
            .message(msg)
            .reply_to_addresses(&self.reply_to_email)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to send email: {:?}", e);
                AppError::EmailSendFailed
            })?;

        tracing::info!("Email sent successfully to {}", to_email);
        Ok(())
    }
}
