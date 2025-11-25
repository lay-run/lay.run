use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Verification code types
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum VerificationCodeType {
    #[serde(rename = "email_verification")]
    EmailVerification,
    #[serde(rename = "password_reset")]
    PasswordReset,
    #[serde(rename = "login")]
    Login,
}

impl VerificationCodeType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::EmailVerification => "email_verification",
            Self::PasswordReset => "password_reset",
            Self::Login => "login",
        }
    }
}

/// Verification code model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct VerificationCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code: String,
    pub code_type: String,
    pub expires_at: DateTime<Utc>,
    pub attempts: i32,
    pub is_used: bool,
    pub created_at: DateTime<Utc>,
}

impl VerificationCode {
    /// Check if the code is valid (not expired, not used, attempts under limit)
    pub fn is_valid(&self) -> bool {
        !self.is_used && self.expires_at > Utc::now() && self.attempts < 5
    }
}
