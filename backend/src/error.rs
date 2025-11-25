use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Database error")]
    DatabaseError,

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Internal server error: {0}")]
    Internal(#[from] anyhow::Error),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized")]
    Unauthorized,

    // Authentication errors
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("User not found")]
    UserNotFound,

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Invalid email format")]
    InvalidEmail,

    #[error("Password is too weak")]
    WeakPassword,

    #[error("Failed to hash password")]
    PasswordHashFailed,

    #[error("Invalid verification code")]
    InvalidVerificationCode,

    #[error("Verification code expired")]
    ExpiredVerificationCode,

    #[error("Too many attempts")]
    TooManyAttempts,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Failed to generate token")]
    TokenGenerationFailed,

    #[error("Email not verified")]
    EmailNotVerified,

    #[error("Failed to send email")]
    EmailSendFailed,

    // AWS SDK errors
    #[error("AWS SDK error: {0}")]
    AwsSdk(String),
}

// Implement From for AWS SDK errors
impl From<aws_sdk_ses::error::BuildError> for AppError {
    fn from(e: aws_sdk_ses::error::BuildError) -> Self {
        AppError::AwsSdk(e.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::DatabaseError => {
                tracing::error!("Database error");
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
            }
            AppError::Database(ref e) => {
                tracing::error!("Database error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
            }
            AppError::Internal(ref e) => {
                tracing::error!("Internal error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            AppError::NotFound(ref msg) => (StatusCode::NOT_FOUND, msg.as_str()),
            AppError::BadRequest(ref msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            AppError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid credentials"),
            AppError::UserNotFound => (StatusCode::NOT_FOUND, "User not found"),
            AppError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AppError::InvalidEmail => (StatusCode::BAD_REQUEST, "Invalid email format"),
            AppError::WeakPassword => (
                StatusCode::BAD_REQUEST,
                "Password must be at least 8 characters with uppercase, lowercase, and numbers",
            ),
            AppError::PasswordHashFailed => {
                tracing::error!("Password hashing failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            AppError::InvalidVerificationCode => {
                (StatusCode::BAD_REQUEST, "Invalid verification code")
            }
            AppError::ExpiredVerificationCode => {
                (StatusCode::BAD_REQUEST, "Verification code has expired")
            }
            AppError::TooManyAttempts => (StatusCode::TOO_MANY_REQUESTS, "Too many attempts"),
            AppError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid or expired token"),
            AppError::TokenGenerationFailed => {
                tracing::error!("Token generation failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            AppError::EmailNotVerified => (StatusCode::FORBIDDEN, "Email not verified"),
            AppError::EmailSendFailed => {
                tracing::error!("Email send failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to send email")
            }
            AppError::AwsSdk(ref msg) => {
                tracing::error!("AWS SDK error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "AWS service error")
            }
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
