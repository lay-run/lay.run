use crate::display::Display;
use reqwest::StatusCode;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CliError {
    #[error("API request failed: {status} - {message}")]
    ApiError { status: StatusCode, message: String },

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

impl CliError {
    pub fn display(&self) {
        match self {
            CliError::ApiError { status, message } => {
                let msg = match status.as_u16() {
                    400 => {
                        if message.contains("email already exists") || message.contains("Email already exists") {
                            "email already registered"
                        } else if message.contains("invalid credentials") || message.contains("Invalid credentials") {
                            "invalid email or password"
                        } else if message.contains("invalid verification code") || message.contains("Invalid verification code") {
                            "invalid or expired verification code"
                        } else if message.contains("passwords do not match") || message.contains("Passwords do not match") {
                            "passwords do not match"
                        } else if message.contains("invalid email format") {
                            "invalid email format"
                        } else {
                            &message.to_lowercase()
                        }
                    }
                    401 => "authentication failed",
                    404 => "not found",
                    429 => {
                        if message.contains("too many") || message.contains("Too many") {
                            "too many attempts, try again later"
                        } else {
                            &message.to_lowercase()
                        }
                    }
                    500..=599 => "server error, try again later",
                    _ => &message.to_lowercase(),
                };
                eprintln!("{}", Display::error(msg));
            }
            CliError::ConfigError(msg) => eprintln!("{}", Display::error(&msg.to_lowercase())),
            CliError::IoError(e) => {
                let msg = if e.kind() == std::io::ErrorKind::NotFound {
                    "not logged in".to_string()
                } else {
                    format!("{}", e).to_lowercase()
                };
                eprintln!("{}", Display::error(&msg));
            }
            CliError::HttpError(e) => {
                let msg = if e.is_timeout() {
                    "request timed out".to_string()
                } else if e.is_connect() {
                    "cannot connect to server".to_string()
                } else {
                    format!("{}", e).to_lowercase()
                };
                eprintln!("{}", Display::error(&msg));
            }
            CliError::JsonError(_) => eprintln!("{}", Display::error("invalid response from server")),
        }
    }
}

pub type Result<T> = std::result::Result<T, CliError>;
