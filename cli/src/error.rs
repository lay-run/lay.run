use colored::Colorize;
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
        let error_prefix = format!("{}", "✗".red().bold());

        match self {
            CliError::ApiError { status, message } => {
                match status.as_u16() {
                    400 => {
                        if message.contains("email already exists") || message.contains("Email already exists") {
                            eprintln!("{} {}", error_prefix, "email already registered".red());
                        } else if message.contains("invalid credentials") || message.contains("Invalid credentials") {
                            eprintln!("{} {}", error_prefix, "invalid email or password".red());
                        } else if message.contains("invalid verification code") || message.contains("Invalid verification code") {
                            eprintln!("{} {}", error_prefix, "invalid or expired verification code".red());
                        } else if message.contains("passwords do not match") || message.contains("Passwords do not match") {
                            eprintln!("{} {}", error_prefix, "passwords do not match".red());
                        } else if message.contains("invalid email format") {
                            eprintln!("{} {}", error_prefix, "invalid email format".red());
                        } else {
                            eprintln!("{} {}", error_prefix, message.to_lowercase().red());
                        }
                    }
                    401 => eprintln!("{} {}", error_prefix, "authentication failed".red()),
                    404 => eprintln!("{} {}", error_prefix, "not found".red()),
                    429 => {
                        if message.contains("too many") || message.contains("Too many") {
                            eprintln!("{} {}", error_prefix, "too many attempts, try again later".red());
                        } else {
                            eprintln!("{} {}", error_prefix, message.to_lowercase().red());
                        }
                    }
                    500..=599 => eprintln!("{} {}", error_prefix, "server error, try again later".red()),
                    _ => eprintln!("{} {}", error_prefix, message.to_lowercase().red()),
                }
            }
            CliError::ConfigError(msg) => eprintln!("{} {}", error_prefix, msg.to_lowercase().red()),
            CliError::IoError(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    eprintln!("{} {}", error_prefix, "not logged in".red());
                } else {
                    eprintln!("{} {}", error_prefix, format!("{}", e).to_lowercase().red());
                }
            }
            CliError::HttpError(e) => {
                if e.is_timeout() {
                    eprintln!("{} {}", error_prefix, "request timed out".red());
                } else if e.is_connect() {
                    eprintln!("{} {}", error_prefix, "cannot connect to server".red());
                } else {
                    eprintln!("{} {}", error_prefix, format!("{}", e).to_lowercase().red());
                }
            }
            CliError::JsonError(_) => eprintln!("{} {}", error_prefix, "invalid response from server".red()),
        }
    }
}

pub type Result<T> = std::result::Result<T, CliError>;
