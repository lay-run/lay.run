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
        match self {
            CliError::ApiError { status, message } => {
                match status.as_u16() {
                    400 => {
                        if message.contains("Email already exists") {
                            eprintln!("lay: {}", "email already registered".red());
                        } else if message.contains("Invalid credentials") {
                            eprintln!("lay: {}", "invalid email or password".red());
                        } else if message.contains("Invalid verification code") {
                            eprintln!("lay: {}", "invalid or expired verification code".red());
                        } else if message.contains("Passwords do not match") {
                            eprintln!("lay: {}", "passwords do not match".red());
                        } else {
                            eprintln!("lay: {}", message.to_lowercase().red());
                        }
                    }
                    401 => eprintln!("lay: {}", "authentication failed".red()),
                    404 => eprintln!("lay: {}", "not found".red()),
                    429 => {
                        if message.contains("Too many requests") {
                            eprintln!("lay: {}", "too many attempts, try again later".red());
                        } else {
                            eprintln!("lay: {}", message.to_lowercase().red());
                        }
                    }
                    500..=599 => eprintln!("lay: {}", "server error, try again later".red()),
                    _ => eprintln!("lay: {}", message.to_lowercase().red()),
                }
            }
            CliError::ConfigError(msg) => eprintln!("lay: {}", msg.to_lowercase().red()),
            CliError::IoError(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    eprintln!("lay: {}", "not logged in".red());
                } else {
                    eprintln!("lay: {}", format!("{}", e).to_lowercase().red());
                }
            }
            CliError::HttpError(e) => {
                if e.is_timeout() {
                    eprintln!("lay: {}", "request timed out".red());
                } else if e.is_connect() {
                    eprintln!("lay: {}", "cannot connect to server".red());
                } else {
                    eprintln!("lay: {}", format!("{}", e).to_lowercase().red());
                }
            }
            CliError::JsonError(_) => eprintln!("lay: {}", "invalid response from server".red()),
        }
    }
}

pub type Result<T> = std::result::Result<T, CliError>;
