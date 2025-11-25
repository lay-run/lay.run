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
                            eprintln!("{}", "Email already registered".red());
                        } else if message.contains("Invalid credentials") {
                            eprintln!("{}", "Invalid email or password".red());
                        } else if message.contains("Invalid verification code") {
                            eprintln!("{}", "Invalid or expired verification code".red());
                        } else {
                            eprintln!("{}", message.red());
                        }
                    }
                    401 => eprintln!("{}", "Authentication failed".red()),
                    404 => eprintln!("{}", "Resource not found".red()),
                    429 => {
                        if message.contains("Too many requests") {
                            eprintln!("{}", "Rate limit exceeded. Please try again later.".red());
                        } else {
                            eprintln!("{}", message.red());
                        }
                    }
                    500..=599 => eprintln!("{}", "Server error. Please try again later.".red()),
                    _ => eprintln!("{}", format!("Error: {}", message).red()),
                }
            }
            CliError::ConfigError(msg) => eprintln!("{}", msg.red()),
            CliError::IoError(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    eprintln!("{}", "Not logged in. Please login or register first.".red());
                } else {
                    eprintln!("{}", format!("IO error: {}", e).red());
                }
            }
            CliError::HttpError(e) => {
                if e.is_timeout() {
                    eprintln!("{}", "Request timed out. Please check your connection.".red());
                } else if e.is_connect() {
                    eprintln!("{}", "Cannot connect to server. Is it running?".red());
                } else {
                    eprintln!("{}", format!("Network error: {}", e).red());
                }
            }
            CliError::JsonError(e) => eprintln!("{}", format!("Invalid response format: {}", e).red()),
        }
    }
}

pub type Result<T> = std::result::Result<T, CliError>;
