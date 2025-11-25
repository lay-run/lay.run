use crate::cli::OutputFormat;
use crate::client::ApiClient;
use crate::config::{save_token, clear_token};
use crate::error::{CliError, Result};
use crate::types::{AuthResponse, CodeSentResponse, LoginRequest, RegisterRequest, ResendCodeRequest, VerifyRequest, VerifyLoginRequest};
use colored::Colorize;

pub async fn register(
    client: &ApiClient,
    email: String,
    password: Option<String>,
    output: OutputFormat,
) -> Result<()> {
    // Validate email format early
    if !is_valid_email(&email) {
        return Err(CliError::ConfigError("invalid email format".to_string()));
    }

    let password = match password {
        Some(p) => p,
        None => {
            let pass = rpassword::prompt_password(&format!("{}", "password: ".magenta()))?;
            let confirm = rpassword::prompt_password(&format!("{}", "confirm: ".magenta()))?;

            if pass != confirm {
                return Err(CliError::ConfigError("passwords do not match".to_string()));
            }

            pass
        }
    };

    let result: CodeSentResponse = client
        .post("/api/auth/register", &RegisterRequest { email: email.clone(), password })
        .await?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{} {}", "→".cyan().bold(), result.message.cyan());
        }
    }

    // Prompt for verification code
    let code = rpassword::prompt_password(&format!("{}", "enter code: ".magenta()))?;

    // Verify email
    verify(client, email, code, output).await
}

pub async fn login(
    client: &ApiClient,
    email: String,
    password: Option<String>,
    output: OutputFormat,
) -> Result<()> {
    // Validate email format early
    if !is_valid_email(&email) {
        return Err(CliError::ConfigError("invalid email format".to_string()));
    }

    let password = match password {
        Some(p) => p,
        None => rpassword::prompt_password(&format!("{}", "password: ".magenta()))?
    };

    let result: CodeSentResponse = client
        .post("/api/auth/login", &LoginRequest { email: email.clone(), password })
        .await?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{} {}", "→".cyan().bold(), result.message.cyan());
        }
    }

    // Prompt for verification code
    let code = rpassword::prompt_password(&format!("{}", "enter code: ".magenta()))?;

    // Verify login
    verify_login(client, email, code, output).await
}

pub async fn verify(
    client: &ApiClient,
    email: String,
    code: String,
    output: OutputFormat,
) -> Result<()> {
    let result: AuthResponse = client
        .post("/api/auth/verify", &VerifyRequest { email, code })
        .await?;

    save_token(&result.token)?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{} {}", "✓".green().bold(), "email verified".green());
        }
    }

    Ok(())
}

pub async fn resend_code(client: &ApiClient, email: String, output: OutputFormat) -> Result<()> {
    let result: CodeSentResponse = client
        .post("/api/auth/resend-code", &ResendCodeRequest { email })
        .await?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{} {}", "→".cyan().bold(), result.message.cyan());
        }
    }

    Ok(())
}

async fn verify_login(
    client: &ApiClient,
    email: String,
    code: String,
    output: OutputFormat,
) -> Result<()> {
    let result: AuthResponse = client
        .post("/api/auth/login/verify", &VerifyLoginRequest { email, code })
        .await?;

    save_token(&result.token)?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{} {}", "✓".green().bold(), "logged in".green());
        }
    }

    Ok(())
}

pub async fn logout(output: OutputFormat) -> Result<()> {
    clear_token()?;

    match output {
        OutputFormat::Json => println!("{{\"message\": \"logged out\"}}"),
        OutputFormat::JsonPretty => {
            println!("{}", serde_json::json!({"message": "logged out"}))
        }
        OutputFormat::Text => {
            println!("{} {}", "✓".cyan().bold(), "logged out".cyan());
        }
    }

    Ok(())
}

fn is_valid_email(email: &str) -> bool {
    // Simple email validation: must contain @ and a dot after @
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let domain = parts[1];
    domain.contains('.') && !email.starts_with('@') && !email.ends_with('@')
}

