use crate::cli::OutputFormat;
use crate::client::ApiClient;
use crate::config::{save_token, clear_token};
use crate::error::{CliError, Result};
use crate::types::{AuthResponse, CodeSentResponse, LoginRequest, RegisterRequest, ResendCodeRequest, VerifyRequest, VerifyLoginRequest};
use crate::ui::Ui;

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
            let pass = rpassword::prompt_password(&Ui::prompt("password: "))?;
            let confirm = rpassword::prompt_password(&Ui::prompt("confirm: "))?;

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
            println!("{}", Ui::info(&result.message));
        }
    }

    // Prompt for verification code
    let code = rpassword::prompt_password(&Ui::prompt("enter code: "))?;

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
        None => rpassword::prompt_password(&Ui::prompt("password: "))?
    };

    let result: CodeSentResponse = client
        .post("/api/auth/login", &LoginRequest { email: email.clone(), password })
        .await?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{}", Ui::info(&result.message));
        }
    }

    // Prompt for verification code
    let code = rpassword::prompt_password(&Ui::prompt("enter code: "))?;

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
            println!("{}", Ui::success("email verified"));
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
            println!("{}", Ui::info(&result.message));
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
            println!("{}", Ui::success("logged in"));
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
            println!("{}", Ui::success("logged out"));
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

