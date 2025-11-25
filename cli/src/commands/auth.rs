use crate::cli::OutputFormat;
use crate::client::ApiClient;
use crate::config::{save_token, clear_token};
use crate::error::{CliError, Result};
use crate::types::{AuthResponse, CodeSentResponse, LoginRequest, RegisterRequest, ResendCodeRequest, VerifyRequest};

pub async fn register(
    client: &ApiClient,
    email: String,
    password: Option<String>,
    output: OutputFormat,
) -> Result<()> {
    let password = match password {
        Some(p) => p,
        None => {
            let pass = rpassword::prompt_password("Password: ")?;
            let confirm = rpassword::prompt_password("Confirm password: ")?;

            if pass != confirm {
                return Err(CliError::ConfigError("Passwords do not match".to_string()));
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
            println!("{}", result.message);
        }
    }

    // Prompt for verification code
    let code = rpassword::prompt_password("Verification code: ")?;

    // Verify email
    verify(client, email, code, output).await
}

pub async fn login(
    client: &ApiClient,
    email: String,
    password: Option<String>,
    output: OutputFormat,
) -> Result<()> {
    let password = match password {
        Some(p) => p,
        None => rpassword::prompt_password("Password: ")?
    };

    let result: CodeSentResponse = client
        .post("/api/auth/login", &LoginRequest { email, password })
        .await?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{}", result.message);
        }
    }

    Ok(())
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
            println!("Email verified successfully");
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
            println!("{}", result.message);
        }
    }

    Ok(())
}

pub async fn logout(output: OutputFormat) -> Result<()> {
    clear_token()?;

    match output {
        OutputFormat::Json => println!("{{\"message\": \"Logged out successfully\"}}"),
        OutputFormat::JsonPretty => {
            println!("{}", serde_json::json!({"message": "Logged out successfully"}))
        }
        OutputFormat::Text => {
            println!("Logged out successfully");
        }
    }

    Ok(())
}

