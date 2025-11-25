use crate::cli::OutputFormat;
use crate::client::ApiClient;
use crate::config::{save_token, clear_token};
use crate::error::Result;
use crate::types::{AuthResponse, CodeSentResponse, LoginRequest, RegisterRequest, ResendCodeRequest, VerifyRequest};
use colored::Colorize;

pub async fn register(
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
        .post("/api/auth/register", &RegisterRequest { email, password })
        .await?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{} {}", "✓".green().bold(), result.message.green());
        }
    }

    Ok(())
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
            println!("{} {}", "✓".green().bold(), result.message.green());
            println!("{}", "Please check your email for the login verification code.".yellow());
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
            println!("{} {}", "✓".green().bold(), "Email verified successfully!".green());
            println!("User ID: {}", result.user.id);
            println!("Email: {}", result.user.email);
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
            println!("{} {}", "✓".green().bold(), result.message.green());
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
            println!("{} {}", "✓".green().bold(), "Logged out successfully".green());
        }
    }

    Ok(())
}

