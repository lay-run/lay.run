use crate::cli::{AuthCommands, AuthSubcommand, Cli, OutputFormat};
use crate::error::{CliError, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct RegisterRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct VerifyRequest {
    email: String,
    code: String,
}

#[derive(Serialize)]
struct ResendCodeRequest {
    email: String,
}

#[derive(Deserialize, Serialize)]
struct AuthResponse {
    user: UserResponse,
    token: String,
}

#[derive(Deserialize, Serialize)]
struct UserResponse {
    id: String,
    email: String,
    email_verified: bool,
}

#[derive(Deserialize, Serialize)]
struct CodeSentResponse {
    message: String,
}

pub async fn execute(cmd: AuthCommands, cli: &Cli) -> Result<()> {
    match cmd.command {
        AuthSubcommand::Register { email, password } => {
            register(&cli.api_url, email, password, cli.output).await
        }
        AuthSubcommand::Login { email, password } => {
            login(&cli.api_url, email, password, cli.output).await
        }
        AuthSubcommand::Verify { email, code } => {
            verify(&cli.api_url, email, code, cli.output).await
        }
        AuthSubcommand::ResendCode { email } => {
            resend_code(&cli.api_url, email, cli.output).await
        }
        AuthSubcommand::Logout => logout(cli.output).await,
    }
}

async fn register(
    api_url: &str,
    email: String,
    password: Option<String>,
    output: OutputFormat,
) -> Result<()> {
    let password = match password {
        Some(p) => p,
        None => {
            rpassword::prompt_password("Password: ")
                .map_err(|e| CliError::IoError(e))?
        }
    };

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/api/auth/register", api_url))
        .json(&RegisterRequest { email, password })
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(CliError::ApiError(error_text));
    }

    let result: CodeSentResponse = response.json().await?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{} {}", "✓".green().bold(), result.message.green());
        }
    }

    Ok(())
}

async fn login(
    api_url: &str,
    email: String,
    password: Option<String>,
    output: OutputFormat,
) -> Result<()> {
    let password = match password {
        Some(p) => p,
        None => {
            rpassword::prompt_password("Password: ")
                .map_err(|e| CliError::IoError(e))?
        }
    };

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/api/auth/login", api_url))
        .json(&LoginRequest { email, password })
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(CliError::ApiError(error_text));
    }

    let result: CodeSentResponse = response.json().await?;

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

async fn verify(
    api_url: &str,
    email: String,
    code: String,
    output: OutputFormat,
) -> Result<()> {
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/api/auth/verify", api_url))
        .json(&VerifyRequest { email, code })
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(CliError::ApiError(error_text));
    }

    let result: AuthResponse = response.json().await?;

    // Save token to config file
    save_token(&result.token)?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{} {}", "✓".green().bold(), "Email verified successfully!".green());
            println!("User ID: {}", result.user.id);
            println!("Email: {}", result.user.email);
            println!("{}", "Token saved to config file.".blue());
        }
    }

    Ok(())
}

async fn resend_code(api_url: &str, email: String, output: OutputFormat) -> Result<()> {
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/api/auth/resend-code", api_url))
        .json(&ResendCodeRequest { email })
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(CliError::ApiError(error_text));
    }

    let result: CodeSentResponse = response.json().await?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{} {}", "✓".green().bold(), result.message.green());
        }
    }

    Ok(())
}

async fn logout(output: OutputFormat) -> Result<()> {
    // Remove saved token
    if let Err(e) = std::fs::remove_file(get_config_path()?) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(CliError::IoError(e));
        }
    }

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

fn save_token(token: &str) -> Result<()> {
    let config_path = get_config_path()?;

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&config_path, token)?;

    Ok(())
}

pub fn load_token() -> Result<String> {
    let config_path = get_config_path()?;
    let token = std::fs::read_to_string(&config_path)?;
    Ok(token.trim().to_string())
}

fn get_config_path() -> Result<std::path::PathBuf> {
    let home = std::env::var("HOME")
        .map_err(|_| CliError::ConfigError("HOME environment variable not set".to_string()))?;

    Ok(std::path::PathBuf::from(home).join(".lay").join("token"))
}
