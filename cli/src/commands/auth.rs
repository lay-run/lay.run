use colored::Colorize;

use crate::cli::OutputFormat;
use crate::client::ApiClient;
use crate::config::should_show_totp_reminder;
use crate::display::Display;
use crate::error::{CliError, Result};
use crate::types::{
    AuthResponse, CodeSentResponse, LoginRequest, RegisterRequest, ResendCodeRequest,
    TotpSetupResponse, TotpVerifyRequest, VerifyLoginRequest, VerifyRequest,
};
use crate::{session, token};

pub async fn register(client: &ApiClient, email: String, output: OutputFormat) -> Result<()> {
    // Validate email format early
    if !is_valid_email(&email) {
        return Err(CliError::ConfigError("invalid email format".to_string()));
    }

    let result: CodeSentResponse =
        client.post("/api/auth/register", &RegisterRequest { email: email.clone() }).await?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{}", Display::info(&result.message));
        }
    }

    // Prompt for verification code
    let code = rpassword::prompt_password(Display::prompt("enter code: "))?;

    // Verify email
    verify(client, email, code, output).await
}

pub async fn login(client: &ApiClient, email: Option<String>, output: OutputFormat) -> Result<()> {
    // Get email from argument or last saved email
    let email = match email {
        Some(e) => e,
        None => {
            if let Some(last_email) = session::load_email() {
                if matches!(output, OutputFormat::Text) {
                    println!("{}", Display::info(&format!("using {}", last_email)));
                }
                last_email
            } else {
                return Err(CliError::ConfigError(
                    "no email provided and no previous login found".to_string(),
                ));
            }
        }
    };

    // Validate email format early
    if !is_valid_email(&email) {
        return Err(CliError::ConfigError("invalid email format".to_string()));
    }

    let result: CodeSentResponse =
        client.post("/api/auth/login", &LoginRequest { email: email.clone() }).await?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{}", Display::info(&result.message));
        }
    }

    // Prompt for verification code
    let code = rpassword::prompt_password(Display::prompt("enter code: "))?;

    // Verify login
    verify_login(client, email, code, output).await
}

pub async fn verify(
    client: &ApiClient,
    email: String,
    code: String,
    output: OutputFormat,
) -> Result<()> {
    let result: AuthResponse =
        client.post("/api/auth/verify", &VerifyRequest { email: email.clone(), code }).await?;

    token::save(&result.token)?;
    session::save_email(&email)?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{}", Display::success("email verified"));
        }
    }

    Ok(())
}

pub async fn resend_code(client: &ApiClient, email: String, output: OutputFormat) -> Result<()> {
    let result: CodeSentResponse =
        client.post("/api/auth/resend-code", &ResendCodeRequest { email }).await?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{}", Display::info(&result.message));
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
        .post("/api/auth/login/verify", &VerifyLoginRequest { email: email.clone(), code })
        .await?;

    token::save(&result.token)?;
    session::save_email(&email)?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{}", Display::success("logged in"));

            // Show TOTP reminder if not enabled
            if !result.user.totp_enabled && should_show_totp_reminder() {
                println!();
                println!(
                    "{}",
                    Display::info("enhance your account security with two-factor authentication")
                );
                println!("  {} {}", "→".cyan().bold(), "lay totp enable your@email.com".white());
                println!();
                println!("  disable this reminder: export LAY_TOTP_REMINDER=false");
            }
        }
    }

    Ok(())
}

pub fn logout(output: OutputFormat) -> Result<()> {
    token::clear()?;

    match output {
        OutputFormat::Json => println!("{{\"message\": \"logged out\"}}"),
        OutputFormat::JsonPretty => {
            println!("{}", serde_json::json!({"message": "logged out"}))
        }
        OutputFormat::Text => {
            println!("{}", Display::success("logged out"));
        }
    }

    Ok(())
}

pub async fn enable_totp(client: &ApiClient, output: OutputFormat) -> Result<()> {
    // Get email from saved session
    let email = session::load_email()
        .ok_or_else(|| CliError::ConfigError("not logged in. use 'lay login' first".to_string()))?;

    // Get TOTP setup info from backend
    let setup: TotpSetupResponse =
        client.post("/api/auth/totp/setup", &LoginRequest { email: email.clone() }).await?;

    // Display QR code
    match output {
        OutputFormat::Text => {
            println!("{}", Display::info("scan this qr code with your authenticator app:"));
            println!();

            match qr2term::print_qr(&setup.uri) {
                Ok(()) => {}
                Err(e) => {
                    println!("{}", Display::error(&format!("failed to generate qr code: {e}")));
                    println!();
                    println!("{}", Display::info("manual entry:"));
                    println!("  secret: {}", setup.secret);
                    println!("  uri: {}", setup.uri);
                }
            }

            println!();
        }
        _ => {
            println!("{}", serde_json::to_string(&setup)?);
        }
    }

    // Prompt for TOTP code to verify
    let code = rpassword::prompt_password(Display::prompt("enter code: "))?;

    // Enable TOTP
    let result: AuthResponse =
        client.post("/api/auth/totp/enable", &TotpVerifyRequest { email, code }).await?;

    token::save(&result.token)?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{}", Display::success("totp enabled"));
        }
    }

    Ok(())
}

pub async fn disable_totp(client: &ApiClient, output: OutputFormat) -> Result<()> {
    // Get email from saved session
    let email = session::load_email()
        .ok_or_else(|| CliError::ConfigError("not logged in. use 'lay login' first".to_string()))?;

    // Disable TOTP
    let result: AuthResponse =
        client.post("/api/auth/totp/disable", &LoginRequest { email }).await?;

    token::save(&result.token)?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => {
            println!("{}", Display::success("totp disabled"));
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
