use crate::cli::{Cli, OutputFormat, UserCommands, UserSubcommand};
use crate::commands::auth::load_token;
use crate::error::{CliError, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct User {
    id: String,
    email: String,
    email_verified: bool,
}

pub async fn execute(cmd: UserCommands, cli: &Cli) -> Result<()> {
    match cmd.command {
        UserSubcommand::Me => get_me(&cli.api_url, cli.output).await,
        UserSubcommand::List { limit, offset } => {
            list_users(&cli.api_url, limit, offset, cli.output).await
        }
    }
}

async fn get_me(api_url: &str, output: OutputFormat) -> Result<()> {
    let token = load_token()?;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/user/me", api_url))
        .bearer_auth(token)
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(CliError::ApiError(error_text));
    }

    let user: User = response.json().await?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&user)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&user)?),
        OutputFormat::Text => {
            println!("{}", "User Information".bold());
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("ID:             {}", user.id);
            println!("Email:          {}", user.email);
            println!(
                "Email Verified: {}",
                if user.email_verified {
                    "✓ Yes".green()
                } else {
                    "✗ No".red()
                }
            );
        }
    }

    Ok(())
}

async fn list_users(
    api_url: &str,
    limit: u32,
    offset: u32,
    output: OutputFormat,
) -> Result<()> {
    let token = load_token()?;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/user/list", api_url))
        .bearer_auth(token)
        .query(&[("limit", limit.to_string()), ("offset", offset.to_string())])
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(CliError::ApiError(error_text));
    }

    let users: Vec<User> = response.json().await?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&users)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&users)?),
        OutputFormat::Text => {
            println!("{}", format!("Users (Showing {} results)", users.len()).bold());
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            for user in users {
                println!(
                    "{} {} {}",
                    user.id.bright_blue(),
                    user.email,
                    if user.email_verified {
                        "✓".green()
                    } else {
                        "✗".red()
                    }
                );
            }
        }
    }

    Ok(())
}
