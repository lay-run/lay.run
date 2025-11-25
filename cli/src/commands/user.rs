use crate::cli::{OutputFormat, UserCommands, UserSubcommand};
use crate::client::ApiClient;
use crate::config::load_token;
use crate::error::Result;
use crate::types::UserResponse;
use colored::Colorize;

pub async fn execute(cmd: UserCommands, client: &ApiClient, output: OutputFormat) -> Result<()> {
    match cmd.command {
        UserSubcommand::Me => get_me(client, output).await,
        UserSubcommand::List { limit, offset } => {
            list_users(client, limit, offset, output).await
        }
    }
}

async fn get_me(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let token = load_token()?;

    let user: UserResponse = client.get_with_token("/api/user/me", &token).await?;

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
                if user.is_verified {
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
    client: &ApiClient,
    _limit: u32,
    _offset: u32,
    output: OutputFormat,
) -> Result<()> {
    let token = load_token()?;

    let users: Vec<UserResponse> = client.get_with_token("/api/user/list", &token).await?;

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
                    if user.is_verified {
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
