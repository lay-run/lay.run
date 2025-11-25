mod auth;
mod health;
mod user;

use crate::cli::{Cli, Commands};
use crate::client::ApiClient;
use crate::error::Result;

pub async fn execute(cli: Cli) -> Result<()> {
    // Set up logging based on verbosity
    match cli.verbose {
        0 => {} // No logging
        1 => eprintln!("[INFO] Verbose mode enabled"),
        _ => eprintln!("[DEBUG] Debug mode enabled"),
    }

    // Create shared API client
    let client = ApiClient::new(cli.api_url)?;

    // Execute the appropriate command
    match &cli.command {
        Commands::Register { email, password } => {
            auth::register(&client, email.clone(), password.clone(), cli.output).await
        }
        Commands::Login { email, password } => {
            auth::login(&client, email.clone(), password.clone(), cli.output).await
        }
        Commands::Verify { email, code } => {
            auth::verify(&client, email.clone(), code.clone(), cli.output).await
        }
        Commands::Resend { email } => {
            auth::resend_code(&client, email.clone(), cli.output).await
        }
        Commands::Logout => auth::logout(cli.output).await,
        Commands::User(user_cmd) => user::execute(user_cmd.clone(), &client, cli.output).await,
        Commands::Health(health_cmd) => health::execute(health_cmd.clone(), &client, cli.output).await,
    }
}
