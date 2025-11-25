mod auth;
mod health;
mod user;

use crate::cli::{Cli, Commands};
use crate::error::Result;

pub async fn execute(cli: Cli) -> Result<()> {
    // Set up logging based on verbosity
    match cli.verbose {
        0 => {} // No logging
        1 => eprintln!("[INFO] Verbose mode enabled"),
        _ => eprintln!("[DEBUG] Debug mode enabled"),
    }

    // Execute the appropriate command
    match &cli.command {
        Commands::Register { email, password } => {
            auth::register(&cli.api_url, email.clone(), password.clone(), cli.output).await
        }
        Commands::Login { email, password } => {
            auth::login(&cli.api_url, email.clone(), password.clone(), cli.output).await
        }
        Commands::Verify { email, code } => {
            auth::verify(&cli.api_url, email.clone(), code.clone(), cli.output).await
        }
        Commands::Resend { email } => {
            auth::resend_code(&cli.api_url, email.clone(), cli.output).await
        }
        Commands::Logout => auth::logout(cli.output).await,
        Commands::User(user_cmd) => user::execute(user_cmd.clone(), &cli).await,
        Commands::Health(health_cmd) => health::execute(health_cmd.clone(), &cli).await,
    }
}
