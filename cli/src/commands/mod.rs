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
        Commands::Auth(auth_cmd) => auth::execute(auth_cmd.clone(), &cli).await,
        Commands::User(user_cmd) => user::execute(user_cmd.clone(), &cli).await,
        Commands::Health(health_cmd) => health::execute(health_cmd.clone(), &cli).await,
    }
}
