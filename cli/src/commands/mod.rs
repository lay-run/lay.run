mod auth;

use crate::cli::{Cli, Commands, RegisterAction, TotpAction};
use crate::client::ApiClient;
use crate::error::Result;
use crate::greeting;

pub async fn execute(cli: Cli) -> Result<()> {
    // Set up logging based on verbosity
    match cli.verbose {
        0 => {} // No logging
        1 => eprintln!("[INFO] Verbose mode enabled"),
        _ => eprintln!("[DEBUG] Debug mode enabled"),
    }

    // Show greeting if no command provided
    let Some(command) = &cli.command else {
        greeting::show();
        return Ok(());
    };

    // Create shared API client
    let client = ApiClient::new(cli.api_url())?;

    // Execute the appropriate command
    match command {
        Commands::Register { email, action } => match action {
            None => auth::register(&client, email.clone(), cli.output).await,
            Some(RegisterAction::Verify { code }) => {
                auth::verify(&client, email.clone(), code.clone(), cli.output).await
            }
            Some(RegisterAction::Resend) => {
                auth::resend_code(&client, email.clone(), cli.output).await
            }
        },
        Commands::Login { email } => auth::login(&client, email.clone(), cli.output).await,
        Commands::Logout => auth::logout(cli.output).await,
        Commands::Totp { action } => match action {
            TotpAction::Enable { email } => {
                auth::enable_totp(&client, email.clone(), cli.output).await
            }
            TotpAction::Disable { email } => {
                auth::disable_totp(&client, email.clone(), cli.output).await
            }
        },
    }
}
