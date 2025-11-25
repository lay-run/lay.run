mod cli;
mod client;
mod commands;
mod config;
mod display;
mod error;
mod types;

use clap::Parser;
use cli::Cli;

#[tokio::main]
async fn main() {
    // Parse command-line arguments
    let cli = Cli::parse();

    // Execute the command and handle errors
    if let Err(e) = commands::execute(cli).await {
        e.display();
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
