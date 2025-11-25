use crate::cli::{HealthCommands, HealthSubcommand, OutputFormat};
use crate::client::ApiClient;
use crate::error::Result;
use crate::types::HealthResponse;
use colored::Colorize;

pub async fn execute(cmd: HealthCommands, client: &ApiClient, output: OutputFormat) -> Result<()> {
    match cmd.command {
        HealthSubcommand::Check => check_health(client, output).await,
        HealthSubcommand::Db => check_db_health(client, output).await,
    }
}

async fn check_health(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let health: HealthResponse = client.get("/api/health").await?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&health)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&health)?),
        OutputFormat::Text => {
            println!(
                "{} API Status: {}",
                "✓".green().bold(),
                health.status.green().bold()
            );
        }
    }

    Ok(())
}

async fn check_db_health(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let health: HealthResponse = client.get("/api/health/db").await?;

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string(&health)?),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(&health)?),
        OutputFormat::Text => {
            println!(
                "{} Database Status: {}",
                "✓".green().bold(),
                health.status.green().bold()
            );
        }
    }

    Ok(())
}
