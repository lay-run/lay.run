use crate::cli::{Cli, HealthCommands, HealthSubcommand, OutputFormat};
use crate::error::{CliError, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct HealthResponse {
    status: String,
}

pub async fn execute(cmd: HealthCommands, cli: &Cli) -> Result<()> {
    match cmd.command {
        HealthSubcommand::Check => check_health(&cli.api_url, cli.output).await,
        HealthSubcommand::Db => check_db_health(&cli.api_url, cli.output).await,
    }
}

async fn check_health(api_url: &str, output: OutputFormat) -> Result<()> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/health", api_url))
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(CliError::ApiError(error_text));
    }

    let health: HealthResponse = response.json().await?;

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

async fn check_db_health(api_url: &str, output: OutputFormat) -> Result<()> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/health/db", api_url))
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(CliError::ApiError(error_text));
    }

    let health: HealthResponse = response.json().await?;

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
