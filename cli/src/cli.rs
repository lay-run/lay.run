use clap::{builder::Styles, Parser, Subcommand};

/// Lay CLI - Command-line interface for the Lay platform
#[derive(Parser)]
#[command(name = "lay")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
#[command(styles = get_styles())]
pub struct Cli {
    /// Enable verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Output format
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    pub fn api_url(&self) -> String {
        std::env::var("LAY_API_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Plain text output
    Text,
    /// JSON output
    Json,
    /// Pretty-printed JSON
    JsonPretty,
}

#[derive(Subcommand, Clone)]
pub enum Commands {
    /// Register and verify a new account
    Register {
        /// Email address
        email: String,

        /// Password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,

        #[command(subcommand)]
        action: Option<RegisterAction>,
    },

    /// Login to your account
    Login {
        /// Email address
        email: String,

        /// Password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Logout (clear stored credentials)
    Logout,
}

#[derive(Subcommand, Clone)]
pub enum RegisterAction {
    /// Verify email with code
    Verify {
        /// Verification code
        code: String,
    },

    /// Resend verification code
    Resend,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Text => write!(f, "text"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::JsonPretty => write!(f, "json-pretty"),
        }
    }
}

fn get_styles() -> Styles {
    Styles::styled()
        .header(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Green))),
        )
        .usage(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Green))),
        )
        .literal(
            anstyle::Style::new()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Cyan))),
        )
        .placeholder(
            anstyle::Style::new()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Yellow))),
        )
        .error(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Red))),
        )
        .valid(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Green))),
        )
        .invalid(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Yellow))),
        )
}
