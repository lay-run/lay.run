use clap::{builder::Styles, Parser, Subcommand};

/// Lay CLI - Command-line interface for the Lay platform
#[derive(Parser)]
#[command(name = "lay")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
#[command(styles = get_styles())]
pub struct Cli {
    /// API endpoint URL
    #[arg(
        short,
        long,
        env = "LAY_API_URL",
        default_value = "http://localhost:3000"
    )]
    pub api_url: String,

    /// Enable verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Output format
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub command: Commands,
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
    /// Register a new account
    Register {
        /// Email address
        email: String,

        /// Password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Login to your account
    Login {
        /// Email address
        email: String,

        /// Password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Verify email with code
    Verify {
        /// Email address
        email: String,

        /// Verification code
        code: String,
    },

    /// Resend verification code
    Resend {
        /// Email address
        email: String,
    },

    /// Logout (clear stored credentials)
    Logout,

    /// User management commands
    User(UserCommands),

    /// Health check commands
    Health(HealthCommands),
}

#[derive(clap::Args, Clone)]
pub struct UserCommands {
    #[command(subcommand)]
    pub command: UserSubcommand,
}

#[derive(Subcommand, Clone)]
pub enum UserSubcommand {
    /// Get current user information
    Me,

    /// List all users (admin only)
    List {
        /// Limit number of results
        #[arg(short, long, default_value_t = 10)]
        limit: u32,

        /// Page offset
        #[arg(short, long, default_value_t = 0)]
        offset: u32,
    },
}

#[derive(clap::Args, Clone)]
pub struct HealthCommands {
    #[command(subcommand)]
    pub command: HealthSubcommand,
}

#[derive(Subcommand, Clone)]
pub enum HealthSubcommand {
    /// Check API health
    Check,

    /// Check database health
    Db,
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
