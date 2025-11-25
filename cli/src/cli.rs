use clap::{Parser, Subcommand, builder::Styles};

/// lay - infrastructure, simplified
#[derive(Parser)]
#[command(name = "lay")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
#[command(styles = get_styles())]
#[command(help_template = "\
{about-with-newline}
usage: lay [options] <command>

commands:
{subcommands}
options:
{options}{after-help}
")]
pub struct Cli {
    /// show more details
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// output format (text, json, json-pretty)
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text, value_name = "format")]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

impl Cli {
    pub fn api_url(&self) -> String {
        std::env::var("LAY_API_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// plain text
    Text,
    /// json output
    Json,
    /// pretty json
    JsonPretty,
}

#[derive(Subcommand, Clone)]
pub enum Commands {
    /// create a new account
    #[command(help_template = "\
{about-with-newline}
usage: lay register [options] <email> [command]

commands:
{subcommands}
arguments:
{positionals}
options:
{options}{after-help}
")]
    Register {
        /// your email
        #[arg(value_name = "email")]
        email: String,

        /// your password (we'll ask if you skip this)
        #[arg(short, long, value_name = "password")]
        password: Option<String>,

        #[command(subcommand)]
        action: Option<RegisterAction>,
    },

    /// sign in to your account
    #[command(help_template = "\
{about-with-newline}
usage: lay login [options] <email>

arguments:
{positionals}
options:
{options}{after-help}
")]
    Login {
        /// your email
        #[arg(value_name = "email")]
        email: String,

        /// your password (we'll ask if you skip this)
        #[arg(short, long, value_name = "password")]
        password: Option<String>,
    },

    /// sign out
    Logout,
}

#[derive(Subcommand, Clone)]
pub enum RegisterAction {
    /// verify your email with a code
    Verify {
        /// the code we sent you
        #[arg(value_name = "code")]
        code: String,
    },

    /// send the code again
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
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Magenta))),
        )
        .usage(anstyle::Style::new().fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Cyan))))
        .literal(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Cyan))),
        )
        .placeholder(
            anstyle::Style::new().fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Blue))),
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
