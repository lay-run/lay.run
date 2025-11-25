use colored::Colorize;

/// Display formatting utilities for CLI output
pub struct Display;

impl Display {
    /// Format success message with checkmark (✓)
    pub fn success(msg: &str) -> String {
        format!("{} {}", "✓".green().bold(), msg.green())
    }

    /// Format info message with arrow (→)
    pub fn info(msg: &str) -> String {
        format!("{} {}", "→".cyan().bold(), msg.cyan())
    }

    /// Format error message with cross (✗)
    pub fn error(msg: &str) -> String {
        format!("{} {}", "✗".red().bold(), msg.red())
    }

    /// Format prompt text (magenta)
    pub fn prompt(text: &str) -> String {
        text.magenta().to_string()
    }
}
