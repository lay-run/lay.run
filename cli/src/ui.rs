use colored::Colorize;

/// UI symbols and utilities
pub struct Ui;

impl Ui {
    /// Success symbol (✓)
    pub fn success(msg: &str) -> String {
        format!("{} {}", "✓".green().bold(), msg.green())
    }

    /// Info symbol (→)
    pub fn info(msg: &str) -> String {
        format!("{} {}", "→".cyan().bold(), msg.cyan())
    }

    /// Error symbol (✗)
    pub fn error(msg: &str) -> String {
        format!("{} {}", "✗".red().bold(), msg.red())
    }

    /// Prompt text (magenta)
    pub fn prompt(text: &str) -> String {
        text.magenta().to_string()
    }
}
