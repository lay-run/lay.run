use colored::Colorize;

use crate::storage::token;
use crate::ui::display::Display;

pub fn show() {
    println!();
    println!("  {}", "░██                       ".magenta());
    println!("  {}", "░██                       ".magenta());
    println!("  {}", "░██  ░██████   ░██    ░██ ".magenta());
    println!("  {}", "░██       ░██  ░██    ░██ ".magenta());
    println!("  {}", "░██  ░███████  ░██    ░██ ".magenta());
    println!("  {}", "░██ ░██   ░██  ░██   ░███ ".magenta());
    println!("  {}", "░██  ░█████░██  ░█████░██ ".magenta());
    println!("  {}", "                      ░██ ".magenta());
    println!("  {}", "                ░███████  ".magenta());
    println!();
    println!("  {}", "infrastructure, simplified".cyan());
    println!();

    // Show user status if logged in
    if let Ok(jwt_token) = token::load() {
        // Decode JWT to get email (simple base64 decode of payload)
        if let Some(email) = extract_email_from_jwt(&jwt_token) {
            println!("  {}", Display::success(&format!("logged in as {email}")));
            println!();
        }
    } else {
        println!("  get started:");
        println!("    {} {}", "→".cyan().bold(), "lay register your@email.com".white());
        println!("    {} {}", "→".cyan().bold(), "lay login your@email.com".white());
        println!();
    }

    println!("  learn more:");
    println!("    {} {}", "→".cyan().bold(), "lay --help".white());
    println!();
}

fn extract_email_from_jwt(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    // Decode the payload (second part)
    let payload = parts[1];
    let decoded = base64_decode(payload)?;
    let json: serde_json::Value = serde_json::from_str(&decoded).ok()?;

    json.get("email").and_then(|v| v.as_str()).map(std::string::ToString::to_string)
}

fn base64_decode(input: &str) -> Option<String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let bytes = engine.decode(input).ok()?;
    String::from_utf8(bytes).ok()
}
