use colored::Colorize;

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
    println!("  get started:");
    println!("    {} {}", "→".cyan().bold(), "lay register your@email.com".white());
    println!();
    println!("  learn more:");
    println!("    {} {}", "→".cyan().bold(), "lay --help".white());
    println!();
}
