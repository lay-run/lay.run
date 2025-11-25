use std::path::PathBuf;

use crate::error::{CliError, Result};

pub fn save_email(email: &str) -> Result<()> {
    let dir = get_dir()?;
    std::fs::create_dir_all(&dir)?;

    let path = dir.join("last_email");
    std::fs::write(&path, email)?;

    Ok(())
}

pub fn load_email() -> Option<String> {
    let dir = get_dir().ok()?;
    let path = dir.join("last_email");

    std::fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

fn get_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .map_err(|_| CliError::ConfigError("HOME environment variable not set".to_string()))?;

    Ok(PathBuf::from(home).join(".config").join("lay"))
}
