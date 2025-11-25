use crate::error::{CliError, Result};
use std::path::PathBuf;

pub fn save_token(token: &str) -> Result<()> {
    let config_path = get_config_path()?;

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&config_path, token)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

pub fn load_token() -> Result<String> {
    let config_path = get_config_path()?;
    let token = std::fs::read_to_string(&config_path)?;
    Ok(token.trim().to_string())
}

pub fn clear_token() -> Result<()> {
    let config_path = get_config_path()?;

    if let Err(e) = std::fs::remove_file(&config_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(CliError::IoError(e));
        }
    }

    Ok(())
}

fn get_config_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .map_err(|_| CliError::ConfigError("HOME environment variable not set".to_string()))?;

    Ok(PathBuf::from(home).join(".lay").join("token"))
}
