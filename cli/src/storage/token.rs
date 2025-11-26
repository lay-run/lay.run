use std::path::PathBuf;

use crate::error::{CliError, Result};

pub fn save(token: &str) -> Result<()> {
    let path = get_path()?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&path, token)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

#[allow(dead_code)]
pub fn load() -> Result<String> {
    let path = get_path()?;
    let token = std::fs::read_to_string(&path)?;
    Ok(token.trim().to_string())
}

pub fn clear() -> Result<()> {
    let path = get_path()?;

    if let Err(e) = std::fs::remove_file(&path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(CliError::IoError(e));
    }

    Ok(())
}

pub fn exists() -> bool {
    get_path().map(|path| path.exists()).unwrap_or(false)
}

fn get_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .map_err(|_| CliError::ConfigError("HOME environment variable not set".to_string()))?;

    Ok(PathBuf::from(home).join(".lay").join("token"))
}
