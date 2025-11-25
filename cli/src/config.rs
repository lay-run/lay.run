pub fn should_show_totp_reminder() -> bool {
    std::env::var("LAY_TOTP_REMINDER").unwrap_or_else(|_| "true".to_string()).to_lowercase()
        != "false"
}
