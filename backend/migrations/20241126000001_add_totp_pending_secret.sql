-- Add pending TOTP secret field for secure 2FA setup
ALTER TABLE users ADD COLUMN totp_pending_secret TEXT;
