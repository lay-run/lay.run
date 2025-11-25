-- Remove password_hash column from users table (passwordless authentication)
ALTER TABLE users DROP COLUMN IF EXISTS password_hash;
