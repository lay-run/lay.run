-- Increase verification code length from 6 to 8 characters
ALTER TABLE verification_codes ALTER COLUMN code TYPE VARCHAR(8);
