-- Create verification codes table
CREATE TABLE IF NOT EXISTS verification_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code VARCHAR(6) NOT NULL,
    code_type VARCHAR(50) NOT NULL, -- 'email_verification', 'password_reset', 'login'
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create index on user_id for faster lookups
CREATE INDEX idx_verification_codes_user_id ON verification_codes(user_id);

-- Create index on code and type for verification
CREATE INDEX idx_verification_codes_code_type ON verification_codes(code, code_type);

-- Create index on expiration for cleanup queries
CREATE INDEX idx_verification_codes_expires_at ON verification_codes(expires_at);
