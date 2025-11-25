-- Modify rate_limits table to support both IP and email-based rate limiting
-- Drop the old unique constraint
ALTER TABLE rate_limits DROP CONSTRAINT IF EXISTS rate_limits_ip_address_endpoint_window_start_key;

-- Add identifier column to store either IP or email
ALTER TABLE rate_limits ADD COLUMN IF NOT EXISTS identifier VARCHAR(255);

-- Migrate existing data: copy ip_address to identifier
UPDATE rate_limits SET identifier = ip_address WHERE identifier IS NULL;

-- Make identifier NOT NULL after migration
ALTER TABLE rate_limits ALTER COLUMN identifier SET NOT NULL;

-- ip_address is now optional (for email-based limits)
ALTER TABLE rate_limits ALTER COLUMN ip_address DROP NOT NULL;

-- Add new unique constraint using identifier instead of ip_address
ALTER TABLE rate_limits ADD CONSTRAINT rate_limits_identifier_endpoint_window_unique
    UNIQUE(identifier, endpoint, window_start);

-- Update index for lookups
DROP INDEX IF EXISTS idx_rate_limits_lookup;
CREATE INDEX idx_rate_limits_identifier_lookup ON rate_limits(identifier, endpoint, window_start);

-- Add comment explaining the identifier column
COMMENT ON COLUMN rate_limits.identifier IS 'Unique identifier for rate limiting - can be IP address or email address';
