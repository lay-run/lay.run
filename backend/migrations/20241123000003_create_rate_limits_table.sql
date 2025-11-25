-- Create rate limits table for IP-based rate limiting
CREATE TABLE IF NOT EXISTS rate_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address INET NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 1,
    window_start TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Composite unique constraint for upsert operations
    UNIQUE(ip_address, endpoint, window_start)
);

-- Index for fast lookups by IP and endpoint
CREATE INDEX idx_rate_limits_lookup ON rate_limits(ip_address, endpoint, window_start);

-- Index for cleanup operations (remove old records)
CREATE INDEX idx_rate_limits_cleanup ON rate_limits(window_start);

-- Optional: Add a comment explaining the table
COMMENT ON TABLE rate_limits IS 'Stores rate limiting data for API endpoints, tracking request counts per IP address within time windows';
