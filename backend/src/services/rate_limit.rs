use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::PgPool;

#[derive(Debug, Clone)]
pub enum RateLimitIdentifier {
    Ip(IpAddr),
    Email(String),
}

impl RateLimitIdentifier {
    pub fn as_string(&self) -> String {
        match self {
            RateLimitIdentifier::Ip(ip) => format!("ip:{}", ip),
            RateLimitIdentifier::Email(email) => format!("email:{}", email),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_window: i32,
    pub window_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_window: 100,                 // 100 requests
            window_duration: Duration::from_secs(60), // per minute
        }
    }
}

impl RateLimitConfig {
    /// Creates a configuration for secure rate limiting (more restrictive)
    pub fn secure() -> Self {
        Self {
            requests_per_window: 20,                  // 20 requests
            window_duration: Duration::from_secs(60), // per minute
        }
    }

    /// Creates a configuration for strict rate limiting (very restrictive)
    pub fn strict() -> Self {
        Self {
            requests_per_window: 10,                  // 10 requests
            window_duration: Duration::from_secs(60), // per minute
        }
    }

    /// Creates a custom configuration
    pub fn new(requests_per_window: i32, window_duration: Duration) -> Self {
        Self { requests_per_window, window_duration }
    }
}

#[derive(Debug)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub current_count: i32,
    pub limit: i32,
    pub window_start: DateTime<Utc>,
    pub retry_after: Option<Duration>,
}

#[derive(Clone)]
pub struct RateLimitService {
    pool: PgPool,
    config: RateLimitConfig,
}

impl RateLimitService {
    pub fn new(pool: PgPool, config: RateLimitConfig) -> Self {
        Self { pool, config }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Check if a request is allowed and increment the counter
    pub async fn check_rate_limit(
        &self,
        identifier: RateLimitIdentifier,
        endpoint: &str,
    ) -> Result<RateLimitResult, sqlx::Error> {
        let now = Utc::now();
        let window_start = self.calculate_window_start(now);
        let identifier_str = identifier.as_string();

        // Store IP address separately for logging (optional)
        let ip_address = match &identifier {
            RateLimitIdentifier::Ip(ip) => Some(ip.to_string()),
            RateLimitIdentifier::Email(_) => None,
        };

        // Use a transaction for consistency
        let mut tx = self.pool.begin().await?;

        // Upsert: increment if exists, insert if not
        let result = sqlx::query_scalar::<_, i32>(
            r"
            INSERT INTO rate_limits (identifier, ip_address, endpoint, request_count, window_start, updated_at)
            VALUES ($1, CAST($2 AS INET), $3, 1, $4, NOW())
            ON CONFLICT (identifier, endpoint, window_start)
            DO UPDATE SET
                request_count = rate_limits.request_count + 1,
                updated_at = NOW()
            RETURNING request_count
            ",
        )
        .bind(&identifier_str)
        .bind(ip_address)
        .bind(endpoint)
        .bind(window_start)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

        let current_count = result;
        let allowed = current_count <= self.config.requests_per_window;

        let retry_after =
            if !allowed { Some(self.calculate_retry_after(window_start)) } else { None };

        Ok(RateLimitResult {
            allowed,
            current_count,
            limit: self.config.requests_per_window,
            window_start,
            retry_after,
        })
    }

    /// Calculate the start of the current time window
    fn calculate_window_start(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        let window_secs = self.config.window_duration.as_secs() as i64;
        let timestamp = now.timestamp();
        let window_start_timestamp = (timestamp / window_secs) * window_secs;

        DateTime::from_timestamp(window_start_timestamp, 0).unwrap_or(now)
    }

    /// Calculate how long until the next window
    fn calculate_retry_after(&self, window_start: DateTime<Utc>) -> Duration {
        let window_end =
            window_start + chrono::Duration::from_std(self.config.window_duration).unwrap();
        let now = Utc::now();

        if window_end > now {
            (window_end - now).to_std().unwrap_or(Duration::from_secs(1))
        } else {
            Duration::from_secs(1)
        }
    }

    /// Clean up old rate limit records (should be called periodically)
    pub async fn cleanup_old_records(&self) -> Result<u64, sqlx::Error> {
        let cutoff =
            Utc::now() - chrono::Duration::from_std(self.config.window_duration * 2).unwrap();

        let result = sqlx::query(
            r"
            DELETE FROM rate_limits
            WHERE window_start < $1
            ",
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get current rate limit status without incrementing
    pub async fn get_status(
        &self,
        identifier: RateLimitIdentifier,
        endpoint: &str,
    ) -> Result<Option<RateLimitResult>, sqlx::Error> {
        let now = Utc::now();
        let window_start = self.calculate_window_start(now);
        let identifier_str = identifier.as_string();

        let result: Option<(i32, DateTime<Utc>)> = sqlx::query_as(
            r"
            SELECT request_count, window_start
            FROM rate_limits
            WHERE identifier = $1 AND endpoint = $2 AND window_start = $3
            ",
        )
        .bind(&identifier_str)
        .bind(endpoint)
        .bind(window_start)
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some((current_count, window_start)) => {
                let allowed = current_count < self.config.requests_per_window;

                let retry_after =
                    if !allowed { Some(self.calculate_retry_after(window_start)) } else { None };

                Ok(Some(RateLimitResult {
                    allowed,
                    current_count,
                    limit: self.config.requests_per_window,
                    window_start,
                    retry_after,
                }))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_config_defaults() {
        let config = RateLimitConfig::default();
        assert_eq!(config.requests_per_window, 100);
        assert_eq!(config.window_duration.as_secs(), 60);
    }

    #[test]
    fn test_rate_limit_config_secure() {
        let config = RateLimitConfig::secure();
        assert_eq!(config.requests_per_window, 20);
        assert_eq!(config.window_duration.as_secs(), 60);
    }
}
