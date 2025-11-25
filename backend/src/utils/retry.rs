use std::future::Future;

use tokio_retry::Retry;
use tokio_retry::strategy::{ExponentialBackoff, jitter};

/// Retry configuration for exponential backoff
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Base delay in milliseconds
    pub base_delay_ms: u64,
    /// Maximum number of retry attempts
    pub max_attempts: usize,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self { base_delay_ms: 100, max_attempts: 3 }
    }
}

impl RetryConfig {
    /// Create a new retry configuration
    pub fn new(base_delay_ms: u64, max_attempts: usize) -> Self {
        Self { base_delay_ms, max_attempts }
    }

    /// Retry an async operation with exponential backoff
    ///
    /// # Arguments
    /// * `operation` - Async function to retry
    ///
    /// # Returns
    /// Result of the operation after retries
    pub async fn retry<F, Fut, T, E>(&self, operation: F) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let strategy =
            ExponentialBackoff::from_millis(self.base_delay_ms).map(jitter).take(self.max_attempts);

        Retry::spawn(strategy, operation).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[tokio::test]
    async fn test_retry_succeeds_immediately() {
        let config = RetryConfig::default();
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let result = config
            .retry(|| {
                let count = call_count_clone.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok::<i32, String>(42)
                }
            })
            .await;

        assert_eq!(result, Ok(42));
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_retry_succeeds_after_failures() {
        let config = RetryConfig::default();
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let result = config
            .retry(|| {
                let count = call_count_clone.clone();
                async move {
                    let current = count.fetch_add(1, Ordering::SeqCst) + 1;
                    if current < 3 { Err("temporary error") } else { Ok(42) }
                }
            })
            .await;

        assert_eq!(result, Ok(42));
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_fails_after_max_attempts() {
        let config = RetryConfig::new(10, 2);
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let result = config
            .retry(|| {
                let count = call_count_clone.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    Err::<i32, &str>("persistent error")
                }
            })
            .await;

        assert_eq!(result, Err("persistent error"));
        // max_attempts includes initial attempt + retries, so 2 means 3 total attempts
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }
}
