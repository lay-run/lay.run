use super::rate_limit::{RateLimitConfig, RateLimitIdentifier};
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierType {
    Ip,
    Email,
}

#[derive(Debug, Clone)]
pub struct EndpointRateLimit {
    pub config: RateLimitConfig,
    pub identifier_type: IdentifierType,
}

impl EndpointRateLimit {
    pub fn new(requests: i32, window_secs: u64, identifier_type: IdentifierType) -> Self {
        Self {
            config: RateLimitConfig::new(requests, Duration::from_secs(window_secs)),
            identifier_type,
        }
    }
}

/// Rate limiting rules for different endpoints
pub struct RateLimitRules;

impl RateLimitRules {
    /// Registration: 3 requests per 15 minutes per IP
    pub fn registration() -> EndpointRateLimit {
        EndpointRateLimit::new(3, 15 * 60, IdentifierType::Ip)
    }

    /// Login: 5 requests per 15 minutes per email/IP
    pub fn login() -> EndpointRateLimit {
        EndpointRateLimit::new(5, 15 * 60, IdentifierType::Email)
    }

    /// Resend code: 3 requests per 5 minutes per email
    pub fn resend_code() -> EndpointRateLimit {
        EndpointRateLimit::new(3, 5 * 60, IdentifierType::Email)
    }

    /// Verification: 10 requests per 10 minutes per IP
    pub fn verification() -> EndpointRateLimit {
        EndpointRateLimit::new(10, 10 * 60, IdentifierType::Ip)
    }

    /// Get rate limit rule for a specific endpoint path
    pub fn for_endpoint(path: &str) -> Option<EndpointRateLimit> {
        match path {
            "/api/auth/register" => Some(Self::registration()),
            "/api/auth/login" => Some(Self::login()),
            "/api/auth/resend-code" => Some(Self::resend_code()),
            "/api/auth/verify" => Some(Self::verification()),
            "/api/auth/login/verify" => Some(Self::verification()),
            _ => None, // No rate limit for other endpoints
        }
    }

    /// Extract the appropriate identifier based on the rule type
    pub fn extract_identifier(
        identifier_type: IdentifierType,
        ip: IpAddr,
        email: Option<String>,
    ) -> Result<RateLimitIdentifier, &'static str> {
        match identifier_type {
            IdentifierType::Ip => Ok(RateLimitIdentifier::Ip(ip)),
            IdentifierType::Email => {
                email
                    .map(RateLimitIdentifier::Email)
                    .ok_or("Email required for rate limiting but not provided")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_rule() {
        let rule = RateLimitRules::registration();
        assert_eq!(rule.config.requests_per_window, 3);
        assert_eq!(rule.config.window_duration.as_secs(), 15 * 60);
        assert_eq!(rule.identifier_type, IdentifierType::Ip);
    }

    #[test]
    fn test_login_rule() {
        let rule = RateLimitRules::login();
        assert_eq!(rule.config.requests_per_window, 5);
        assert_eq!(rule.config.window_duration.as_secs(), 15 * 60);
        assert_eq!(rule.identifier_type, IdentifierType::Email);
    }

    #[test]
    fn test_resend_code_rule() {
        let rule = RateLimitRules::resend_code();
        assert_eq!(rule.config.requests_per_window, 3);
        assert_eq!(rule.config.window_duration.as_secs(), 5 * 60);
        assert_eq!(rule.identifier_type, IdentifierType::Email);
    }

    #[test]
    fn test_verification_rule() {
        let rule = RateLimitRules::verification();
        assert_eq!(rule.config.requests_per_window, 10);
        assert_eq!(rule.config.window_duration.as_secs(), 10 * 60);
        assert_eq!(rule.identifier_type, IdentifierType::Ip);
    }

    #[test]
    fn test_endpoint_matching() {
        assert!(RateLimitRules::for_endpoint("/api/auth/register").is_some());
        assert!(RateLimitRules::for_endpoint("/api/auth/login").is_some());
        assert!(RateLimitRules::for_endpoint("/api/auth/resend-code").is_some());
        assert!(RateLimitRules::for_endpoint("/api/auth/verify").is_some());
        assert!(RateLimitRules::for_endpoint("/api/auth/login/verify").is_some());
        assert!(RateLimitRules::for_endpoint("/api/other").is_none());
    }
}
