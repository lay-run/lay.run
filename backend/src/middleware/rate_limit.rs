use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

use crate::services::{rate_limit::RateLimitService, rate_limit_rules::RateLimitRules};

/// Rate limiting middleware with endpoint-specific rules
pub async fn rate_limit_middleware(
    State(rate_limit_service): State<RateLimitService>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, RateLimitError> {
    let ip = addr.ip();
    let endpoint = request.uri().path().to_string();

    // Check if this endpoint has a specific rate limit rule
    let rule = match RateLimitRules::for_endpoint(&endpoint) {
        Some(r) => r,
        None => {
            // No rate limiting for this endpoint
            return Ok(next.run(request).await);
        }
    };

    // Extract email from request body if needed
    const MAX_BODY_SIZE: usize = 10 * 1024 * 1024; // 10MB
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_BODY_SIZE)
        .await
        .map_err(|e| RateLimitError::BodyReadError(e.to_string()))?;

    let email = if rule.identifier_type == crate::services::rate_limit_rules::IdentifierType::Email
    {
        extract_email_from_body(&bytes).ok()
    } else {
        None
    };

    // Extract the appropriate identifier
    let identifier = RateLimitRules::extract_identifier(rule.identifier_type, ip, email)
        .map_err(RateLimitError::IdentifierError)?;

    // Create a temporary service with the endpoint-specific config
    let endpoint_service = RateLimitService::new(rate_limit_service.pool().clone(), rule.config);

    // Check rate limit
    let result = endpoint_service
        .check_rate_limit(identifier, &endpoint)
        .await
        .map_err(|e| RateLimitError::DatabaseError(e.to_string()))?;

    if !result.allowed {
        // Rate limit exceeded
        let retry_after_secs = result.retry_after.map(|d| d.as_secs()).unwrap_or(60);

        return Err(RateLimitError::RateLimitExceeded {
            retry_after_secs,
            limit: result.limit,
            current: result.current_count,
        });
    }

    // Reconstruct the request with the body
    let request = Request::from_parts(parts, Body::from(bytes));

    // Add rate limit headers to response
    let mut response = next.run(request).await;
    add_rate_limit_headers(response.headers_mut(), &result);

    Ok(response)
}

/// Extract email from JSON request body
fn extract_email_from_body(bytes: &[u8]) -> Result<String, &'static str> {
    let body_str = std::str::from_utf8(bytes).map_err(|_| "Invalid UTF-8 in body")?;
    let json: serde_json::Value =
        serde_json::from_str(body_str).map_err(|_| "Invalid JSON in body")?;

    json.get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or("Email field not found in request body")
}

/// Add rate limit information headers to the response
fn add_rate_limit_headers(
    headers: &mut HeaderMap,
    result: &crate::services::rate_limit::RateLimitResult,
) {
    // X-RateLimit-Limit: The maximum number of requests allowed in the window
    if let Ok(value) = result.limit.to_string().try_into() {
        headers.insert("X-RateLimit-Limit", value);
    }

    // X-RateLimit-Remaining: The number of requests remaining in the current window
    let remaining = (result.limit - result.current_count).max(0);
    if let Ok(value) = remaining.to_string().try_into() {
        headers.insert("X-RateLimit-Remaining", value);
    }

    // X-RateLimit-Reset: Unix timestamp when the rate limit resets
    if let Some(retry_after) = result.retry_after {
        let reset_timestamp =
            (chrono::Utc::now() + chrono::Duration::from_std(retry_after).unwrap()).timestamp();
        if let Ok(value) = reset_timestamp.to_string().try_into() {
            headers.insert("X-RateLimit-Reset", value);
        }
    }
}

#[derive(Debug)]
pub enum RateLimitError {
    RateLimitExceeded {
        retry_after_secs: u64,
        limit: i32,
        current: i32,
    },
    DatabaseError(String),
    BodyReadError(String),
    IdentifierError(&'static str),
}

impl IntoResponse for RateLimitError {
    fn into_response(self) -> Response {
        match self {
            RateLimitError::RateLimitExceeded {
                retry_after_secs,
                limit,
                current,
            } => {
                let body = serde_json::json!({
                    "error": "Rate limit exceeded",
                    "message": format!("Too many requests. Limit: {} requests. Current: {} requests.", limit, current),
                    "retry_after_seconds": retry_after_secs,
                })
                .to_string();

                let mut response = (StatusCode::TOO_MANY_REQUESTS, body).into_response();

                // Add Retry-After header (standard HTTP header)
                if let Ok(value) = retry_after_secs.to_string().try_into() {
                    response.headers_mut().insert("Retry-After", value);
                }

                response
            }
            RateLimitError::DatabaseError(msg) => {
                tracing::error!("Rate limit database error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
            }
            RateLimitError::BodyReadError(msg) => {
                tracing::error!("Failed to read request body: {}", msg);
                (StatusCode::BAD_REQUEST, "Failed to read request body").into_response()
            }
            RateLimitError::IdentifierError(msg) => {
                tracing::error!("Failed to extract identifier: {}", msg);
                (StatusCode::BAD_REQUEST, msg).into_response()
            }
        }
    }
}
