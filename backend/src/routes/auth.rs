use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::models::user::UserResponse;
use crate::models::verification_code::VerificationCodeType;
use crate::services::auth::AuthService;
use crate::services::email::EmailService;

/// Application state containing services
#[derive(Clone)]
pub struct AppState {
    pub auth_service: AuthService,
    pub email_service: EmailService,
}

/// Request body for user registration
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
}

/// Request body for verification
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub email: String,
    pub code: String,
}

/// Request body for login
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
}

/// Request body for resending verification code
#[derive(Debug, Deserialize)]
pub struct ResendCodeRequest {
    pub email: String,
}

/// Response for successful authentication
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub token: String,
}

/// Response for login verification (may require TOTP)
#[derive(Debug, Serialize)]
#[serde(tag = "status")]
pub enum LoginVerifyResponse {
    #[serde(rename = "success")]
    Success { user: UserResponse, token: String },
    #[serde(rename = "totp_required")]
    TotpRequired { message: String },
}

/// Response for code sent
#[derive(Debug, Serialize)]
pub struct CodeSentResponse {
    pub message: String,
}

/// Response for TOTP setup
#[derive(Debug, Serialize)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub uri: String,
}

/// Request body for TOTP verification
#[derive(Debug, Deserialize)]
pub struct TotpVerifyRequest {
    pub email: String,
    pub code: String,
}

/// Login metadata
#[derive(Debug, Clone)]
pub struct LoginMetadata {
    pub ip: String,
    pub user_agent: String,
    pub device: String,
    pub browser: String,
    pub os: String,
    pub location: Option<String>,
    pub timestamp: chrono::DateTime<Utc>,
}

impl LoginMetadata {
    pub async fn from_request(headers: &HeaderMap, addr: Option<SocketAddr>) -> Self {
        let user_agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("Unknown")
            .to_string();

        // Parse user agent - handle CLI user agents specially
        let (device, browser, os) = if user_agent.starts_with("lay-cli/") {
            // Parse CLI user agent: "lay-cli/0.1.0 (linux/x86_64)"
            let version = user_agent
                .strip_prefix("lay-cli/")
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("unknown");

            let os_info = if let Some(start) = user_agent.find('(') {
                if let Some(end) = user_agent.find(')') {
                    &user_agent[start + 1..end]
                } else {
                    "unknown"
                }
            } else {
                "unknown"
            };

            let (os_name, arch) = os_info.split_once('/').unwrap_or((os_info, ""));
            let os_display = match os_name {
                "linux" => format!("Linux {}", arch),
                "macos" => format!("macOS {}", arch),
                "windows" => format!("Windows {}", arch),
                _ => format!("{} {}", os_name, arch),
            };

            ("CLI".to_string(), format!("lay-cli v{}", version), os_display)
        } else {
            // Try parsing browser user agents with woothee
            let parser = woothee::parser::Parser::new();
            let result = parser.parse(&user_agent);

            if let Some(r) = result {
                let device = r.category.to_string();
                let browser = format!("{} {}", r.name, r.version);
                let os = if r.os_version.as_ref() != "UNKNOWN" {
                    format!("{} {}", r.os, r.os_version)
                } else {
                    r.os.to_string()
                };
                (device, browser, os)
            } else {
                ("Unknown".to_string(), "Unknown".to_string(), "Unknown".to_string())
            }
        };

        // Get IP address (check for X-Forwarded-For or X-Real-IP first)
        let ip = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|s| s.to_string())
            .or_else(|| {
                headers.get("x-real-ip").and_then(|v| v.to_str().ok()).map(|s| s.to_string())
            })
            .or_else(|| addr.map(|a| a.ip().to_string()))
            .unwrap_or_else(|| "Unknown".to_string());

        // Attempt to geolocate IP (with timeout)
        let location = if ip != "Unknown"
            && ip != "127.0.0.1"
            && !ip.starts_with("192.168.")
            && !ip.starts_with("10.")
        {
            match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                ipgeolocate::Locator::get(&ip, ipgeolocate::Service::IpApi),
            )
            .await
            {
                Ok(Ok(loc)) => {
                    let mut parts = Vec::new();
                    if !loc.city.is_empty() {
                        parts.push(loc.city);
                    }
                    if !loc.region.is_empty() {
                        parts.push(loc.region);
                    }
                    if !loc.country.is_empty() {
                        parts.push(loc.country);
                    }
                    if !parts.is_empty() { Some(parts.join(", ")) } else { None }
                }
                _ => None, // Timeout or error - just skip geolocation
            }
        } else {
            None
        };

        Self { ip, user_agent, device, browser, os, location, timestamp: Utc::now() }
    }
}

/// POST /api/auth/register
/// Register a new user and send verification code
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<CodeSentResponse>)> {
    // Register user
    let user = state.auth_service.register_user(&payload.email).await;

    let user = match user {
        Ok(user) => user,
        Err(crate::error::AppError::UserAlreadyExists) => {
            // Return success message even if user exists to prevent enumeration
            return Ok((
                StatusCode::CREATED,
                Json(CodeSentResponse {
                    message: format!("verification code sent to {}", payload.email),
                }),
            ));
        }
        Err(e) => return Err(e),
    };

    // Generate verification code
    let code = state
        .auth_service
        .create_verification_code(user.id, VerificationCodeType::EmailVerification)
        .await?;

    // Send verification email
    state.email_service.send_verification_code(&user.email, &code).await?;

    Ok((
        StatusCode::CREATED,
        Json(CodeSentResponse { message: format!("verification code sent to {}", user.email) }),
    ))
}

/// POST /api/auth/verify
/// Verify email with code and return JWT token
pub async fn verify(
    State(state): State<AppState>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<AuthResponse>> {
    // Find user by email
    let user = state.auth_service.find_user_by_email(&payload.email).await?;

    // Verify code
    state
        .auth_service
        .verify_code(user.id, &payload.code, VerificationCodeType::EmailVerification)
        .await?;

    // Fetch updated user (now verified)
    let user = state.auth_service.find_user_by_id(user.id).await?;

    // Generate PASETO token
    let token = state.auth_service.generate_token(&user)?;

    Ok(Json(AuthResponse { user: user.into(), token }))
}

/// POST /api/auth/login
/// Send verification code to user's email
pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Result<(StatusCode, Json<CodeSentResponse>)> {
    // Extract login metadata
    let metadata = LoginMetadata::from_request(&headers, Some(addr)).await;

    // Find user by email
    let user = state.auth_service.find_user_by_email(&payload.email).await;

    let user = match user {
        Ok(user) => user,
        Err(_) => {
            // Return success message even if user doesn't exist to prevent enumeration
            return Ok((
                StatusCode::OK,
                Json(CodeSentResponse {
                    message: format!("verification code sent to {}", payload.email),
                }),
            ));
        }
    };

    // Generate login verification code
    let code =
        state.auth_service.create_verification_code(user.id, VerificationCodeType::Login).await?;

    // Send login code email with metadata
    state.email_service.send_login_code(&user.email, &code, &metadata).await?;

    Ok((
        StatusCode::OK,
        Json(CodeSentResponse { message: format!("verification code sent to {}", user.email) }),
    ))
}

/// POST /api/auth/login/verify
/// Verify login code and return JWT token or request TOTP
pub async fn verify_login(
    State(state): State<AppState>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<LoginVerifyResponse>> {
    // Find user by email
    let user = state.auth_service.find_user_by_email(&payload.email).await?;

    // Verify login code
    state.auth_service.verify_code(user.id, &payload.code, VerificationCodeType::Login).await?;

    // Check if TOTP is enabled
    if user.totp_enabled {
        // Don't issue token yet, require TOTP verification
        return Ok(Json(LoginVerifyResponse::TotpRequired {
            message: "TOTP code required".to_string(),
        }));
    }

    // TOTP not enabled, issue token immediately
    let token = state.auth_service.generate_token(&user)?;

    Ok(Json(LoginVerifyResponse::Success { user: user.into(), token }))
}

/// POST /api/auth/login/verify-totp
/// Verify TOTP code during login and return JWT token
pub async fn verify_login_totp(
    State(state): State<AppState>,
    Json(payload): Json<TotpVerifyRequest>,
) -> Result<Json<AuthResponse>> {
    // Find user by email
    let user = state.auth_service.find_user_by_email(&payload.email).await?;

    // User must have TOTP enabled
    if !user.totp_enabled {
        return Err(crate::error::AppError::BadRequest("TOTP not enabled".to_string()));
    }

    // Get TOTP secret
    let totp_secret = user
        .totp_secret
        .as_ref()
        .ok_or(crate::error::AppError::BadRequest("TOTP not configured".to_string()))?;

    // Verify TOTP code
    state.auth_service.verify_totp(totp_secret, &payload.code)?;

    // Generate PASETO token
    let token = state.auth_service.generate_token(&user)?;

    Ok(Json(AuthResponse { user: user.into(), token }))
}

/// POST /api/auth/resend-code
/// Resend verification code
pub async fn resend_code(
    State(state): State<AppState>,
    Json(payload): Json<ResendCodeRequest>,
) -> Result<Json<CodeSentResponse>> {
    // Find user by email
    let user = state.auth_service.find_user_by_email(&payload.email).await;

    // Return same message regardless of whether user exists to prevent enumeration
    let user = match user {
        Ok(user) => user,
        Err(_) => {
            return Ok(Json(CodeSentResponse {
                message: format!("verification code sent to {}", payload.email),
            }));
        }
    };

    // Generate new verification code
    let code = state
        .auth_service
        .create_verification_code(user.id, VerificationCodeType::EmailVerification)
        .await?;

    // Send verification email
    state.email_service.send_verification_code(&user.email, &code).await?;

    Ok(Json(CodeSentResponse { message: format!("verification code sent to {}", user.email) }))
}

/// POST /api/auth/totp/setup
/// Generate TOTP secret and provisioning URI for user
pub async fn setup_totp(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<TotpSetupResponse>> {
    // Find user by email
    let user = state.auth_service.find_user_by_email(&payload.email).await?;

    // User must be verified
    if !user.is_verified {
        return Err(crate::error::AppError::EmailNotVerified);
    }

    // Generate TOTP secret and URI
    let (secret, uri) = state.auth_service.generate_totp_secret(&user.email)?;

    // Store pending secret on server (security: don't trust client)
    state.auth_service.store_pending_totp_secret(user.id, &secret).await?;

    Ok(Json(TotpSetupResponse { secret, uri }))
}

/// POST /api/auth/totp/enable
/// Enable TOTP for user after verifying code
pub async fn enable_totp(
    State(state): State<AppState>,
    Json(payload): Json<TotpVerifyRequest>,
) -> Result<Json<AuthResponse>> {
    // Find user by email
    let user = state.auth_service.find_user_by_email(&payload.email).await?;

    // User must be verified
    if !user.is_verified {
        return Err(crate::error::AppError::EmailNotVerified);
    }

    // Get pending secret from database (security: never trust client-provided secrets)
    let pending_secret = user
        .totp_pending_secret
        .ok_or(crate::error::AppError::BadRequest("TOTP setup not initiated".to_string()))?;

    // Verify the TOTP code with the server-stored secret
    state.auth_service.verify_totp(&pending_secret, &payload.code)?;

    // Enable TOTP for user and clear pending secret
    state.auth_service.enable_totp(user.id, &pending_secret).await?;

    // Fetch updated user
    let user = state.auth_service.find_user_by_id(user.id).await?;

    // Generate PASETO token
    let token = state.auth_service.generate_token(&user)?;

    Ok(Json(AuthResponse { user: user.into(), token }))
}

/// POST /api/auth/totp/disable
/// Disable TOTP for user
pub async fn disable_totp(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>> {
    // Find user by email
    let user = state.auth_service.find_user_by_email(&payload.email).await?;

    // Disable TOTP
    state.auth_service.disable_totp(user.id).await?;

    // Fetch updated user
    let user = state.auth_service.find_user_by_id(user.id).await?;

    // Generate PASETO token
    let token = state.auth_service.generate_token(&user)?;

    Ok(Json(AuthResponse { user: user.into(), token }))
}
