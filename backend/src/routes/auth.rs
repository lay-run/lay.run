use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::models::{user::UserResponse, verification_code::VerificationCodeType};
use crate::services::{auth::AuthService, email::EmailService};

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
    pub password: String,
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
    pub password: String,
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

/// Response for code sent
#[derive(Debug, Serialize)]
pub struct CodeSentResponse {
    pub message: String,
}

/// POST /api/auth/register
/// Register a new user and send verification code
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<CodeSentResponse>)> {
    // Register user
    let user = state
        .auth_service
        .register_user(&payload.email, &payload.password)
        .await?;

    // Generate verification code
    let code = state
        .auth_service
        .create_verification_code(user.id, VerificationCodeType::EmailVerification)
        .await?;

    // Send verification email
    state
        .email_service
        .send_verification_code(&user.email, &code)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(CodeSentResponse {
            message: format!("verification code sent to {}", user.email),
        }),
    ))
}

/// POST /api/auth/verify
/// Verify email with code and return JWT token
pub async fn verify(
    State(state): State<AppState>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<AuthResponse>> {
    // Find user by email
    let user = state
        .auth_service
        .find_user_by_email(&payload.email)
        .await?;

    // Verify code
    state
        .auth_service
        .verify_code(
            user.id,
            &payload.code,
            VerificationCodeType::EmailVerification,
        )
        .await?;

    // Fetch updated user (now verified)
    let user = state.auth_service.find_user_by_id(user.id).await?;

    // Generate JWT token
    let token = state.auth_service.generate_jwt(&user)?;

    Ok(Json(AuthResponse {
        user: user.into(),
        token,
    }))
}

/// POST /api/auth/login
/// Login with email and password, send verification code
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<(StatusCode, Json<CodeSentResponse>)> {
    // Find user and verify password
    let user = state
        .auth_service
        .find_user_by_email(&payload.email)
        .await?;

    // Verify password
    state
        .auth_service
        .verify_password(&payload.password, &user.password_hash)?;

    // Generate login verification code
    let code = state
        .auth_service
        .create_verification_code(user.id, VerificationCodeType::Login)
        .await?;

    // Send login code email
    state
        .email_service
        .send_login_code(&user.email, &code)
        .await?;

    Ok((
        StatusCode::OK,
        Json(CodeSentResponse {
            message: format!("verification code sent to {}", user.email),
        }),
    ))
}

/// POST /api/auth/login/verify
/// Verify login code and return JWT token
pub async fn verify_login(
    State(state): State<AppState>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<AuthResponse>> {
    // Find user by email
    let user = state
        .auth_service
        .find_user_by_email(&payload.email)
        .await?;

    // Verify login code
    state
        .auth_service
        .verify_code(user.id, &payload.code, VerificationCodeType::Login)
        .await?;

    // Generate JWT token
    let token = state.auth_service.generate_jwt(&user)?;

    Ok(Json(AuthResponse {
        user: user.into(),
        token,
    }))
}

/// POST /api/auth/resend-code
/// Resend verification code
pub async fn resend_code(
    State(state): State<AppState>,
    Json(payload): Json<ResendCodeRequest>,
) -> Result<Json<CodeSentResponse>> {
    // Find user by email
    let user = state
        .auth_service
        .find_user_by_email(&payload.email)
        .await?;

    // Generate new verification code
    let code = state
        .auth_service
        .create_verification_code(user.id, VerificationCodeType::EmailVerification)
        .await?;

    // Send verification email
    state
        .email_service
        .send_verification_code(&user.email, &code)
        .await?;

    Ok(Json(CodeSentResponse {
        message: format!("verification code sent to {}", user.email),
    }))
}
