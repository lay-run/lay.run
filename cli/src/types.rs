use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct VerifyRequest {
    pub email: String,
    pub code: String,
}

#[derive(Serialize)]
pub struct VerifyLoginRequest {
    pub email: String,
    pub code: String,
}

#[derive(Serialize)]
pub struct ResendCodeRequest {
    pub email: String,
}

#[derive(Deserialize, Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub token: String,
}

#[derive(Deserialize, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub is_verified: bool,
    pub created_at: String,
}

#[derive(Deserialize, Serialize)]
pub struct CodeSentResponse {
    pub message: String,
}
