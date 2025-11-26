use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub token: String,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "status")]
pub enum LoginVerifyResponse {
    #[serde(rename = "success")]
    Success { user: UserResponse, token: String },
    #[serde(rename = "totp_required")]
    TotpRequired { message: String },
}

#[derive(Deserialize, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub is_verified: bool,
    pub totp_enabled: bool,
    pub created_at: String,
}

#[derive(Deserialize, Serialize)]
pub struct CodeSentResponse {
    pub message: String,
}

#[derive(Deserialize, Serialize)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub uri: String,
}
