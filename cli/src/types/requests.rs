use serde::Serialize;

#[derive(Serialize)]
pub struct RegisterRequest {
    pub email: String,
}

#[derive(Serialize)]
pub struct LoginRequest {
    pub email: String,
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

#[derive(Serialize)]
pub struct TotpVerifyRequest {
    pub email: String,
    pub code: String,
}
