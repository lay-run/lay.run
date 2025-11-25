pub mod auth;
pub mod health;

use axum::Router;
use axum::routing::{get, post};
use sqlx::PgPool;

use crate::services::auth::AuthService;
use crate::services::email::EmailService;

pub fn create_routes(
    pool: PgPool,
    auth_service: AuthService,
    email_service: EmailService,
) -> Router {
    let auth_state = auth::AppState { auth_service, email_service };

    Router::new()
        // Health routes
        .route("/health", get(health::health_check))
        .route("/health/db", get(health::db_health_check))
        .with_state(pool)
        // Auth routes
        .route("/auth/register", post(auth::register))
        .route("/auth/verify", post(auth::verify))
        .route("/auth/login", post(auth::login))
        .route("/auth/login/verify", post(auth::verify_login))
        .route("/auth/resend-code", post(auth::resend_code))
        .route("/auth/totp/setup", post(auth::setup_totp))
        .route("/auth/totp/enable", post(auth::enable_totp))
        .route("/auth/totp/disable", post(auth::disable_totp))
        .with_state(auth_state)
}
