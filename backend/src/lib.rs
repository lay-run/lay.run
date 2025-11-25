pub mod config;
pub mod db;
pub mod error;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod services;

use axum::{middleware::from_fn_with_state, Router};
use services::{auth::AuthService, email::EmailService, rate_limit::RateLimitService};
use sqlx::PgPool;
use tower_http::{
    cors::CorsLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use tracing::Level;

pub fn create_app(
    pool: PgPool,
    auth_service: AuthService,
    email_service: EmailService,
    rate_limit_service: RateLimitService,
) -> Router {
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO));

    Router::new()
        .nest("/api", routes::create_routes(pool, auth_service, email_service))
        .layer(CorsLayer::permissive())
        .layer(trace_layer)
        .layer(from_fn_with_state(
            rate_limit_service,
            middleware::rate_limit::rate_limit_middleware,
        ))
}
