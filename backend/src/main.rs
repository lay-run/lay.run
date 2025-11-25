use backend::{
    config::Config,
    create_app, db,
    services::{
        auth::AuthService,
        email::EmailService,
        rate_limit::{RateLimitConfig, RateLimitService},
    },
};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    // Load configuration
    let config = Config::from_env()?;
    tracing::info!("Configuration loaded");

    // Create database connection pool
    let pool = db::create_pool(&config.database_url).await?;

    // Run migrations
    db::run_migrations(&pool).await?;

    // Initialize services
    let auth_service = AuthService::new(pool.clone(), config.jwt_secret.clone());
    let email_service = EmailService::new(
        config.ses_from_email.clone(),
        config.ses_reply_to_email.clone(),
    )
    .await?;

    // Initialize rate limiting service
    // The actual rate limits are endpoint-specific and defined in rate_limit_rules.rs:
    // - Registration: 3 requests per 15 minutes per IP
    // - Login: 5 requests per 15 minutes per email
    // - Resend code: 3 requests per 5 minutes per email
    // - Verification: 10 requests per 10 minutes per IP
    let rate_limit_service = RateLimitService::new(
        pool.clone(),
        RateLimitConfig::default(), // Default config, actual limits are per-endpoint
    );

    // Spawn cleanup task to remove old rate limit records every 5 minutes
    let cleanup_service = rate_limit_service.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // 5 minutes
        loop {
            interval.tick().await;
            match cleanup_service.cleanup_old_records().await {
                Ok(deleted) => {
                    if deleted > 0 {
                        tracing::debug!("Cleaned up {} old rate limit records", deleted);
                    }
                }
                Err(e) => tracing::error!("Failed to cleanup rate limit records: {}", e),
            }
        }
    });

    tracing::info!("Services initialized");

    // Create application
    let app = create_app(pool, auth_service, email_service, rate_limit_service);

    // Start server
    let listener = tokio::net::TcpListener::bind(&config.server_address()).await?;
    tracing::info!("Server listening on {}", config.server_address());

    // IMPORTANT: Use into_make_service_with_connect_info to extract client IP addresses
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
