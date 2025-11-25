use axum::{extract::State, http::StatusCode, Json};
use serde_json::json;
use sqlx::PgPool;

use crate::error::Result;

pub async fn health_check() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "message": "Service is healthy"
    }))
}

pub async fn db_health_check(State(pool): State<PgPool>) -> Result<(StatusCode, Json<serde_json::Value>)> {
    sqlx::query("SELECT 1")
        .fetch_one(&pool)
        .await?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "message": "Database connection is healthy"
        })),
    ))
}
