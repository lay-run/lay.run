# Backend API

A clean Rust REST API backend using Axum and SQLx with PostgreSQL.

## Features

- **Axum** - Fast, ergonomic web framework
- **SQLx** - Compile-time checked SQL queries with async support
- **PostgreSQL** - Production-ready database
- **Tower** - Middleware for CORS, tracing, and more
- **Structured error handling** - Custom error types with proper HTTP responses
- **Database migrations** - Built-in migration support
- **Environment configuration** - Easy configuration via .env files
- **Logging & Tracing** - Built-in observability

## Project Structure

```
backend/
├── src/
│   ├── main.rs           # Application entry point
│   ├── lib.rs            # Library root, app setup
│   ├── config.rs         # Configuration management
│   ├── db.rs             # Database connection & migrations
│   ├── error.rs          # Error handling
│   ├── models/           # Database models
│   │   └── mod.rs
│   └── routes/           # API routes
│       ├── mod.rs
│       └── health.rs     # Health check endpoints
├── migrations/           # Database migrations (SQLx)
├── Cargo.toml           # Dependencies
├── .env.example         # Environment variables template
└── README.md            # This file
```

## Setup

### Prerequisites

- Rust (latest stable)
- PostgreSQL 14+
- sqlx-cli (for migrations)

### Install sqlx-cli

```bash
cargo install sqlx-cli --no-default-features --features postgres
```

### Environment Setup

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Update the `.env` file with your database credentials:
```env
DATABASE_URL=postgres://username:password@localhost:5432/backend
HOST=0.0.0.0
PORT=3000
RUST_LOG=info,backend=debug
```

### Database Setup

1. Create the database:
```bash
createdb backend
```

Or using psql:
```sql
CREATE DATABASE backend;
```

2. Create and run migrations:
```bash
# Create a new migration
sqlx migrate add create_users_table

# Run migrations
sqlx migrate run
```

## Running the Application

### Development

```bash
cargo run
```

### Production Build

```bash
cargo build --release
./target/release/backend
```

## API Endpoints

### Health Checks

- `GET /api/health` - Basic health check
- `GET /api/health/db` - Database connection health check

### Example Health Check Response

```json
{
  "status": "ok",
  "message": "Service is healthy"
}
```

## Creating Migrations

Migrations are located in the `migrations/` directory. SQLx runs them automatically on startup.

Example migration:

```bash
sqlx migrate add create_users_table
```

This creates a file like `migrations/20240101000000_create_users_table.sql`:

```sql
-- Add migration script here
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
```

## Development Tips

### Adding a New Route

1. Create a new file in `src/routes/` (e.g., `users.rs`)
2. Define your handlers
3. Add the module to `src/routes/mod.rs`
4. Register routes in `create_routes()`

### Adding a New Model

1. Create a new file in `src/models/` (e.g., `user.rs`)
2. Define your struct with SQLx derives
3. Add the module to `src/models/mod.rs`

### Error Handling

Use the `AppError` enum from `src/error.rs`. It automatically converts to proper HTTP responses:

```rust
use crate::error::{AppError, Result};

async fn my_handler() -> Result<Json<Data>> {
    let data = fetch_data().await?; // Errors auto-convert to AppError
    Ok(Json(data))
}
```

## Testing

```bash
# Run all tests
cargo test

# Run with logging
RUST_LOG=debug cargo test
```

## Best Practices

- ✅ Use prepared statements via SQLx for SQL injection protection
- ✅ Validate input data before processing
- ✅ Use proper error types instead of unwrap()
- ✅ Log errors with context using tracing
- ✅ Keep routes thin, business logic in separate modules
- ✅ Use transactions for multi-step database operations
- ✅ Add database indexes for frequently queried columns
