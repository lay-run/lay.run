# Backend

Rust backend service for lay.run authentication and infrastructure management.

## Structure

```
backend/
├── src/
│   ├── models/       # Database models
│   ├── routes/       # API endpoints
│   ├── services/     # Business logic
│   ├── middleware/   # Request middleware
│   └── main.rs
├── migrations/       # SQL migrations
└── Cargo.toml
```

## Environment Variables

Required:
- `DATABASE_URL` - PostgreSQL connection string
- `JWT_SECRET` - Secret key for JWT signing
- `SES_FROM_EMAIL` - AWS SES sender email
- `SES_REPLY_TO_EMAIL` - Reply-to email address

Optional:
- `HOST` - Server host (default: 0.0.0.0)
- `PORT` - Server port (default: 3000)
- `RUST_LOG` - Log level (default: info)
- `AWS_REGION` - AWS region (default: us-east-1)
- `AWS_PROFILE` - AWS profile name

## Database

PostgreSQL with sqlx for migrations and queries.

Migrations run automatically on startup.

## API Endpoints

- `POST /api/auth/register` - Create account
- `POST /api/auth/verify` - Verify email
- `POST /api/auth/login` - Send login code
- `POST /api/auth/login/verify` - Verify login code
- `POST /api/auth/login/verify-totp` - Verify TOTP code
- `POST /api/auth/totp/setup` - Generate TOTP secret
- `POST /api/auth/totp/enable` - Enable TOTP
- `POST /api/auth/totp/disable` - Disable TOTP
- `GET /health` - Health check
- `GET /health/db` - Database health check
