# CLI

Command-line interface for lay.run.

## Structure

```
cli/src/
├── services/         # API client and service layer
├── storage/          # Local data persistence (token, session)
├── ui/               # User interface components
├── types/            # Request/response types
├── commands/         # Command handlers
├── cli.rs            # CLI argument parsing
├── config.rs         # Configuration
├── error.rs          # Error types
└── main.rs           # Entry point
```

## Environment Variables

Optional:
- `LAY_API_URL` - Backend API URL (default: http://localhost:3000)
- `LAY_TOTP_REMINDER` - Show TOTP reminder on login (default: true)

## Commands

Authentication:
- `lay register <email>` - Create account
- `lay login [email]` - Sign in (uses last email if omitted)
- `lay logout` - Sign out

Two-factor authentication:
- `lay totp enable` - Enable TOTP
- `lay totp disable` - Disable TOTP

Options:
- `-o, --output <format>` - Output format: text, json, json-pretty
- `-v, --verbose` - Show more details

## Data Storage

Local files stored in `~/.lay/`:
- `token` - JWT authentication token
- `session` - Last used email address
