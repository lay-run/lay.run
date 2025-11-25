# Lay CLI

Command-line interface for the Lay platform, built with Rust and Clap.

## Features

- ✨ **Modern CLI Design** - Built with Clap v4 derive macros (latest best practices)
- 🎨 **Multiple Output Formats** - Text, JSON, and pretty JSON output
- 🔐 **Authentication** - Register, login, verify email, and manage sessions
- 👤 **User Management** - View user information
- 🏥 **Health Checks** - Monitor API and database status
- 🌈 **Colored Output** - Beautiful terminal output with colored formatting
- 📝 **Environment Variables** - Configure via `LAY_API_URL` env var
- 🔒 **Secure Password Input** - Hidden password prompts

## Installation

### From Source

```bash
cd cli
cargo build --release
```

The binary will be at `target/release/lay-cli`.

### Install to PATH

```bash
cargo install --path .
```

## Usage

### Global Options

```bash
lay-cli [OPTIONS] <COMMAND>

Options:
  -a, --api-url <API_URL>  API endpoint URL [env: LAY_API_URL] [default: http://localhost:8000]
  -v, --verbose            Enable verbose output (use -vv for debug)
  -o, --output <OUTPUT>    Output format: text, json, json-pretty [default: text]
  -h, --help              Print help
  -V, --version           Print version
```

### Authentication Commands

#### Register a New Account

```bash
# With password prompt (recommended)
lay-cli auth register --email user@example.com

# With password in command (not recommended for production)
lay-cli auth register --email user@example.com --password mypassword
```

#### Login

```bash
# With password prompt
lay-cli auth login --email user@example.com

# With password in command
lay-cli auth login --email user@example.com --password mypassword
```

#### Verify Email

```bash
lay-cli auth verify --email user@example.com --code 123456
```

#### Resend Verification Code

```bash
lay-cli auth resend-code --email user@example.com
```

#### Logout

```bash
lay-cli auth logout
```

### User Commands

#### Get Current User Info

```bash
lay-cli user me
```

#### List Users (Admin Only)

```bash
# List first 10 users
lay-cli user list

# List with pagination
lay-cli user list --limit 20 --offset 10
```

### Health Commands

#### Check API Health

```bash
lay-cli health check
```

#### Check Database Health

```bash
lay-cli health db
```

## Output Formats

### Text (Default)

Human-readable, colored output:

```bash
lay-cli auth register --email user@example.com
```

Output:
```
✓ Registration successful. Please check your email for verification code.
```

### JSON

Machine-readable JSON:

```bash
lay-cli --output json auth register --email user@example.com
```

Output:
```json
{"message":"Registration successful. Please check your email for verification code."}
```

### Pretty JSON

Formatted JSON for readability:

```bash
lay-cli --output json-pretty user me
```

Output:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "email_verified": true
}
```

## Configuration

### Environment Variables

```bash
# Set API URL via environment variable
export LAY_API_URL=https://api.example.com
lay-cli auth login --email user@example.com
```

### Stored Credentials

After successful verification, the authentication token is stored in `~/.lay/token`.

## Examples

### Complete Registration Flow

```bash
# 1. Register
lay-cli auth register --email user@example.com

# 2. Verify (check your email for the code)
lay-cli auth verify --email user@example.com --code 123456

# 3. Get your user info
lay-cli user me
```

### Login Flow

```bash
# 1. Login
lay-cli auth login --email user@example.com

# 2. Verify login (check your email for the code)
lay-cli auth verify --email user@example.com --code 654321

# 3. Get your user info
lay-cli user me
```

### Using with Different Environments

```bash
# Development
lay-cli --api-url http://localhost:8000 health check

# Staging
lay-cli --api-url https://staging.example.com health check

# Production
export LAY_API_URL=https://api.example.com
lay-cli health check
```

### Verbose Output

```bash
# Info level
lay-cli -v auth login --email user@example.com

# Debug level
lay-cli -vv auth login --email user@example.com
```

## Development

### Build

```bash
cargo build
```

### Run

```bash
cargo run -- --help
cargo run -- auth register --email test@example.com
```

### Test

```bash
cargo test
```

### Check

```bash
cargo check
```

## Architecture

The CLI follows modern Rust best practices:

- **Clap v4 Derive Macros** - Declarative CLI definition
- **Async/Await** - Tokio runtime for async operations
- **Reqwest** - HTTP client with rustls for TLS
- **Thiserror** - Custom error types
- **Colored** - Terminal color output
- **Rpassword** - Secure password input

### Project Structure

```
cli/
├── src/
│   ├── main.rs           # Entry point
│   ├── cli.rs            # CLI definitions (Clap)
│   ├── error.rs          # Error types
│   └── commands/
│       ├── mod.rs        # Command dispatcher
│       ├── auth.rs       # Authentication commands
│       ├── user.rs       # User commands
│       └── health.rs     # Health check commands
├── Cargo.toml
└── README.md
```

## Best Practices Implemented

Based on latest Clap v4 and Rust CLI recommendations:

1. **Derive Macros** - Using `#[derive(Parser)]` for clean, declarative CLI structure
2. **Subcommands** - Organized commands into logical groups (auth, user, health)
3. **Environment Variables** - Support for `LAY_API_URL` via `#[arg(env)]`
4. **Help Text** - Comprehensive help documentation with `///` doc comments
5. **Error Handling** - Custom error types with thiserror for better UX
6. **Output Formats** - Multiple output formats for different use cases
7. **Value Enums** - Type-safe output format selection
8. **Security** - Password prompts instead of command-line args
9. **Testing** - `Command::debug_assert()` for compile-time CLI validation
10. **Colored Output** - Enhanced readability with colored terminal output

## License

MIT
