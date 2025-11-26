# Lay

## Project Structure

```
lay/
├── backend/     # Rust backend service
├── cli/         # Command-line interface
└── process-compose.yml
```

## Requirements

- [Devbox](https://www.jetify.com/devbox)
- [direnv](https://direnv.net/)

Devbox manages all other dependencies (Rust, Podman, PostgreSQL client, AWS CLI).

## Setup

Install dependencies and enter development shell:

```bash
devbox shell
```

## Running

Start all services in background:
```bash
devbox run up
```

View logs (Ctrl+B then D to detach):
```bash
devbox run logs
```

Stop all services:
```bash
devbox run down
```
