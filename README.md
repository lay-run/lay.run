# Lay

## Project Structure

```
lay/
├── backend/     # Rust backend service
├── cli/         # Command-line interface
└── process-compose.yml
```

## Setup

Development environment managed with [Devbox](https://www.jetify.com/devbox).

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
