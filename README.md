# SecureAuthService

SecureAuthService is a production-ready authentication microservice designed for banking-grade workloads. It implements strong password handling, multi-factor authentication (TOTP and WebAuthn/Passkeys), rate limiting, CSRF protection, audit logging, and session management built on **FastAPI**, **SQLAlchemy 2.x**, **Alembic**, **PostgreSQL**, **Redis**, and **Gunicorn/Uvicorn**.

## Features

- **Strong credential storage** using Argon2id with configurable cost factors and a 10k password blacklist.
- **Email verification** and asynchronous SMTP delivery.
- **Session-based authentication** with HttpOnly, Secure, SameSite=Strict cookies and sliding idle timeout.
- **CSRF protection** using the double-submit token pattern.
- **Multi-factor authentication** via TOTP and WebAuthn/Passkeys.
- **Password reset** with single-use, time-bound tokens.
- **Rate limiting** and account lockout protection backed by Redis.
- **Audit logging** of authentication events.
- **Role-based access control** (user, staff, admin) and step-up authentication checks.
- **Comprehensive test suite** with pytest, httpx, coverage, and containerized Postgres/Redis via testcontainers.

## Project Structure

```
app/
  api/            # FastAPI routers and dependencies
  core/           # Configuration, security utilities, rate limiter
  db/             # Database models and session management
  middleware/     # Security middlewares
  schemas/        # Pydantic schemas
  services/       # Domain services (email, tokens, TOTP, WebAuthn, sessions)
  utils/          # Reusable helpers (cookies, Redis client)
alembic/          # Migration environment and versions
resources/        # Password blacklist (top 10k common passwords)
tests/            # Async integration tests
```

## Requirements

- Python 3.11+
- PostgreSQL 15+
- Redis 7+
- Access to SMTP server (Mailhog included in Docker for local development)
- `pip`, `virtualenv`, and optionally `docker`/`docker compose`

## Environment Configuration

Copy `.env.example` to `.env` and adjust values:

```bash
cp .env.example .env
```

Key variables:

- `DATABASE_URL`: Async SQLAlchemy DSN (e.g. `postgresql+asyncpg://user:pass@host:5432/db`).
- `REDIS_URL`: Redis connection string (e.g. `redis://localhost:6379/0`).
- `SECRET_KEY`: Application signing secret.
- `CSRF_SECRET`: Secret used when deriving CSRF tokens.
- `TOTP_ENCRYPTION_KEY`: 32-character key used to encrypt TOTP secrets at rest (recommend storing in a KMS in production).
- `FRONTEND_ORIGIN`: Allowed CORS origin for browser clients.
- `SMTP_*`: SMTP credentials for email delivery.
- `WEBAUTHN_RP_ID` / `WEBAUTHN_RP_NAME`: Relying Party configuration for WebAuthn/Passkeys.

> **Security Note:** In production environments secrets should be loaded from a dedicated secret manager (AWS KMS/Secrets Manager, GCP Secret Manager, Hashicorp Vault, etc.) and rotated regularly. TLS termination with HSTS enforcement must be handled at the edge/reverse proxy.

## Local Development

### Install Dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pre-commit install
```

### Database Migration

Run Alembic migrations against your configured database:

```bash
alembic upgrade head
```

### Start the API (development)

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The OpenAPI docs are available at `http://localhost:8000/docs`.

### Redis & Mailhog (optional)

For local testing you can run Redis and Mailhog using Docker compose:

```bash
docker compose up redis mailhog
```

Mailhog UI: `http://localhost:8025`

## Docker Deployment

A production-ready container is provided via the `Dockerfile` and `docker-compose.yml`.

```bash
docker compose up --build
```

Services:

- `api`: FastAPI service served by Gunicorn + Uvicorn workers.
- `db`: PostgreSQL 15.
- `redis`: Redis 7 (rate limiting, session metadata, MFA challenges).
- `mailhog`: SMTP sink for local email preview.

## Running Tests

The tests spin up ephemeral PostgreSQL and Redis containers using `testcontainers`. Docker must be available in the environment.

```bash
pytest
```

To generate coverage:

```bash
coverage run -m pytest
coverage html
```

## Rate Limiting & Security Headers

- SlowAPI enforces limits (default 50 requests / 10 minutes) on `/auth/*` endpoints backed by Redis.
- Additional lockout logic protects against brute-force login attempts.
- HTTP responses include strict security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`).
- Session cookies are HttpOnly, Secure, and `SameSite=Strict`.
- CSRF protected endpoints require the `X-CSRF-Token` header matching the `csrf_token` cookie (double-submit strategy).

## Alembic Migrations

Generate new migrations with:

```bash
alembic revision --autogenerate -m "describe change"
```

Apply migrations:

```bash
alembic upgrade head
```

Downgrade (for development/testing only):

```bash
alembic downgrade base
```

## Pre-commit Hooks

Run formatting and linting:

```bash
pre-commit run --all-files
```

Configured hooks:

- `black` (code formatting)
- `isort` (import sorting)
- `flake8` (linting with bugbear extensions)

## Thunder Client / Postman Collection

A Thunder Client (compatible with Postman) export is provided at `postman/secure-auth-collection.json`. Import it into your API client and set the `BASE_URL` environment variable to target your deployment (e.g. `http://localhost:8000`).

## Production Hardening Checklist

- Terminate TLS with HSTS enabled (e.g. via Nginx/Envoy/Cloud load balancer).
- Enable logging aggregation and SIEM monitoring of `audit_logs`.
- Store secrets in a managed vault and enable automatic rotation.
- Use managed database services with encryption at rest and backup policies.
- Monitor Redis and Postgres capacity; tune slowapi limits to business requirements.
- Configure a Web Application Firewall (WAF) and DDoS protection.
- Integrate background job runner (Celery/RQ) for high-volume email delivery if required.

