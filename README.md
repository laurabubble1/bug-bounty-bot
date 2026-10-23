# Scopeguard — authorized audit starter

A small, modular FastAPI + Celery starter for **explicitly authorized, bounded web checks**. The included plugin sends one inert, unique marker per declared query parameter, does not execute payloads, and records only a short finding description—not response bodies.

> Safety default: Docker Compose uses an isolated internal network and only allows the `demo-target` hostname. No public target is enabled by default. Keep the dashboard bound to localhost; authentication, TLS, tenant isolation, and a formal scope approval workflow are required before any shared or internet-facing deployment.

## Structure

```text
app/
  api.py                  REST API and SSE log stream
  main.py                 FastAPI lifecycle and dashboard serving
  models.py               Target, Endpoint, ScanJob, Finding, LogEntry
  schemas.py              Request/response validation
  tasks.py                Celery job execution and retention task
  core/
    config.py             Environment-backed settings
    database.py           Async SQLAlchemy engine/session
    celery_app.py         Celery/Redis configuration and schedule
    security.py           Exact-host allowlist and URL/IP checks
  plugins/
    base.py               BaseScannerPlugin extension interface
    reflection.py         Bounded benign-marker example plugin
    registry.py           Explicit plugin registry
  static/index.html       Minimal monitoring dashboard
  demo_target.py          Private compose-only reflection fixture
Dockerfile
 docker-compose.yml       API, worker, beat, Redis, PostgreSQL, demo target
.env.example
requirements.txt
```

## Start the isolated demo

1. Copy `.env.example` to `.env` and change `POSTGRES_PASSWORD` to a local development value. Keep the provided `AUTHORIZED_HOSTS=demo-target` for the demo.
2. Start services from the project root with `docker compose up --build -d`.
3. Open `http://127.0.0.1:8000`. The dashboard is published only on loopback.
4. The dashboard pre-fills `http://demo-target:8080/search`; check the authorization confirmation and register it. The target has no host-published port and is reachable only on the isolated Compose network.
5. Select the registered target, leave the parameter as `q`, and queue the reflection check. Logs stream in the browser; the demo fixture returns the inert marker and a low-severity informational finding appears.
6. Inspect service logs with `docker compose logs -f web worker beat`, and stop the stack with `docker compose down`. Add `-v` only when intentionally deleting persistent local database/Redis data.

Alternative smoke test: `curl http://127.0.0.1:8000/health` should return `{"status":"ok"}`.

## API

- `POST /api/targets` — register a URL and explicit authorization assertion.
- `GET /api/targets` — list targets.
- `POST /api/jobs` — queue the registered target's plugin with declared parameter names.
- `GET /api/jobs`, `GET /api/jobs/{id}` — job status.
- `GET /api/jobs/{id}/logs?after_id=0` — log records.
- `GET /api/jobs/{id}/events` — Server-Sent Events stream; supports `Last-Event-ID` via `after_id` query parameter.
- `GET /api/findings` — deduplicated findings.
- `GET /api/workers` — Celery worker ping status.
- `GET /api/plugins` — plugin registry.

Interactive API documentation is available at `/docs`.

## Add a plugin

Subclass `BaseScannerPlugin` in `app/plugins/`, implement its async `scan(base_url, options, log)` method, return `PluginFinding` values, then register an instance in `app/plugins/registry.py`. Keep plugins inside the policy envelope: validate scope before each request; use fixed timeouts, small response limits, no redirects, conservative request counts/rates, and no state-changing methods. Do not implement unrestricted crawling, brute-force/fuzzing, exploit payloads, or arbitrary URL fetches in this starter.

## Scope and operational safeguards

- Only exact hostnames in `AUTHORIZED_HOSTS` are accepted; wildcards are not supported. `demo-target` is the only HTTP exception. Other targets must use HTTPS and resolve to public IPs.
- The worker disables redirect-following, caps response reads at 64 KiB, sends at most one request per declared parameter plus one retry for a connection/timeout failure, and sleeps between attempts. Job input is capped at three parameter names by the API schema and plugin settings.
- Compose uses an `internal: true` network to prevent worker egress. **Do not remove this isolation casually.** A real deployment requires a controlled egress proxy/firewall, DNS-rebinding-resistant destination pinning, per-target quotas, and explicit scope verification—not just a hostname setting.
- The API has no authentication. Compose binds its port to `127.0.0.1`; do not bind it to a public interface or place it behind a public proxy without adding authentication, authorization, CSRF protections where applicable, TLS, and audit logging.
- `.env.example` values are development defaults, not production secrets. Store production credentials in a secret manager.
- Startup uses `Base.metadata.create_all` for convenience. Adopt Alembic migrations before production use.
- Celery Beat runs daily retention: log rows older than `LOG_RETENTION_DAYS` and completed/failed jobs older than `JOB_RETENTION_DAYS` are removed. Job deletion cascades to associated findings/logs; PostgreSQL data persists in named volumes.

## Deployment note

The supplied Compose file is a local/VPS **starter**, not a production-secure deployment. For production, pin and scan image versions, add reverse-proxy TLS and authentication, rotate secrets, add database backups and migrations, resource limits, alerting, and an outbound network policy. Enable only authorized egress and preserve target-level rate limits. Review legal and program rules before every assessment.

## CI and Git workflow

The GitHub Actions workflow at `.github/workflows/ci.yml` runs Ruff and Mypy, then pytest against PostgreSQL 16 and Redis 7, and builds the Docker image. Pytest enforces a 70% coverage minimum. Pip dependencies are cached using the requirements files. Run the same checks locally after installing `requirements-dev.txt`.

Suggested branch model: protect `main` as the release branch; use `develop` for integration if the team needs a staging branch; create short-lived branches such as `feature/<topic>` or `fix/<topic>` from `develop` (or `main` for trunk-based teams), then merge through reviewed pull requests. Require CI checks on protected branches.

### Initialize and push the first Git commit

These commands are for a repository that has not yet been initialized. Replace the remote URL with the repository you created on GitHub. If using only `main`, omit the `develop` branch commands.

```sh
git init -b main
git add .
git commit -m "chore: initialize backend and CI"
git remote add origin https://github.com/OWNER/REPOSITORY.git
git push -u origin main
git switch -c develop
git push -u origin develop
```

Do not commit `.env`; the tracked `.env.example` contains only local development defaults. Add branch protection and require the workflow checks in GitHub repository settings.
