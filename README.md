# Scopeguard — authorized audit starter

A small, modular FastAPI + Celery starter for **explicitly authorized, bounded web checks**. The included plugins send inert, bounded requests: one checks a declared query parameter for reflection, and one passively reviews common response security headers. Findings are observations for manual validation, not proof of exploitable vulnerabilities.

> Safety default: Docker Compose disables ordinary outbound masquerading on its app bridge, and only allows the `demo-target` hostname for manual checks. No public target is enabled by default. Keep the dashboard bound to localhost; authentication, TLS, tenant isolation, and a formal scope approval workflow are required before any shared or internet-facing deployment.

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
    security_headers.py   One-request passive header review
    registry.py           Explicit plugin registry
  source_analysis.py      Pinned-commit GitHub fetch and non-executing source checks
  static/index.html       Minimal monitoring dashboard
  demo_target.py          Private compose-only reflection fixture
Dockerfile
 docker-compose.yml       API, worker, beat, Redis, PostgreSQL, demo target
.env.example
requirements.txt
```

## Start the isolated demo

1. Copy `.env.example` to `.env` and change `POSTGRES_PASSWORD` to a local development value. Keep the provided `AUTHORIZED_HOSTS=demo-target` for the demo.
2. Start all local features from the project root with `docker compose -f docker-compose.yml -f docker-compose.discovery.yml -f docker-compose.source.yml -f docker-compose.webscan.yml up --build -d`. For the isolated local web demo only, `docker compose up --build -d` is enough.
3. Open `http://127.0.0.1:8000`. The dashboard is published only on loopback.
4. The dashboard pre-fills `http://demo-target:8080/search`; check the authorization confirmation and register it. The target has no host-published port and is reachable only on the isolated Compose network.
5. Select the registered target and choose a web check. **Parameter reflection** uses the declared `q` parameter and checks whether its inert marker appears in the response. **Passive response review** makes one GET request with a harmless Origin header, reads response headers only, and checks common browser security headers, cookie attributes, and CORS behavior. Logs stream in the browser and observations appear for manual review.
6. Use **Download manual report draft** on an observation to get a Markdown template with the target, observation, and spaces for your confirmed reproduction steps and impact. Validate it yourself and submit it through the program's official channel.
7. Inspect logs with the same four compose files followed by `logs -f web worker beat source-worker`. Stop the stack using those same four `-f` options followed by `down`. Add `-v` only when intentionally deleting persistent local database/Redis data.

## Discover public bounty opportunities

The dashboard currently searches the read-only HackerOne researcher API. Create a personal API token and set `HACKERONE_API_USERNAME` to your HackerOne username and `HACKERONE_API_TOKEN` to the token value in the local, ignored `.env` file. Never paste tokens into chat or commit them. Bugcrowd discovery is paused until researcher API credential access is clarified.

To enable **discovery API access only**, start with the optional Compose overlay:

```sh
docker compose -f docker-compose.yml -f docker-compose.discovery.yml up --build -d
```

The overlay gives the web/API container outbound network access to query the provider APIs. The web scan worker remains on the isolated network. The dashboard stays bound to localhost. This is still a local starter without app authentication, so do not expose it to a public interface. Use the same compose files with `down` to stop every service started by the overlays.

The new dashboard section searches the first page of your HackerOne account-visible listing (up to 100 programs), then fetches eligible scopes for at most 20 active public bounty programs per search. Pagination, account permissions, and update timing can limit results; every result is a snapshot. Open the official program brief and confirm the current policy, exact asset, exclusions, bounty eligibility, and rate limits before testing. Discovery never adds assets to scan targets or queues scans. Only `GET` API requests are issued.

## Campaign source review — first phase

1. Search HackerOne and use **Add to my campaigns** for a program you choose.
2. Open the official brief and review the displayed scope snapshot. Scope approval is blocked when the provider indicates that the snapshot is incomplete.
3. Approve the reviewed snapshot. This is your assertion that you checked the current program rules and scope; it does not independently verify authorization.
4. Enter a public GitHub repository that exactly matches a source-code asset in that campaign and a full 40- or 64-character commit SHA. The source worker checks the repository again against the approved snapshot before fetching it.
5. The dispatcher selects reusable checks from the catalogue according to repository contents. The source catalogue scans a bounded set of files for credential-like patterns (matched values are never saved), selected risky Python API patterns, and bundled Semgrep rules for JavaScript, TypeScript, Go, Java, PHP, Ruby, and C# when those languages are present. Semgrep uses local rules with metrics disabled; it does not fetch registry rules. Findings are candidates; inspect the exact commit and validate impact before reporting.

The source worker runs only when `docker-compose.source.yml` is included. It has a separate queue, no HackerOne credentials, a read-only container filesystem, and a 500 MB temporary workspace. The worker validates GitHub-only repository URLs and disables Git redirects; its Docker bridge itself permits outbound connectivity generally, so production use should add a domain-level egress firewall. It never runs the repository's tests, build scripts, package installers, or other project code. The bundled rules cover a small set of patterns and do not replace dependency advisory analysis or deeper taint analysis. Source scans are pinned to an immutable commit and produce a manual report draft through the dashboard.

## Campaign app checks

1. Add a HackerOne campaign and approve its complete current scope as above.
2. Select that campaign and enter an HTTPS URL whose exact host and any path restriction match an asset in the approved snapshot. The dispatcher always runs the passive response review. If you enter up to three declared query parameter names, it also runs the inert reflection check.
3. The worker rechecks campaign approval and asset matching before it sends requests. Requests are bounded, use GET only, do not follow redirects, and the reflection response read is capped. Review each candidate and download its manual report draft.

Include `docker-compose.webscan.yml` only when you are ready to scan a public campaign asset. It gives the web worker an outbound network route; the application still checks the exact campaign asset and public DNS result, but this bridge is not a network-layer destination firewall. Keep the dashboard on loopback and use only campaigns and checks allowed by the current program policy.

## Two campaign-specific AI agents

The dashboard's **Campaign agents** action starts a campaign planner and a source-review agent for the campaign you select. First save the current official policy and approve the complete scope snapshot. If discovery did not return the policy, paste it into the campaign's policy field and save; that clears approval so you must review and approve the updated snapshot again. The planner may queue only the existing bounded web checks against an exact approved HTTPS asset. The source agent runs the existing non-executing source checks against a public GitHub repository named in the approved scope or policy, resolves the default branch to a full commit SHA, then reviews bounded credential-redacted excerpts from that pinned revision. Programs that clearly require a locally owned installation (including the Phabricator wording in its published brief) are not tested remotely.

These agents use the OpenAI Responses API. Add `OPENAI_API_KEY` to your ignored local `.env`; never put it in the dashboard or commit it. The policy, approved asset list, static findings, and up to 30 KB of small redacted source excerpts may be sent to OpenAI. Each run stores its policy/scope snapshot, pinned SHA, plans, and candidate results for review. The agents do not submit reports. Start with all four overlays:

```sh
docker compose -f docker-compose.yml -f docker-compose.discovery.yml -f docker-compose.webscan.yml -f docker-compose.agents.yml up --build -d
```

The `agent-worker` gets the OpenAI key and outbound route; the ordinary web/API container does not receive that key. The app-check agent still needs the webscan overlay because it queues the existing web worker. The agent queue indicator appears in the dashboard worker badge. To stop these services, use the same four compose files with `down`.

Alternative smoke test: `curl http://127.0.0.1:8000/health` should return `{"status":"ok"}`.

## API

- `POST /api/targets` — register a URL and explicit authorization assertion.
- `GET /api/targets` — list targets.
- `POST /api/jobs` — queue the registered target's plugin with declared parameter names.
- `GET /api/jobs`, `GET /api/jobs/{id}` — job status.
- `GET /api/jobs/{id}/logs?after_id=0` — log records.
- `GET /api/jobs/{id}/events` — Server-Sent Events stream; supports `Last-Event-ID` via `after_id` query parameter.
- `GET /api/findings` — deduplicated findings.
- `GET /api/findings/{id}/report` — download an unconfirmed Markdown report draft for manual completion.
- `GET /api/workers` — Celery worker ping status.
- `GET /api/plugins` — plugin registry (parameter reflection and passive HTTP response review).
- `GET /api/test-programs` — reusable source and web check catalogue.
- `POST /api/campaigns` / `GET /api/campaigns` — store and list researcher-selected campaign scope snapshots.
- `PUT /api/campaigns/{id}/scope` — refresh a snapshot from a new provider search; this resets approval.
- `POST /api/campaigns/{id}/approve-scope` — record your review of a complete scope snapshot.
- `POST /api/campaigns/{id}/agents` — queue both campaign-specific agents for an approved campaign.
- `GET /api/campaign-agent-runs` and `GET /api/campaign-agent-runs/{id}` — inspect their plans and review candidates.
- `GET /api/campaign-agent-runs/{id}/report` — download a combined manual review draft (never submitted automatically).
- `POST /api/campaigns/{id}/web-runs` — automatically dispatch campaign app checks for an exact approved HTTPS asset.
- `GET /api/campaign-web-runs` and `GET /api/campaign-web-runs/{id}/report` — view app run results and download a manual report draft.
- `POST /api/campaigns/{id}/source-runs` — queue automatic source-check dispatch for an in-scope GitHub repository and pinned commit.
- `GET /api/source-runs` and `GET /api/source-runs/{id}/report` — view source review results and download a manual report draft.
- `GET /api/opportunities?search=<term>` — read-only, account-authenticated HackerOne program discovery.

Interactive API documentation is available at `/docs`.

## Add a plugin

Subclass `BaseScannerPlugin` in `app/plugins/`, implement its async `scan(base_url, options, log)` method, return `PluginFinding` values, then register an instance in `app/plugins/registry.py`. Keep plugins inside the policy envelope: validate scope before each request; use fixed timeouts, small response limits, no redirects, conservative request counts/rates, and no state-changing methods. Do not implement unrestricted crawling, brute-force/fuzzing, exploit payloads, or arbitrary URL fetches in this starter. Source review uses bundled static rules; it does not run repositories' tests, builds, or package installers. The tool does not submit findings to bounty programs.

For open-source projects or beta versions, register only a deployment that the relevant program explicitly includes in scope, and check the program's rules and rate limits before scanning. Treat every result as a lead: reproduce it safely, confirm impact, check for duplicates, and prepare the report manually. The tool does not determine bounty eligibility or guarantee payment.

### Real target access

The default Compose network disables ordinary outbound masquerading and only `demo-target` is allowed for manual web targets. This is a practical local default, not a network-layer firewall. Campaign-based app runs can be enabled with `docker-compose.webscan.yml`; that overlay gives the web worker an outbound bridge, while application checks still require an approved campaign and an exact scope match. The local dashboard has no authentication. Do not expose it publicly. A production deployment needs authenticated access, expiring scope records, audit history, destination controls, and a reviewed egress proxy/firewall with DNS-rebinding-resistant destination pinning.

## Scope and operational safeguards

- Manual targets require exact hostnames in `AUTHORIZED_HOSTS`; wildcard allowlist entries are not supported. Campaign web targets must match an exact or wildcard scope asset and resolve to public IPs. `demo-target` is the only HTTP exception for manual demo use; campaign app checks require HTTPS.
- Campaign web checks make one passive GET plus at most three inert reflection GETs when parameter names are supplied. The reflection check disables redirects, caps response reads at 64 KiB, retries a connection/timeout failure once, and sleeps between attempts.
- Default Compose disables bridge masquerading to reduce ordinary worker egress while keeping the dashboard's loopback port available. This is not an egress firewall. The opt-in web-scan overlay adds an outbound bridge for campaign checks, but does not restrict destinations at the network layer. **Do not expose the dashboard or enable this overlay casually.** A production deployment requires a controlled egress proxy/firewall, DNS-rebinding-resistant destination pinning, per-target quotas, and explicit scope verification—not just a hostname setting.
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
