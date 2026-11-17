# DoxShield — Team Exxeta1

DoxShield is a team-built Q-Hack 2026 project exploring data sovereignty and privacy risks on macOS. It combines local device observations with vendor information and local language-model analysis to help users inspect potential risks. Scores are heuristic indicators, not proof of data transfers or legal compliance.

## Implemented capabilities

- Installed application inventory and macOS TCC permission inspection.
- Active TCP connection monitoring, jurisdiction estimates and tracker matching.
- Browser cookie inspection, subject to macOS permissions and browser support.
- Risk scoring, consumer/business dashboards and PDF reporting.
- Privacy-policy retrieval and analysis through Ollama/Mistral, with local caching.
- Local alerts, optional Resend email alerts, and custom email OTP/JWT login.

## Architecture

Electron launches a Python FastAPI sidecar on `127.0.0.1:8765`. The React/TypeScript renderer reads REST endpoints and server-sent events. The sidecar contains `scanner/`, `ai/`, `alerts/` and JSON reference datasets. Persistent scan results, settings, policy caches and alert history live in `~/.doxshield`.

Stack: Electron, React, TypeScript, Vite, Tailwind, Zustand, FastAPI, Pydantic, httpx, Ollama and Resend. The original [architecture diagram](architecture-diagram.png) is retained as a historical project asset; this README describes the inspected implementation.

## Local setup

Use macOS, Node.js 18+ with npm, Python 3.11+ and, for policy analysis, Ollama with the Mistral model. Native scanners need macOS utilities and permissions. Model downloads need several GB of disk space.

```bash
git clone https://github.com/sohamshindework/DoxShield-Exxeta1.git
cd DoxShield-Exxeta1
python3 -m venv sidecar/.venv
sidecar/.venv/bin/python -m pip install -r sidecar/requirements.txt
npm ci
cp .env.example .env
```

The `main` branch contains the cleaned application history through M4. The legacy `local-main` branch is outside this cleaned lineage; use `main` for development and do not merge the legacy history into it.

Alternatively, `./setup.sh` installs/checks Homebrew, Python, Node and Ollama, pulls Mistral, creates the virtual environment and installs dependencies. Review it first: it can install system tools. The manual steps give control over those installations. Python dependencies currently have minimum versions rather than a lockfile.

## Environment and running

Edit the root `.env` locally; it must never be committed. The backend loads that file explicitly without overriding exported variables.

| Variable | Purpose |
| --- | --- |
| `JWT_SECRET` | Server-only signing secret, at least 32 characters and unique; required for OTP login. Set it privately yourself. |
| `RESEND_API_KEY` | Server-only provider key for OTP emails and optional email alerts. |
| `SIDECAR_PORT` | Keep `8765`; renderer URLs currently use that fixed port. |
| `OLLAMA_HOST` | Defaults to local Ollama at `http://localhost:11434`. A remote value sends model inputs to that server. |
| `OLLAMA_MODEL` | Defaults to `mistral`. |
| `CLERK_PUBLISHABLE_KEY`, `VITE_CLERK_PUBLISHABLE_KEY` | Optional public configuration retained for compatibility; current login uses custom OTP, not Clerk. |

No Clerk secret is required by the inspected application. Never prefix server credentials with `VITE_`, which exposes values to renderer bundles. Missing email configuration disables email login/delivery; onboarding can be skipped for local scanning. Delivery failures no longer print OTPs or pretend email was sent. Changing `JWT_SECRET` invalidates existing signed sessions.

```bash
ollama serve                 # in another terminal, if not already running
ollama pull mistral          # one-time model download
./start.sh                   # launches Electron; Electron starts the sidecar
```

For backend-only development: `sidecar/.venv/bin/python sidecar/main.py`. Grant Full Disk Access only if you intend to inspect protected browser/TCC databases. Missing permissions can leave observations incomplete.

## Scanner backends and demo mode

DoxShield selects a scanner backend with the `DOXSHIELD_BACKEND` environment variable:

- `macos` (default): the real system scanners. macOS only; needs the usual permissions.
- `fixture`: synthetic, clearly-labelled sample data from `sidecar/fixtures/`. It performs no system access, runs anywhere (Linux, CI, demos), and cannot switch to real scanning. Responses carry `"synthetic": true`, and `/health` reports the active backend.

```bash
DOXSHIELD_BACKEND=fixture sidecar/.venv/bin/python sidecar/main.py
```

IP geolocation is offline only: private/loopback detection plus the bundled provider ranges in `sidecar/data/ip_ranges.json`. No observed IP address is sent to any third-party service; addresses that cannot be resolved locally are reported as Unknown.

## Incidents and storage

Scan results become structured incidents through explicit detection rules
(`sidecar/incidents/detection.py`): a transfer to a destination without an EU
adequacy decision combined with a sensitive app permission, a connection or
cookie matching a known tracker, and a new destination country for an app
(against a baseline). Each incident cites the exact evidence it was built from,
tags that evidence as an observed fact, a heuristic indicator or an AI
interpretation, and carries a heuristic (not calibrated) confidence with a
"for DPO review" follow-up. No incident states a legal conclusion.

Incidents, evidence, proposed actions, approvals and an append-only audit log are
stored with SQLAlchemy (`sidecar/incidents/`). The database is chosen by
`DATABASE_URL` and defaults to a local SQLite file, so development and tests need
no server. `docker-compose` provides PostgreSQL 16, and Alembic manages the schema:

```bash
docker compose up -d db
export DATABASE_URL=postgresql+psycopg://doxshield:doxshield@localhost:5432/doxshield
pip install "psycopg[binary]>=3.1"
alembic upgrade head
```

The audit log is hash-chained: each event stores the previous event's hash, and
`verify_audit_chain` recomputes the chain to detect tampering.

## MCP tool server

DoxShield exposes its capabilities over the Model Context Protocol
(`sidecar/mcp_server/`, official SDK). Read-only investigation tools are the
default (app inventory, connections, offline IP jurisdiction, tracker checks,
permissions, knowledge search, EU alternatives, incident and evidence retrieval,
heuristic risk indicators). Action tools — DPO-notification draft, ticket draft,
alert-email draft, and a dry-run block-rule generator — refuse to run without a
valid, matching, approved `approval_id`. Block rules are written to a file and
never applied; alert emails are drafted, never sent; no tool returns secrets.

```bash
cd sidecar && DOXSHIELD_BACKEND=fixture .venv/bin/python -m mcp_server.server   # stdio MCP server
```

## Investigation agent (M4)

A single LangGraph agent (`sidecar/agent/`) investigates an incident or app:
**triage → investigate → assess → propose actions → human approval → execute →
report**. It gathers evidence only through the MCP read-only tools, under a tool
budget, and every claim in its assessment cites evidence it actually retrieved.
It pauses with a LangGraph interrupt before any action; an approver (never the
person who started the run) approves each exact payload once, and only drafts or
dry-run rule files are produced. With no local model configured the assessment is
rules-only and says so. See [docs/M4_AGENT.md](docs/M4_AGENT.md) for the graph,
budgets, approval model, data boundaries and limitations.

```bash
.venv/bin/alembic upgrade head
cd sidecar && DOXSHIELD_BACKEND=fixture DOXSHIELD_DEMO_IDENTITIES=1 ../.venv/bin/python main.py
```

## Validation and builds

```bash
npm run build
./node_modules/.bin/tsc --noEmit -p tsconfig.node.json
./node_modules/.bin/tsc --noEmit -p tsconfig.web.json
DOXSHIELD_BACKEND=fixture sidecar/.venv/bin/python -m pytest -q   # Python tests, synthetic backend
ruff check sidecar/scanner/backend.py sidecar/scanner/ip_geo.py sidecar/incidents sidecar/mcp_server sidecar/agent sidecar/ai/llm_gateway.py tests
DATABASE_URL=sqlite:///tmp-check.db alembic upgrade head && DATABASE_URL=sqlite:///tmp-check.db alembic check
sidecar/.venv/bin/python -m pip check
bash -n setup.sh start.sh
gitleaks git . --log-opts='--all --full-history' --redact=100
```

`npm run pack` creates an unpacked distribution; `npm run dist` invokes electron-builder for a macOS ARM64 DMG. Run the build first. Packaged Python/runtime availability, signing and notarization require separate validation. There is no `build:mac` script. Type checking currently reports inherited unused declarations, missing preload API declarations and an alert argument type mismatch; the Vite build passes independently. See [the remediation report](SECURITY_REMEDIATION.md) for exact results and remaining risks.

## Security, privacy and limitations

Local inference does not mean fully offline operation: the scan flow downloads policy pages, and optional email delivery shares email/alert information with Resend. IP geolocation has been offline-only since M1. The M4 agent sends nothing off the machine by default: its model gateway accepts only a local Ollama host, and policy fetching is opt-in. Local caches can contain sensitive device observations; safeguard them and remove them when appropriate. Cookies and permissions may be inaccessible.

The sidecar binds to loopback and refuses requests driven by other websites: only local renderer origins are accepted, the packaged app proves itself with a per-launch token, and CORS is limited to local origins (`sidecar/request_guard.py`). Most data/settings endpoints still have no user authentication, so any local process can call them. OTP abuse controls and Electron sandbox/distribution hardening need further review. Keep this hackathon application on a trusted machine. It is not production-certified, a compliance assessment or an autonomous security system. The M4 agent provides decision support only; every action needs human approval and is limited to drafts and dry-run rule files.

## Acknowledgments and license

Original project: **Team Exxeta1**, Q-Hack 2026, Exxeta Digital Independence & Digital Sovereignty challenge. The original README described the project as the challenge winner; that award claim has not been independently verified in this cleanup. Individual team-member roles and Soham Shinde's specific contributions are **pending team confirmation**. Existing source and team attribution are retained without inventing individual responsibilities.

[MIT License](LICENSE), with the original 2026 copyright notice retained from the repository's `main` branch.
