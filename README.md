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
# From the local sanitized checkout supplied with this cleanup:
cd DoxShield-sanitized
python3 -m venv sidecar/.venv
sidecar/.venv/bin/python -m pip install -r sidecar/requirements.txt
npm ci
cp .env.example .env
```

The public remote still has a license-only `main`; `local-main` retains exposed history. Clone instructions will be updated after approved publication.

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

## Validation and builds

```bash
npm run build
./node_modules/.bin/tsc --noEmit -p tsconfig.node.json
./node_modules/.bin/tsc --noEmit -p tsconfig.web.json
sidecar/.venv/bin/python -m unittest discover -s tests -v
sidecar/.venv/bin/python -m pip check
bash -n setup.sh start.sh
gitleaks git . --log-opts='--all --full-history' --redact=100
```

`npm run pack` creates an unpacked distribution; `npm run dist` invokes electron-builder for a macOS ARM64 DMG. Run the build first. Packaged Python/runtime availability, signing and notarization require separate validation. There is no `build:mac` script. Type checking currently reports inherited unused declarations, missing preload API declarations and an alert argument type mismatch; the Vite build passes independently. See [the remediation report](SECURITY_REMEDIATION.md) for exact results and remaining risks.

## Security, privacy and limitations

Local inference does not mean fully offline operation: policy pages are downloaded, the IP geolocation fallback queries a third-party HTTP service with destination IPs, and optional email delivery shares email/alert information with Resend. Local caches can contain sensitive device observations; safeguard them and remove them when appropriate. Cookies and permissions may be inaccessible.

The sidecar binds to loopback but most data/settings endpoints have no authentication and CORS is permissive. OTP abuse controls and Electron sandbox/distribution hardening need further review. Keep this hackathon application on a trusted machine. It is not production-certified, a compliance assessment or an autonomous security system. No new agentic functionality is part of this maintenance.

## Acknowledgments and license

Original project: **Team Exxeta1**, Q-Hack 2026, Exxeta Digital Independence & Digital Sovereignty challenge. The original README described the project as the challenge winner; that award claim has not been independently verified in this cleanup. Individual team-member roles and Soham Shinde's specific contributions are **pending team confirmation**. Existing source and team attribution are retained without inventing individual responsibilities.

[MIT License](LICENSE), with the original 2026 copyright notice retained from the repository's `main` branch.
