# Security

DoxShield is a hackathon prototype. Do not use it as a production security boundary or a legal compliance assessment.

Never post credentials, OTPs, scan reports, browser databases or personal device information in public issues. Report suspected vulnerabilities privately to the repository owner through a verified private channel; use GitHub private vulnerability reporting if the owner enables it.

If a credential is exposed, revoke/rotate it with its provider, inspect provider activity and delivery logs, update local deployment configuration, and then remove it from every published reachable ref. Deleting a file or rewriting history does not revoke a key or erase clones/caches. Avoid publishing backup refs or archives containing the old history.

See SECURITY_REMEDIATION.md for the November 2026 local audit, configuration behavior changes and unresolved risks. Enable GitHub secret scanning, push protection, dependency alerts and private vulnerability reporting where available. These settings have not been changed by this cleanup.

## Secret scanning

Secrets are scanned both in CI and before each commit, using [gitleaks](https://github.com/gitleaks/gitleaks) (pinned to v8.30.1).

- **CI:** `.github/workflows/security-secret-scan` (`gitleaks.yml`) scans the working tree and the full commit history on every push and pull request, and fails the build on any finding.
- **Local pre-commit hook:** run `gitleaks protect --staged` before every commit. Enable it once, either way:
  - with the pre-commit framework — `pip install pre-commit && pre-commit install` (uses `.pre-commit-config.yaml`); or
  - dependency-light — `bash scripts/install-hooks.sh` (installs a git hook that only needs the `gitleaks` binary).

`.gitleaks.toml` keeps all default rules and allowlists only `.env.example`, which contains placeholders. Never add real secrets to the allowlist.

## Investigation agent (M4) security model

- The agent can only call read-only MCP tools while investigating. Action tools
  run only after a human approval that is bound to the exact payload, the
  investigation, an approver who did not start the run or propose the action, and
  is single-use and time-limited. Actions are drafts or dry-run rule files only.
- Tool output, app metadata, incident text and privacy policies are untrusted
  data: cleaned, bounded, never executed, and passed to a model only inside a
  marked data block. The model cannot call tools or create actions.
- The model gateway (`sidecar/ai/llm_gateway.py`) is off by default and only
  accepts a loopback Ollama host. LangSmith tracing is forced off.
- Demo identities (`DOXSHIELD_DEMO_IDENTITIES=1`) work only with the synthetic
  fixture backend.

## Local sidecar exposure

- Every sidecar HTTP request passes `sidecar/request_guard.py` before any
  handler runs:
  - `Host` must be a loopback name (blocks DNS rebinding);
  - local dev origins (`http://localhost:*`, `127.0.0.1`, `[::1]`) are allowed;
  - any other `Origin` is refused;
  - browser requests with a missing or opaque (`null`/`file://`) origin need the
    per-launch `X-DoxShield-Client` token. The packaged renderer sends no
    `Origin` from `file://`; websites' links, images, forms and sandboxed
    iframes have no token.
  CORS allows only local origins, and the sidecar has no WebSocket endpoints.
- The token is 32 bytes from Node's CSPRNG, generated at each launch and passed to the
  sidecar through its environment. It is never logged, stored or bundled. The
  Electron main process adds it only to requests from the app window's own pages
  and strips any value a page tries to set. The renderer cannot read it. The app
  window cannot navigate to other sites, and only `http(s)` links open externally.
- Local processes running as the same user are a separate boundary and are not
  authenticated (they could also read the sidecar's environment).
- With the fixture backend, the live monitor reads synthetic data only and no
  alert email is sent for synthetic observations or scans.
- See `docs/M4_AGENT.md` for limits and known limitations.
