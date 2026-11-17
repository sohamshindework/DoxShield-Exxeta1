# Changelog

Development of the cleaned DoxShield project, by milestone. Dates are 2026.

## M4 — LangGraph investigation agent (17 Nov)

- Added one bounded LangGraph agent (`sidecar/agent/`): triage → investigate
  (one MCP read-only call per step) → assess → propose actions → `await_approval`
  (LangGraph `interrupt`) → execute → report. The plan is deterministic; the model
  never chooses tools, sets priority or proposes actions.
- The agent talks to the existing MCP server through an MCP client session, with a
  read/action scope split, client timeout and strict response parsing. Budgets:
  14 tool calls (retries included), 40 graph steps, 40 evidence items, no retries
  for action tools.
- Evidence records with provenance, trust level, limitations and hash are stored
  in `investigation_evidence`; every claim is checked in code against them. Claims
  are typed observed / inference / uncertainty / recommendation; legal
  conclusions are rejected. Review priority is a documented rule, not a score.
- **Approval gate strengthened (same system as M3):** approvals are now bound to
  the exact payload hash, investigation and incident, approver role and
  non-proposer identity; single-use (atomic consume); expire after 24 h; invalid
  after revision or cancellation. The MCP action tools enforce this; the agent
  re-validates before calling them. M3 test helper updated to create bound
  approvals (no assertions removed).
- Added `ai/llm_gateway.py` (off by default; local Ollama only; record/replay for
  tests) and opt-in privacy-policy statement extraction with verbatim-quote checks
  and prompt-injection flags. LangSmith tracing forced off.
- API: `/api/incidents`, `/api/incidents/detect`, `/api/investigations…`
  (start, progress, decision, revise, cancel, report), `/api/audit/verify`. Roles
  viewer / analyst / approver from the signed login token; fixture-only demo
  identities; Origin guard on state-changing routes.
- UI: an Investigations page (progress, evidence, assessment, approval review,
  execution status, report) using the existing design system.
- Alembic migration `a4c1e2f0b7d3` (investigations, investigation evidence,
  approval-binding columns).
- Fixed an M2 defect: detection reused one evidence object across two incidents,
  so saving all detected incidents failed on a duplicate evidence id.
- Tests: 88 new (141 total). Docs: `docs/M4_AGENT.md`.
- **Security fixes (pre-existing P1s):**
  - The live network monitor called the macOS scanner directly, even with
    `DOXSHIELD_BACKEND=fixture`, and could email alerts. It now uses the selected
    backend, and no alert email is sent for synthetic observations or scans.
  - CORS allowed every origin, so any website could drive the sidecar (change
    settings, trigger scans and alert emails). Added `sidecar/request_guard.py`:
    foreign origins and cross-site requests are refused, the packaged Electron
    renderer authenticates with a per-launch token (`X-DoxShield-Client`), and
    CORS is limited to local origins. 16 tests (157 total).
- **Packaged-app verification (17 Nov):** the real packaged app was launched and
  driven over DevTools. Defects found and fixed:
  - Every renderer request got 403. Chromium sends `file://` requests with **no**
    `Origin` (not `null`), so the guard refused them before checking the token.
    Browser requests with a missing or opaque origin are now allowed only with
    the token.
  - The token was attached to sidecar requests from any page in the session.
    It is now limited to the app window's own pages, and that window can no
    longer navigate away from the app. `window.open` only opens `http(s)` links
    externally.
  - DNS rebinding: requests with a non-loopback `Host` are refused.
  - Fixture isolation: synthetic full scans no longer fetch vendor policy pages
    or call a model, and the icon endpoint no longer runs `mdfind`/`sips` on the
    real machine in fixture mode.
  - 13 new or updated regression tests (170 total).

## M3 — MCP tool server (16 Nov)

- Added an MCP server (`sidecar/mcp_server/`) exposing DoxShield capabilities over
  the Model Context Protocol (official SDK, FastMCP). Tool logic lives in plain,
  testable methods; the server is a thin adapter with a per-tool timeout.
- Read-only tools: `list_apps`, `get_app_details`, `get_connections`,
  `lookup_ip_jurisdiction` (offline), `check_tracker`, `get_permissions`,
  `analyze_privacy_policy` (returns the policy URL; model analysis is M4),
  `search_knowledge`, `find_eu_alternatives`, `get_incidents`, `get_evidence`,
  `local_risk_indicators`.
- Gated action tools: `draft_dpo_notification`, `create_ticket`,
  `send_alert_email` (drafts only, never sends), `propose_block_rule` (dry-run —
  writes a rule file, never touches the firewall). Each refuses to run without a
  valid, matching, approved `approval_id`.
- No tool exposes secrets or `.env`. Added seed knowledge files
  (`sidecar/knowledge/`) with sources and dates; M5 expands them.
- Tests: tool behaviour on the fixture backend, approval gating (missing, forged,
  wrong-kind and rejected approvals), block-rule dry-run, and a server smoke test
  that lists tools with schemas and calls one.

## M2 — Structured privacy incidents (16 Nov)

- Added incident models (`sidecar/incidents/models.py`): `Incident`, `Evidence`,
  `ProposedAction`, `Approval` and an append-only `AuditEvent`. Evidence is
  tagged observed / heuristic / AI; confidence is a heuristic score, not a
  calibrated probability.
- Added detection rules (`sidecar/incidents/detection.py`): non-adequate transfer
  with a sensitive permission, known tracker (connection and cookie), and new
  destination country (against a baseline). Every incident cites its evidence and
  states no legal conclusion.
- Added a SQLAlchemy store (`sidecar/incidents/db.py`, `store.py`) with a
  tamper-evident, hash-chained audit log (`verify_audit_chain`). `DATABASE_URL`
  selects the backend; defaults to SQLite. Added Alembic migrations and a
  `docker-compose` PostgreSQL 16 service.
- Tests: model hashing, fixture-scan detection (expected incident set),
  store round-trip, and an audit tamper test that breaks verification.

## M1 — Portability and safe demo mode (16 Nov)

- Added a scanner backend interface (`sidecar/scanner/backend.py`) with two
  implementations: `MacOSBackend` (delegates to the existing scanners, unchanged)
  and `FixtureBackend` (synthetic data, no system access). Selected with
  `DOXSHIELD_BACKEND=macos|fixture`.
- Added synthetic fixtures under `sidecar/fixtures/` (apps, connections, cookies,
  permissions). Fixture results are flagged `"synthetic": true`; `/health` reports
  the active backend.
- Routed the sidecar API scan endpoints through the selected backend, so the app
  runs on Linux/CI with synthetic data and never triggers real scanning in fixture
  mode.
- Made IP geolocation offline only: removed the `ip-api.com` HTTP lookup (and the
  `httpx` dependency from that module). No observed IP address leaves the machine.
- Added Python tests (`test_backend.py`, `test_ip_geo_offline.py`,
  `test_api_fixture.py`), ruff/mypy configuration, and a GitHub Actions `ci`
  workflow that lints, type-checks (lenient) and runs the tests on Linux with the
  fixture backend.

## M0 — Security foundation (14–16 Nov)

- Removed tracked secrets, build artefacts and local files; rebuilt a clean,
  secret-free history that preserves original team authorship (Team Exxeta1).
- Exposed Resend API key revoked at the provider. No real Clerk secret identified.
- Added gitleaks secret scanning: a CI workflow (`security-secret-scan`) over the
  full history, a pre-commit configuration, and a native hook installer.
- Hardened auth: removed the hardcoded JWT fallback secret and stopped logging
  OTP codes and recipients. See `SECURITY_REMEDIATION.md`.
