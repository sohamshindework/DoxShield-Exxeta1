# DoxShield security remediation — 14 November 2026

## A. Security findings

Verified target: `https://github.com/sohamshindework/DoxShield-Exxeta1`, public, owner `sohamshindework`. The connected GitHub account has read access only. Default `main` points to `89d05b6` and contains only MIT LICENSE. `local-main` points to `5b5b17c`, whose parent is `430dac7`; these two commits contain the application. These histories are unrelated. No tags, additional advertised branches, GitHub Actions workflows or open pull requests were found. Hidden/fork refs, closed PR content, provider usage and repository settings are not fully audited.

| Finding | File/reference | Current/history status | Required action |
| --- | --- | --- | --- |
| Resend API credential with non-placeholder format | `.env`, introduced in `430dac70de34e39cc3e4601a7fb511921bd16b4f`, retained by `5b5b17c` on `local-main` | Tracked at remote application tip and in its history | **Critical: Soham must revoke/rotate it in Resend, review usage/email activity, and privately update local/deployed configuration. Rotation is unconfirmed.** |
| Clerk secret entry is a placeholder | `.env`, both application commits | Removed from cleaned tree; original remote retains it | No usable Clerk secret identified. If any real Clerk secret was shared separately, rotate it in Clerk. No revocation is claimed. |
| Clerk publishable entries are placeholders/public configuration | `.env`, `.env.example` | Safe empty entries retained in example | Public/publishable configuration is distinct from server credentials; do not place secrets in VITE variables. |
| Fixed JWT signing fallback | `sidecar/auth.py`, both application commits | Removed from cleaned application; original history retains it | Set a private unique JWT_SECRET yourself (minimum 32 characters). Treat sessions signed using the known fallback as untrusted; change signing material and invalidate old sessions. No new credentials generated. |
| OTP values and recipient addresses logged; provider errors masked as success | `sidecar/auth.py`, both application commits | Fixed locally | Missing email configuration/provider failure returns failure, removes pending OTP, and logs no OTP/provider exception. Old local logs may still need private deletion. |
| Private paths/machine identifiers | `.claude/settings.local.json`, bytecode, `.DS_Store`, `src/pages/Cookies.tsx`, original commit author metadata | Removed/sanitized in candidate | Original audit clone and GitHub still retain the historical material. Author name/date retained; machine-local author email replaced with existing verified GitHub noreply identity in the candidate. |

Gitleaks 8.30.1 scanned all three reachable original commits with `--all --full-history --redact=100`: one generic API-key finding in `.env`. A supplemental scan inspected every reachable Git blob for Clerk/Resend key formats, private-key markers, GitHub tokens, machine paths and email locations, without printing matching values. Environment values were inspected in memory only. The Clerk secret placeholder was distinguished from the actual Resend finding. No database credential, private key or additional access token was identified by these checks. This is not a guarantee that all possible secret formats were detected. Example/test email addresses and the Resend default sender are legitimate configuration/examples.

`npm audit --json` reports **46 vulnerabilities: 3 critical, 29 high, 12 moderate, 2 low** in the unchanged lockfile. Direct dependencies rated high/critical include jspdf (critical), Electron, electron-builder, electron-updater, Vite, PostCSS and Clerk React. Counts include dependency/advisory aggregation, not demonstrated exploitability. No automatic fix or dependency upgrade was applied. Dependency remediation and compatibility testing remain required; this repository is not certified secure.

Additional inherited runtime risks: most loopback API endpoints do not enforce authentication, CORS is permissive, OTP endpoints lack rate limiting, Electron sandbox is disabled, and distribution signing/hardened runtime is disabled. These need a separate compatibility-reviewed hardening pass. Local model analysis may involve remote policy downloads and HTTP IP geolocation; optional alerts send information through Resend.

## B. Files cleaned

Removed 38 inappropriate tracked paths: `.env`, `.claude/settings.local.json`, four `.DS_Store` files, all 20 tracked `out/` files (including its `.DS_Store`), 12 Python bytecode files, and the ad hoc `test-root.js` debug script. Exact path inventory follows below. `out/` was confirmed to be Vite/Electron generated JS/CSS/HTML, not source. Rebuilding generates it locally, and ignore rules keep it out of the sanitized history.

Retained all application source, the architecture diagram, JSON reference data, entitlements, package-lock.json, build/configuration files and team attribution. Restored the original MIT LICENSE from main to the application tree. Replaced the contributor-specific filesystem path in cookie permission instructions with a generic project path.

Root ignore rules now cover `.env` variants with safe example exceptions, Python caches/environments/tool caches, node_modules, Electron/build/distribution outputs, editor/OS files, logs and temporary files. Source, reference JSON, lockfiles and `.env.example` remain trackable. Ignore rules are verified with `git check-ignore` and candidate tracked-file inspection.

## C. Git remediation and rollback

The original clone is retained locally as `DoxShield-Exxeta1` on `security/repository-hardening` for reviewing the staged cleanup. It intentionally retains original refs and objects and therefore **still contains the exposed reachable history**. Do not push/mirror it or publish an archive of it. No existing branch/tag was deleted, reset, force-updated or garbage-collected.

An independent local `DoxShield-sanitized` checkout is prepared with no remote configured. It contains a new `security/clean-history` history: original license root, sanitized replay of both legitimate application commits, then the reviewed maintenance changes. Original names, messages and author dates are retained for replayed commits. The original machine-local email is replaced by Soham's GitHub noreply identity already present in main. Historical sensitive/generated paths are excluded; the known JWT fallback and contributor path are also sanitized in historical snapshots. The maintenance commit uses a clearly synthetic maintenance identity. No original contaminated commit objects are copied into this repository. Commit IDs necessarily change. This keeps the small, meaningful development sequence rather than collapsing authorship into an orphan snapshot.

The existing original clone is the private local rollback/reference source; no new secret-bearing backup branch, tag, bundle or public repository is created. Restoring from it would restore the exposure and must never be a casual remote rollback. Prefer reverting an application change on the sanitized lineage. Keep the original clone private until incident handling is complete, then remove it only with the owner's approval.

Proposed remote plan, **not executed**:

1. Soham confirms rotation, reviews this candidate and the remaining security/build risks, and coordinates a contributor freeze. Although only Soham appears as Git author, this is a team project; sharing cannot be ruled out. Recheck all remote refs, tags, PRs, forks and collaborators immediately before publishing.
2. With separate explicit authorization and write access, publish the sanitized candidate as a review branch. Publishing alone does not remove old history.
3. After final owner approval, advance main to the reviewed sanitized history. This candidate descends from the existing license root, so main can ordinarily advance without a force push if unchanged. Replace local-main with the sanitized lineage using an explicit expected-old-SHA lease, or delete that contaminated branch only if authorized. Changing the default branch is unnecessary if main receives the application. Do not merge the contaminated history into main.
4. Verify every published branch/tag and any PR refs; coordinate GitHub sensitive-data removal for retained caches/PR views as needed. Ask contributors to reclone or carefully clean their local refs; avoid merging/pushing the old lineage back.
5. Enable appropriate branch protection, secret scanning/push protection, dependency alerts and private reporting. Re-audit the published repository.

The task explicitly requires approval before remote history rewrites, branch deletion or default-branch changes, and prohibits automatic pushes. No remote mutation occurred. Rewriting cannot erase independent clones, caches, screenshots or provider use; rotation remains mandatory.

## D. Application validation

Environment: Node v26.6.0, npm 11.18.0, Python 3.14.0, macOS host. Lockfile unchanged; Python's minimum-version requirements resolved into an isolated local virtualenv, without editing dependency declarations.

| Command/check | Result |
| --- | --- |
| `npm ci --ignore-scripts --cache /private/tmp/doxshield-npm-online-cache --no-audit --no-fund --fetch-retries=0 --fetch-timeout=30000` | PASS after approved network access; 711 packages. Lifecycle scripts/Electron binary install skipped deliberately for build-only checks. Initial sandbox install lacked DNS access and was stopped. |
| `sidecar/.venv/bin/python -m pip install --cache-dir /private/tmp/doxshield-pip-cache -r sidecar/requirements.txt` | PASS after approved network access. Initial sandbox attempt failed DNS. |
| `npm run build` | PASS: main, preload and renderer compiled. Existing package-module/Browserslist warnings and large bundles remain. |
| `./node_modules/.bin/tsc --noEmit -p tsconfig.node.json` | FAIL: two inherited unused icon declarations. |
| `./node_modules/.bin/tsc --noEmit -p tsconfig.web.json` | FAIL: 18 inherited diagnostics, including missing preload method typings, unused declarations and an alert argument mismatch. Both configurations' diagnostics match an original-source baseline exactly. |
| `sidecar/.venv/bin/python -m unittest discover -s tests -v` | PASS: six security regressions for missing signing/email config, private failure handling, successful OTP/JWT/single-use, repeated failed alert delivery and backend import/health. Provider calls are mocked. |
| `sidecar/.venv/bin/python -m pip check` | PASS: no broken installed requirements. |
| Python `ast.parse` over 14 source modules, excluding virtualenv | PASS. |
| `bash -n setup.sh start.sh` | PASS. Setup/launcher were not executed because they install/start system tools and scan the host. |
| Original-history Gitleaks | FAIL as expected: one Resend-format generic API-key finding. Redacted output only. |
| Sanitized candidate `gitleaks git . --log-opts='--all --full-history' --redact=100` and `gitleaks dir . --redact=100` | PASS: four reachable commits and current tree, no findings. Exact exposed-value scan over every reachable candidate blob also passed. Ignore checks passed for 14 private/generated paths and eight required files/templates; candidate Git status was clean. |
| `npm audit --json` | FAIL: 46 known dependency vulnerabilities; no automatic upgrades. |
| Electron GUI, installed-app/cookie/network scanning, Ollama inference, real OTP/email delivery, packaged DMG/signing | NOT RUN. Requires device permission/privacy review, real privately configured credentials/model and packaged runtime validation. No credentials used and no email sent. |

No original automated backend test suite was found. New tests exercise security behavior; they do not start the app lifespan/device monitor or perform provider integration. Current tests show dependency/API deprecation warnings. No claim is made that type checks or dependency security checks pass.

## E. Repository quality and configuration

README now describes the inspected capabilities, architecture, setup, root example environment, actual npm scripts, tests, privacy boundaries, limitations, Q-Hack team context and license. Unsupported production/compliance/offline claims and nonexistent build commands/assets were removed or qualified. Individual contributions and unverified award status are clearly marked for confirmation. Original historical README/diagram assets remain attributable to the team.

Configuration behavior changes are deliberate and covered by tests: backend dotenv uses an explicit project-root path; externally exported values still take precedence. JWT login now requires a private configured signing key; missing Resend config/provider failure is a real failure rather than a logged OTP fallback. Scanning and onboarding skip remain available. Failed alert delivery is recorded as skipped and returns false; skipped events no longer suppress a later retry as if sent. Raw provider exceptions are not logged. Setup uses npm ci and explains actual login requirements. No server-only credentials are bundled into the renderer; build config uses normal Vite public variable exposure and contains no secret injection.

## F. Outstanding actions

- **Soham: revoke/rotate the exposed Resend key, review provider usage, confirm incident containment. This is critical and unconfirmed.** Verify any separately shared real Clerk credentials; none found here.
- Set private signing configuration yourself, invalidate fallback-signed sessions and privately inspect old logs for OTP/recipient disclosure. No new credentials were generated.
- Review the candidate and authorize specific remote publishing/ref replacements. Connected account is read-only, so an owner/write-capable session is required.
- Resolve known dependency advisories and inherited type errors; pin/test Python resolution for stronger reproducibility.
- Confirm team roles/award details, collaborator/fork/PR dependencies, GitHub settings and sensitive-data removal needs.
- Validate real macOS scanner permissions, packaged runtime, local model and privately configured email integration. Review loopback auth, OTP abuse controls, Electron sandbox and signing before any production use.

## Removed path inventory

- `.DS_Store`
- `.claude/settings.local.json`
- `.env`
- `out/.DS_Store`
- `out/main/index.js`
- `out/preload/index.js`
- `out/renderer/assets/Alerts-BLCpfRRz.js`
- `out/renderer/assets/AppDetail-Dq43cZQ1.js`
- `out/renderer/assets/Applications-BVP7snnX.js`
- `out/renderer/assets/Cookies-BGEeJgck.js`
- `out/renderer/assets/NetworkMonitor-JibZTfql.js`
- `out/renderer/assets/Onboarding-BUY8jRde.js`
- `out/renderer/assets/Settings-CxAHeDxL.js`
- `out/renderer/assets/brain-SS-dKlMh.js`
- `out/renderer/assets/chevron-up-Uw_ywkKL.js`
- `out/renderer/assets/circle-check-big-XZiHCxUY.js`
- `out/renderer/assets/filter-CMglO0sL.js`
- `out/renderer/assets/globe-C7PPJs4N.js`
- `out/renderer/assets/index-R9CsD_Yp.js`
- `out/renderer/assets/index-r9iPUF4z.css`
- `out/renderer/assets/lock-CKIoV8ym.js`
- `out/renderer/assets/search-ZpfdpDmc.js`
- `out/renderer/index.html`
- `sidecar/.DS_Store`
- `sidecar/__pycache__/auth.cpython-314.pyc`
- `sidecar/__pycache__/main.cpython-314.pyc`
- `sidecar/ai/__pycache__/__init__.cpython-314.pyc`
- `sidecar/ai/__pycache__/ollama_client.cpython-314.pyc`
- `sidecar/ai/__pycache__/policy_analyzer.cpython-314.pyc`
- `sidecar/ai/__pycache__/risk_engine.cpython-314.pyc`
- `sidecar/scanner/__pycache__/__init__.cpython-314.pyc`
- `sidecar/scanner/__pycache__/apps.cpython-314.pyc`
- `sidecar/scanner/__pycache__/cookies.cpython-314.pyc`
- `sidecar/scanner/__pycache__/ip_geo.cpython-314.pyc`
- `sidecar/scanner/__pycache__/network.cpython-314.pyc`
- `sidecar/scanner/__pycache__/permissions.cpython-314.pyc`
- `src/.DS_Store`
- `test-root.js`
