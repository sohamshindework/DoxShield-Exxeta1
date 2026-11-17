#!/usr/bin/env bash
# Install a local pre-commit hook that blocks commits containing secrets.
# Dependency-light alternative to the pre-commit framework: needs only gitleaks.
# Run once from the repository root: bash scripts/install-hooks.sh
set -euo pipefail

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "gitleaks not found. Install it first: https://github.com/gitleaks/gitleaks" >&2
  exit 1
fi

hook_dir="$(git rev-parse --git-path hooks)"
mkdir -p "$hook_dir"

cat > "$hook_dir/pre-commit" <<'HOOK'
#!/usr/bin/env bash
# DoxShield: block commits whose staged changes contain secrets.
set -euo pipefail
if ! command -v gitleaks >/dev/null 2>&1; then
  echo "[pre-commit] gitleaks not installed; skipping secret scan." >&2
  exit 0
fi
gitleaks protect --staged --redact --no-banner
HOOK

chmod +x "$hook_dir/pre-commit"
echo "Installed gitleaks pre-commit hook at $hook_dir/pre-commit"
