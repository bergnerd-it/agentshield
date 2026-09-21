#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
export UV_CACHE_DIR="${UV_CACHE_DIR:-${ROOT_DIR}/backend/.uv-cache}"

for cmd in uv pnpm; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "ERROR: Required tool '${cmd}' is not installed or not in PATH." >&2
        exit 1
    fi
done

echo "=== Running AgentShield Dependency Vulnerability Audits ==="

# 1. Backend vulnerability scan via pip-audit
echo "--- Scanning Backend Python Dependencies (pip-audit) ---"
cd "${ROOT_DIR}/backend"
uv run pip-audit --desc
echo "Backend dependency audit passed cleanly."

# 2. Frontend vulnerability scan via pnpm audit
echo "--- Scanning Frontend NPM Dependencies (pnpm audit) ---"
cd "${ROOT_DIR}/frontend"
pnpm audit --audit-level=high
echo "Frontend dependency audit found no high or critical vulnerabilities."

echo "=== Dependency Audits Met the High/Critical Release Gate ==="
