#!/usr/bin/env bash
set -euo pipefail

# Determine project root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/dist/sbom"
export UV_CACHE_DIR="${UV_CACHE_DIR:-${ROOT_DIR}/backend/.uv-cache}"

for cmd in uv pnpm; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "ERROR: Required tool '${cmd}' is not installed or not in PATH." >&2
        exit 1
    fi
done

echo "=== Generating AgentShield CycloneDX SBOMs ==="
mkdir -p "${OUTPUT_DIR}"

# 1. Backend SBOM (Python)
echo "--- Generating Backend SBOM (CycloneDX JSON) ---"
cd "${ROOT_DIR}/backend"
TMP_REQ="$(mktemp "${TMPDIR:-/tmp}/requirements-locked.XXXXXX.txt")"
FRONTEND_LOG="$(mktemp "${TMPDIR:-/tmp}/cyclonedx-frontend.XXXXXX.log")"
trap 'rm -f "${TMP_REQ}" "${FRONTEND_LOG}"' EXIT

uv export --frozen --format requirements-txt --no-dev --no-emit-project -o "${TMP_REQ}" >/dev/null
uv run cyclonedx-py requirements "${TMP_REQ}" -o "${OUTPUT_DIR}/backend-sbom.json" >/dev/null
echo "Backend SBOM generated at ${OUTPUT_DIR}/backend-sbom.json"

# 2. Frontend SBOM (Node.js / React)
echo "--- Generating Frontend SBOM (CycloneDX JSON) ---"
cd "${ROOT_DIR}/frontend"
if ! pnpm exec cyclonedx-npm \
    --ignore-npm-errors \
    --omit dev \
    --output-reproducible \
    --validate \
    --output-file "${OUTPUT_DIR}/frontend-sbom.json" \
    >"${FRONTEND_LOG}" 2>&1; then
    cat "${FRONTEND_LOG}" >&2
    exit 1
fi
echo "Frontend SBOM generated at ${OUTPUT_DIR}/frontend-sbom.json"

echo "=== SBOM Generation Completed Successfully ==="
