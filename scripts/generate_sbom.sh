#!/usr/bin/env bash
set -euo pipefail

# Determine project root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/dist/sbom"

echo "=== Generating AgentShield CycloneDX SBOMs ==="
mkdir -p "${OUTPUT_DIR}"

# 1. Backend SBOM (Python)
echo "--- Generating Backend SBOM (CycloneDX JSON) ---"
cd "${ROOT_DIR}/backend"
TMP_REQ="$(mktemp "${TMPDIR:-/tmp}/requirements-locked.XXXXXX.txt")"
trap 'rm -f "${TMP_REQ}"' EXIT

uv export --frozen --format requirements-txt --no-dev -o "${TMP_REQ}"
uv run cyclonedx-py requirements "${TMP_REQ}" -o "${OUTPUT_DIR}/backend-sbom.json"
echo "Backend SBOM generated at ${OUTPUT_DIR}/backend-sbom.json"

# 2. Frontend SBOM (Node.js / React)
echo "--- Generating Frontend SBOM (CycloneDX JSON) ---"
cd "${ROOT_DIR}/frontend"
pnpm exec cyclonedx-npm --ignore-npm-errors --output-file "${OUTPUT_DIR}/frontend-sbom.json"
echo "Frontend SBOM generated at ${OUTPUT_DIR}/frontend-sbom.json"

echo "=== SBOM Generation Completed Successfully ==="
