# AgentShield Milestone 6 Implementation Prompt: Audit and Integrations

Read `AGENTS.md`, `AgentShield_V1_Specification.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `SECURITY.md`, `docs/PRIVACY.md`, `docs/TESTING.md`, and all accepted Architecture Decision Records (`docs/adr/0001` through `docs/adr/0010`) completely.

Inspect the current repository and verify that Milestone 5 is complete. Run all existing backend and frontend quality gates before making any modifications:
```bash
# Backend Quality Gates
cd backend
UV_CACHE_DIR=.uv-cache uv run ruff check .
UV_CACHE_DIR=.uv-cache uv run ruff format --check .
UV_CACHE_DIR=.uv-cache uv run pyright
UV_CACHE_DIR=.uv-cache uv run pytest

# Frontend Quality Gates
cd ../frontend
pnpm lint
pnpm typecheck
pnpm test -- --run
```
If any pre-existing tests fail, stop and report them before writing code.

---

## 1. Milestone 6 Scope and Objectives

Implement only **Milestone 6 – Audit and Integrations**:

1. **Privacy-Preserving Audit Service and Data Access**:
   - Complete metadata capture for all proxy decisions and terminal outcomes (UUID, timestamps, correlation/session IDs, agent, project, provider, model, endpoint, direction, request/response size, duration, proxy overhead, finding categories and counts, detectors and confidence, applied policy rules and version, action, technical status, SHA-256 fingerprint of normalized content, safe error class).
   - Strict adherence to ADR 0004: Raw prompts, LLM responses, provider credentials, local proxy tokens, and detected secret values are strictly forbidden from entering persistent audit storage.
   - Server-side pagination, sorting, and filtering by timestamp range, action, provider, agent, and project.

2. **JSON and Standalone HTML Audit Exports**:
   - Management API endpoint `POST /api/v1/audit/export` accepting filter criteria (`format: "json" | "html"`, `start_time`, `end_time`, `agent`, `provider`, `action`, `project`).
   - Direct HTTP file delivery via `Content-Disposition: attachment; filename="agentshield-audit-<timestamp>.<ext>"`.
   - Standalone HTML export: A fully self-contained HTML report with embedded responsive styling, timeline visualization, summary statistics, policy versions, and latency breakdown without external CDN dependencies or third-party scripts.
   - Zero raw prompts, provider secrets, or confidential values in any export artifact.

3. **Codex and Claude Code Integration Adapters**:
   - Independently tested adapters for OpenAI Codex CLI and Anthropic Claude Code CLI.
   - Target configuration files:
     - OpenAI Codex: `~/.codex/config.toml` (configuring model provider base URL to `http://127.0.0.1:8765/proxy/openai/v1` and dedicated proxy token).
     - Anthropic Claude Code: `~/.claude.json` (configuring primary API key / proxy token and custom Anthropic base URL `http://127.0.0.1:8765/proxy/anthropic/v1`).
   - Per-integration proxy token authentication: Generate distinct proxy tokens during adapter configuration, enabling automatic attribution (`agent="codex"` and `agent="claude-code"`) for audit logging and policy rules, with seamless fallback to the global proxy token.
   - Non-destructive configuration management: Never overwrite existing configurations blindly; preserve unrelated user settings and environment keys.

4. **Configuration Preview, Atomic Backup, and 1-Click Rollback**:
   - Generate structured unified diff previews before applying any changes to tool configuration files.
   - Atomic modification workflow: Write new configuration to a temporary sibling file and rename atomically.
   - Automatic timestamped backups (`.bak.<timestamp>`) recorded in the `integration_configs` SQLite table (`last_backup_path`).
   - 1-click rollback restoring the exact previous configuration state atomically.
   - Dedicated CLI commands:
     ```bash
     agentshield configure codex [--preview] [--path <custom-path>]
     agentshield configure claude-code [--preview] [--path <custom-path>]
     agentshield rollback codex
     agentshield rollback claude-code
     ```
   - Management API endpoints:
     ```text
     GET  /api/v1/integrations
     GET  /api/v1/integrations/{agent}/preview
     POST /api/v1/integrations/{agent}/configure
     POST /api/v1/integrations/{agent}/rollback
     ```

5. **Enhanced System Diagnostics (`agentshield doctor`)**:
   - Full implementation of Specification §17.2:
     - Python runtime version and platform prerequisites.
     - Loopback port availability (`127.0.0.1:8765`).
     - Data directory write access.
     - SQLite WAL mode and Alembic migration state.
     - OS-native credential store availability (`keyring`).
     - Presence of provider credentials (OpenAI, Anthropic) in credential store or dev environment without printing values.
     - Agent configuration status for Codex and Claude Code (verifying whether local configs point to AgentShield proxy).
     - Upstream provider reachability probe: Non-blocking check with short timeout (1-2s) reporting `WARN` (not hard `FAIL`) if offline to support air-gapped development.
     - Proxy-loop detection verification.
     - Frontend SPA production bundle availability.
     - Active security profiles and detector engine readiness.
     - Mandatory prominent terminal/banner warning stating that AgentShield Version 1 is a cooperative proxy that does not enforce direct egress outside the proxy.
     - Meaningful exit codes (0 for pass/warnings, 1 for critical failure).

6. **Frontend Dashboard Updates (`AuditPage` and `IntegrationsPage`)**:
   - Full implementation of `frontend/src/pages/AuditPage.tsx`:
     - Privacy-preserving audit event table with pagination and server-side filtering (action, provider, agent, date range).
     - Audit event inspection drawer/modal displaying finding counts, rule IDs, timing overhead, normalized SHA-256 fingerprint, and technical status.
     - Direct JSON and HTML download buttons wired to `POST /api/v1/audit/export`.
   - Full implementation of `frontend/src/pages/IntegrationsPage.tsx`:
     - Status cards for Codex and Claude Code displaying integration status, config path, and active proxy token.
     - Config change preview using the Monaco / Diff viewer component.
     - Action controls for "Configure / Apply", "Test Connection", and "Rollback".
     - Visible notification reminding operators of cooperative proxy boundaries.
   - Regenerate OpenAPI schema and TypeScript client (`frontend/src/api/schema.ts` and `types.ts`).
   - Vitest component tests covering `AuditPage` and `IntegrationsPage`.

7. **Automated Playwright End-to-End Test Harness (ADR 0010)**:
   - Implement the six mandatory browser-driven test scenarios deferred from Milestone 5:
     1. **Full approve flow:** Client proxy request triggers `REQUIRE_APPROVAL` → approval hold created → SSE updates UI in real time → operator clicks "Approve" → client receives upstream response.
     2. **Full deny flow:** Client proxy request triggers approval hold → operator clicks "Deny" with reason in UI → client receives HTTP 403 Problem Details.
     3. **Timeout failure:** Client proxy request triggers approval hold → timeout window elapses without operator decision → request fails closed with HTTP 403 `approval-timeout`.
     4. **Unauthorized dashboard access:** Unauthenticated browser request to `/api/v1/approvals` returns HTTP 401.
     5. **Real-time SSE card updates:** In-flight approval hold arrives via SSE and updates dashboard queue live without manual page refresh.
     6. **Multi-tab concurrency:** Request approved in browser tab A causes tab B to update to resolved state in real time via SSE.
   - Run tests against a local offline backend proxy and local mock provider server.

Do not implement transparent TLS interception, OS firewall changes, MCP proxying, cloud telemetry, or Milestone 7 hardening documentation yet.

---

## 2. Non-Negotiable Security Invariants

- Never disable TLS verification.
- Never forward local proxy tokens or admin tokens upstream to LLM providers.
- Never send provider credentials to the frontend or print them in CLI output, doctor reports, logs, exceptions, or audit exports.
- Never store raw prompts, full LLM responses, detected secret values, or unencrypted provider credentials in SQLite.
- Never make live external provider calls from automated tests; use local mock provider servers exclusively.
- Fail closed for all strict-mode required checks and missing upstream credentials.
- Bind strictly to loopback (`127.0.0.1`).

---

## 3. Architecture & File Structure

```text
backend/src/agentshield/
├── audit/
│   ├── __init__.py
│   ├── service.py          # Audit querying, aggregations, and export generation
│   └── exporters/
│       ├── __init__.py
│       ├── json_exporter.py # Sanitized JSON streaming export
│       └── html_exporter.py # Self-contained HTML report with embedded styles
├── integrations/
│   ├── __init__.py
│   ├── base.py             # Base integration adapter protocol/abstract class
│   ├── manager.py          # Backup, preview, atomic write, and rollback manager
│   ├── codex.py            # OpenAI Codex adapter (~/.codex/config.toml)
│   └── claude_code.py      # Claude Code adapter (~/.claude.json)
├── core/
│   └── diagnostics.py      # Shared diagnostic service powering 'agentshield doctor'
├── cli.py                  # CLI commands: doctor, configure, rollback
├── persistence/
│   ├── models.py           # Updated AuditEvent and IntegrationConfig models if needed
│   └── repository.py       # Enhanced AuditRepository and IntegrationRepository
└── api/
    └── routes/
        ├── audit.py        # POST /api/v1/audit/export
        └── integrations.py # GET/POST /api/v1/integrations endpoints

frontend/src/
├── pages/
│   ├── AuditPage.tsx       # Audit table, details view, and export actions
│   └── IntegrationsPage.tsx # Codex/Claude cards, preview diff, and rollback
├── api/
│   ├── schema.ts           # Regenerated OpenAPI schema
│   └── types.ts            # Regenerated OpenAPI client types
└── e2e/
    ├── approvals.spec.ts   # Playwright E2E scenarios 1-3, 5-6 (ADR 0010)
    └── auth.spec.ts        # Playwright E2E scenario 4 (ADR 0010)
```

---

## 4. Detailed Implementation Requirements

### 4.1 Audit Service & Export Engine (`backend/src/agentshield/audit/`)
- Implement `AuditExportService` in `agentshield.audit.service`:
  - Query audit events from `AuditRepository` matching filter criteria (`date_from`, `date_to`, `agent`, `provider`, `action`, `project`).
  - Strict serialization allowlist: Retain only timestamp, request/session ID, agent, project, provider, model, endpoint, direction, action, rule ID, finding category counts, duration, sizes, technical status, and SHA-256 fingerprint.
  - JSON Exporter (`json_exporter.py`): Formats sanitized records with export metadata (filter criteria, timestamp, total record count, AgentShield version).
  - HTML Exporter (`html_exporter.py`): Produces a self-contained HTML page:
    - CSS inlined in `<style>` tags with a clean modern dark/light-compatible layout matching the dashboard aesthetic.
    - Summary metrics bar: Total events, blocked count, redacted count, approval count, average duration.
    - Filterable/sortable table with expand-for-details functionality using standard HTML/JS without external CDN script tags.
    - Prominent banner indicating: *"Privacy-Preserving Audit Report – Raw prompts and detected secrets are excluded by design."*
- Create `backend/src/agentshield/api/routes/audit.py`:
  - `POST /api/v1/audit/export`: Accepts `AuditExportRequest(format: "json" | "html", ...filters)`.
  - Streams response with `media_type="application/json"` or `"text/html"` and header `Content-Disposition: attachment; filename="agentshield-audit-...<ext>"`.
  - Register route under `/api/v1/audit` and include in `app.py`.

### 4.2 Codex and Claude Code Integration Adapters (`backend/src/agentshield/integrations/`)
- Base Adapter Protocol (`base.py`):
  - Defines methods: `detect() -> IntegrationStatus`, `preview() -> ConfigDiff`, `apply(token: str) -> None`, `rollback() -> None`, `test_connection() -> bool`.
- Codex Adapter (`codex.py`):
  - Config path default: `Path.home() / ".codex" / "config.toml"`.
  - Reads existing TOML (using Python 3.11+ `tomllib` and deterministic TOML writer or formatted key-value serializer).
  - Modifies/adds model provider endpoint targeting `http://127.0.0.1:8765/proxy/openai/v1` and dedicated proxy token.
  - Preserves all unrelated TOML sections and comments where possible.
- Claude Code Adapter (`claude_code.py`):
  - Config path default: `Path.home() / ".claude.json"` (and checks `~/.claude/settings.json`).
  - Reads JSON configuration, preserving existing user preferences.
  - Sets Anthropic custom proxy base URL to `http://127.0.0.1:8765/proxy/anthropic/v1` and dedicated proxy token.
- Integration Manager (`manager.py`):
  - Generates unique proxy token for each agent (e.g. `ast_codex_<hex>` or registers in token store).
  - Creates backup files before writing (`<file>.bak.<timestamp>`).
  - Writes new configuration atomically (write to temp file in same directory, `os.replace`).
  - Updates `IntegrationConfig` record in SQLite with status, `last_backup_path`, and timestamp.
  - Rollback reads `last_backup_path`, validates file integrity, restores original file atomically, and updates SQLite status.

### 4.3 Integration API & CLI Commands
- Add FastAPI routes in `backend/src/agentshield/api/routes/integrations.py`:
  - `GET /api/v1/integrations`: Lists supported agents, current detection status, config paths, and backup timestamps.
  - `GET /api/v1/integrations/{agent}/preview`: Returns unified diff of planned configuration changes.
  - `POST /api/v1/integrations/{agent}/configure`: Executes atomic backup and configuration update.
  - `POST /api/v1/integrations/{agent}/rollback`: Executes rollback from last backup.
- Expand `backend/src/agentshield/cli.py`:
  - `agentshield configure codex [--preview] [--path PATH]`
  - `agentshield configure claude-code [--preview] [--path PATH]`
  - `agentshield rollback codex`
  - `agentshield rollback claude-code`

### 4.4 Diagnostic Engine (`agentshield doctor`)
- Create `backend/src/agentshield/core/diagnostics.py`:
  - Implements diagnostic check runner executing the 12 required checks from Specification §17.2:
    1. Python Runtime & OS platform
    2. Data directory write permissions
    3. SQLite WAL mode & Alembic migration status
    4. Default port (8765) availability & running instance detection
    5. Local authentication token files & POSIX 0600 permissions
    6. Native credential store (`keyring`) status
    7. Upstream provider credentials check (verifying existence of OpenAI/Anthropic credentials without printing values)
    8. Coding agent configuration status (checking if Codex / Claude Code are configured for AgentShield)
    9. Upstream provider reachability (non-blocking async probe with 1-2s timeout; reports `WARN` if offline)
    10. Loop detection guard verification
    11. Frontend SPA production assets (`index.html` in dist dir)
    12. Active security profile and detector engine readiness
- Update `doctor()` in `backend/src/agentshield/cli.py` to use `diagnostics.py`, rendering Rich tables and outputting the mandatory direct-egress boundary warning:
  ```text
  ⚠️  Notice: AgentShield Version 1 is a cooperative reverse proxy.
  It inspects only traffic explicitly routed through its loopback endpoints.
  Direct network requests made outside the proxy are not intercepted or blocked.
  ```

### 4.5 Frontend Dashboard Implementation
- `frontend/src/pages/AuditPage.tsx`:
  - Replace placeholder with complete React component.
  - Displays filter bar: Action (`ALL`, `BLOCK`, `REDACT`, `REQUIRE_APPROVAL`, `WARN`, `ALLOW`), Provider (`ALL`, `openai`, `anthropic`), Agent, and Date range.
  - Data table with sorting and pagination.
  - Inspection modal/drawer showing event details, finding counts, and policy rules.
  - "Export JSON" and "Export HTML" buttons that download files via `POST /api/v1/audit/export`.
- `frontend/src/pages/IntegrationsPage.tsx`:
  - Replace placeholder with complete React component.
  - Cards for Codex and Claude Code showing status badge (`Configured`, `Not Configured`, `Error`), config path, and backup status.
  - "Preview Changes" modal rendering unified diff via Monaco/DiffViewer.
  - "Apply Configuration" and "Rollback" buttons with loading and confirmation states.
- Client Regeneration:
  - Export updated OpenAPI JSON from FastAPI backend and regenerate frontend client (`schema.ts` and `types.ts`).
- Component Tests:
  - Unit/integration tests in `frontend/tests/AuditPage.test.tsx` and `frontend/tests/IntegrationsPage.test.tsx` verifying filter updates, table rendering, diff display, and action triggers.

### 4.6 Playwright Browser E2E Tests (ADR 0010)
- Ensure `playwright.config.ts` passes `UV_CACHE_DIR` to `webServer`.
- Implement `frontend/e2e/approvals.spec.ts`:
  - **Scenario 1 (Approve Flow):** Send proxy request triggering `REQUIRE_APPROVAL` → SSE delivers card to UI → click "Approve" → verify card resolves to Approved and client receives HTTP 200 mock response.
  - **Scenario 2 (Deny Flow):** Send proxy request triggering `REQUIRE_APPROVAL` → click "Deny" with operator reason → verify card resolves to Denied and client receives HTTP 403 Problem Details.
  - **Scenario 3 (Timeout Failure):** Send proxy request with short timeout → verify card transitions to Expired and client receives HTTP 403 `approval-timeout`.
  - **Scenario 5 (Real-time SSE updates):** Verify that newly submitted approval hold renders dynamically without manual page refresh.
  - **Scenario 6 (Multi-tab concurrency):** Open two browser contexts/tabs to Dashboard; approving in Tab 1 updates Tab 2 via SSE within 2 seconds.
- Implement `frontend/e2e/auth.spec.ts`:
  - **Scenario 4 (Unauthorized access):** Access `/api/v1/approvals` without token and verify HTTP 401 response and redirect to error state.

---

## 5. Step-by-Step Delivery Plan

1. **Step 1: Audit Service and Exports**
   - Create `backend/src/agentshield/audit/` with JSON and HTML exporters.
   - Implement `POST /api/v1/audit/export` in `backend/src/agentshield/api/routes/audit.py`.
   - Add unit and integration tests in `backend/tests/test_audit_export.py`.

2. **Step 2: Integration Adapters and Rollback Engine**
   - Implement `backend/src/agentshield/integrations/` (Codex, Claude Code, Manager).
   - Implement per-integration proxy token attribution.
   - Implement management API routes in `backend/src/agentshield/api/routes/integrations.py`.
   - Implement CLI commands in `backend/src/agentshield/cli.py`.
   - Add unit and integration tests in `backend/tests/test_integrations.py`.

3. **Step 3: Enhanced Diagnostics (`agentshield doctor`)**
   - Implement `backend/src/agentshield/core/diagnostics.py`.
   - Update `doctor` CLI command with all 12 checks, egress warning banner, and exit codes.
   - Add unit tests in `backend/tests/test_doctor.py`.

4. **Step 4: Frontend Audit & Integrations Pages**
   - Regenerate OpenAPI client.
   - Implement `AuditPage.tsx` and `IntegrationsPage.tsx`.
   - Add Vitest component tests in `frontend/tests/`.

5. **Step 5: Playwright End-to-End Test Suite**
   - Implement the 6 mandatory E2E test scenarios from ADR 0010 in `frontend/e2e/`.
   - Verify local execution against offline backend proxy.

6. **Step 6: Full Verification and Quality Gates**
   - Run complete backend test suite (ruff, pyright, pytest).
   - Run complete frontend test suite (eslint, typecheck, vitest, playwright).
   - Verify zero secret leakage in logs, audit records, exports, or DOM.

---

## 6. Definition of Done for Milestone 6

Milestone 6 is complete when:
- `POST /api/v1/audit/export` successfully exports filtered JSON and standalone styled HTML reports containing zero raw payloads or secrets.
- Codex and Claude Code configurations can be previewed, backed up, atomically modified, and rolled back via both CLI and Management API.
- Dedicated per-integration tokens correctly attribute proxy traffic to `agent="codex"` and `agent="claude-code"`.
- `agentshield doctor` executes all 12 diagnostic checks, handles offline reachability with `WARN`, displays the direct egress notice, and exits with code 0 on success.
- Frontend `AuditPage` and `IntegrationsPage` render correctly, support all operator actions, and pass component tests.
- All six mandatory Playwright E2E scenarios from ADR 0010 pass reliably in headless browser execution.
- All backend and frontend quality commands succeed with zero errors, zero warnings, and zero skipped security tests.
