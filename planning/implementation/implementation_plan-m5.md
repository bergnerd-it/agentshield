# Milestone 5: Local React Dashboard and Manual Approval Workflows

## 1. Milestone 4 Baseline Verification Report

Before planning Milestone 5, the Milestone 4 baseline on branch `feature/m5` (HEAD at `064da5e`: "milestone-4 review fixes") was systematically verified against all required quality gates and review findings.

### Quality Gate Results
- **Backend Quality Gates:**
  - `uv run ruff format --check .`: **PASS** (87 files checked, 0 unformatted)
  - `uv run ruff check .`: **PASS** (0 errors, 0 warnings)
  - `uv run pyright`: **PASS** (strict mode: 0 errors, 0 warnings, 0 informations)
  - `uv run pytest`: **PASS** (194 passed, 2 skipped due to local mock environment)
- **Frontend Quality Gates:**
  - `pnpm lint`: **PASS** (ESLint clean)
  - `pnpm typecheck`: **PASS** (TypeScript strict clean)
  - `pnpm test`: **PASS** (Vitest 3/3 passed)
  - `pnpm build`: **PASS** (Vite production build succeeds, assets emitted to `dist/`)
  - `pnpm exec playwright test`: **ENVIRONMENT LIMITATION** in standard sandbox mode (macOS seatbelt blocks non-bypassed binding of TCP port 8766 by `agentshield start`, raising `PermissionError: [Errno 1] Operation not permitted`). Distinguishable from application defects.

### Disposition of Previous M4 Review Findings
1. **Dropped holdback text in streaming rehydration:** **RESOLVED** in `064da5e` (`StreamingRehydrator.flush()` handles all keys including `openai_resp_*`, `openai_chat_*_tc_*_args`, and `anthropic_*_json`; tested in `test_streaming_rehydrator_flush_all_key_patterns`).
2. **Provider-correct flushing before completion events:** **RESOLVED** in `064da5e` (`StreamingRehydrator.transform_event()` flushes holdback on completion/done events before yielding the terminal event).
3. **Missing Responses API rehydration integration tests:** **RESOLVED** in `064da5e` (`test_streaming_rehydrator_openai_responses_api` and `test_openai_responses_streaming_rehydration`).
4. **Missing tool-argument JSON rehydration tests:** **BASIC RESOLVED** (`test_streaming_rehydrator_openai_tool_calls` and `test_streaming_rehydrator_anthropic_input_json_delta` verify fragmented placeholder reassembly across SSE deltas; edge-case escaping tests for quotes, backslashes, newlines, and Unicode inside streaming tool-arguments were omitted in the M4 baseline).
5. **Missing backpressure tests:** **RESOLVED** in `064da5e` (`test_streaming_pipeline_backpressure` verifies slow consumer pausing upstream generator).
6. **Missing latency instrumentation:** **RESOLVED** in `064da5e` (TTFB logged on first byte in `StreamingPipeline.process()`).
7. **Missing safe warnings for unresolved placeholders:** **RESOLVED** in `064da5e` (`logger.warning("Unresolved placeholder %s...", ...)` in `rehydrate_text()`).
8. **Missing streaming threat-model documentation:** **RESOLVED** in `064da5e` (Threats T-14 and T-14a updated in `docs/THREAT_MODEL.md`).
9. **Insufficient evidence concerning credentials split across chunks:** **GAP IDENTIFIED** in M4 baseline: `ProxyForwardClient.forward_stream` performs `if credential.encode("utf-8") in chunk:` on each chunk in isolation without a cross-chunk rolling buffer. If an upstream provider key is fragmented across two TCP chunks, `ProxyForwardClient` would not detect it. (Note: per M5 prompt instructions, we do not silently modify M4 code, but document this disposition clearly).

---

## 2. Exact Milestone 5 Requirements

According to `AgentShield_V1_Specification.md` §19 (Milestone 5), §14 (Manual Approval), and §16 (Management API & UI):

1. **Management API Implementation:**
   - `GET /api/v1/health` & `GET /api/v1/status` (existing)
   - `GET /api/v1/events` (paginated, sortable, filterable event list from SQLite `AuditEvent`)
   - `GET /api/v1/events/{id}` (single event audit details)
   - `GET /api/v1/events/stream` (SSE live traffic feed and approval notifications)
   - `GET /api/v1/approvals` (list pending approval requests)
   - `GET /api/v1/approvals/{id}` (approval request details with masked findings and diff preview)
   - `POST /api/v1/approvals/{id}/approve` (atomic approval transition)
   - `POST /api/v1/approvals/{id}/deny` (atomic denial transition)
   - `GET /api/v1/policies` (list available policies and active profile)
   - `POST /api/v1/policies` (create/import policy)
   - `PUT /api/v1/policies/{id}` (update policy)
   - `GET /api/v1/detectors` (list active detectors and status)
   - `GET /api/v1/settings` & `PUT /api/v1/settings` (read/update settings, redacting any secrets)
2. **Approval Engine & Lifecycle:**
   - Hold requests when policy evaluation yields `PolicyAction.REQUIRE_APPROVAL` *before* contacting upstream provider.
   - Assign cryptographically random UUID, calculate request content fingerprint (SHA-256), and set expiration (default 60s, configurable).
   - Atomic state transitions: `PENDING` -> `APPROVED` | `DENIED` | `EXPIRED` | `CANCELLED`.
   - Monitor downstream client connection: if client disconnects while pending, release resources and transition to `CANCELLED` (never forward upstream).
   - Handle races / concurrent decisions cleanly (HTTP 409 Conflict if already decided).
   - Approval is strictly bound to request fingerprint; cannot be replayed or reused for modified payloads.
   - Do not allow approval to bypass non-overridable security invariants (e.g. detected raw credentials).
3. **Local React Dashboard & Live Traffic UI:**
   - Real backend-connected views using TanStack Query and generated OpenAPI TypeScript client.
   - **Dashboard:** Service status, active security profile, request counts by decision (`ALLOW`, `WARN`, `REDACT`, `REQUIRE_APPROVAL`, `BLOCK`), findings breakdown, latency metrics.
   - **Live Traffic:** Real-time stream of incoming/completed requests with filters (agent, project, provider, action, time), detail view with findings.
   - **Approvals View:** Pending requests list, countdown timer showing remaining seconds, masked findings explanation, diff preview, Approve and Deny action buttons.
   - **Policies View:** View current active profile rules, inspect effective precedence (`BLOCK > REQUIRE_APPROVAL > REDACT > WARN > ALLOW`), view rule details.
   - **Settings View:** View provider settings (without disclosing API keys), ports, limits, timeouts, detector status, and explicit display of protection limits.
4. **Sensitive-Content Preview & Monaco Diff:**
   - Show original vs redacted comparison for pseudonymized/redacted payloads.
   - Monaco diff editor integration for code/JSON payloads with inert fallback for resource-constrained environments.
   - Retrieve preview only via authenticated management endpoints; strictly mask secrets (`[REDACTED_SECRET_...]`).
   - Render untrusted input as inert text (no `dangerouslySetInnerHTML`).
   - Ephemeral in-memory retention: clear previews when resolved or expired.
5. **Live Updates & Reconnection:**
   - SSE live feed via `/api/v1/events/stream` with automatic reconnect logic.
   - authoritative refresh on reconnect to reconcile missed events and avoid duplicate entries.
6. **Local Security:**
   - Enforce separate proxy authentication (`require_proxy_auth`) and management authentication (`require_admin_auth`).
   - Maintain strict loopback Host & Origin validation, restrictive CSP, no-sniff headers, and no wildcard CORS.

---

## 3. Affected Modules & Architecture

### Backend (`backend/src/agentshield/`)
- **[NEW]** `backend/src/agentshield/approvals/models.py`: Approval domain models (`ApprovalRequest`, `ApprovalDecision`, `ApprovalState`).
- **[NEW]** `backend/src/agentshield/approvals/manager.py`: In-memory `ApprovalManager` maintaining active holds, `asyncio.Event`/`Future` signaling, expiration timers, and atomic transitions.
- **[NEW]** `backend/src/agentshield/api/routes/approvals.py`: Approval management endpoints (`GET /api/v1/approvals`, `GET /api/v1/approvals/{id}`, `POST /api/v1/approvals/{id}/approve`, `POST /api/v1/approvals/{id}/deny`).
- **[NEW]** `backend/src/agentshield/api/routes/events.py`: Audit and live traffic endpoints (`GET /api/v1/events`, `GET /api/v1/events/{id}`, `GET /api/v1/events/stream`).
- **[NEW]** `backend/src/agentshield/api/routes/policies.py`: Security policy endpoints (`GET /api/v1/policies`, `POST /api/v1/policies`, `PUT /api/v1/policies/{id}`).
- **[NEW]** `backend/src/agentshield/api/routes/settings.py`: Settings and detector status endpoints (`GET /api/v1/settings`, `PUT /api/v1/settings`, `GET /api/v1/detectors`).
- **[MODIFY]** `backend/src/agentshield/api/routes/proxy.py`: Intercept `PolicyAction.REQUIRE_APPROVAL` in `_inspect_body` / `_handle_proxy_request` to hold requests with `ApprovalManager` before upstream dispatch.
- **[MODIFY]** `backend/src/agentshield/api/app.py`: Register new routers in FastAPI app; include `ApprovalManager` lifespan management.
- **[MODIFY]** `backend/src/agentshield/api/dependencies.py`: Add dependency providers for `ApprovalManager`, `PolicyRepository`, `SettingsRepository`, `AuditRepository`.

### Frontend (`frontend/src/`)
- **[MODIFY]** `frontend/openapi.json`: Regenerate from FastAPI `app.openapi()`.
- **[MODIFY]** `frontend/src/api/schema.ts`: Regenerate TypeScript types via `openapi-typescript`.
- **[MODIFY]** `frontend/src/api/client.ts`: Add typed TanStack Query hooks and API clients for approvals, events, SSE stream, policies, detectors, and settings.
- **[NEW]** `frontend/src/components/DiffViewer.tsx`: Monaco diff editor (or inert fallback diff viewer) displaying original vs redacted payloads.
- **[NEW]** `frontend/src/components/ApprovalCard.tsx`: Dedicated approval card showing masked findings, countdown timer, and action buttons.
- **[NEW]** `frontend/src/hooks/useLiveEvents.ts`: SSE connection hook with automatic reconnection and cache reconciliation.
- **[MODIFY]** `frontend/src/pages/DashboardPage.tsx`: Live stats, metrics, decision breakdown, and active alerts.
- **[MODIFY]** `frontend/src/pages/TrafficPage.tsx`: Live traffic log table with filter bar and event inspection drawer.
- **[MODIFY]** `frontend/src/pages/ApprovalsPage.tsx`: Pending approval queue with real-time countdowns and one-click actions.
- **[MODIFY]** `frontend/src/pages/PoliciesPage.tsx`: Policy rules viewer, profile selector, and rule precedence explanation.
- **[MODIFY]** `frontend/src/pages/SettingsPage.tsx`: Safe settings inspector, detector statuses, and protection boundary declarations.

---

## 4. API Contracts and Approval State Transitions

### State Machine
```
                  ┌───────────────┐
                  │    PENDING    │
                  └───────┬───────┘
          ┌───────────────┼───────────────┬───────────────┐
          │               │               │               │
      (approve)        (deny)         (timeout)     (disconnect)
          ▼               ▼               ▼               ▼
  ┌───────────────┐┌───────────────┐┌───────────────┐┌───────────────┐
  │   APPROVED    ││    DENIED     ││    EXPIRED    ││   CANCELLED   │
  └───────────────┘└───────────────┘└───────────────┘└───────────────┘
```
- Only requests in `PENDING` may transition. Any subsequent attempt returns `409 Conflict`.
- On `APPROVED`: Request resumes and forwards upstream.
- On `DENIED` or `EXPIRED`: Request is aborted with `ContentBlockedError` (HTTP 403 / 502 Problem Details).
- On `CANCELLED`: Client disconnect detected; pending hold aborted, no upstream call made.

### Management API Contracts (Summary)
1. `GET /api/v1/approvals`: Returns array of active `ApprovalSummary` (id, timestamp, expires_at, remaining_seconds, provider, model, endpoint, finding_summary, status).
2. `GET /api/v1/approvals/{id}`: Returns `ApprovalDetail` including masked original payload, redacted payload, findings metadata, and diff availability.
3. `POST /api/v1/approvals/{id}/approve`: Body empty or `{ "reason": "..." }`. Returns `{ "status": "approved", "id": "..." }`.
4. `POST /api/v1/approvals/{id}/deny`: Body `{ "reason": "..." }`. Returns `{ "status": "denied", "id": "..." }`.
5. `GET /api/v1/events/stream`: `text/event-stream` yielding:
   - `event: approval_pending` (when a new hold occurs)
   - `event: approval_resolved` (when an approval is approved, denied, expired, or cancelled)
   - `event: audit_event` (when a proxy request completes)
   - `: keepalive` ping comments every 15s.

---

## 5. Handling of Sensitive Data in UI

- **No Secrets in Frontend:** Detected secrets are masked as `[REDACTED_SECRET_...]` or filtered entirely. Provider API keys are never returned by any management API.
- **Inert Rendering:** All payload text and diff content rendered as plain text inside preformatted blocks or Monaco editor instances without HTML interpretation (`escapeHtml` / text node binding).
- **Ephemeral State:** Pending diff previews are stored only in memory in the backend with TTL matching approval expiry. Frontend does not persist request bodies or diffs in `localStorage` or `sessionStorage`.
- **Masked Previews:** Findings displayed with category, matched placeholder, and offset only, with raw match text omitted or masked if it contains sensitive patterns.

---

## 6. Live-Update and Reconnect Behavior

- Frontend hook `useLiveEvents` connects to `GET /api/v1/events/stream`.
- On connection drop:
  - Immediate visual badge shows "Reconnecting...".
  - Exponential backoff retry (1s, 2s, 5s, max 10s).
  - Upon successful reconnection: triggers `queryClient.invalidateQueries` for `['approvals']` and `['events']` to reconcile any state transitions missed while disconnected.
- Event deduplication using unique `event_id` and monotonic timestamps prevents duplicate row rendering.

---

## 7. Requirement-to-Test Mapping

| Requirement | Test Location | Scope |
|-------------|---------------|-------|
| Approval hold before upstream dispatch | `backend/tests/test_approvals.py` | Verify provider mock receives 0 calls while pending |
| Approval granted forwards upstream | `backend/tests/test_approvals.py` | Verify request proceeds and returns upstream response |
| Denial returns blocked response | `backend/tests/test_approvals.py` | Verify 403 Problem Details returned to client |
| Approval timeout transitions to EXPIRED | `backend/tests/test_approvals.py` | Injected clock/short timeout verifies deny-by-default |
| Client disconnect transitions to CANCELLED | `backend/tests/test_approvals.py` | Simulated disconnect verifies upstream call aborted |
| Concurrent decision race condition | `backend/tests/test_approvals.py` | Simultaneous approve/deny calls return 200 and 409 |
| Management API pagination & filtering | `backend/tests/test_management_api.py` | Verify filtering by provider, action, date ranges |
| Masked sensitive preview | `backend/tests/test_management_api.py` | Verify secrets are masked and not disclosed in DTOs |
| Management API auth separation | `backend/tests/test_management_api.py` | Verify proxy token cannot access `/api/v1/approvals` |
| Frontend components & pages | `frontend/tests/Approvals.test.tsx`, `Dashboard.test.tsx` | Vitest component tests with Mocked Query Provider |
| End-to-end approval flow | `frontend/e2e/approvals.spec.ts` | Playwright test verifying live approval UI flow |

---

## 8. Explicit Exclusions & Unresolved Decisions

### Explicit Exclusions (Preserved for Future Milestones)
- **Milestone 6 Scope:** Privacy-preserving audit export (JSON/HTML download buttons wired in UI but full exporter logic is M6), Claude Code / Codex CLI configuration adapters (`agentshield doctor` config fixing).
- **Milestone 7 Scope:** Tauri / OS-native desktop packaging, OS firewall integration, TLS interception.

### Open Decisions & Dependencies
1. **Monaco Editor in Frontend:**
   - Installing `@monaco-editor/react` requires network access (`BypassSandbox: true` for `pnpm add`).
   - *Design Proposal:* We will build a clean, dependency-free side-by-side / inline syntax diff component natively in React, and if `@monaco-editor/react` is approved to be installed, wrap it as a progressive enhancement. This ensures 100% offline reproducibility and zero build fragility.
2. **Dashboard Management Authentication:**
   - In production same-origin mode, the backend requires `Authorization: Bearer <admin_token>`.
   - *Design Proposal:* Provide an authentication banner / modal in the dashboard allowing the developer to supply the admin token (or store it in `sessionStorage` for the local session), with clear instructions pointing to `~/.agentshield/admin_token`.
