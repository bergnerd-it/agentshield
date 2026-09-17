# Fix Milestone 5 Review Findings

Fix all issues identified in the Milestone 5 code review for AgentShield.
You are continuing work performed by other agents.
Do not assume access to their conversations.
Do not treat the M5 completion report as proof of correctness.

---

## 1. Read Project Instructions First

Before touching any code, read these files completely (resolve paths from the repository root):

- `AGENTS.md`
- `AgentShield_V1_Specification.md`
- `docs/ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`
- `planning/implementation/prompt-milestone-5.md`
- `planning/implementation/report-milestone-5.md`
- `planning/implementation/review-milestone-5.md` (this file, the code review you are implementing)

Identify every finding listed in this document. Confirm each finding against the actual source code
before writing a fix. If a finding describes a condition that no longer exists in the current
working tree, note the discrepancy and skip the fix — do not silently rewrite code.

---

## 2. Verify the Baseline

Run the full quality gates before making any changes.
Record the exact output; use it as your regression baseline.

```bash
cd backend
uv sync --frozen
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest          # expected: 207 passed, 2 skipped
```

```bash
cd frontend
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test              # expected: 9 passed, 3 files
pnpm build
```

Do not proceed if any gate is already failing before your changes.

---

## 3. Fixes — Implement in the Order Listed

### FIX-1 (MUST): SSE Event-Name Mismatch — `approval_decided` → `approval_resolved`

**File:** `frontend/src/hooks/useLiveEvents.ts`

**Problem:** The frontend listens for `"approval_decided"` but the backend (`ApprovalManager.approve()`,
`deny()`, `cancel()`, `expire()`) publishes `"approval_resolved"`. No approval-resolution SSE event
ever reaches the frontend. The approval queue never updates in real time when an operator approves or
denies from another tab.

**Fix:** In the `eventTypes` array, replace `'approval_decided'` with `'approval_resolved'`.
Update the corresponding `invalidateQueries` branch to also respond to `'approval_resolved'`.

**Acceptance criteria:**
- `approval_resolved` appears in the registered event-type list.
- `'approval_decided'` is gone.
- The invalidation branch covers `'approval_resolved'`.

---

### FIX-2 (MUST): SSE Event-Name Mismatch — `proxy_request` → `audit_event`

**File:** `frontend/src/hooks/useLiveEvents.ts`

**Problem:** The backend publishes `"audit_event"` from `_record_audit()` in
`backend/src/agentshield/api/routes/proxy.py` (line ~141). The hook listens for
`"proxy_request"`, which is never published. Live traffic updates on the Traffic page never arrive
via SSE.

**Fix:** Replace `'proxy_request'` with `'audit_event'` in the `eventTypes` array.
Update the corresponding `invalidateQueries` branch to use `'audit_event'` instead of
`'proxy_request'`.

**Acceptance criteria:**
- `'audit_event'` appears in the event-type list.
- `'proxy_request'` is gone.
- The invalidation branch for audit events covers `'audit_event'`.

---

### FIX-3 (MUST): Payload Not Cleared After `approve()`

**File:** `backend/src/agentshield/approvals/manager.py`

**Problem:** `deny()`, `cancel()`, and `expire()` all call `req.clear_payloads()` immediately
after the state transition, dropping sensitive in-memory payload data. `approve()` does not.
After a successful approval the masked payload (`raw_payload_masked`) persists in memory until
the `OrderedDict` history cap evicts the entry. Additionally, `GET /api/v1/approvals/{id}` will
return the full `raw_payload_masked` content for an already-approved request.

**Fix:** Add `req.clear_payloads()` at the end of the `approve()` method, after the future is
resolved and the SSE event is published — consistent with the other terminal-state methods.

**Acceptance criteria:**
- `approve()` calls `req.clear_payloads()` before returning.
- After approval, `req.raw_payload_masked` and `req.redacted_payload` are `None`.
- Existing test `test_proxy_hold_and_approve_flow` still passes.
- Add a new test `test_approval_payloads_cleared_after_approve` that:
  1. Creates a hold with non-None `raw_payload_masked` and `redacted_payload`.
  2. Calls `manager.approve(req.id)`.
  3. Asserts `req.raw_payload_masked is None` and `req.redacted_payload is None`.

---

### FIX-4 (SHOULD): Memory Eviction Unboundedness Under PENDING Flood

**File:** `backend/src/agentshield/approvals/manager.py`

**Problem:** The eviction loop in `create_request()` stops as soon as it hits the oldest
non-terminal entry, allowing the `OrderedDict` to grow past `max_history` when all entries are
PENDING. Under a sustained flood of REQUIRE_APPROVAL traffic where nothing is decided, memory
grows unboundedly.

**Fix:** Add a separate `max_pending` limit (default 200, sourced from
`settings.approval_max_pending` which already exists in `core/config.py`). When creating a new
request, if the current number of PENDING holds equals `max_pending`, fail-closed by raising a
new `ApprovalQueueFullError` (HTTP 503, `urn:agentshield:error:approval-queue-full`) before
adding the new hold. Do not silently evict a PENDING hold — that would create a silent upstream
block.

Steps:
1. Add `ApprovalQueueFullError` to `backend/src/agentshield/core/errors.py` (status 503).
2. Update `ApprovalManager.__init__` to accept a `max_pending: int = 200` parameter.
3. At the start of `create_request()`, count pending holds and raise `ApprovalQueueFullError`
   if the count equals or exceeds `max_pending`.
4. In `backend/src/agentshield/api/dependencies.py`, pass `max_pending` from settings when
   constructing `ApprovalManager` in `get_approval_manager()`.
5. Add test: `test_approval_manager_queue_full_rejects_new_hold`:
   - Create a manager with `max_pending=2`.
   - Create 2 pending holds.
   - Assert `ApprovalQueueFullError` is raised on the third.

**Acceptance criteria:**
- `ApprovalQueueFullError` exists in `errors.py`.
- `ApprovalManager` enforces `max_pending`.
- New test passes.
- All existing tests pass.

---

### FIX-5 (SHOULD): Operator Reason Leaked to Agent in HTTP 403 Body

**File:** `backend/src/agentshield/core/errors.py`

**Problem:** `ApprovalDeniedError.__init__` appends the operator-supplied `reason` string to
the `detail` field, which appears in the HTTP 403 Problem Details response body returned to the
coding agent. Operators may include internal policy context or project names in the reason.

**Fix:** Remove the `reason` from the client-facing `detail` string. The reason is already
preserved in `ApprovalRequest.decision_reason` and accessible via the admin-only management API.
The 403 body returned to the agent should be generic:
`"Manual approval denied for request '{request_id}'. Request blocked."`

**Acceptance criteria:**
- `ApprovalDeniedError.detail` never includes the operator reason string.
- Add test: `test_approval_denied_error_does_not_leak_reason` — create the error with a reason,
  assert the reason text is not present in `exc.detail`.
- Existing `test_proxy_hold_and_deny_flow` still passes.

---

### FIX-6 (SHOULD): Add SSE Broadcast Tests

**File:** `backend/tests/test_approvals.py` (add to existing file) or new `test_sse_events.py`

**Problem:** The completion report claims `test_events_stream_broadcasts_approvals` exists but
it does not. No test verifies that `ApprovalManager.publish_event()` delivers to subscribers or
that the SSE stream endpoint emits events correctly.

**Add the following four tests:**

1. **`test_approval_manager_pub_sub`** (sync): Subscribe a queue, call `publish_event`, assert
   the queue contains the expected `(event_type, data)` tuple.

2. **`test_approval_manager_create_publishes_pending_event`** (async): Subscribe before
   `create_request()`, assert the queue receives `("approval_pending", {...})` with correct
   `id` and `provider`.

3. **`test_approval_manager_approve_publishes_resolved_event`** (async): Subscribe, create a
   hold, approve it, assert the queue receives `("approval_resolved", {"status": "approved", ...})`.

4. **`test_sse_stream_requires_admin_auth`** (integration, using `TestClient`): Assert that
   `GET /api/v1/events/stream` returns 401 with no token, 401 with a proxy token, and 200 with
   an admin token (response media type is `text/event-stream`).

**Acceptance criteria:**
- All four tests pass.
- No real network calls or external LLM providers.
- No synthetic secrets appear in test output.

---

### FIX-7 (SHOULD): Admin Token in SSE URL — Record Accepted Deviation in ADR

**File:** new `docs/adr/ADR-007-sse-token-in-url.md` (verify next available ADR number from
the existing files in `docs/adr/` and use the correct sequential number)

**Problem:** `useLiveEvents.ts` passes the admin token as a URL query parameter because the
`EventSource` browser API does not support custom request headers. The token is visible in
browser history, server access logs, and DevTools Network panel — conflicting with "keep secrets
out of URLs" (AGENTS.md §4). This is an accepted constraint, not a code defect, but must be
formally recorded.

**Fix:** Write the ADR. Do not change any code.

ADR must include:
- **Status:** Accepted
- **Context:** `EventSource` spec prohibits custom headers; dashboard is local-only
  (127.0.0.1:8765); the admin token is not a provider/upstream credential; the query-param path
  in `require_admin_auth` already exists for this reason.
- **Decision:** Accept token-in-URL for `/api/v1/events/stream` only. All other management API
  calls continue using `Authorization: Bearer` headers.
- **Consequences:** Token appears in local server access logs; document that log retention
  should be minimal for local-only operation. Consider a short-lived single-use session token
  issued by `POST /api/v1/events/session` as a future improvement (do not implement now).

**Acceptance criteria:**
- ADR file exists with status `Accepted`.
- ADR references the EventSource API limitation and the loopback scope.
- No code changes.

---

### FIX-8 (DEFER WITH ADR): Playwright End-to-End Tests

**File:** new `docs/adr/ADR-008-playwright-e2e-deferred.md` (next number after FIX-7)

**Problem:** `prompt-milestone-5.md` §5 prohibits substituting component tests for E2E approval
verification. Playwright tests are missing and were not implemented.

**Fix:** Write the ADR formally deferring E2E tests to Milestone 6. Do not implement Playwright
tests now.

ADR must include:
- **Status:** Accepted — deferred to M6
- **Context:** Full E2E browser tests were not completed in M5. Backend integration tests cover
  the proxy/approval lifecycle; component tests cover frontend rendering; but the combined
  browser-driven flow is untested.
- **Decision:** Defer Playwright tests to Milestone 6. E2E tests gate completion of M7.
- **Scenarios that must be covered in M6:**
  1. Full approve flow: proxy request → SSE card appears → operator clicks Approve → upstream
     response received by client.
  2. Full deny flow: proxy request → operator clicks Deny → 403 returned to client.
  3. Timeout: proxy request → no action → 403 approval-timeout.
  4. Unauthorized access to `/api/v1/approvals` → 401.
  5. SSE event received and approval card updates live without page refresh.
  6. Simultaneous approval from two tabs — second tab sees the resolved state without requiring
     a manual refresh.

**Acceptance criteria:**
- ADR file exists with status `Accepted`.
- ADR lists all six required E2E scenarios.
- No Playwright tests implemented (deferred).

---

## 4. Update `planning/implementation/report-milestone-5.md`

After completing all fixes:

1. Change the **Verdict** line from `PASS` to `PASS WITH CONDITIONS (REMEDIATED)`.
2. Add a section `## 10. Review Remediation` with:
   - Each fix (FIX-1 through FIX-8) and a one-line summary of what was changed.
   - New test counts from the quality gate runs.
   - References to the two new ADRs (FIX-7, FIX-8).
3. Do not delete or modify any existing section of the report — only append.

---

## 5. Quality Gates — Must Pass After All Fixes

```bash
cd backend
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest
# All previous tests pass; at least 6 new tests added (FIX-3×1, FIX-4×1, FIX-5×1, FIX-6×4)
```

```bash
cd frontend
pnpm lint
pnpm typecheck
pnpm test
pnpm build
# All 9 previous tests pass; no new type errors
```

Inspect test output for any synthetic secret values or credential strings.
Assert none are present in logs or output.

---

## 6. Do Not

- Do not begin Milestone 6.
- Do not commit, push, merge, or deploy without explicit authorization.
- Do not introduce new dependencies.
- Do not refactor code unrelated to the listed fixes.
- Do not silently skip a fix without recording an accepted deviation in an ADR.
- Do not weaken or delete existing tests.
- Do not change the `max_history` default (500) — only add the `max_pending` cap.
- Do not implement Playwright tests (deferred by FIX-8 ADR).
