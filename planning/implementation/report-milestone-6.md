# Code Review: Milestone 6 – Audit Exports, Integration Adapters, Diagnostics, UI & E2E

**Reviewer:** Antigravity Agent  
**Date:** 2026-09-18  
**Scope:** All files added or modified in Milestone 6 (Steps 1–5).  
**Basis:** Specification §12–17, `docs/ARCHITECTURE.md`, ADR 0002/0004/0010, `docs/TESTING.md`, `AGENTS.md`.

---

## Executive Summary

All five M6 steps are implemented and pass the full quality gate (228 backend unit tests, 17 frontend unit tests, 10 Playwright E2E tests, zero Pyright/Ruff/ESLint/TypeScript errors). The implementation correctly enforces the three highest-priority security invariants: the metadata allowlist in the export pipeline, atomic sibling-file write + timestamped backup in the integration manager, and fail-WARN (not FAIL) for upstream reachability in the diagnostics check.

No critical security failures were found. The findings below are two **MEDIUM** correctness gaps, four **LOW** concerns, and several **NOTE**-level observations.

---

## Rating by Component

| Component | Rating | Summary |
|---|---|---|
| Audit Export Service | ✅ PASS | Allowlist correct, HTML escaping thorough, no CDN |
| Integration Adapters (Codex, Claude Code) | ✅ PASS | Render logic correct, detection heuristics reasonable |
| Integration Manager | ✅ PASS | Atomic write pattern correct, backup/rollback safe |
| Integration API Routes | ✅ PASS | All endpoints admin-authenticated, NotFoundError handled |
| Diagnostics Service | ✅ PASS with NOTE | All 12 §17.2 checks present, runtime version check is soft |
| Proxy Timeout Override | ✅ PASS with MEDIUM | Correct behaviour, but suppresses all DB exceptions silently |
| Frontend – AuditPage | ✅ PASS with NOTE | Metadata not allowlisted at the events list API layer |
| Frontend – IntegrationsPage | ✅ PASS | Correct API wiring, token not exposed in DOM |
| Backend Unit Tests | ✅ PASS with LOW | Good coverage; a few missing negative paths |
| Playwright E2E | ✅ PASS | 10/10 tests green; `EADDRINUSE` guard is pragmatic |

---

## Component-Level Findings

### 1. Audit Export Service (`audit/service.py`, `exporters/*.py`)

**PASS — no blocking issues.**

#### Positive observations
- `_SAFE_METADATA_KEYS` frozenset is the single source of truth; the allowlist filter is applied in `sanitize_event()` before either exporter ever sees the data (`service.py` lines 52–54). This is the correct architecture for ADR 0004.
- `contextlib.suppress(Exception)` is used only to guard JSON parsing of stored blobs. The documented fallback is an empty dict, which is safe.
- HTML exporter escapes every dynamic value through `html.escape()`. The embedded JS `toggleDetails()` function only receives a numeric loop index — never user-controlled content — so XSS via JSON injection is not possible.
- No CDN links, external `<script src>`, or remote font imports appear in the HTML template. The `https://` absence assertion in the unit test (line 234) is a correct regression guard.
- `Cache-Control: no-store` on the export response prevents browser or proxy caching.

#### MEDIUM — `metadata_json` in the events list API is not allowlist-filtered

**File:** `backend/src/agentshield/api/routes/events.py`, `_to_event_response()` (lines 61–64)  
**Description:** `GET /api/v1/events` deserialises `metadata_json` and returns the full parsed dict — including any keys the export allowlist would strip (e.g. a hypothetical `raw_prompt` key written by a future code path). The export service's allowlist is not applied to the live events API.  
**Impact:** No current confirmed leak because the proxy only writes allowlisted keys today. This is a defence-in-depth gap.  
**Recommendation:** Import and apply `_SAFE_METADATA_KEYS` (or extract `sanitize_event()`) inside `_to_event_response()` to close the gap consistently.

#### LOW — `safe_details` name in `html_exporter.py` implies only the escape is the safety boundary

**File:** `backend/src/agentshield/audit/exporters/html_exporter.py` lines 68–75  
**Description:** `safe_details` includes the full `meta` dict which is already allowlist-filtered, but the name and lack of comment could mislead future maintainers.  
**Recommendation:** Add an inline comment: `# meta is already allowlist-filtered by AuditExportService.sanitize_event()`.

---

### 2. Integration Adapters (`codex.py`, `claude_code.py`)

**PASS — no blocking issues.**

#### Positive observations
- API key values are read only to compute `has_token=bool(api_key)` — they are never logged, stored, or returned in the status response.
- Claude Code fallback path detection (`__init__` lines 24–31) is pragmatic and correctly handles the two known config locations.

#### LOW — Token written to agent config file is readable to any process running as the file owner

**Description:** The proxy token placed in `~/.codex/config.toml` (mode 0o600) grants proxy access. Users should be aware this is an inherent cooperative proxy trade-off.  
**Recommendation:** No code change required. Confirm `docs/THREAT_MODEL.md` covers config file compromise. Add one line to the CLI `configure` command output noting the token grants proxy access.

#### NOTE — `codex.py` `render_config()` line-by-line TOML parser does not handle inline tables or multiline strings

**Description:** `stripped.startswith("base_url")` will fail for inline tables or quoted keys. Codex CLI generates standard TOML, so this is acceptable in V1.  
**Recommendation:** Document the assumption in the function docstring. Consider `tomli-w` for re-serialisation in a future milestone.

---

### 3. Integration Manager (`integrations/manager.py`)

**PASS — no blocking issues.**

#### Positive observations
- Atomic write (lines 154–161): write to `.tmp.{uuid}` → `Path.replace(target)` is POSIX-atomic within the same filesystem. The `finally` block cleans up the temp file if `replace()` throws.
- Token files are read fresh from disk on every `get_agent_for_token()` call — no stale-token window from in-memory caching.
- `ensure_secure_dir()` is called on `target.parent` before any write.

#### MEDIUM — Atomic write does not roll back backup if the DB commit fails

**File:** `backend/src/agentshield/integrations/manager.py`, `apply()` (lines 131–177)  
**Description:** Sequence: (1) backup, (2) write config, (3) DB commit. If step 3 fails, the config file is updated but `last_backup_path` and `updated_at` are not recorded. A subsequent `rollback()` will still find the backup via the glob fallback, but the DB and filesystem diverge.  
**Recommendation:** Wrap the DB commit in a `try/except Exception` and log a warning on failure so the divergence is visible.

---

### 4. Integration API Routes (`api/routes/integrations.py`)

**PASS — no blocking issues.**

#### Positive observations
- All five endpoints require `require_admin_auth`.
- The `/test` probe returns `success/failure` but never leaks the integration token or any upstream credential in the response.
- `NotFoundError` for unknown `agent` types is caught and converted to the documented Problem Details format by the global exception handler.

#### NOTE — `/test` probes port `settings.port` on loopback; traverses the proxy inspection pipeline

**Description:** Intentional — verifies real authentication. Should be documented in the endpoint description.

---

### 5. Diagnostics Service (`core/diagnostics.py`)

**PASS — all 12 §17.2 checks implemented.**

#### Positive observations
- Check 9 (upstream reachability) correctly returns `WARN` not `FAIL` when providers are unreachable. The test explicitly asserts this (lines 70–72).
- Check 7 (credentials) outputs only `"OpenAI: present"` / `"not set"` — no key value or fingerprint. The test asserts the synthetic secrets are absent from the details string.
- Check 5 (token permissions) asserts `0o600` on non-Windows platforms.
- Check 12 (security profile) instantiates a real `DetectorEngine` with a synthetic fingerprint key — the correct pattern for a functional health check.

#### LOW — Check 1 (runtime) always returns OK regardless of Python version

**File:** `backend/src/agentshield/core/diagnostics.py`, `check_runtime()` (lines 86–93)  
**Description:** The version is reported but never compared to the required minimum (3.14). Running on Python 3.12 would return `OK`.  
**Recommendation:**
```python
if sys.version_info < (3, 14):
    return DiagnosticCheckResult(
        name="Python Runtime", status=DiagnosticStatus.WARN,
        details=f"Python {py_ver} found; AgentShield requires ≥ 3.14")
```

#### NOTE — `check_agent_configurations()` uses hardcoded port 8765 instead of `self.settings.port`

**File:** `backend/src/agentshield/core/diagnostics.py` lines 259–260  
**Description:** If the user runs on a non-default port, the detection would incorrectly report `not routed`.  
**Recommendation:** Use `f"http://127.0.0.1:{self.settings.port}/proxy/openai"`.

---

### 6. Proxy Timeout Override (`api/routes/proxy.py` lines 201–208)

**PASS with one note.**

#### Positive observations
- Wrapped in `contextlib.suppress(Exception)` — a DB failure does not block an in-flight approval. The fallback to `settings.approval_timeout_seconds` is correct fail-open behaviour.
- `effective_timeout` is passed to both `create_request()` and `wait_for_decision()` — the same value is used for the TTL and the wait loop (no drift).

#### LOW — Silent suppression hides DB errors in approval timeout lookup

**File:** `backend/src/agentshield/api/routes/proxy.py` lines 202–208  
**Recommendation:** Add `except Exception: logger.debug("Could not read approval_timeout_seconds from DB, using default", exc_info=True)` before suppressing to aid diagnostics.

---

### 7. Settings In-Memory Sync (`api/routes/settings.py` lines 120–128)

**PASS.**  
Mutation of the in-memory `Settings` singleton is intentional and documented with `# pyright: ignore` comments. Works correctly in single-worker deployments.

#### NOTE — Multi-worker deployment would cause settings drift

**Description:** Each uvicorn worker has its own `Settings` memory. The DB-backed `SettingsRepository` lookup in `proxy.py` mitigates this for `approval_timeout_seconds`, but `settings.profile` used directly by the proxy would diverge.  
**Recommendation:** Document in `docs/ARCHITECTURE.md` that multi-worker deployment is not supported in V1.

---

### 8. Frontend – AuditPage (`frontend/src/pages/AuditPage.tsx`)

**PASS — no blocking security issues.**

#### Positive observations
- The inspection modal renders only decision metadata and finding counts — no raw prompt text or secret values.
- Export blob URL is created and immediately revoked after `link.click()` — no lingering blob references in memory.
- Export `limit` is set to 1000 in the UI payload, lower than the backend cap of 50,000.

#### NOTE — `datetime-local` captures local time but label does not indicate this

**Description:** `new Date(startTime).toISOString()` correctly converts to UTC before sending to the backend. However, the label "From Date" gives no timezone indication. Users in non-UTC zones may set unexpected filter windows.  
**Recommendation:** Add "(local time)" to the label or show the resolved UTC time below the input.

---

### 9. Frontend – `client.ts` API Layer

**PASS — no blocking issues.**

- `testIntegration()` uses an inline anonymous response type that matches `ConnectionTestResponse`. Minor brittleness; acceptable for V1.
- `configureIntegration()` and `rollbackIntegration()` correctly send POST with no body — backend accepts `body: ConfigureRequest | None = None`.

---

### 10. Backend Unit Tests

**PASS — adequate coverage.**

#### Well covered
- Allowlist stripping (`test_audit_export_service_json_serialization_and_allowlist` line 207: asserts `"UNSAFE_PROMPT_DO_NOT_LEAK" not in content`).
- Codex TOML rendering with existing sections preserved.
- Apply/backup/rollback cycle with content verification.
- Per-integration token generation, attribution, and management API CRUD.
- All 12 diagnostics check names present; offline → WARN; credential values absent from details.

#### LOW — No test for `export_with_corrupt_metadata_json`

**Recommendation:**
```python
def test_export_tolerates_corrupt_metadata_json(audit_db):
    repo = AuditRepository(audit_db)
    repo.record_event(AuditEvent(…, metadata_json="invalid{json"))
    service = AuditExportService(repo)
    content, _, _ = service.export(export_format="json")
    data = json.loads(content)
    assert data["events"][-1]["metadata"] == {}
```

#### LOW — No test for `rollback()` when no backup exists

**Recommendation:** Add test that calls `manager.rollback("codex", config_path=<fresh_path>)` and asserts `NotFoundError` is raised.

---

### 11. Playwright E2E Suite (`frontend/e2e/approvals.spec.ts`)

**PASS — 10/10 tests green.**

#### Positive observations
- `EADDRINUSE` guard (lines 29–33) prevents CI flakiness from port contention.
- `workers: 1, fullyParallel: false` prevents port 8768 race conditions.
- `getAdminTokenForTest()` / `getProxyTokenForTest()` read token files from disk at runtime — no hardcoded credentials.

#### NOTE — E2E tests assume backend is pre-started on port 8765

**Recommendation:** Add a comment in `playwright.config.ts` noting the backend startup prerequisite for CI documentation.

---

## Security Invariant Compliance

| Invariant | Status | Notes |
|---|---|---|
| No raw prompts/responses in exports | ✅ Enforced | Allowlist in `service.py`; test asserts `UNSAFE_PROMPT_DO_NOT_LEAK` absent |
| No secrets persisted | ✅ Enforced | Integration tokens only in 0o600 files; not in SQLite |
| No credentials forwarded to frontend | ✅ Enforced | `IntegrationStatusResponse` contains `has_token: bool` only |
| Admin auth on all new endpoints | ✅ Enforced | All `/api/v1/audit/export` and `/api/v1/integrations/*` require admin token |
| No wildcard CORS | ✅ Inherited | No CORS changes in M6 |
| No CDN in HTML export | ✅ Enforced | Inline CSS only; unit test asserts absence of external URLs |
| Fail closed on detector error | ✅ Not changed in M6 | |
| No unencrypted credential fallback | ✅ No new credential storage | Integration tokens use `write_secure_file` (0o600) |

---

## ADR Compliance

| ADR | Relevant M6 Change | Status |
|---|---|---|
| ADR 0002 — Native Keyring | Diagnostics check 6 rejects null/fail backends | ✅ Compliant |
| ADR 0004 — Privacy-Preserving Audit | Export allowlist; gap at live events API layer | ⚠ MEDIUM gap |
| ADR 0010 — Manual Approval Workflow | E2E suite covers all 5 ADR 0010 scenarios | ✅ Compliant |

---

## Prioritised Follow-Up Items

| Priority | Area | Action |
|---|---|---|
| MEDIUM | `events.py` | Apply `_SAFE_METADATA_KEYS` filter in `_to_event_response()` |
| MEDIUM | `manager.py` | Log warning when DB commit fails after successful config write |
| LOW | `diagnostics.py` | Add Python ≥3.14 version check to `check_runtime()` |
| LOW | `diagnostics.py` | Replace hardcoded `8765` with `self.settings.port` in `check_agent_configurations()` |
| LOW | `test_audit_export.py` | Add corrupt `metadata_json` tolerance test |
| LOW | `test_integrations.py` | Add `rollback()` with no backup → `NotFoundError` test |
| NOTE | `docs/THREAT_MODEL.md` | Confirm config file compromise is documented as cooperative proxy limitation |
| NOTE | `docs/ARCHITECTURE.md` | Document single-worker requirement due to in-memory settings |
| NOTE | `AuditPage.tsx` | Add timezone indicator to date filter labels |
| NOTE | `playwright.config.ts` | Document backend startup prerequisite |

---

## Conclusion

Milestone 6 is **accepted**. All five deliverables are correctly implemented and fully tested. No critical or high-severity security failures were found. The two MEDIUM items are defence-in-depth improvements (not active data leaks). The LOW and NOTE items are quality and documentation improvements. None require blocking the milestone.

The implementation demonstrates sound security engineering: the export allowlist is a single source of truth applied before any formatter; integration mutations are filesystem-atomic with pre-write backups; the diagnostics service correctly distinguishes transient network failures (WARN) from local configuration failures (FAIL); and the Playwright suite provides end-to-end coverage of the approval workflow against a real mock upstream server.
