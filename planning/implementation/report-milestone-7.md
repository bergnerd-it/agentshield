# Milestone 7 Code Review Report

**Project:** AgentShield V1  
**Milestone:** 7 — Hardening and Documentation  
**Review date:** 2026-09-18  
**Scope:** All files modified or created in the `feature/m7` branch

---

## Executive Summary

The milestone delivers all seven specified deliverables: Milestone 6 fixes, synthetic attack corpus, performance benchmarking, SBOM/vulnerability scanning, cross-platform hardening, customer demonstration suite, and documentation updates. The quality gate (ruff, pyright 0 errors, 312 pytest passes, 17 vitest passes, 10 Playwright passes) was confirmed passing.

**However, four critical defects must be fixed before merge:**

1. A Python 2 syntax error (`except A, B:`) in `conftest.py`, `run_demo.py`, and `benchmark.py` — these files crash on import under Python 3.14.
2. A shebang mismatch in `reset_demo.py` — makes the file unrunnable via `python3` or `uv run`.

In addition, two security-relevant major issues exist in production source code (token content in diagnostic output; unvalidated backup path used as filesystem path) and several medium-priority issues affect CI supply-chain hygiene, test reliability, and frontend accessibility.

---

## Severity Key

| Symbol | Severity | Meaning |
|--------|----------|---------|
| 🔴 | **Critical** | Will crash at runtime or import time; or violates a non-negotiable security invariant |
| 🟠 | **Major** | Security-relevant or correctness gap; must be fixed before production |
| 🟡 | **Medium** | Quality or reliability issue; should be fixed in a follow-up |
| 🔵 | **Minor** | Code hygiene, documentation polish, or low-risk gap |
| ⚪ | **Observation** | Suggestion with no functional impact |

---

## Part 1 — Backend Source Code

### 1.1 `backend/src/agentshield/proxy/sse.py`

**Purpose (M7):** CRLF holdback for `\r` split across chunk boundaries, ensuring SSE events parse correctly on Windows-style streams.

| # | Sev | Line | Issue |
|---|-----|------|-------|
| S-1 | 🔵 | 131–138 | After `PayloadTooLargeError` is raised the parser's internal counters are not reset and no `_errored` flag is set. A caller that catches the error and continues feeding data will get inconsistent results. Add an `_errored: bool` guard and raise on subsequent `feed()` calls. |
| S-2 | 🔵 | 188–197 | `SSESerializer.serialize()` does not strip embedded `\n` or `\r` from `event.event`, `event.id`, or `event.comment`. A malformed upstream response containing a newline in those fields would produce broken SSE framing. |

**Overall:** Excellent. Core CRLF logic is correct, well-tested, and memory-bounded. Both issues are minor defence-in-depth gaps.

---

### 1.2 `backend/src/agentshield/api/routes/events.py`

**Purpose (M7):** Added `_SAFE_METADATA_KEYS` allowlist filtering on the SSE broadcast and event list endpoints; also adds the audit event list, stream, and detail endpoints.

| # | Sev | Line | Issue |
|---|-----|------|-------|
| E-1 | 🟡 | 148–155 | `is_testclient = "testclient" in request.headers.get("user-agent", "").lower()` is test-infrastructure leakage into production code. This heuristic is spoofable and undocumented. Replace with an injected timeout parameter or a proper shutdown event. |
| E-2 | ⚪ | 163 | `event_type` is written raw into the SSE frame with no newline sanitisation. All callers currently use hard-coded string literals, so risk is negligible, but `publish_event()` should validate or sanitise `event_type` as a defence-in-depth measure. |

**Overall:** Correct and secure. Allowlist filtering is DRY (shared with `audit/service.py`). Admin auth is enforced on all three endpoints. Both findings are minor.

---

### 1.3 `backend/src/agentshield/integrations/manager.py`

**Purpose (M7):** Added a DB commit warning log when the filesystem rollback succeeds but the SQLite record update fails.

| # | Sev | Line | Issue |
|---|-----|------|-------|
| M-1 | 🟠 | 193 | `last_backup_path` is read from SQLite and used directly as a `Path` object without validating that it lies within `target.parent` or `settings.data_dir`. If the SQLite database were tampered with, this could be exploited for a path-traversal write during rollback. Validate the resolved path before use. |
| M-2 | 🔵 | 219 | `rollback()` constructs the temp file in `target.parent` without calling `ensure_secure_dir()`, inconsistent with `apply()` which calls it explicitly. |
| M-3 | ⚪ | 65–66 | `get_token_path()` and `get_or_create_token()` accept arbitrary `agent_type` strings. Callers always call `get_adapter()` first, but adding an internal assertion would make the invariant explicit. |

**Overall:** Token handling and atomic file replacement are correct. The backup-path issue (M-1) is the only security-relevant concern.

---

### 1.4 `backend/src/agentshield/core/diagnostics.py`

**Purpose (M7):** Python version check raised to `>= 3.14`; dynamic port check added.

| # | Sev | Line | Issue |
|---|-----|------|-------|
| D-1 | 🟠 | 192 | `adm_tok[:7]` and `prx_tok[:7]` are embedded in the `details` string of `DiagnosticCheckResult`. The first 7 characters are currently the deterministic prefix (`as_adm_` / `as_prx_`), which contains no entropy. However this is a fragile pattern: if the prefix length or format changes, real token entropy would appear in CLI stdout, log output, and any future API exposing diagnostics — violating AGENTS.md §4. **Fix:** Replace token content with only the file path and permission mode. |
| D-2 | 🔵 | 124 | `check_database()` calls `run_migrations()` (Alembic `upgrade head`) as a side effect of a read-only diagnostic command. While safe when already at head, this is unexpected mutation from a "read" operation. Replace with `alembic check` semantics. |
| D-3 | 🔵 | 114–118 | Raw OS/SQLAlchemy exception messages are embedded in `DiagnosticCheckResult.details` without passing through the safe-logging layer (`sanitize_text()`). These strings may contain filesystem paths or ORM internals. |
| D-4 | ⚪ | 381 | `fingerprint_key = b"0" * 32` is a synthetic sentinel value for the detector smoke-test. Add a comment clarifying it is not the real key. |

**Overall:** Functionally correct. D-1 is a security-quality issue: while not currently exploitable, it violates the spirit of AGENTS.md §4 and should be fixed proactively.

---

### 1.5 `backend/src/agentshield/cli.py`

**Purpose (M7):** Added `SO_REUSEADDR` to the port-collision detection socket to prevent `TIME_WAIT` false positives during test cycles.

| # | Sev | Line | Issue |
|---|-----|------|-------|
| C-1 | 🟡 | 100 | `# pyright: ignore[reportAttributeAccessIssue]` on `settings.profile = profile` bypasses strict Pyright mode, which is required by AGENTS.md §7. Fix: validate the string against the `Literal` values before assignment, or reconstruct `Settings` with the new value. |
| C-2 | ⚪ | 91–99 | `os.environ` mutation before `uvicorn.run()` combined with module-level `get_settings()` caching is fragile. If any import-time code calls `get_settings()` first, the cached instance will have wrong values. Document this ordering constraint. |

**Overall:** Correct and secure. The `SO_REUSEADDR` addition achieves its goal. C-1 is the only meaningful issue.

---

### 1.6 `backend/src/agentshield/audit/service.py`

**Purpose (M7):** Exports `SAFE_METADATA_KEYS` as a module-level constant so `events.py` can share the allowlist without duplication.

| # | Sev | Line | Issue |
|---|-----|------|-------|
| A-1 | ⚪ | 30 | `_SAFE_METADATA_KEYS = SAFE_METADATA_KEYS` is a redundant no-op alias (both names refer to the same object). Remove the private alias. |
| A-2 | ⚪ | 112–119 | `export()` uses an `if/else` on `export_format` with `"json"` as the silent fallback. Using `assert_never(export_format)` after the `elif "html"` branch would make exhaustiveness explicit. |
| A-3 | ⚪ | 83 | `limit=10000` for the export query is hardcoded. Document this ceiling or make it configurable via `Settings`. |

**Overall:** Excellent. The allowlist design is the right pattern. All findings are minor polish items.

---

## Part 2 — Test Suite and Corpus

### 2.1 `conftest.py`

| # | Sev | Line | Issue |
|---|-----|------|-------|
| T-0 | 🔴 | 13 | `except PermissionError, OSError:` — **Python 2 syntax.** Python 3 requires `except (PermissionError, OSError):`. This causes a `SyntaxError` at collection time and **breaks the entire test suite**. Highest-priority fix in the milestone. |

---

### 2.2 `backend/tests/test_attack_corpus.py`

| # | Sev | Location | Issue |
|---|-----|----------|-------|
| AC-1 | 🟡 | 312–319 | The search-token extraction heuristic (splitting corpus payload on `=` or `:`) is fragile. For PEM private keys it produces the entire PEM block. A per-item `search_token` field in the corpus JSON would be deterministic and explicit. |
| AC-2 | 🟡 | `OBF-SPLIT-001` | The corpus description says "split strings in consecutive JSON messages" but the payload is identical to `SEC-OPENAI-001` — a single string. The split-across-SSE-events scenario from TESTING.md §5 is not actually exercised. |
| AC-3 | 🔵 | 341–345 | The loop `for rec in mock_server.recorded_requests:` is dead code when `len(...) == 0` was already asserted on line 338. Remove or comment out. |
| AC-4 | 🔵 | Corpus | `AKIAIOSFODNN7EXAMPLE` and `wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY` are the canonical AWS documentation examples. Some scanners specifically allowlist these. Verify that AgentShield's secret detector catches them. |
| AC-5 | ⚪ | `obfuscation.json` | No homoglyph (e.g. Cyrillic lookalike) corpus item. TESTING.md §3 lists this as a required encoding variant. |
| AC-6 | ⚪ | `pii.json` | All PII items have `must_not_leak: false`. Since PII is pseudonymised, the raw value should also not appear in upstream captures or audit exports. Consider adding `must_not_leak: true` for top-level name and email items. |

---

### 2.3 `backend/tests/test_performance.py`

| # | Sev | Location | Issue |
|---|-----|----------|-------|
| P-1 | 🟡 | `test_median_proxy_overhead_under_30ms` | Wall-clock latency assertion is environment-sensitive and may produce non-deterministic false failures on loaded CI runners. Mark with `@pytest.mark.slow` and document CI tolerance. |
| P-2 | 🟡 | Entire file | TESTING.md §7 explicitly requires p95 and p99 assertions where sample size permits. With 25 samples, p95 is measurable. Add a p95 < 100 ms assertion. |
| P-3 | 🔵 | `test_payload_exceeding_10mib_rejected_with_413` | No corresponding test for a payload of exactly 10 MiB (boundary: should be allowed). |
| P-4 | ⚪ | All | The 30 ms assertion measures full round-trip latency through TestClient + ASGI, not isolated pre-request scanning overhead as specified in §18.4. Document this distinction. |

---

### 2.4 `backend/tests/test_demo_scenario.py`

| # | Sev | Location | Issue |
|---|-----|----------|-------|
| DS-1 | 🟠 | Step 10 | `DiagnosticsService(settings=demo_settings)` is constructed without injecting `http_client`. The real implementation issues outbound HTTP requests (reachability checks). This may make real external connections, violating TESTING.md §1. Inject `httpx.MockTransport` as in `test_doctor.py`. |
| DS-2 | 🟡 | Step 8 | `asyncio.run(asyncio.sleep(0.05))` is used as a polling sleep inside a `ThreadPoolExecutor` worker. TESTING.md §10 explicitly prohibits arbitrary sleep-based polling. Use a `threading.Event` signalled by `ApprovalManager.subscribe()` instead. |
| DS-3 | 🔵 | Fixture | `demo_env` fixture does not call `reset_settings(None)` in teardown, unlike all other fixtures in `conftest.py`. May leave global settings state dirty. |
| DS-4 | ⚪ | Step 9 | Checks that `Erika Mustermann` and `synthetic_key` are absent from the audit export but does not verify that the raw value of `GreenfieldGrantService` is also absent. |

---

### 2.5 `backend/tests/test_audit_export.py`

| # | Sev | Location | Issue |
|---|-----|----------|-------|
| AE-1 | ⚪ | 233 | The HTML CDN assertion allows `"http://"` if the `or` conditions for `w3.org` or `127.0.0.1` are satisfied. A future template accidentally adding another `http://` external resource could pass. Tighten to an explicit allowlist. |

**Overall:** Strong. The `UNSAFE_PROMPT_DO_NOT_LEAK` regression guard and corrupt-metadata graceful-fallback test are particularly good.

---

### 2.6 `backend/tests/test_integrations.py`

| # | Sev | Location | Issue |
|---|-----|----------|-------|
| I-1 | 🟡 | `test_proxy_traffic_attribution_via_integration_tokens` | No `get_forward_client` override injected. Currently safe because all test requests contain secrets and are blocked at 403. But if a future iteration adds a non-blocked request, it will hit the real upstream. Inject a mock client explicitly. |
| I-2 | 🔵 | Line 168 | `repo.list_events(limit=5)` assumes most-recent-first ordering. If this ordering guarantee changes, the test will silently check the wrong event. |

---

### 2.7 `backend/tests/test_doctor.py`

| # | Sev | Location | Issue |
|---|-----|----------|-------|
| DR-1 | 🟡 | `test_cli_doctor_output_banner` | Calls `runner.invoke(app, ["doctor"])` without injecting a mock credential store or HTTP client. May access the real system keyring or make real network calls, violating TESTING.md §1. |
| DR-2 | 🔵 | Line 117 | `"X-AgentShield-Loop-Detect" in result.output or "System Diagnostics" in result.output` — the `or` weakens the assertion. Separate into two `assert` statements. |

---

### 2.8 `backend/tests/test_management_api.py`

| # | Sev | Location | Issue |
|---|-----|----------|-------|
| MA-1 | 🟡 | `mgmt_client` fixture | Does not use `yield` and therefore never calls `app.dependency_overrides.clear()`. Leaks overrides that could affect other tests if fixture scope is widened. Refactor to `yield` + cleanup. |
| MA-2 | ⚪ | Line 134 | `get_db_session` imported and used inside test body, bypassing the injected session. Prefer the fixture-provided client for all data setup. |

---

### 2.9 `backend/tests/test_sse_parser.py`

**Overall:** Excellent coverage. Minor gaps only.

| # | Sev | Location | Issue |
|---|-----|----------|-------|
| SSE-1 | ⚪ | All | No test for `SSESerializer` output when `event`, `id`, or `comment` contain embedded newlines (complement to source-code issue S-2). |
| SSE-2 | ⚪ | All | No tests for the `retry:` field or zero-length data (`data:\n\n`). |

---

### 2.10 Corpus Files

| File | Finding |
|------|---------|
| `secrets.json` | ⚪ All correctly marked synthetic. AWS docs example keys should be verified (AC-4). Missing YAML and `.env` password format entries. |
| `pii.json` | ⚪ All fictional or standard test data. Missing multi-sink `must_not_leak` coverage (AC-6). |
| `custom_terms.json` | ✅ Clearly fictional internal identifiers. |
| `obfuscation.json` | 🔵 `OBF-SPLIT-001` does not test split-across-SSE-events (AC-2). No homoglyph items (AC-5). |
| `false_positives.json` | ⚪ Reasonable starting set. Missing SHA256 hashes, hex colour codes, base64 data URIs. |

---

## Part 3 — Scripts and CI

### 3.1 `scripts/run_demo.py`

| # | Sev | Line | Issue |
|---|-----|------|-------|
| RD-1 | 🔴 | 27 | `except PermissionError, OSError:` — **Python 2 syntax.** Script will raise `SyntaxError` on import and will not execute on Python 3.14. Fix: `except (PermissionError, OSError):` |
| RD-2 | 🔵 | 296 | `import concurrent.futures` inside function body. Move to module top level per PEP 8. |
| RD-3 | ⚪ | Docstring | `--interactive` flag documented in usage comment but not implemented in `argparse` setup. |

---

### 3.2 `scripts/reset_demo.py`

| # | Sev | Line | Issue |
|---|-----|------|-------|
| RST-1 | 🔴 | 1 | Shebang is `#!/usr/bin/env bash` on a `.py` file intended to be run as `python3 reset_demo.py` or `uv run scripts/reset_demo.py`. Both invocations fail because Python parses the bash shebang as a syntax error. Fix: change shebang to `#!/usr/bin/env python3` and restructure as a proper Python script (remove the `python3 -c '...'` heredoc wrapper). |
| RST-2 | ⚪ | Docs | `run_demo.py` uses `tempfile.mkdtemp(prefix="agentshield_demo_")` (places dirs in `$TMPDIR`). `reset_demo.py` targets `~/.agentshield-demo`. The two scripts clean up different directories. Document this. |

---

### 3.3 `backend/scripts/benchmark.py`

| # | Sev | Line | Issue |
|---|-----|------|-------|
| BM-1 | 🔴 | 32 | `except PermissionError, OSError:` — **Python 2 syntax.** Script will not execute on Python 3.14. Fix: `except (PermissionError, OSError):` |
| BM-2 | 🟠 | 390–395 | p95, p99, TTFB p50, and payload-limit rows in the generated `PERFORMANCE.md` show hard-coded `✅ PASS` strings regardless of measured values. Only p50 overhead is dynamically evaluated. The report may misrepresent failures. Apply the same dynamic evaluation pattern used for p50. |

---

### 3.4 `scripts/generate_sbom.sh`

| # | Sev | Location | Issue |
|---|-----|----------|-------|
| SBOM-1 | ⚪ | All | No explicit pre-flight checks for required tools — failure messages come from the OS, not the script. |

**Overall:** Correct. `set -euo pipefail`, `trap … EXIT` cleanup, and frozen lockfile exports are all implemented correctly.

---

### 3.5 `scripts/scan_dependencies.sh`

| # | Sev | Location | Issue |
|---|-----|----------|-------|
| SCAN-1 | ⚪ | All | Audit findings printed to stdout but not archived as CI artefacts. Consider `--format json -o dist/audit/pip-audit.json` + `upload-artifact` for traceability. |

**Overall:** Correct. Exit-code propagation and `--audit-level=high` gate are both implemented correctly.

---

### 3.6 `.github/workflows/ci.yml`

| # | Sev | Location | Issue |
|---|-----|----------|-------|
| CI-1 | 🟠 | All `uses:` lines | All GitHub Actions are pinned to mutable major-version tags (`@v4`, `@v5`), not immutable commit SHA digests. AGENTS.md §12 states "Do not execute unpinned remote scripts in CI." **Fix:** Pin each `uses:` to its full commit SHA. |
| CI-2 | 🟠 | Top level | No `permissions:` block declared. Default `GITHUB_TOKEN` has broad read/write access. Add `permissions: contents: read` to enforce least privilege. |
| CI-3 | 🟡 | `security` job | The `security` job runs in parallel with `backend` and `frontend`. SBOMs are generated even from failing builds. Add `needs: [backend, frontend]`. |
| CI-4 | ⚪ | `security` job | No SBOM retention policy on `upload-artifact@v4` — defaults to 90 days. Consider `retention-days: 365` for release SBOMs. |

---

## Part 4 — Documentation

### Overclaims and Limitations Audit

No overclaims detected in any document. GDPR compliance, complete PII detection, and direct-egress enforcement are all explicitly disclaimed. The cooperative reverse proxy limitation is consistently and accurately stated in README, THREAT_MODEL.md, ARCHITECTURE.md, SECURITY.md, and DEMO.md.

| # | Sev | File | Issue |
|---|-----|------|-------|
| DOC-1 | 🟡 | `docs/PERFORMANCE.md:3` | `**Version:** 0.1.0` — version mismatch. SECURITY.md and README both state `1.0.0`. Must be corrected before public release. |
| DOC-2 | 🔵 | `docs/ARCHITECTURE.md:215` | Section `5.1` heading appears twice — the second occurrence (Manual Approval Architecture) should be numbered `5.2`. |
| DOC-3 | ⚪ | `docs/DEMO.md:163` | Example output hard-codes `"All 4 detectors healthy"`. If the detector count changes, this becomes stale. Mark as illustrative. |
| DOC-4 | ⚪ | `docs/PRIVACY.md:128` | "Milestone 3 request tests" is now historical wording. Rephrase to describe current test coverage. |

---

## Part 5 — Frontend

### 5.1 `frontend/src/pages/AuditPage.tsx`

**Functional correctness:** ✅ Pagination, filtering, date conversion (local → ISO UTC), and export are all correct. No raw payload, credentials, or provider keys appear in any rendered state.

| # | Sev | Line | Issue |
|---|-----|------|-------|
| UI-1 | 🟡 | L401 | The audit detail modal has `role="dialog"` and `aria-modal="true"` but no focus trap is implemented. Keyboard users can Tab out of the modal without closing it, and screen readers may not confine navigation to modal content. This violates WCAG 2.1 SC 2.1.2. Use the native `<dialog>` element or add a focus trap. |
| UI-2 | 🟡 | L401 | No `onKeyDown` Escape-key handler on the modal. ARIA Authoring Practices require `role="dialog"` modals to close on Escape. |
| UI-3 | ⚪ | L320 | `<tr onClick={...}>` is not keyboard-focusable by default. If row-click is a primary interaction path, add `role="button"` + `tabIndex={0}` + `onKeyDown`. |
| UI-4 | ⚪ | L352 | `aria-label={\`Inspect event ${evt.id}\`}` — UUIDs are verbose when announced by screen readers. A timestamp-based label would be more natural. |

---

### 5.2 `frontend/e2e/approvals.spec.ts`

**Coverage:** Core approval flows (approve, deny, timeout, live SSE, multi-tab concurrency) and auth-boundary rejections are all tested.

| # | Sev | Location | Issue |
|---|-----|----------|-------|
| E2E-1 | 🟡 | Lines 82, 129, 225, 270–277 | `page.locator('.approval-card')` uses a CSS class selector. If the class name is refactored, tests break silently. Replace with `data-testid="approval-card"` and `page.getByTestId(...)`. |
| E2E-2 | 🟡 | Line 136 | `card.locator('input')` is an unscoped bare input locator. Replace with `card.getByRole('textbox', { name: /reason/i })`. |
| E2E-3 | 🟡 | Line 210 | `await page.waitForTimeout(1000)` is a fixed-delay wait for SSE connection — a common source of CI flakiness. Use `waitForResponse` to detect the SSE connection handshake instead. |
| E2E-4 | ⚪ | Scenario numbering | Scenarios jump from 3 to 5. Confirm whether Scenario 4 (client-disconnect cancellation) was intentionally omitted or missed. |

---

### 5.3 `frontend/playwright.config.ts`

**Overall:** `reuseExistingServer: false`, `workers: 1`, correct port (8766), and clearly synthetic `AGENTSHIELD_OPENAI_API_KEY` are all correct.

| # | Sev | Location | Issue |
|---|-----|----------|-------|
| PW-1 | ⚪ | `projects` | Only Chromium is tested. Firefox coverage would increase confidence for an operator-facing dashboard. |

---

## Issue Summary Table

### 🔴 Critical — Fix Immediately

| ID | File | Description |
|----|------|-------------|
| T-0 | `conftest.py:13` | `except PermissionError, OSError:` — Python 2 syntax crashes entire test suite |
| RD-1 | `scripts/run_demo.py:27` | `except PermissionError, OSError:` — Python 2 syntax, script will not execute |
| BM-1 | `backend/scripts/benchmark.py:32` | `except PermissionError, OSError:` — Python 2 syntax, script will not execute |
| RST-1 | `scripts/reset_demo.py:1` | Bash shebang on `.py` file — `python3`/`uv run` invocations fail |

### 🟠 Major — Fix Before Production

| ID | File | Description |
|----|------|-------------|
| D-1 | `core/diagnostics.py:192` | Token content (`adm_tok[:7]`) in diagnostic details — fragile, violates AGENTS.md §4 spirit |
| M-1 | `integrations/manager.py:193` | Backup path from SQLite used as filesystem path without bounds validation — latent path traversal |
| BM-2 | `backend/scripts/benchmark.py:390–395` | Hard-coded `✅ PASS` for p95/p99/TTFB in generated PERFORMANCE.md |
| DS-1 | `test_demo_scenario.py` Step 10 | `DiagnosticsService` constructed without `http_client` injection — may make real outbound connections |
| CI-1 | `.github/workflows/ci.yml` | GitHub Actions not SHA-pinned — violates AGENTS.md §12 |
| CI-2 | `.github/workflows/ci.yml` | No `permissions:` block — default broad GITHUB_TOKEN scope |

### 🟡 Medium — Fix in Follow-Up

| ID | File | Description |
|----|------|-------------|
| E-1 | `events.py:148–155` | `is_testclient` heuristic is test-infrastructure leakage into production code |
| C-1 | `cli.py:100` | `# pyright: ignore` on profile assignment violates strict Pyright requirement |
| DOC-1 | `PERFORMANCE.md:3` | Version string `0.1.0` should be `1.0.0` |
| DS-2 | `test_demo_scenario.py` Step 8 | Polling `asyncio.sleep` — violates TESTING.md §10 |
| P-1 | `test_performance.py` | Wall-clock latency assertion is flaky in CI environments |
| P-2 | `test_performance.py` | Missing p95/p99 latency assertions (required by TESTING.md §7) |
| P-3 | `test_performance.py` | No boundary test for exactly 10 MiB payload |
| AC-1 | `test_attack_corpus.py:312–319` | Fragile search-token extraction heuristic |
| AC-2 | `obfuscation.json` | OBF-SPLIT-001 does not test split-across-SSE-events scenario |
| UI-1 | `AuditPage.tsx:401` | Modal missing focus trap — violates WCAG 2.1 SC 2.1.2 |
| UI-2 | `AuditPage.tsx:401` | Modal missing Escape-key handler — violates ARIA Authoring Practices |
| E2E-1 | `approvals.spec.ts` | CSS class selectors `.approval-card` — use `data-testid` |
| E2E-2 | `approvals.spec.ts:136` | Bare `locator('input')` — use `getByRole('textbox')` |
| E2E-3 | `approvals.spec.ts:210` | `waitForTimeout(1000)` — use deterministic signal |
| CI-3 | `ci.yml` | `security` job runs independently — add `needs: [backend, frontend]` |
| MA-1 | `test_management_api.py` | `mgmt_client` fixture does not clean up `dependency_overrides` |
| DR-1 | `test_doctor.py` | `test_cli_doctor_output_banner` may access real keyring and network |
| I-1 | `test_integrations.py` | No `get_forward_client` mock in attribution test |

### 🔵 Minor / ⚪ Observation

Remaining items (S-1, S-2, E-2, M-2, M-3, D-2–4, C-2, A-1–3, AC-3–6, DS-3–4, AE-1, DR-2, MA-2, I-2, SSE-1–2, SBOM-1, SCAN-1, CI-4, DOC-2–4, UI-3–4, E2E-4, PW-1) are code hygiene, documentation polish, or low-risk observations with no immediate functional impact.

---

## Recommended Resolution Order

### 1. Immediately (before any further CI run)
- Fix Python 2 syntax in `conftest.py` (T-0), `run_demo.py` (RD-1), `benchmark.py` (BM-1)
- Fix shebang in `reset_demo.py` (RST-1)

### 2. Before merge to main
- Fix token prefix in diagnostic output — use file path + permission mode only (D-1)
- Validate backup path is within expected directory before use in rollback (M-1)
- Fix `PERFORMANCE.md` version string `0.1.0` → `1.0.0` (DOC-1)
- Fix dynamic SLA evaluation for p95/p99/TTFB rows in `benchmark.py` (BM-2)
- Inject `httpx.MockTransport` in `test_demo_scenario.py` Step 10 (DS-1)
- Pin GitHub Actions to SHA digests and add `permissions: contents: read` (CI-1, CI-2)

### 3. Follow-up iteration
- Modal focus trap + Escape handler (UI-1, UI-2)
- Playwright selector hardening via `data-testid` (E2E-1, E2E-2, E2E-3)
- SSE parser poisoned-state flag and serialiser newline guard (S-1, S-2)
- p95/p99 performance assertions + boundary test (P-2, P-3)
- `mgmt_client` fixture cleanup (MA-1)
- `security` CI job dependency on `backend`+`frontend` (CI-3)
- Corpus gaps: homoglyph, genuine split-SSE scenario, YAML/env password formats (AC-2, AC-5)
- Replace `is_testclient` heuristic in `events.py` with an injected configuration (E-1)
- Remove `# pyright: ignore` in `cli.py` by validating profile against Literal values (C-1)
