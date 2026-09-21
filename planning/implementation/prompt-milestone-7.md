# AgentShield Milestone 7 Implementation Prompt: Hardening and Documentation

Read `AGENTS.md`, `AgentShield_V1_Specification.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `SECURITY.md`, `docs/PRIVACY.md`, `docs/TESTING.md`, all accepted Architecture Decision Records (`docs/adr/0001` through `docs/adr/0010`), and the Milestone 6 review report `planning/implementation/report-milestone-6.md` completely.

Inspect the current repository and verify that Milestone 6 is complete and all existing backend and frontend quality gates pass before making any modifications:
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
pnpm exec playwright test
```
If any pre-existing tests fail, stop and report them before writing code.

---

## 1. Milestone 7 Scope and Objectives

Milestone 7 is the final milestone of AgentShield Version 1: **Hardening and Documentation**. It hardens the system against evasion and disclosure, measures performance against defined SLAs, locks down the software supply chain, ensures robust cross-platform execution, delivers a turnkey customer demonstration, and finalizes all security and architectural documentation to fulfill the Version 1 Definition of Done (Specification §20).

Milestone 7 encompasses seven primary deliverables:

1. **Milestone 6 Review Fixes & Defense-in-Depth**:
   - Filter `metadata_json` with `_SAFE_METADATA_KEYS` in the live events API (`backend/src/agentshield/api/routes/events.py`) to prevent internal metadata leaks on `GET /api/v1/events`.
   - Add warning logging for DB commit failures in the Integration Manager (`backend/src/agentshield/integrations/manager.py`) to make filesystem/database divergences visible.
   - Enforce Python `>= 3.14` version requirement in `agentshield doctor` (`backend/src/agentshield/core/diagnostics.py`).
   - Use dynamic port `self.settings.port` instead of hardcoded `8765` in agent configuration diagnostic checks.
   - Add missing negative unit tests: corrupt `metadata_json` tolerance in audit export and `rollback()` with no backup raising `NotFoundError`.
   - Add local time indication to date filter inputs in `frontend/src/pages/AuditPage.tsx`.

2. **Synthetic Attack Corpus & Multi-Sink Leak Verification Suite**:
   - Establish a versioned, declarative attack corpus in `backend/tests/corpus/` organized by attack family into structured JSON datasets:
     - `secrets.json`: Provider API keys (OpenAI, Anthropic), cloud credentials (AWS, GCP), GitHub tokens, private keys (PEM), JWTs, passwords across JSON, YAML, `.env`, Java, Python, HTTP headers.
     - `pii.json`: Personal names, organizations, email addresses, phone numbers, IBANs, IP addresses (English and German contexts).
     - `custom_terms.json`: Internal Java package names, class names, database identifiers, confidential project codes.
     - `obfuscation.json`: Base64 encoded secrets, URL encoded secrets, zero-width characters, homoglyphs, split strings across JSON boundaries and SSE events.
     - `false_positives.json`: Legitimate source code literals, UUIDs, Git hashes, public fixture values that must NOT be flagged.
   - Implement a parameterized test suite in `backend/tests/test_attack_corpus.py` executing both direct detector scans and end-to-end proxy requests against mock providers.
   - Implement multi-sink leak assertions: Automatically verify that detected synthetic secrets are absent from mock provider captures, application logs, SQLite tables, audit export artifacts (JSON & HTML), and API error responses.

3. **Performance Benchmarking & SLA Report (`docs/PERFORMANCE.md`)**:
   - Create a standalone, reproducible benchmark script `backend/scripts/benchmark.py`:
     - Measures median (p50), p95, and p99 proxy overhead before upstream dispatch on small text requests (verifying Specification §18.4 target: median overhead < 30 ms).
     - Measures streaming first-byte latency (TTFB) overhead.
     - Measures memory usage and latency under maximum allowed request sizes (10 MiB limit).
     - Benchmarks concurrency under simulated slow upstream responses.
     - Generates/refreshes the structured performance report in `docs/PERFORMANCE.md` documenting environment, methodology, and latency distributions.
   - Implement lightweight automated pytest assertions in `backend/tests/test_performance.py` verifying the <30 ms median SLA and 10 MiB payload limit rejection (HTTP 413).

4. **SBOM Generation & Dependency Vulnerability Scanning**:
   - Establish CycloneDX JSON standard for release artifacts across backend and frontend.
   - Implement `scripts/generate_sbom.sh`:
     - Backend: Generates CycloneDX JSON SBOM via `uv export` and `cyclonedx-py`.
     - Frontend: Generates CycloneDX JSON SBOM via `@cyclonedx/cyclonedx-npm`.
     - Output saved to `dist/sbom/`.
   - Implement `scripts/scan_dependencies.sh`:
     - Backend: Runs `pip-audit` against locked dependencies.
     - Frontend: Runs `pnpm audit --audit-level=high`.
   - Update `.github/workflows/ci.yml` with a dedicated supply-chain security job validating that dependencies contain zero high/critical vulnerabilities and SBOM generation succeeds.

5. **Cross-Platform Hardening & CI Matrix Verification**:
   - Audit and harden path and OS-specific behavior across macOS, Linux, and Windows:
     - Normalize paths using `pathlib.Path` across CLI, adapters, and diagnostics.
     - Verify atomic sibling-file replace behavior across platforms in `IntegrationManager`.
     - Verify CRLF and LF line ending support in SSE streaming parsing and Monaco diff preview.
     - Gracefully handle headless Linux environments in `agentshield doctor` where the native keyring service may be absent.
   - Verify CI matrix (`ubuntu-latest`, `macos-latest`, `windows-latest`) in `.github/workflows/ci.yml`.

6. **Turnkey Local Customer Demonstration & Reset Scripts**:
   - Implement `scripts/run_demo.py`:
     - Automated and interactive runner for the 10 demonstration steps from Specification §21.
     - Operates entirely against local mock providers without paid API keys or external network egress.
   - Implement `scripts/reset_demo.py`:
     - Safe demo reset script removing only the isolated demo data directory and demo tokens, strictly refusing dangerous roots or user home directories.
   - Implement `backend/tests/test_demo_scenario.py` asserting that the complete 10-step demonstration executes deterministically and passes without leaks.
   - Update `docs/DEMO.md` and `README.md` with step-by-step instructions, expected terminal outputs, and copy-pasteable curl commands.

7. **Version 1 Security Documentation & Sign-Off**:
   - Update `docs/THREAT_MODEL.md`: Document coding-agent config token readability by file owner as an inherent cooperative proxy limitation; document cooperative egress boundaries; document in-memory vault TTL bounds.
   - Update `docs/ARCHITECTURE.md`: Reflect complete V1 components and document the single-worker requirement due to in-memory settings sync.
   - Update `SECURITY.md`: Update supported versions table for Version 1.0.0, document SBOM availability, and confirm vulnerability reporting procedures.
   - Update `docs/PRIVACY.md`: Document audit allowlist guarantees and zero-raw-prompt persistence.
   - Update `README.md`: Update status to Version 1 Complete, add quickstart guide, demo instructions, and prominent cooperative proxy notice.
   - Complete review against Specification §20 "Definition of Done".

Do not introduce transparent TLS interception, OS firewall rules, MCP proxying, cloud services, multi-tenant RBAC, or unencrypted credential fallback.

---

## 2. Non-Negotiable Security Invariants

- Never disable TLS certificate verification.
- Never forward local proxy tokens or admin credentials to upstream LLM providers.
- Never store raw prompts, LLM responses, detected secret values, or unencrypted provider credentials in SQLite, logs, exports, or DOM.
- Never rehydrate secrets, passwords, tokens, private keys, or credentials under any circumstance.
- Never make external network or paid provider calls from automated tests or demonstration scripts; use local mock providers exclusively.
- Fail closed for credentials, strict-mode required checks, and oversized payloads.
- Bind strictly to loopback (`127.0.0.1`).
- Performance targets must never justify silently bypassing a security detector or policy check.

---

## 3. Architecture & File Structure

```text
backend/
├── scripts/
│   └── benchmark.py            # Latency, TTFB, memory benchmark script -> docs/PERFORMANCE.md
├── src/agentshield/
│   ├── api/routes/
│   │   └── events.py           # Apply _SAFE_METADATA_KEYS allowlist to GET /api/v1/events
│   ├── core/
│   │   └── diagnostics.py      # Python >= 3.14 check, dynamic port in agent check
│   └── integrations/
│       └── manager.py          # Log warning on DB commit failure after config write
└── tests/
    ├── corpus/                 # Structured attack corpus datasets
    │   ├── secrets.json        # Synthetic API keys, tokens, private keys, passwords
    │   ├── pii.json            # English & German personal names, emails, phones, IBANs
    │   ├── custom_terms.json   # Internal classes, projects, databases
    │   ├── obfuscation.json    # Base64, URL encoding, zero-width chars, homoglyphs
    │   └── false_positives.json # Source code literals, UUIDs, Git hashes
    ├── test_attack_corpus.py   # Parametrized detection and multi-sink leak test suite
    ├── test_performance.py     # Automated pytest SLA assertions (<30ms median, 10MiB limit)
    └── test_demo_scenario.py   # Automated verification of the 10-step demo script

scripts/
├── generate_sbom.sh            # Generates CycloneDX JSON SBOMs for backend & frontend
├── scan_dependencies.sh        # Executes pip-audit and pnpm audit quality gates
├── run_demo.py                 # Reproducible 10-step customer demo script
└── reset_demo.py               # Safe demo cleanup script

docs/
├── PERFORMANCE.md              # Measured p50/p95/p99 latency, TTFB, memory benchmarks
├── THREAT_MODEL.md             # Updated with token storage & cooperative proxy boundaries
├── ARCHITECTURE.md             # Updated with final component map & single-worker notes
├── PRIVACY.md                  # Updated with audit allowlist and zero-retention proofs
└── DEMO.md                     # Turnkey customer demonstration walkthrough

.github/workflows/
└── ci.yml                      # Added supply-chain security job (SBOM & dependency scan)

README.md                       # Updated status (V1 Complete), demo instructions, boundary notice
SECURITY.md                     # Updated V1 support table and SBOM policies
```

---

## 4. Detailed Implementation Requirements

### 4.1 Milestone 6 Review Items (`events.py`, `manager.py`, `diagnostics.py`, UI)
1. **Live Events Metadata Allowlist (`backend/src/agentshield/api/routes/events.py`)**:
   - In `_to_event_response()`, filter `metadata_json` through `_SAFE_METADATA_KEYS` (imported from `agentshield.audit.service`) so that `GET /api/v1/events` cannot reflect arbitrary internal keys to the client.
2. **Integration DB Error Logging (`backend/src/agentshield/integrations/manager.py`)**:
   - In `apply()`, wrap the database recording/commit step in `try/except Exception` and log an explicit warning (`"Config written atomically to %s, but failed to record backup path in database: %s"`) so that filesystem/database discrepancies are observable.
3. **Diagnostics Python Version & Port Checks (`backend/src/agentshield/core/diagnostics.py`)**:
   - In `check_runtime()`, assert `sys.version_info >= (3, 14)`: return `DiagnosticStatus.OK` if met, or `DiagnosticStatus.WARN` with message `"Python {py_ver} found; AgentShield requires >= 3.14"`.
   - In `check_agent_configurations()`, replace the hardcoded port `8765` with `self.settings.port` when checking Codex and Claude Code target URLs.
4. **Missing Unit Tests**:
   - In `backend/tests/test_audit_export.py`, add `test_export_tolerates_corrupt_metadata_json()` asserting that corrupt JSON in stored event metadata falls back gracefully to `{}` without failing the export.
   - In `backend/tests/test_integrations.py`, add `test_rollback_without_backup_raises_not_found()` asserting that `manager.rollback()` raises `NotFoundError` when no backup file exists.
5. **Frontend Audit Filter Label (`frontend/src/pages/AuditPage.tsx`)**:
   - Update "From Date" and "To Date" labels to include `(local time)` to eliminate operator confusion before UTC conversion.

### 4.2 Synthetic Attack Corpus & Multi-Sink Leak Test Suite
1. **Corpus Datasets (`backend/tests/corpus/`)**:
   - Create structured JSON files with schemas:
     ```json
     [
       {
         "id": "SEC-OPENAI-001",
         "category": "SECRET_API_KEY",
         "description": "Synthetic OpenAI project key",
         "payload": "sk-proj-DEMOONLYfakekey1234567890abcdefghijklmnopqrstuvwxyz",
         "expected_action_balanced": "BLOCK",
         "expected_action_strict": "BLOCK",
         "must_not_leak": true
       }
     ]
     ```
   - `secrets.json`: Cover OpenAI keys (`sk-proj-...`), Anthropic keys (`sk-ant-...`), AWS access keys (`AKIA...`), GitHub personal access tokens (`ghp_...`), RSA/EC private keys (`-----BEGIN PRIVATE KEY-----`), JWTs, database connection strings with passwords (`postgres://user:secretpass@host/db`).
   - `pii.json`: Personal names (Erika Mustermann, John Doe), organizations (Alpine Example GmbH), email addresses, phone numbers, IBANs, IPv4/IPv6 addresses in English and German contexts.
   - `custom_terms.json`: Internal Java class names (`GreenfieldGrantService`), internal package names (`com.company.internal`), secret project codes (`PROJECT_NEBULA`).
   - `obfuscation.json`: Base64 encoded secrets (`c2stcHJvai1ERU1PT05MWWZha2VrZXk=`), URL-encoded secrets (`sk-proj%2DDEMO`), zero-width spaces (`\u200b`, `\u200c`), Unicode homoglyphs, and payloads split across multiple JSON string chunks or SSE stream chunks.
   - `false_positives.json`: Safe code snippets, UUIDs, Git SHA-1 hashes, standard library calls, fixture constants that must evaluate to `ALLOW` (or `must_not_leak: false`).
2. **Parametrized Pytest Suite (`backend/tests/test_attack_corpus.py`)**:
   - Test 1: Detector Unit Verification. Feed every corpus item to `DetectorEngine` and assert expected finding category, span, and confidence.
   - Test 2: Policy Enforcement Verification. Feed corpus items through the policy engine under `strict`, `balanced`, and `permissive` profiles and verify resulting actions (`BLOCK`, `REDACT`, `WARN`, `ALLOW`).
   - Test 3: Multi-Sink Leak Verification. Execute end-to-end proxy requests against mock upstream servers for each secret corpus item. Assert:
     - Mock upstream capture does NOT contain the synthetic secret.
     - Application logs and HTTP access logs do NOT contain the synthetic secret.
     - SQLite database tables (`audit_events`, `approvals`, etc.) do NOT contain the synthetic secret.
     - Audit export JSON and HTML outputs do NOT contain the synthetic secret.
     - HTTP response bodies (errors, Problem Details) do NOT contain the synthetic secret.

### 4.3 Performance Benchmarking & SLA Report (`docs/PERFORMANCE.md`)
1. **Benchmark Tool (`backend/scripts/benchmark.py`)**:
   - Spin up a local mock upstream server and an in-process or sub-process AgentShield instance on loopback.
   - Execute benchmark suites:
     - **Pre-request proxy overhead**: Measure round-trip latency through proxy minus direct mock server latency for small text requests (100–500 tokens). Calculate median (p50), p95, and p99.
     - **Streaming TTFB overhead**: Measure time-to-first-byte delay added by proxy streaming pipeline.
     - **Detection breakdown**: Measure standalone latency for regex detector vs Presidio PII analyzer.
     - **Memory bounds**: Stream a 10 MiB payload and verify memory footprint remains bounded without unbounded buffering.
   - Output markdown results directly into `docs/PERFORMANCE.md` including machine architecture, Python version, sample counts, and SLA compliance tables.
2. **Automated Pytest Performance Assertions (`backend/tests/test_performance.py`)**:
   - Execute automated timing checks against mock upstream:
     - Assert median pre-request overhead for small text requests is < 30 ms (Specification §18.4).
     - Assert that requests exceeding `max_request_size_bytes` (10 MiB) are rejected with HTTP 413 `Payload Too Large` before buffer exhaustion.

### 4.4 SBOM Generation & Dependency Vulnerability Scanning
1. **CycloneDX SBOM Generation (`scripts/generate_sbom.sh`)**:
   - Ensure script is executable (`chmod +x scripts/generate_sbom.sh`).
   - Backend SBOM:
     ```bash
     uv export --frozen --format requirements-txt --no-dev -o /tmp/requirements-locked.txt
     uv run cyclonedx-py requirements /tmp/requirements-locked.txt -o dist/sbom/backend-sbom.json
     ```
   - Frontend SBOM:
     ```bash
     cd frontend && pnpm dlx @cyclonedx/cyclonedx-npm --output-file ../dist/sbom/frontend-sbom.json
     ```
   - Output structured, valid CycloneDX 1.5 JSON files.
2. **Dependency Vulnerability Scanning (`scripts/scan_dependencies.sh`)**:
   - Backend:
     ```bash
     uv run pip-audit
     ```
   - Frontend:
     ```bash
     cd frontend && pnpm audit --audit-level=high
     ```
   - Ensure script returns exit code 0 if clean and non-zero if actionable vulnerabilities exist.
3. **CI Workflow Integration (`.github/workflows/ci.yml`)**:
   - Add a `security` job in GitHub Actions running on `ubuntu-latest`:
     - Runs `scripts/scan_dependencies.sh`.
     - Runs `scripts/generate_sbom.sh` and uploads `dist/sbom/` artifacts.

### 4.5 Cross-Platform Hardening & CI Matrix
1. **Path Handling & Slashes**:
   - Audit all occurrences of `str(path)` or slash concatenation in `backend/src/agentshield/integrations/`, `core/config.py`, and `cli.py`. Ensure all filesystem operations use `pathlib.Path` methods (`resolve()`, `parent`, `/`).
2. **Line Ending Resilience**:
   - Ensure `backend/src/agentshield/proxy/sse.py` correctly parses both `\r\n` (Windows CRLF) and `\n` (POSIX LF) stream boundaries without event fragmentation.
3. **Diagnostics on Headless Linux**:
   - In `backend/src/agentshield/core/diagnostics.py`, ensure `check_credential_store()` returns a descriptive `WARN` (e.g. `"Headless Linux: OS keyring backend unavailable; fallback dev mode active"`) rather than raising unhandled exceptions when dbus/secret-service is not running.
4. **CI Verification**:
   - Verify that all three matrix operating systems in `.github/workflows/ci.yml` (`ubuntu-latest`, `macos-latest`, `windows-latest`) pass backend and frontend quality gates.

### 4.6 Turnkey Local Customer Demonstration & Reset
1. **Demo Runner Script (`scripts/run_demo.py`)**:
   - Standalone Python script executable via `uv run scripts/run_demo.py [--interactive | --auto]`.
   - Executes all 10 scenario steps from Specification §21 against an embedded or background mock provider:
     1. Start / verify AgentShield loopback service.
     2. Verify mock provider availability.
     3. Ensure `balanced` profile is active.
     4. Send clean coding prompt; verify HTTP 200 and successful forwarding.
     5. Send prompt containing synthetic API key; verify HTTP 403 `BLOCK` and upstream non-receipt.
     6. Send prompt containing Erika Mustermann and `GreenfieldGrantService`; verify pseudonymization into `<AS:PERSON:...>` and `<AS:INTERNAL_CLASS:...>`.
     7. Verify rehydration of placeholder in mock response.
     8. Send prompt triggering `REQUIRE_APPROVAL`; approve via Management API; verify client receives response.
     9. Export audit report; verify total absence of confidential test values.
     10. Run `agentshield doctor` and verify diagnostic output including direct egress warning banner.
2. **Demo Reset Script (`scripts/reset_demo.py`)**:
   - Deletes only designated demo data directory (e.g., `~/.agentshield-demo` or `.demo-data/`).
   - Strictly validates target path before deletion: refuses paths equal to `~`, `/`, workspace root, or non-demo directories.
3. **Automated Test (`backend/tests/test_demo_scenario.py`)**:
   - Runs the 10 demo steps in pytest to ensure zero regressions in the demonstration flow.
4. **Documentation Updates**:
   - Update `docs/DEMO.md` with full step-by-step commands and terminal output examples.
   - Update `README.md` with copy-pasteable demonstration instructions.

### 4.7 Security Documentation & Version 1 Sign-Off
1. **`docs/THREAT_MODEL.md`**:
   - Document coding-agent config token readability by file owner as an inherent cooperative proxy limitation.
   - Reaffirm direct egress non-enforcement as an explicit trust boundary.
   - Document in-memory vault boundaries and TTL bounds.
2. **`docs/ARCHITECTURE.md`**:
   - Document single-worker uvicorn requirement for in-memory settings sync.
   - Update architecture diagrams and component summaries.
3. **`SECURITY.md`**:
   - Update supported versions table to include Version 1.0.0.
   - Document SBOM availability and dependency scanning procedures.
4. **`docs/PRIVACY.md`**:
   - Reaffirm zero raw payload persistence, audit export allowlist guarantees, and safe diagnostics.
5. **`README.md`**:
   - Update project status to "Version 1 Complete (Milestones 1 through 7)".
   - Include quickstart guide, demo instructions, and prominent cooperative proxy notice.
6. **Definition of Done Check**:
   - Systematically verify that all 14 criteria of Specification §20 are satisfied and verified by automated tests or documentation.

---

## 5. Step-by-Step Delivery Plan

1. **Step 1: Milestone 6 Review Fixes and Missing Unit Tests**
   - Apply `_SAFE_METADATA_KEYS` filter in `events.py`.
   - Add DB commit error logging in `manager.py`.
   - Update `diagnostics.py` runtime version check and dynamic port check.
   - Add corrupt `metadata_json` test and missing rollback test.
   - Update date filter label in `AuditPage.tsx`.
   - Run backend and frontend tests to ensure clean baseline.

2. **Step 2: Synthetic Attack Corpus & Multi-Sink Leak Test Suite**
   - Create `backend/tests/corpus/` with JSON datasets (`secrets.json`, `pii.json`, `custom_terms.json`, `obfuscation.json`, `false_positives.json`).
   - Implement `backend/tests/test_attack_corpus.py` covering detector accuracy, policy enforcement, and multi-sink zero-leak assertions.
   - Run pytest and ensure all attack vectors are neutralized with zero leaks.

3. **Step 3: Performance Benchmarking & SLA Documentation**
   - Create `backend/scripts/benchmark.py` measuring latency, TTFB, and memory.
   - Execute benchmark and generate `docs/PERFORMANCE.md`.
   - Implement `backend/tests/test_performance.py` asserting <30 ms median overhead SLA and 10 MiB limit.

4. **Step 4: SBOM Generation & Dependency Vulnerability Scanning**
   - Create `scripts/generate_sbom.sh` using `cyclonedx-py` and `@cyclonedx/cyclonedx-npm`.
   - Create `scripts/scan_dependencies.sh` using `pip-audit` and `pnpm audit`.
   - Update `.github/workflows/ci.yml` with security workflow job.
   - Execute both scripts locally to verify clean outputs.

5. **Step 5: Cross-Platform Hardening**
   - Audit Path handling, CRLF line endings in SSE parsing, and headless Linux keyring handling.
   - Verify tests pass cleanly on POSIX and Windows environments.

6. **Step 6: Customer Demonstration Scripts & Automated Test**
   - Implement `scripts/run_demo.py` and `scripts/reset_demo.py`.
   - Implement `backend/tests/test_demo_scenario.py`.
   - Update `docs/DEMO.md` and `README.md` with complete demonstration instructions.

7. **Step 7: Version 1 Documentation & Quality Gate Verification**
   - Update `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, `SECURITY.md`, `docs/PRIVACY.md`, and `README.md`.
   - Run full test suite:
     - `ruff check .` and `ruff format --check .`
     - `pyright`
     - `pytest` (including corpus, performance, and demo tests)
     - `pnpm lint`
     - `pnpm typecheck`
     - `pnpm test`
     - `pnpm exec playwright test`
     - Dependency audit and SBOM generation
   - Verify all 14 criteria of Specification §20 "Definition of Done".

---

## 6. Definition of Done for Milestone 7

Milestone 7 is complete when:
- All Milestone 6 review findings (events metadata allowlist, manager error logging, diagnostics version check, dynamic port, unit tests) are resolved.
- Declarative attack corpus (`backend/tests/corpus/`) covers all specified secret families, PII, internal identifiers, obfuscations, and false positives.
- `backend/tests/test_attack_corpus.py` passes, verifying that blocked or redacted values never leak to provider captures, logs, SQLite, exports, or error responses.
- `backend/scripts/benchmark.py` generates `docs/PERFORMANCE.md`, documenting that median pre-request overhead is under 30 ms for small text requests and memory remains bounded.
- `scripts/generate_sbom.sh` generates valid CycloneDX SBOMs for backend and frontend into `dist/sbom/`.
- `scripts/scan_dependencies.sh` and CI security job confirm zero high or critical dependency vulnerabilities.
- Cross-platform path handling, CRLF streaming, and headless Linux diagnostics are verified.
- `scripts/run_demo.py` and `scripts/reset_demo.py` provide a completely reproducible 10-step customer demo, verified by `test_demo_scenario.py`.
- `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, `SECURITY.md`, `docs/PRIVACY.md`, and `README.md` are updated to reflect Version 1 completion and the cooperative proxy boundary.
- All backend and frontend quality commands (ruff, pyright, pytest, eslint, typecheck, vitest, playwright) pass with zero errors, zero warnings, and zero skipped security tests.
