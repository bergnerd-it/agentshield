# Milestone 2 – Non-Streaming LLM Proxy Verification Report

### 1. Environment and Versions

- **Host Environment**: macOS (Darwin 25.6.0, ARM64 / Apple Silicon)
- **Python Version**: CPython 3.14.7 (managed via `uv`)
- **Package Manager / Toolchain**: `uv` 0.7.20
- **Node.js Runtime**: Node.js v26.8.1
- **Node Package Manager**: `pnpm` 11.25.0
- **Database**: SQLite 3 (WAL mode enabled, PRAGMA foreign_keys=ON, busy_timeout=5000ms)
- **Git Commit**: `8aa1881657c7b5480b213b374e90c597f5591f8b` on branch `milestone-2`
- **Working Tree**: Clean

---

### 2. Summary of Implemented Functionality

Milestone 2 implements the core non-streaming reverse proxy layer for OpenAI and Anthropic LLM endpoints:

- **OpenAI Protocol Adapter (`agentshield.proxy.openai.adapter`)**:
  - Implements translation and header forwarding for `/v1/responses` and `/v1/chat/completions`.
  - Injects `Authorization: Bearer <API_KEY>` from native `CredentialStore`.
  - Preserves unknown JSON fields and custom agent metadata without truncation or schema mutation.
  - Rejects streaming (`stream: true`) with HTTP 400 Problem Details (`urn:agentshield:error:streaming-not-supported`).

- **Anthropic Protocol Adapter (`agentshield.proxy.anthropic.adapter`)**:
  - Implements translation and header forwarding for `/v1/messages`.
  - Injects `x-api-key: <API_KEY>` from native `CredentialStore`.
  - Preserves and forwards `anthropic-version` (defaults to `2023-06-01` if omitted) and `anthropic-beta` headers.
  - Preserves unknown JSON payload fields.
  - Rejects streaming (`stream: true`) with HTTP 400 Problem Details.

- **HTTP Forwarding Client (`agentshield.proxy.client`)**:
  - Asynchronous HTTP forwarding using `httpx.AsyncClient` with connection pooling.
  - Configured with `retries=0` to guarantee zero automatic retries for non-idempotent LLM completion requests.
  - Strips hop-by-hop headers (`Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Trailers`, `Transfer-Encoding`, `Upgrade`, `Content-Length`, `Content-Encoding`).
  - Implements client disconnect detection (`_send_with_disconnect_guard`), immediately cancelling upstream requests when the client disconnects.
  - Maps upstream timeout errors to HTTP 504 Gateway Timeout (`urn:agentshield:error:gateway-timeout`) and network failures to HTTP 502 Bad Gateway (`urn:agentshield:error:bad-gateway`).

- **Authentication Separation (`agentshield.api.dependencies`)**:
  - Distinct authentication gates for administrative endpoints (`require_admin_auth`) and proxy endpoints (`require_proxy_auth`).
  - Local proxy token validated via `0600` POSIX-restricted file and constant-time comparison (`secrets.compare_digest`).
  - Strips incoming local credentials (`Authorization`, `x-api-key`, `x-agentshield-token`) before forwarding upstream.
  - Injects upstream provider credentials from secure `CredentialStore` into outbound request.

- **Loop Detection (`agentshield.proxy.loop_detector`)**:
  - Injects `x-agentshield-loop-detection: 1` header into outbound requests.
  - Detects and rejects self-referential incoming requests (containing loop marker header) with HTTP 508 Loop Detected (`urn:agentshield:error:loop-detected`).
  - Detects upstream URLs targeting loopback on the active port and rejects them prior to connection attempts.

- **Credential Store Protocol (`agentshield.core.credentials`)**:
  - Protocol abstraction supporting `KeyringCredentialStore` (using system keyring via `keyring` package) and `InMemoryCredentialStore` (for deterministic offline testing).
  - Dev-mode fallback to environment variables (`AGENTSHIELD_OPENAI_API_KEY`, `AGENTSHIELD_ANTHROPIC_API_KEY`, etc.) only when `dev_mode=True`.

- **Mock Providers & Contract Testing (`tests/mock_providers.py`)**:
  - In-memory mock ASGI servers for OpenAI (`MockOpenAIServer`) and Anthropic (`MockAnthropicServer`) supporting status code emulation, error payload injection, and recorded request inspection.

---

### 3. Changed and Newly Created Files

#### Plans & Configuration
- `.junie/plans/milestone-2-non-streaming-proxy.md` — Milestone 2 plan and task tracking
- `backend/pyproject.toml` — Added `keyring>=24.3.1` dependency
- `backend/uv.lock` — Locked dependencies including `keyring`, `jaraco.classes`, `jaraco.context`, `jaraco.functools`, `more-itertools`

#### Backend Application Code (`backend/src/agentshield/`)
- `backend/src/agentshield/api/app.py` — Registered `/proxy` router and shutdown cleanup hook
- `backend/src/agentshield/api/dependencies.py` — Added proxy authentication, credential store, and adapter dependencies
- `backend/src/agentshield/api/routes/proxy.py` — Proxy endpoints for `/openai/v1/responses`, `/openai/v1/chat/completions`, `/anthropic/v1/messages`
- `backend/src/agentshield/core/config.py` — Added proxy timeouts, max body size (10 MiB), and upstream URLs
- `backend/src/agentshield/core/credentials.py` — Credential store interface, Keyring integration, and in-memory store
- `backend/src/agentshield/core/errors.py` — Added `MissingCredentialError`, `ProxyLoopError`, `StreamingNotSupportedError`, `GatewayTimeoutError`, `BadGatewayError`, `PayloadTooLargeError`
- `backend/src/agentshield/persistence/db.py` — Updated engine typing and migration helper
- `backend/src/agentshield/proxy/__init__.py` — Package exports
- `backend/src/agentshield/proxy/types.py` — `ProxyRequest`, `ProxyResponse`, `Provider` enum, hop-by-hop and local auth header constants (including RFC `trailer` and `trailers`)
- `backend/src/agentshield/proxy/client.py` — Asynchronous `ProxyForwardClient` with disconnect guard and zero retries
- `backend/src/agentshield/proxy/loop_detector.py` — Loop detection logic and marker header validation
- `backend/src/agentshield/proxy/openai/__init__.py` — Package exports
- `backend/src/agentshield/proxy/openai/adapter.py` — OpenAI protocol adapter
- `backend/src/agentshield/proxy/anthropic/__init__.py` — Package exports
- `backend/src/agentshield/proxy/anthropic/adapter.py` — Anthropic protocol adapter

#### Tests (`backend/tests/`)
- `backend/tests/__init__.py` — Package marker
- `backend/tests/conftest.py` — Added proxy test fixtures
- `backend/tests/mock_providers.py` — In-memory mock OpenAI and Anthropic ASGI servers
- `backend/tests/test_credentials.py` — Unit tests for keyring, in-memory store, and dev-mode fallback gating
- `backend/tests/test_persistence.py` — Updated test assertions
- `backend/tests/test_proxy_openai.py` — Contract and error forwarding tests for OpenAI
- `backend/tests/test_proxy_anthropic.py` — Contract and error forwarding tests for Anthropic
- `backend/tests/test_proxy_security.py` — Security, token isolation, loop detection, Trailer/Content-Encoding stripping, and cancellation tests

---

### 4. Commands Executed

#### Backend Quality Gates
```bash
cd backend
uv sync --frozen
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest -v
```

#### Frontend Quality Gates
```bash
cd frontend
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm exec playwright test
```

---

### 5. Test, Lint, Type-Check, and Build Results

| Check / Tool | Target | Exit Code | Result Details |
| :--- | :--- | :--- | :--- |
| **Ruff (Format)** | `backend/` | `0` | 46 files verified, all formatted cleanly |
| **Ruff (Lint)** | `backend/` | `0` | All lint checks passed with zero errors |
| **Pyright (Strict)** | `backend/` | `0` | 0 errors, 0 warnings, 0 notes across all source and test files |
| **Pytest (Unit & Integration)** | `backend/tests/` | `0` | 61 passed in 0.80s (100% pass rate) |
| **ESLint** | `frontend/` | `0` | 0 errors, 0 warnings |
| **TypeScript (`tsc`)** | `frontend/` | `0` | 0 type errors |
| **Vitest** | `frontend/tests/` | `0` | 3 passed in 424ms |
| **Vite Build** | `frontend/` | `0` | Production build succeeded (`dist/` generated) |
| **Playwright (E2E Smoke)** | `frontend/e2e/` | `0` | 1 passed in 1.4s on macOS host (`e2e/smoke.spec.ts`) |

---

### 6. Reproducible Manual Proxy Smoke Tests

To manually and reproducibly verify the LLM reverse proxy without connecting to live external providers, use the following procedure:

#### Step A: Launch Mock Upstream Provider
Start a standalone mock upstream server on port 9000 that emulates OpenAI and Anthropic endpoints:

```python
# Save as mock_upstream_runner.py
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

@app.post("/v1/responses")
async def mock_responses(request: Request):
    headers = dict(request.headers)
    body = await request.json()
    return {
        "id": "resp-synth-001",
        "object": "response",
        "model": body.get("model", "gpt-4o"),
        "received_auth": headers.get("authorization"),
        "received_loop_header": headers.get("x-agentshield-loop-detection"),
    }

@app.post("/v1/chat/completions")
async def mock_chat(request: Request):
    body = await request.json()
    return {
        "id": "chatcmpl-synth-001",
        "object": "chat.completion",
        "choices": [{"message": {"role": "assistant", "content": "Synthetic completion response"}}],
    }

@app.post("/v1/messages")
async def mock_messages(request: Request):
    headers = dict(request.headers)
    return {
        "id": "msg-synth-001",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "Synthetic Anthropic response"}],
        "received_version": headers.get("anthropic-version"),
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=9000)
```

Run in Terminal 1:
```bash
python3 mock_upstream_runner.py
```

#### Step B: Launch AgentShield in Dev Mode
Run in Terminal 2 with mock upstream URLs and synthetic API keys:
```bash
cd backend
export AGENTSHIELD_DEV_MODE=true
export AGENTSHIELD_OPENAI_UPSTREAM_BASE_URL=http://127.0.0.1:9000
export AGENTSHIELD_ANTHROPIC_UPSTREAM_BASE_URL=http://127.0.0.1:9000
export AGENTSHIELD_OPENAI_API_KEY=sk-synth-real-upstream-openai-99999
export AGENTSHIELD_ANTHROPIC_API_KEY=sk-ant-synth-real-upstream-anthropic-88888
uv run python -m agentshield.cli start --host 127.0.0.1 --port 8765
```

Retrieve the local proxy token from the generated token file:
```bash
PROXY_TOKEN=$(cat ~/.local/share/agentshield/proxy.token 2>/dev/null || cat ~/Library/Application\ Support/AgentShield/proxy.token)
```

#### Step C: Execute Sanitized Curl Requests

##### Scenario 1: OpenAI Responses API
```bash
curl -i -X POST http://127.0.0.1:8765/proxy/openai/v1/responses \
  -H "Authorization: Bearer $PROXY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o", "input": "Say hello"}'
```
**Expected Result**:
- Status: `HTTP/1.1 200 OK`
- Body contains `id: resp-synth-001`, `received_auth: Bearer sk-synth-real-upstream-openai-99999`, and `received_loop_header: 1`.

##### Scenario 2: OpenAI Chat Completions API
```bash
curl -i -X POST http://127.0.0.1:8765/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer $PROXY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}], "custom_metadata": 123}'
```
**Expected Result**:
- Status: `HTTP/1.1 200 OK`
- Body contains `id: chatcmpl-synth-001` and faithful completion output.

##### Scenario 3: Anthropic Messages API
```bash
curl -i -X POST http://127.0.0.1:8765/proxy/anthropic/v1/messages \
  -H "x-api-key: $PROXY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model": "claude-3-5-sonnet-20241022", "messages": [{"role": "user", "content": "Hello"}]}'
```
**Expected Result**:
- Status: `HTTP/1.1 200 OK`
- Body contains `id: msg-synth-001` and `received_version: 2023-06-01`.

##### Scenario 4: Streaming Guard (HTTP 400)
```bash
curl -i -X POST http://127.0.0.1:8765/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer $PROXY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o", "messages": [{"role": "user", "content": "Stream me"}], "stream": true}'
```
**Expected Result**:
- Status: `HTTP/1.1 400 Bad Request`
- Problem Details: `urn:agentshield:error:streaming-not-supported`.

##### Scenario 5: Missing Proxy Authentication (HTTP 401)
```bash
curl -i -X POST http://127.0.0.1:8765/proxy/openai/v1/responses \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o", "input": "No auth"}'
```
**Expected Result**:
- Status: `HTTP/1.1 401 Unauthorized`
- Problem Details: `urn:agentshield:error:unauthorized`.

##### Scenario 6: Proxy Loop Detection (HTTP 508)
```bash
curl -i -X POST http://127.0.0.1:8765/proxy/openai/v1/responses \
  -H "Authorization: Bearer $PROXY_TOKEN" \
  -H "x-agentshield-loop-detection: 1" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o", "input": "Loop test"}'
```
**Expected Result**:
- Status: `HTTP/1.1 508 Loop Detected`
- Problem Details: `urn:agentshield:error:loop-detected`.

---

### 7. Security and Privacy Invariants Verification

1. **Environment-Variable Credential Fallback strictly requires `dev_mode=True`**:
   - Analyzed `agentshield.core.credentials.KeyringCredentialStore` and `InMemoryCredentialStore`.
   - Verified that `get_provider_key()` checks `self.dev_mode` (derived from `settings.dev_mode`).
   - When `dev_mode=False` (production default), `get_provider_key()` returns `None` and strictly refuses to inspect environment variables (`AGENTSHIELD_OPENAI_API_KEY`, `OPENAI_API_KEY`, `AGENTSHIELD_ANTHROPIC_API_KEY`, `ANTHROPIC_API_KEY`).
   - Verified with dedicated unit tests in `test_credentials.py` (`test_keyring_credential_store_dev_mode_fallback` and `test_in_memory_credential_store_dev_mode_fallback`).
2. **Local AgentShield Token Never Forwarded Upstream**:
   - Verified that `Authorization`, `x-api-key`, and `x-agentshield-token` incoming headers containing local tokens are stripped by `_build_headers` and never appear in recorded upstream requests.
3. **Provider Credentials Never Returned to Client**:
   - Verified that provider API keys from `CredentialStore` are never present in proxy response headers or bodies returned to the client.
4. **Provider Credentials Not Stored in SQLite**:
   - Inspected all SQLite database tables (`app_settings`, `security_policies`, `integration_configs`, `audit_events`). Zero API keys, tokens, or credentials exist in SQLite storage.
5. **Raw Payloads Absent from Logs**:
   - Inspected log outputs. The safe logging layer (`agentshield.core.logging`) sanitizes API keys and tokens via regex masking, and proxy routes log only URLs and status codes, never raw request or response bodies.
6. **TLS Verification Not Disabled**:
   - Confirmed that `verify=False` is nowhere in the codebase. All default HTTPX transports perform strict standard TLS certificate verification.
7. **No External Provider Requests in Tests**:
   - All tests utilize in-memory `MockOpenAIServer`, `MockAnthropicServer`, `httpx.ASGITransport`, or `httpx.MockTransport`. No real network calls are made to `api.openai.com` or `api.anthropic.com`.

---

### 8. Content-Encoding and RFC Trailer Header Semantics Review

1. **Content-Encoding Handling**:
   - In HTTP specifications (RFC 9110 §8.4), `Content-Encoding` indicates end-to-end compression (such as `gzip` or `br`).
   - When `ProxyForwardClient` receives an upstream response via `httpx.AsyncClient`, HTTPX automatically decodes the compressed content into raw decompressed bytes (`response.content`).
   - If `Content-Encoding: gzip` were relayed downstream in `response.headers` alongside `response.content`, downstream clients would attempt to decompress already-decompressed plaintext, causing decoding failures.
   - Therefore, stripping `Content-Encoding` from relayed response headers correctly preserves HTTP representation semantics.
   - On inbound request forwarding, request bodies are buffered as uncompressed JSON, so removing `Content-Encoding` from outbound request headers ensures upstream servers receive accurate uncompressed representations.

2. **RFC Trailer Header Handling**:
   - RFC 7230 §4.4 / §6.1 and RFC 9110 §6.6.2 specify the hop-by-hop header for chunked trailers as `Trailer` (singular).
   - In `backend/src/agentshield/proxy/types.py`, `HOP_BY_HOP_HEADERS` previously included only `trailers` (plural).
   - Defect confirmed: `trailer` (singular) was missing from `HOP_BY_HOP_HEADERS`.
   - Resolution: Added `"trailer"` to `HOP_BY_HOP_HEADERS` and created regression test `test_trailer_headers_not_relayed` verifying that both singular `Trailer` and plural `Trailers` headers are stripped from outbound requests and relayed responses.

---

### 9. Issues Discovered and Resolution Status

| Issue | Category | Description | Resolution Status |
| :--- | :--- | :--- | :--- |
| **1. Merge Conflict Markers in Test Files** | Test Infrastructure | `test_proxy_anthropic.py` and `test_proxy_openai.py` contained unresolved git conflict markers around mock server imports. | **Confirmed and Fixed**: Cleaned conflict markers and consolidated mock server imports. |
| **2. Missing RFC Standard `Trailer` in Hop-by-Hop Headers** | Protocol Correctness | `HOP_BY_HOP_HEADERS` contained `"trailers"` (plural) but missed the standard RFC `"trailer"` (singular) header. | **Confirmed and Fixed**: Added `"trailer"` to `HOP_BY_HOP_HEADERS` in `types.py` and added regression tests in `test_proxy_security.py`. |
| **3. Credential Store Fallback in Production Mode** | Security Invariant | Potential risk of accidental environment variable credential fallback when `dev_mode=False`. | **Rejected as Code Defect / Verified & Tested**: Implementation was confirmed to strictly gate on `self.dev_mode`. Added explicit unit test `test_keyring_credential_store_dev_mode_fallback`. |
| **4. Playwright Execution on macOS Host** | Verification Gate | Playwright E2E browser tests could not run in headless container due to missing shared libraries. | **Confirmed and Resolved**: Executed Playwright suite on macOS host; passed 100% (1 test in 1.4s). |

---

### 10. Premature Milestone 3 Functionality Check

Confirmed that no Milestone 3 functionality was implemented prematurely:
- No PII detectors (Microsoft Presidio) or regex secret scanner engines.
- No policy evaluation engine (`ALLOW`, `WARN`, `REDACT`, `BLOCK`).
- No pseudonymization or rehydration logic.
- No Monaco diff UI or approval workflow.

---

### 11. Final Verdict

**Verdict**: **PASS (UNCONDITIONAL)**

All Milestone 2 verification conditions have been completely satisfied:
- Playwright E2E browser suite executed and passed on macOS host.
- All manual proxy smoke tests documented with reproducible startup, configuration, and curl commands.
- Dev-mode credential fallback verified and tested.
- Content-Encoding and RFC Trailer header semantics reviewed and fixed.
- All quality gates (Ruff, Pyright strict, 61 Pytest tests, Vitest, ESLint, TypeScript typecheck, Vite build, Playwright E2E) passed with exit code 0.
