# Implementation Plan: Milestone 4 – Streaming and Rehydration

AgentShield mediates coding-agent LLM traffic. Milestone 4 implements SSE streaming passthrough for OpenAI and Anthropic endpoints, bounded rolling response scanning, reversible pseudonymization for eligible data classes, and stream rehydration with backpressure and cancellation support.

## 1. Exact Milestone 4 Scope and Exclusions

### In-Scope (per `AgentShield_V1_Specification.md` §19 Milestone 4 & §9.2, §12)
- **SSE streaming passthrough**:
  - `POST /proxy/openai/v1/responses` (with `stream: true`)
  - `POST /proxy/openai/v1/chat/completions` (with `stream: true`)
  - `POST /proxy/anthropic/v1/messages` (with `stream: true`)
  - Incremental chunk handling (handling fragmented chunks, partial UTF-8 multibyte sequences, multi-event chunks, CRLF and LF framing, multi-line `data:`, comments, keepalive, and `[DONE]` markers).
- **Rolling response scan**:
  - Bounded holdback buffer for incremental response scanning and placeholder rehydration.
  - Response-side credential leak prevention (fail closed if exact upstream key is reflected).
  - Stream termination if an enforceable blocking finding is detected mid-stream.
  - Transparent documentation of the streaming security boundary: tokens already emitted cannot be recalled.
- **Reversible pseudonymization**:
  - In-memory session-scoped `PseudonymVault` with configurable TTL and collision-resistant placeholders.
  - Eligible categories: `PII_*` and `CUSTOM_TERM`.
  - Non-eligible categories: All `SECRET_*` categories are strictly prohibited from reversible mapping and rehydration.
  - Placeholders scoped by session and category: e.g. `<AS:{CATEGORY}:{SESSION_PREFIX}:{INDEX:04d}>`.
- **Rehydration**:
  - Rehydrate exact issued placeholders in non-streaming responses.
  - Rehydrate exact issued placeholders in streaming responses across split chunk/event boundaries.
  - Expired or unknown placeholders are preserved unchanged without guessing.
- **Lifecycle, resource limits, and cancellation**:
  - Bounded memory buffers (max event size, max holdback size).
  - Prompt propagation of downstream client disconnects to cancel upstream tasks.
  - Backpressure preservation using asynchronous iteration.
  - Correct error behavior: upstream errors before streaming preserve provider status/headers; errors after streaming starts terminate the stream safely without fabricating completion markers.

### Explicit Exclusions (Deferred to Later Milestones)
- **Milestone 5**: Local React Dashboard enhancements, Monaco diff viewer, `REQUIRE_APPROVAL` workflow and approval queue.
- **Milestone 6**: Audit event persistence for findings, JSON/HTML audit exports, Codex/Claude Code CLI configuration integration, `agentshield doctor`.
- **Milestone 7**: Cross-platform desktop packaging (Tauri), Rust sidecars, process isolation, OS firewall integration, transparent TLS interception, PostgreSQL, cloud services.

---

## 2. Requirement-to-Test Mapping

| Specification Requirement | Planned Verification & Tests |
|---|---|
| Incremental SSE parsing (CRLF, LF, multi-line `data:`, comments, partial chunks, split UTF-8) | Unit tests in `test_sse_parser.py` testing fragmented chunks, byte-at-a-time feeding, multibyte UTF-8 characters split across chunk boundaries. |
| Memory bounds & DoS protection (no unbounded buffers) | Unit tests asserting `PayloadTooLargeError` or stream error when an SSE line or event exceeds maximum configured limits. |
| Reversible pseudonym vault (session scoping, TTL, collisions) | Unit tests in `test_pseudonym_vault.py` testing session isolation, collision avoidance when input text already contains placeholder, TTL expiration, and strict rejection of secret categories. |
| Request-side pseudonymization integration | Integration tests in `test_proxy_filtering.py` verifying that eligible PII/custom terms are replaced with session placeholders and registered in the vault. |
| Non-streaming response rehydration | Integration tests verifying that non-streaming mock responses containing placeholders are faithfully restored to original values. |
| Streaming response rehydration across split event boundaries | Integration tests in `test_streaming_rehydration.py` where a placeholder is split across multiple SSE deltas and rehydrated cleanly before reaching the client. |
| Upstream error before headers sent | Contract tests in `test_proxy_streaming.py` asserting upstream 4xx/5xx status codes and JSON error bodies are passed to downstream client intact. |
| Mid-stream failure / disconnect | Tests verifying that mid-stream upstream drops or timeouts terminate the stream without fabricating `[DONE]` or successful completion. |
| Client disconnect cancellation | Tests verifying that client disconnect cancels upstream HTTPX request and releases all resources/buffers. |
| Response credential leak check | Tests verifying that upstream echoing provider API key in an SSE event immediately triggers stream abort and safe gateway error logging. |
| Provider contract tests (OpenAI Chat, OpenAI Responses, Anthropic Messages) | Mock server contract tests for all 3 supported endpoints in streaming mode. |
| Real local HTTP/TCP socket tests | Real socket server integration tests (`test_streaming_socket_integration.py`) verifying incremental delivery, backpressure, and socket disconnects. |
| Synthetic secret leak check | Assert that synthetic secrets never appear in logs, Problem Details, or client outputs. |

---

## 3. Affected Modules & Proposed Changes

### Domain & Filtering Layer
- `backend/src/agentshield/pseudonyms/models.py` [NEW]:
  - Data structures: `PseudonymMapping`, `PseudonymEntry`, `SessionId`.
- `backend/src/agentshield/pseudonyms/vault.py` [NEW]:
  - `InMemoryPseudonymVault`: Session-scoped storage with monotonic index, collision detection against original text, TTL cleanup, lookup, and reverse lookup. Rejects any `is_secret` category.
- `backend/src/agentshield/filtering/redaction/service.py`:
  - Enhance `redact_payload` to accept optional `PseudonymVault` and `session_id`. When provided, reversible categories generate session-scoped placeholders and record the mappings in the vault.

### Proxy & Streaming Layer
- `backend/src/agentshield/proxy/sse.py` [NEW]:
  - Incremental `SSEParser`: consumes bytes, emits parsed `SSEEvent` (event, data, id, retry, comments). Handles fragmented inputs and multi-byte UTF-8 without data corruption.
  - `SSESerializer`: formats `SSEEvent` back to standard SSE wire format.
- `backend/src/agentshield/proxy/rehydration.py` [NEW]:
  - `rehydrate_text(text, vault, session_id)` for non-streaming strings and JSON objects.
  - `StreamingRehydrator`: rolling holdback buffer to handle placeholders split across consecutive SSE text deltas for OpenAI and Anthropic streams.
- `backend/src/agentshield/proxy/payload.py`:
  - Update `parse_proxy_payload(raw_body)` to allow `stream: bool`, replacing the immediate `StreamingNotSupportedError` when `stream: true`. Keep duplicate key and non-finite number rejections.
- `backend/src/agentshield/proxy/types.py`:
  - Enhance `ProxyRequest` with `session_id: str | None` and `is_streaming: bool`.
- `backend/src/agentshield/proxy/client.py`:
  - Add `forward_stream(proxy_request, client_request)`:
    - Streams upstream response via `client.stream(...)`.
    - Handles disconnect monitoring with prompt cancellation.
    - Extracts upstream headers and status code.
    - If status code != 200, buffers the error body and returns non-streaming `ProxyResponse`.
    - If status code == 200, yields chunks via an async generator while monitoring read-idle timeout and validating against reflected provider credentials.
- `backend/src/agentshield/proxy/openai/adapter.py` & `backend/src/agentshield/proxy/anthropic/adapter.py`:
  - Support `stream: true` in payload, setting `is_streaming = True` on `ProxyRequest`.
- `backend/src/agentshield/api/routes/proxy.py`:
  - When `is_streaming` is True:
    - Invoke `forward_client.forward_stream(...)`.
    - If upstream returned an error (status != 200), return normal `Response(content=..., status_code=...)`.
    - If streaming, return FastAPI `StreamingResponse` wrapping the streaming rehydration and response scanning generator, with `media_type="text/event-stream"`.
    - Handle non-streaming responses with response rehydration if session mappings exist.
- `backend/src/agentshield/core/config.py`:
  - Add settings: `pseudonym_ttl_seconds: int = 3600`, `sse_max_event_bytes: int = 65536`, `stream_holdback_bytes: int = 256`.
- `backend/src/agentshield/api/dependencies.py`:
  - Add `get_pseudonym_vault()` dependency providing the singleton vault.

### Documentation & Tracking
- `docs/ARCHITECTURE.md`: update streaming and pseudonym vault section with implemented design.
- `docs/THREAT_MODEL.md`: review streaming boundary (T-14, T-17) and confirm documentation integrity.
- `README.md`: update milestone status to reflect Milestone 4 completion.

---

## 4. Streaming Lifecycle and Error Handling

```
Client (Coding Agent)              AgentShield Proxy                Upstream Provider
       |                                   |                                |
       |--- POST /proxy/... (stream:true)->|                                |
       |                                   |-- 1. Check Body & Headers      |
       |                                   |-- 2. Request Scan & Policy     |
       |                                   |   (Block -> 403 error)         |
       |                                   |   (Redact -> Pseudonymize)     |
       |                                   |-- 3. Resolve Credential        |
       |                                   |-- 4. Connect Upstream -------->|
       |                                   |                                |
       |                                   |<-- Upstream Status & Headers --|
       |                                   |                                |
       |                                   |-- [If status != 200]:          |
       |<-- Preserved Upstream Error ------|    Read error body & return    |
       |                                   |                                |
       |<-- 200 OK text/event-stream ------|-- [If status == 200]:          |
       |                                   |    Start downstream stream     |
       |                                   |                                |
       |                                   |<-- SSE chunk 1 ----------------|
       |<-- Rehydrated SSE event 1 --------|    (Parse, Holdback, Rehydrate,|
       |                                   |     Scan for credentials)      |
       |<-- Rehydrated SSE event 2 --------|<-- SSE chunk 2 ----------------|
       |                                   |                                |
       |-- [If Client Disconnects]:        |                                |
       |   Detect disconnect ------------->|-- Cancel Upstream ------------>|
       |                                   |                                |
       |                                   |<-- [If Upstream Fails/Drops] --|
       |-- Terminate Stream Safely --------|    (Do NOT send [DONE])        |
```

### Error Handling Rules
1. **Upstream error before streaming starts**: The proxy has not sent downstream headers yet. It reads the bounded upstream error body and returns the provider's exact HTTP status code, safe headers, and error payload to the client.
2. **Upstream error after streaming starts**: Downstream HTTP headers (200 OK) have already been committed. The proxy terminates the connection without emitting a completion marker (`[DONE]` or `message_stop`), signalling stream failure to the client.
3. **Reflected credential in stream**: If a chunk contains the upstream API key, the stream is aborted immediately with an error logged via the safe logging pipeline.
4. **Client disconnect**: Monitored concurrently. If `request.is_disconnected()` fires, the upstream generator task is cancelled and connection closed immediately.

---

## 5. Interaction with Milestone 3 Filtering and Policies

1. **Request Phase**:
   - Exactly preserves Milestone 3 ordering: `Normalize -> Scan -> Policy -> Redact -> Credential -> Forward`.
   - In Milestone 3, redaction was irreversible. In Milestone 4:
     - Non-reversible categories (e.g. unknown custom terms with irreversible setting) continue using irreversible replacements.
     - Reversible categories (PII and eligible custom terms) generate session placeholders stored in the `PseudonymVault`.
     - Secrets always `BLOCK` and never receive placeholders or mappings.
2. **Response Phase**:
   - Rehydration reverses only exact placeholders that were generated by this AgentShield instance for this active session.
   - Non-eligible categories and unmapped placeholders remain untouched.
   - Rolling scan checks emitted tokens for secrets and provider credentials.

---

## 6. Buffering, Resource Limits, and Cancellation Strategy

- **Max Event Size**: Configurable hard limit (default 64 KiB) per SSE event. If exceeded, stream is terminated to prevent memory exhaustion attacks.
- **Holdback Buffer**: A sliding window bounded by the maximum placeholder length (e.g. 128 bytes) holds text that starts with `<AS:` until either the closing `>` is received or the prefix cannot match any known placeholder format.
- **Backpressure**: Event loop streaming uses `async for chunk in response.aiter_bytes():` and yields to FastAPI `StreamingResponse`. Network backpressure from a slow client naturally throttles upstream reads because the generator pauses.
- **Timeouts**:
  - Connect timeout: `proxy_connect_timeout_seconds` (default 10s).
  - Read-idle timeout: `proxy_read_timeout_seconds` (default 60s) enforced between chunks.
  - Overall stream timeout: handled naturally by client cancellation or keepalives.

---

## 7. Verification Plan

### Automated Test Suites
1. **Unit Tests**:
   - `backend/tests/test_sse_parser.py`: SSE parsing, chunk fragmentation, multi-byte UTF-8 boundaries, multi-line data, comments, line ending variants (`\r\n`, `\n`).
   - `backend/tests/test_pseudonym_vault.py`: Vault storage, TTL expiration, collision detection, session isolation, secret rejection.
   - `backend/tests/test_streaming_rehydration.py`: Rehydration of deltas across split chunk boundaries for OpenAI Chat, OpenAI Responses, and Anthropic Messages formats.
2. **Provider Contract & Mock Tests**:
   - `backend/tests/test_proxy_streaming.py`: Full streaming requests to OpenAI and Anthropic endpoints with `MockOpenAIServer` and `MockAnthropicServer` streaming handlers.
   - Tests covering normal streaming, client disconnect, upstream error before streaming, upstream drop mid-stream, provider credential reflection.
3. **Real Local TCP Socket Integration Tests**:
   - `backend/tests/test_streaming_socket_integration.py`: Test against a live Uvicorn server over a local TCP port to assert actual wire-level chunked transfer encoding, incremental delivery latency, and client socket close detection.
4. **Quality Gates**:
   - `cd backend && env -u SSL_CERT_FILE uv run --no-sync ruff format --check .`
   - `cd backend && env -u SSL_CERT_FILE uv run --no-sync ruff check .`
   - `cd backend && env -u SSL_CERT_FILE uv run --no-sync pyright`
   - `cd backend && env -u SSL_CERT_FILE uv run --no-sync pytest`
   - `cd frontend && pnpm lint && pnpm typecheck && pnpm test && pnpm build`
   - `cd frontend && env -u SSL_CERT_FILE pnpm exec playwright test`
