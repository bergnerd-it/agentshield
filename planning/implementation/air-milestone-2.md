Read AGENTS.md, AgentShield_V1_Specification.md, docs/ARCHITECTURE.md,
docs/THREAT_MODEL.md, SECURITY.md, docs/PRIVACY.md, docs/TESTING.md,
and all accepted ADRs completely.

Inspect the current repository and verify that Milestone 1 is complete.
Run all existing backend and frontend quality gates before making changes.
If Milestone 1 has blockers, stop and report them.

Then implement only Milestone 2 – Non-Streaming LLM Proxy:

* OpenAI Responses API proxy
* Anthropic Messages API proxy
* separate local proxy and upstream authentication
* native credential-store abstraction
* local mock provider servers
* provider contract and integration tests
* correct forwarding of supported and unknown payload fields
* safe preservation of provider status codes and errors
* request timeout and client-cancellation handling
* proxy-loop detection
* no automatic retries for non-idempotent requests

Do not implement streaming, detectors, redaction, policy enforcement,
approvals, audit UI, MCP, internet proxying, or later milestones yet.

Never call real provider APIs from tests. Never disable TLS verification,
log raw payloads, store provider credentials in SQLite, or forward local
AgentShield tokens upstream.

First produce a concise implementation plan. Then implement Milestone 2,
run all backend and frontend quality gates, and report:

1. changed files,
2. architecture decisions,
3. tests executed and results,
4. remaining limitations,
5. any deviations from the specification.

Do not begin Milestone 3.


============================

Enter Plan mode

I will start by reviewing the core specifications, architecture documentation, ADRs, and testing guidelines to understand Milestone 2 requirements and verify the current Milestone 1 state.
I have gathered all the technical details needed for Milestone 2 – Non-Streaming LLM Proxy. I am now submitting the comprehensive implementation plan covering credential abstraction, OpenAI and Anthropic provider adapters, proxy routing, cancellation and loop detection, and offline mock provider testing.# Requirements

Overview & Goals

The goal of Milestone 2 is to implement a non-streaming, protocol-faithful reverse proxy for OpenAI and Anthropic LLM APIs. AgentShield acts as an intermediary for coding agents (such as Codex or Claude Code), authenticating local client connections with a local proxy token, swapping in real upstream credentials managed securely in the operating system's native credential store, forwarding request payloads (preserving both supported and unknown fields), and transparently relaying provider responses, status codes, and error payloads.

Scope

In Scope (Milestone 2)
* OpenAI Responses API Proxy: POST /proxy/openai/v1/responses
* OpenAI Chat Completions API Proxy: POST /proxy/openai/v1/chat/completions
* Anthropic Messages API Proxy: POST /proxy/anthropic/v1/messages
* Local & Upstream Authentication Separation: Local clients authenticate via local proxy token (Authorization: Bearer <local_token> or x-api-key: <local_token>); AgentShield securely injects upstream provider credentials (Authorization: Bearer <openai_key> or x-api-key: <anthropic_key>). Local tokens are stripped and never sent upstream.
* Native Credential Store Abstraction: Secure abstraction over OS keyring (keyring package) with fallback and memory implementations for tests.
* Payload & Protocol Fidelity: Preserve supported parameters, custom/unknown parameters, and JSON structure without unwanted data stripping.
* Hop-by-Hop Header Stripping: Remove hop-by-hop headers (Connection, Keep-Alive, Proxy-Authenticate, Transfer-Encoding, etc.) before forwarding.
* Provider Status Codes & Error Preservation: Relay provider error payloads and HTTP status codes (e.g. 400, 401, 429, 500, 529) verbatim rather than collapsing them into generic 500 errors.
* Request Timeout & Client Cancellation: Propagate client disconnects to cancel upstream requests, handle upstream timeouts with HTTP 504.
* Proxy Loop Detection: Detect and reject recursive requests targeting the local proxy itself.
* Non-Idempotent Request Handling: Disable automatic retries for LLM generation requests.
* Local Mock Provider Servers: In-memory ASGI mock provider endpoints allowing full integration testing without live provider calls or real credentials.

Out of Scope (Deferred to Future Milestones)
* Milestone 3: Content scanning detectors (secrets, PII, custom terms), policy engine (ALLOW, WARN, REDACT, BLOCK), and approval coordinator.
* Milestone 4: SSE streaming passthrough (stream: true), rolling response scan, reversible pseudonymization, and rehydration.
* Milestone 5: Full dashboard UI, approvals lifecycle, Monaco diff viewer.
* Milestone 6: Privacy-preserving audit export, Codex and Claude Code configuration adapters.
* Milestone 7: Hardening, attack corpus, and packaging.
* Unsupported in Version 1: TLS interception, root CA installation, OS firewall modification, MCP proxying, internet forward proxying.

User Stories

* As a coding agent (e.g. Codex), I want to send OpenAI Responses or Chat Completions requests to http://127.0.0.1:8765/proxy/openai/v1/responses with my local proxy token so that my requests are safely forwarded to OpenAI with proper upstream authentication.
* As a coding agent (e.g. Claude Code), I want to send Anthropic Messages requests to http://127.0.0.1:8765/proxy/anthropic/v1/messages with my local proxy token so that my requests are forwarded to Anthropic with appropriate headers (anthropic-version, anthropic-beta).
* As a security-conscious developer, I want my real OpenAI and Anthropic API keys stored in the OS credential store and never sent to the client, logged, or stored in SQLite.
* As a developer, I want provider errors (such as 429 rate limits or 400 invalid request) relayed faithfully with provider error details so my coding agent can handle them natively.

Functional Requirements

1. Proxy Route Endpoints:
  * POST /proxy/openai/v1/responses forwards non-streaming requests to upstream OpenAI Responses API.
  * POST /proxy/openai/v1/chat/completions forwards non-streaming requests to upstream OpenAI Chat Completions API.
  * POST /proxy/anthropic/v1/messages forwards non-streaming requests to upstream Anthropic Messages API.
2. Authentication Handling:
  * Verify incoming requests against the local proxy token from auth.py.
  * Strip local authentication headers (Authorization, x-api-key, X-AgentShield-Token).
  * Retrieve provider API key from CredentialStore. If missing, return HTTP 500 Problem Details with clear instructions on configuring provider credentials.
  * Inject provider credentials into upstream request.
3. Payload & Header Forwarding:
  * Strip hop-by-hop headers.
  * Preserve provider-specific headers (e.g. anthropic-version, anthropic-beta, OpenAI-Organization, OpenAI-Project).
  * Forward JSON body unmodified, preserving all unknown and vendor-specific fields.
4. Streaming Guard:
  * If stream: true is requested, return HTTP 400 Problem Details specifying that streaming proxying is enabled in Milestone 4.
5. Upstream Response & Error Relay:
  * Relay upstream HTTP status code (200, 400, 401, 429, 500, 529, etc.).
  * Relay upstream content-type and response body.
  * Do not wrap provider errors in RFC 7807 problem details when they originate from the provider.
6. Cancellation, Timeouts, and Loop Detection:
  * On downstream client disconnect (request.is_disconnected()), cancel the upstream task immediately.
  * On upstream timeout, return HTTP 504 Gateway Timeout Problem Details.
  * On loop detection (e.g. request targeting AgentShield itself), return HTTP 508 / 400 Loop Detected Problem Details.

Non-Functional & Security Requirements

* No Real Network Calls in Tests: All automated tests must run against local mock provider servers.
* Fail Safe on Missing Credentials: If native keyring is unavailable and no credentials exist, fail with actionable error without silent unencrypted fallback.
* Zero Credential Leaks: Never log provider credentials, local proxy tokens, or raw request/response payloads.
* Strict Quality Gates: Pass Pyright strict mode, Ruff linting/formatting, and pytest test suite.

Technical Design

Current Implementation

Milestone 1 established the foundation in app.py:
* Local token management for admin and proxy authentication in auth.py and dependencies.py.
* Loopback binding, Host/Origin validation, and Security Headers in middleware.py.
* SQLite database configuration with WAL mode and Alembic migrations in db.py.
* Sanitized logging in logging.py and RFC 7807 error models in errors.py.

Key Decisions

1. Modular Proxy Package Structure: Place proxy-related abstractions in backend/src/agentshield/proxy/ with dedicated submodules:
  * openai/adapter.py: OpenAI Responses and Chat Completions protocol adapter.
  * anthropic/adapter.py: Anthropic Messages protocol adapter.
  * client.py: Shared asynchronous HTTP forwarding client (httpx.AsyncClient).
  * loop_detector.py: Self-referential loop detection.
2. Native Credential Store Abstraction: Implement CredentialStore interface in backend/src/agentshield/core/credentials.py with KeyringCredentialStore using keyring (service name agentshield), and InMemoryCredentialStore for testing. In dev_mode, support environment variable lookups (AGENTSHIELD_OPENAI_API_KEY, AGENTSHIELD_ANTHROPIC_API_KEY) with sanitized warnings.
3. Transparent Error and Status Relay: Unlike management API endpoints which use RFC 7807 Problem Details, proxy routes relay upstream HTTP status codes and provider JSON error responses directly to preserve agent error handling.
4. Header Normalization & Hop-by-Hop Stripping:
  * Strip standard hop-by-hop headers (connection, keep-alive, proxy-authenticate, proxy-authorization, te, trailers, transfer-encoding, upgrade, content-length, host).
  * Strip local auth headers (authorization, x-api-key, x-agentshield-token).
  * Inject provider-specific authentication headers (Authorization: Bearer <key> for OpenAI; x-api-key: <key> for Anthropic).
5. No Automatic Retries: Set HTTPX retry count to 0 for non-idempotent LLM generation requests to prevent unintended duplicate execution.

Components & File Structure
1
2
3
4
5
6
1
2
3
4
5Architecture DiagramData Models & ContractsTesting

Validation Approach

All tests run locally in an isolated offline environment using in-memory ASGI mock provider endpoints. No live external API calls are made, and synthetic test keys are used exclusively.

Key Scenarios

1. OpenAI Responses API Forwarding (POST /proxy/openai/v1/responses):
  * Send valid OpenAI payload with local proxy token.
  * Verify upstream mock receives request with Authorization: Bearer <upstream_openai_key>.
  * Verify local proxy token is not sent upstream.
  * Verify response status 200 and response body are returned to client.

2. OpenAI Chat Completions Forwarding (POST /proxy/openai/v1/chat/completions):
  * Verify chat completions requests forward model, messages, temperature, and custom parameters.
  * Verify unknown payload fields are preserved and received by the upstream mock.

3. Anthropic Messages API Forwarding (POST /proxy/anthropic/v1/messages):
  * Send valid Anthropic payload with local proxy token and anthropic-version: 2023-06-01.
  * Verify upstream mock receives x-api-key: <upstream_anthropic_key> and anthropic-version.
  * Verify response status 200 and JSON body are returned to client.

4. Preservation of Unknown Payload Fields:
  * Include non-standard fields (e.g. {"custom_vendor_param": 12345}) in request body.
  * Verify the upstream mock server receives these fields intact.

5. Upstream Error & Status Code Preservation:
  * Mock upstream returns 400 Bad Request, 401 Invalid Key, 429 Rate Limit Exceeded, 500 Internal Error, and 529 Overloaded.
  * Verify AgentShield returns identical status code and provider error JSON body.

6. Authentication Failures:
  * Request without proxy token returns 401 Unauthorized Problem Details.
  * Request with invalid proxy token returns 401 Unauthorized Problem Details.
  * Request when upstream provider key is missing from credential store returns 500 Problem Details with clear error.

7. Loop Detection:
  * Request configured to target AgentShield's own proxy endpoint is detected and blocked with 400/508 Loop Detected.

8. Client Disconnect & Upstream Cancellation:
  * Disconnect during processing terminates upstream request without unhandled exceptions.

9. Streaming Guard:
  * Request containing "stream": true returns HTTP 400 Problem Details explaining that streaming is scheduled for Milestone 4.

10. Zero Credential Leaking:
  * Assert that logs, responses, and error traces never contain the upstream provider API keys or local proxy tokens.

Delivery Steps

Step 1: Implement native credential-store abstraction and proxy configuration
The backend provides a secure credential-store interface and configuration for OpenAI and Anthropic upstream endpoints.

* Add keyring>=24.3.0 to pyproject.toml dependencies for OS-native credential storage.
* Implement the CredentialStore abstraction interface in backend/src/agentshield/core/credentials.py with KeyringCredentialStore and InMemoryCredentialStore (for tests/fallback).
* Update config.py to include proxy settings: upstream provider base URLs (https://api.openai.com and https://api.anthropic.com), default timeouts (connect, read, write), maximum request payload size (10 MiB), and dev-mode fallback key lookups.
* Update dependencies.py to provide credential store instances via dependency injection.

Step 2: Build provider adapters, loop detection, and HTTP forwarding client
Provider adapters normalize headers, inject upstream credentials, strip local tokens, and detect proxy loops.

* Create backend/src/agentshield/proxy/types.py defining provider payload structures, headers, and forwarding context.
* Create backend/src/agentshield/proxy/loop_detector.py to prevent cyclic proxy requests by inspecting destination endpoints and detecting X-AgentShield-Loop-Detection markers.
* Implement the OpenAI provider adapter in backend/src/agentshield/proxy/openai/adapter.py for Responses API (/v1/responses) and Chat Completions API (/v1/chat/completions), replacing local auth with Authorization: Bearer <upstream_openai_key> and stripping hop-by-hop headers.
* Implement the Anthropic provider adapter in backend/src/agentshield/proxy/anthropic/adapter.py for Messages API (/v1/messages), replacing local auth with x-api-key: <upstream_anthropic_key> and forwarding anthropic-version / anthropic-beta headers.
* Implement non-streaming HTTP client in backend/src/agentshield/proxy/client.py using httpx.AsyncClient with custom timeouts, no automatic retries for non-idempotent requests, and upstream cancellation on client disconnect.

Step 3: Implement proxy routes and upstream error preservation
FastAPI proxy endpoints validate local proxy tokens, route requests to adapters, and return provider status codes and error bodies without collapsing them.

* Create backend/src/agentshield/api/routes/proxy.py mounting POST /proxy/openai/v1/responses, POST /proxy/openai/v1/chat/completions, and POST /proxy/anthropic/v1/messages.
* Secure endpoints using require_proxy_auth dependency to enforce local proxy authentication while ensuring local tokens never reach upstream adapters.
* Preserve unknown payload fields in JSON request bodies and pass them through unmutated.
* Reject requests with stream: true safely with HTTP 400 Problem Details explaining streaming is scheduled for Milestone 4.
* Preserve upstream status codes (400, 401, 403, 404, 429, 500, 502, 529) and upstream error JSON bodies directly to the client without translating them into generic 500 errors.
* Handle client disconnects and timeouts with HTTP 504 Gateway Timeout or HTTP 502 Bad Gateway.
* Register proxy routes in app.py.

Step 4: Add local mock provider test suite and contract tests
A local mock provider server and test suite validate all Milestone 2 contract, security, and error-handling requirements offline.

* Create backend/tests/mock_providers.py implementing local mock ASGI handlers for OpenAI (Responses and Chat Completions) and Anthropic (Messages) APIs.
* Implement backend/tests/test_proxy_openai.py testing successful forwarding, unknown field preservation, authentication header replacement, status code preservation, and loop detection.
* Implement backend/tests/test_proxy_anthropic.py testing Messages API forwarding, header handling (anthropic-version, anthropic-beta), custom fields, and error codes.
* Implement backend/tests/test_credentials.py testing native credential store abstraction, keyring handling, missing key failure, and dev mode fallback.
* Implement backend/tests/test_proxy_security.py verifying that local proxy tokens are never sent upstream, provider API keys are never exposed to the client, and synthetic secrets are absent from logs.
