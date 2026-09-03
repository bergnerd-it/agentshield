# Testing Strategy

Status: Version 1 quality baseline

## 1. Goals

Testing must demonstrate both functional behavior and the absence of known disclosure paths. Coverage percentage alone is not sufficient. High-risk paths require behavior, failure, cancellation, concurrency, and leak tests.

All automated tests run without real provider credentials, external provider APIs, customer source code, or real personal data.

## 2. Test Layers

### 2.1 Unit Tests

Cover pure domain behavior:

- detector positive, negative, boundary, and encoding cases;
- policy precedence and profile defaults;
- placeholder generation, collision handling, TTL, and rehydration;
- secret classes that can never enter the reversible mapping;
- normalization and safe fingerprinting;
- safe error and log serialization.

The filtering, policy, redaction, and pseudonymization core should target at least 90% branch coverage. This is a review signal, not permission to omit behavior-based tests.

### 2.2 Component Tests

Test components with controlled adapters:

- SQLAlchemy repositories against temporary SQLite databases;
- migrations from an empty database;
- credential-store behavior through fake adapters;
- approval state machine with an injected clock;
- OpenAI and Anthropic payload normalization;
- audit serialization and retention cleanup;
- agent-configuration preview, backup, atomic write, validation, and rollback.

### 2.3 Provider Contract Tests

Use local mock HTTP servers to verify:

- request paths and provider-specific headers;
- local token removal and upstream token insertion;
- preservation of supported and unknown payload fields;
- provider status codes and safe error bodies;
- non-streaming responses;
- valid, fragmented, malformed, and interrupted SSE;
- rate limits, timeouts, slow responses, and disconnects;
- no unintended retries.

Capture what the mock provider receives and assert that blocked or redacted values never cross the boundary.

### 2.4 API Security Tests

At minimum:

- missing, invalid, expired, and wrong-purpose local tokens;
- management token used at proxy endpoint and vice versa;
- hostile Host headers;
- absent and hostile Origin headers where applicable;
- CORS preflight behavior;
- oversized body and decompression limits;
- malformed JSON and duplicate keys;
- proxy-loop markers;
- disallowed custom provider endpoints;
- safe Problem Details without reflected confidential content.

### 2.5 Frontend Tests

Use Vitest and Testing Library for components and Playwright for complete flows:

- health and degraded status;
- event filtering and pagination;
- sanitized diff rendering;
- approval, denial, timeout, and already-completed state;
- policy validation and effective precedence;
- provider settings without secret disclosure;
- keyboard navigation and accessible names;
- absence of synthetic secrets in DOM, browser storage, console, URLs, and screenshots.

### 2.6 End-to-End Tests

Start the real backend, built frontend, temporary SQLite database, fake credential store, and mock providers. Exercise:

1. allowed request;
2. warning-only request;
3. blocked synthetic credential;
4. PII pseudonymization and eligible rehydration;
5. approval before provider contact;
6. client cancellation during approval;
7. streaming termination on an enforceable finding;
8. audit export without raw content;
9. integration backup and rollback.

## 3. Synthetic Security Corpus

Maintain a versioned corpus of clearly synthetic cases for:

- provider-style keys;
- AWS-style credentials;
- GitHub-style tokens;
- JWTs;
- PEM private keys;
- passwords in JSON, YAML, `.env`, Java, Python, shell, and HTTP text;
- email, phone, IBAN, and IP patterns;
- German and English names and organizations;
- internal Java package, class, database, and project names;
- Base64 and URL encoding;
- zero-width characters and homoglyphs;
- values split across JSON nodes or SSE events;
- plausible false positives such as UUIDs, hashes, fixtures, and ordinary source literals.

Corpus values must be unmistakably synthetic and must never accidentally match a real credential.

## 4. Leak-Test Procedure

Each security test generates a unique marker. At test completion, recursively inspect all test-controlled outputs:

- mock-provider captures;
- application and access logs;
- SQLite database content;
- audit JSON and HTML;
- API responses;
- browser DOM, console, and storage;
- crash reports and temporary files.

Expected behavior determines whether the provider capture may contain a sanitized placeholder. The original synthetic secret must be absent everywhere except the in-memory test input and an explicitly isolated test assertion.

## 5. Streaming Tests

Streaming requires dedicated tests for:

- CRLF and LF framing;
- multi-line `data` fields;
- comments and keepalive events;
- JSON tokens split across arbitrary chunks;
- a finding split across events;
- maximum event and rolling-window sizes;
- backpressure from a slow client;
- upstream disconnect;
- downstream disconnect;
- policy termination after partial delivery;
- no reordering or duplicate forwarding.

## 6. Concurrency and State Tests

- concurrent requests cannot share pseudonym mappings across projects or sessions;
- one approval cannot complete twice;
- approval and cancellation races have one atomic terminal state;
- policy changes do not change the immutable version attached to an in-flight request;
- retention cleanup does not delete active approval or mapping state;
- SQLite busy handling is bounded and deterministic.

## 7. Performance Tests

Measure separately:

- baseline proxy overhead without content scanning;
- regex and custom-term scanning;
- Presidio-enabled scanning;
- first-byte delay for streaming;
- memory use under maximum allowed request size;
- concurrency with a slow mock provider;
- export generation over a representative audit database.

Report p50, p95, and p99 where sample size permits. Security checks must not be silently disabled to meet a target.

## 8. Platform Matrix

CI should cover:

| Area | macOS | Linux | Windows |
| --- | ---: | ---: | ---: |
| Backend unit/integration | Required | Required | Required |
| Frontend unit/build | Required | Required | Required |
| Credential-store adapter | Required | Required or documented limitation | Required |
| Agent integration fixtures | Required | Required | Required |
| Playwright smoke test | Required | Required | Required where stable |

Platform-specific failures must not be hidden by silently changing to insecure storage.

## 9. Quality Gates

A pull request that changes production behavior must pass:

```bash
cd backend
uv sync --frozen
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest
```

```bash
cd frontend
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm exec playwright test
```

Release additionally requires:

- leak-test corpus pass;
- dependency vulnerability scan;
- SBOM generation;
- migration-from-empty test;
- local demo pass;
- current threat-model review;
- no skipped high-severity security test.

## 10. Test Failure Policy

- Never weaken an assertion solely to make CI green.
- Never replace a deterministic failure with an arbitrary sleep.
- Never record a new snapshot without reviewing it for semantics and disclosure.
- Quarantine a flaky test only with an owner, issue, reason, and deadline; security-boundary tests may not be quarantined.
- A leaked synthetic secret is a release blocker even when all functional tests pass.
