# AgentShield Architecture

Status: target architecture for Version 1  
Audience: implementers, reviewers, security engineers, and customer architects

## 1. Context

Coding agents can place prompts, source code, tool results, and credentials into calls to external LLM providers. AgentShield provides a local mediation boundary for traffic that the user explicitly routes through it.

The Version 1 architecture is a modular monolith with two logical planes:

- **Data plane:** latency-sensitive proxying, normalization, scanning, policy enforcement, redaction, rehydration, and streaming.
- **Control plane:** settings, policies, approvals, integrations, audit queries, exports, and UI delivery.

They initially run in one process but use separate modules, routes, credentials, and domain interfaces.

## 2. System Context

```mermaid
flowchart LR
    A["Coding Agent"] -->|"Provider API"| B["AgentShield"]
    U["Local User"] -->|"Browser UI"| B
    B -->|"TLS"| P["Approved LLM Provider"]
    B --> S["OS Credential Store"]
    B --> D["Local SQLite"]
```

Only traffic through AgentShield is mediated. Direct coding-agent traffic to another endpoint is outside the Version 1 enforcement boundary.

## 3. Architectural Principles

1. **Honest boundary:** never claim control over bypass traffic.
2. **Secure by default:** secrets block; required checks fail closed in strict mode.
3. **Minimize retained data:** store decisions and fingerprints, not raw prompts.
4. **Deterministic enforcement:** detectors produce findings; policies decide actions.
5. **Protocol fidelity:** security processing must not casually change provider semantics.
6. **Bounded resources:** buffers, queues, request sizes, and approval waits have limits.
7. **Replaceable adapters:** provider, credential-store, persistence, and integration details stay behind interfaces.
8. **Local first:** no cloud component is required for Version 1.
9. **Test without external services:** local mock providers cover all automated tests.

## 4. Logical Components

### 4.1 Local Runtime

Owns process lifecycle, loopback binding, single-instance behavior, configuration loading, migrations, health checks, and static frontend delivery.

### 4.2 Proxy API

Exposes provider-compatible routes. It authenticates the local client, normalizes supported payloads, invokes the inspection pipeline, and forwards permitted traffic through a provider adapter.

### 4.3 Provider Adapters

OpenAI and Anthropic adapters own:

- upstream URL construction;
- endpoint validation before credential access;
- provider authentication;
- required headers;
- provider-specific error preservation;
- streaming event parsing and forwarding;
- cancellation propagation.

Adapters must not decide data-protection policy.

Production provider profiles accept only the documented provider hostname over
HTTPS on the default TLS port. Development mode additionally permits explicit
loopback HTTP or HTTPS endpoints for local mock providers. Endpoint URLs with
userinfo, query strings, fragments, or non-loopback custom hosts are rejected
before the native credential store is accessed.

### 4.4 Normalization Layer

Creates a provider-neutral `ScanContext` containing direction, provider, model, endpoint, selected headers, structured text locations, session information, and byte limits. It preserves sufficient location data to apply safe replacements to the original payload.

### 4.5 Detector Engine

Runs enabled detectors and returns `Finding` objects. Initial detector families are:

- credentials and secrets;
- PII;
- custom terms and regular expressions;
- unsupported content;
- response-side suspicious instructions where configured.

Detector failures are explicit inputs to the policy engine. They are never silently treated as “no findings.”

### 4.6 Policy Engine

Evaluates immutable policy versions against context, findings, detector health, and the selected profile. It returns one `PolicyDecision` using the documented action precedence.

### 4.7 Redaction Service

Applies replacements using locations produced during normalization and scanning. It preserves JSON structure and validates the transformed payload before forwarding.

### 4.8 Pseudonym Vault

Maintains collision-resistant mappings for reversible data classes. Version 1 should prefer in-memory mappings with bounded TTL. If mappings are persisted, they require protected storage and explicit retention behavior.

The vault never accepts credentials or secret classes as reversible values.

### 4.9 Approval Coordinator

Creates one-time approval requests, notifies the UI, waits for a bounded decision, verifies request fingerprints, and handles denial, expiration, and client cancellation.

### 4.10 Audit Service

Records privacy-preserving event metadata after each decision and terminal outcome. It uses centralized safe serialization and must not receive raw provider credentials or unredacted secret values.

### 4.11 Integration Adapters

Inspect, preview, back up, modify, validate, and restore coding-agent configurations. Version 1 provides adapters for Codex and Claude Code. Format-specific logic must not leak into the rest of the application.

### 4.12 Management API and React UI

The management API exposes status, events, approvals, policies, detectors, settings, and exports. The React UI consumes a generated TypeScript client. It is an operator interface, not an enforcement boundary.

## 5. Request Lifecycle

```mermaid
sequenceDiagram
    participant A as Coding Agent
    participant P as AgentShield Proxy
    participant F as Filter and Policy
    participant L as LLM Provider

    A->>P: Provider-compatible request
    P->>P: Authenticate and bound input
    P->>F: Normalize and scan
    F-->>P: Policy decision
    alt Allowed or redacted
        P->>L: Sanitized request over TLS
        L-->>P: Response or SSE stream
        P->>F: Response scanning
        P-->>A: Safe response
    else Approval required
        P-->>A: Wait while approval is pending
    else Blocked
        P-->>A: Safe structured error
    end
```

### 5.1 Mandatory Ordering

For outbound requests:

1. authenticate local proxy client;
2. apply header and size limits;
3. strictly parse and normalize supported payload, rejecting malformed JSON,
   duplicate keys, and unsupported streaming requests;
4. execute required detectors;
5. evaluate policy;
6. obtain approval where required;
7. apply and validate redaction;
8. obtain upstream credential from the native store;
9. call the provider;
10. record a sanitized audit outcome.

No request body bytes may be sent upstream before required outbound scanning and approval are complete.

Non-streaming provider responses are consumed through a decoded-byte limit
before release to the client. Exact provider credentials found in any response
header or in the bounded response body cause a safe gateway failure. Fixed and
`Connection`-nominated hop-by-hop headers are removed in both directions.

## 6. Streaming Architecture

Outbound request content is fully scanned before upstream transmission. Inbound SSE is processed event by event through a bounded parser and rolling scan window.

Key rules:

- never buffer an unbounded stream;
- preserve valid SSE framing and event order;
- propagate client cancellation upstream;
- bound rolling windows and per-event sizes;
- terminate the stream when an enforceable response finding is detected;
- record that content already delivered before a later finding cannot be recalled.

Response streaming has an inherent limitation: content released before a future malicious token cannot be retroactively removed. Strict response policies may therefore require a larger holdback window or non-streaming operation. This trade-off must be visible in configuration and documentation.

## 7. Authentication Model

AgentShield uses two local security contexts:

- **Proxy token:** configured in the coding agent and accepted only by proxy endpoints.
- **Management session/token:** accepted only by management endpoints and the UI.

Real upstream credentials remain in the native credential store. The proxy replaces local authentication with upstream authentication only after policy approval.

The backend binds to loopback and validates Host and Origin. Loopback binding is defense in depth, not authentication.

## 8. Persistence Model

SQLite is the Version 1 source of truth for:

- settings that are not secrets;
- policy definitions and immutable versions;
- detector configuration without secret values;
- sanitized audit events;
- approval metadata where necessary.

Provider credentials remain outside SQLite. Raw payload retention is disabled by default. Use Alembic for every schema change and enable WAL mode with explicit busy timeout and transaction handling.

Suggested primary entities:

- `policy`
- `policy_version`
- `detector_configuration`
- `audit_event`
- `approval_request`
- `integration_backup`

Do not store pseudonym mappings in ordinary audit tables.

## 9. Failure Semantics

| Failure | Default behavior |
| --- | --- |
| Secret found | Block |
| Required detector unavailable in strict mode | Block |
| Required detector unavailable in balanced mode | Configured warning or block; never silent |
| Credential store unavailable | Do not call provider |
| Policy store unavailable | Block protected requests |
| Audit store unavailable | Strict profile blocks; other profiles follow explicit configuration |
| Approval timeout | Block |
| Client disconnect during approval | Cancel |
| Client disconnect during provider stream | Cancel upstream |
| Provider response exceeds its decoded-byte limit | Terminate upstream and return a safe gateway error |
| Provider response contains the exact provider credential | Block the response and return a safe gateway error |
| Provider error | Preserve safe provider semantics |
| Malformed supported payload | Reject before provider call |

## 10. Extension Points

Define typed interfaces for:

- `Detector`
- `PolicyRepository`
- `AuditRepository`
- `CredentialStore`
- `ProviderAdapter`
- `AgentIntegration`
- `Clock`
- `IdGenerator`

Avoid a general plugin framework in early milestones. Stable internal interfaces are sufficient until a real external plugin use case exists.

## 11. Deployment Model

Version 1 runs as a local process:

```text
127.0.0.1:8765
```

In development, Vite may use a separate loopback port. In the production build, FastAPI serves static frontend assets from the same origin.

Cross-platform distribution is initially source/CLI based. Tauri packaging and a hardened Rust sidecar are future architectural options, not Version 1 dependencies.

## 12. Observability

Expose local health, readiness, detector status, request counts, decisions, and latency metrics. Telemetry must use an allowlist of safe attributes. External telemetry exporters are disabled by default.

Correlation IDs must not encode user content. Content fingerprints should use a versioned normalization procedure and, where correlation resistance matters, a keyed digest rather than a plain reusable hash.

## 13. Architecture Fitness Checks

CI should verify:

- domain packages do not import FastAPI;
- frontend DTOs are generated rather than duplicated;
- network tests cannot reach public provider endpoints;
- logs and audit output exclude the synthetic secret corpus;
- streaming buffers remain bounded;
- migrations apply from an empty database;
- accepted ADRs and referenced documentation links exist.

## 14. Future Evolution

Potential later components include:

- controlled web-fetch gateway;
- MCP mediation;
- process sandbox and enforced egress;
- TLS interception under an explicitly managed trust model;
- Tauri desktop packaging;
- Rust data-plane sidecar;
- central team policy service;
- PostgreSQL and multi-user operation.

Each changes the threat model and requires a new or superseding ADR before implementation.
