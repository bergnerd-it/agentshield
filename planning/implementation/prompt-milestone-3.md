Read the following project documents completely before making any changes:

- AGENTS.md
- AgentShield_V1_Specification.md
- README.md
- ARCHITECTURE.md
- THREAT_MODEL.md
- SECURITY.md
- PRIVACY.md
- TESTING.md
- all accepted Architecture Decision Records
- report-milestone-2.md
- any repository-native issue or task files relevant to Milestone 3

Treat AGENTS.md, the V1 specification, and accepted ADRs as authoritative.
If documents conflict, follow the precedence rules defined in AGENTS.md
and report the conflict before implementation.

## Phase 1: Verify the baseline

Inspect the current repository and verify that Milestone 2 is complete.

Run all existing backend and frontend quality gates, including:

Backend:
- dependency synchronization from the lockfile
- Ruff formatting check
- Ruff linting
- Pyright
- complete pytest suite

Frontend:
- dependency installation from the lockfile
- lint
- TypeScript typecheck
- Vitest
- production build
- Playwright E2E tests where the execution environment supports them

Also verify that the remaining conditions from report-milestone-2.md have
been resolved, particularly:

- Playwright verification,
- correct Content-Encoding handling,
- RFC-correct Trailer header handling,
- explicit and secure dev-mode credential fallback,
- reproducible proxy smoke tests.

If Milestone 2 has unresolved blockers, security defects, failing quality
gates, or uncommitted unrelated changes, stop and report them. Do not
begin Milestone 3.

## Phase 2: Produce an implementation plan

Locate the exact “Milestone 3” section in AgentShield_V1_Specification.md.

Before changing code, produce a concise implementation plan that includes:

1. the exact Milestone 3 requirements found in the specification,
2. affected modules and files,
3. proposed domain models and interfaces,
4. detector and policy-processing order,
5. security and privacy implications,
6. tests to be added,
7. explicit exclusions belonging to later milestones.

Do not silently reinterpret or expand the milestone.

## Phase 3: Implement Milestone 3 only

Implement only Milestone 3 as defined in the specification.

The expected scope includes, where required by the authoritative
Milestone 3 specification:

### Finding model and detector contract

Create a provider-independent detector abstraction and a normalized,
strongly typed Finding model.

A finding should carry the information required by the specification,
such as:

- stable category,
- severity,
- detector identifier and version,
- start and end offsets,
- confidence,
- safe display metadata,
- optional replacement proposal.

Detector code must remain independent of FastAPI, HTTP provider adapters,
the frontend, and persistence.

Validate all offsets and ensure that findings never expose secret values
through their representations, logs, exception messages, or audit data.

### Secret detection

Implement deterministic detection of the secret types required by the
specification, including the configured token, credential, and private-key
patterns.

Where required, combine:

- well-defined regular expressions,
- validation rules,
- entropy-based detection,
- configurable allowlists or exclusions.

Minimize false positives and document known limitations.

A detected credential or private key must default to a fail-closed action.
Secrets must not be reversibly pseudonymized.

### PII detection

Implement the specified PII detector integration, including Microsoft
Presidio if required by the specification.

The integration must:

- support the configured languages and entity types,
- normalize external detector results into the common Finding model,
- behave deterministically in tests,
- avoid downloading models or making network requests during tests,
- handle an unavailable detector according to the configured fail-safe
  behavior,
- document that PII detection cannot guarantee complete identification.

### Project-specific terms

Implement configurable detection of internal project names, package names,
class names, domain terminology, or other customer-specific identifiers
as required by the specification.

Configuration must be validated and must not permit unsafe arbitrary code
execution.

Matching behavior, case sensitivity, word boundaries, exclusions, and
precedence must be explicit and tested.

### Policy engine

Implement a provider-independent policy engine with the actions required
by the specification:

- ALLOW
- WARN
- REDACT
- REQUIRE_APPROVAL
- BLOCK

Policy evaluation must be deterministic and explainable.

Define and test:

- severity precedence,
- category precedence,
- handling of overlapping findings,
- handling of conflicting rules,
- default behavior when no rule matches,
- behavior when a detector fails,
- behavior for malformed or unsupported content,
- strict, balanced, and audit profiles where required.

Security decisions must be made exclusively in the backend. The frontend
must not be a security boundary.

### Redaction and pseudonymization

Implement redaction and reversible pseudonymization only where required
by the Milestone 3 specification.

Requirements include:

- deterministic placeholders within one session,
- no collisions between placeholders,
- correct handling of repeated values,
- offset-safe replacement when findings overlap,
- replacement from the end of the text toward the beginning or an
  equivalent safe algorithm,
- no automatic rehydration of secrets,
- session-local and time-limited mappings,
- no plaintext mappings in logs, audit events, or SQLite,
- cleanup when the session expires.

If response rehydration belongs to a later milestone, provide only the
domain abstraction required now and do not integrate it prematurely.

### Proxy integration

Integrate the Milestone 3 processing pipeline into the existing
non-streaming OpenAI and Anthropic proxy paths only to the extent required
by the specification.

Preserve Milestone 2 behavior:

- local and upstream credentials remain separated,
- unknown provider fields remain intact,
- provider errors and status codes remain correctly forwarded,
- no automatic retries are introduced,
- timeout and cancellation behavior remain intact,
- proxy-loop detection remains active,
- raw payloads are never logged.

Only inspect or modify explicitly supported textual request fields.
Unsupported binary, image, audio, file, or multipart content must follow
the specification’s safe default behavior.

Do not mutate unrelated JSON values or structural fields.

### Privacy-safe observability

Logs and errors may contain:

- request IDs,
- detector identifiers,
- categories,
- severities,
- finding counts,
- decisions,
- durations,
- payload sizes.

They must not contain:

- raw prompts,
- raw model responses,
- detected secret values,
- original PII values,
- reversible pseudonym mappings,
- provider credentials,
- local AgentShield tokens.

## Required tests

Add comprehensive unit, integration, contract, and security tests.

At minimum, cover the cases required by the specification, including:

- every supported secret pattern,
- representative true-positive and false-positive cases,
- PII normalization,
- configurable project terms,
- Unicode input,
- zero-width and unusual whitespace characters,
- URL-encoded and Base64-like values where required,
- multiple findings in one payload,
- repeated values,
- adjacent and overlapping findings,
- deterministic policy precedence,
- each policy action,
- audit, balanced, and strict profiles,
- detector failure and timeout behavior,
- redaction without leaking original values,
- stable session-scoped pseudonyms,
- session isolation and expiry,
- secrets never being reversibly pseudonymized,
- OpenAI request integration,
- Anthropic request integration,
- preservation of unrelated and unknown JSON fields,
- absence of raw payloads and credentials in logs and exceptions,
- regression tests for all Milestone 1 and Milestone 2 behavior.

Use synthetic fixtures only. Never place real credentials, customer data,
personal data, production source code, or confidential identifiers in
the repository.

Tests must not:

- contact real OpenAI or Anthropic endpoints,
- download models from the internet,
- require real provider credentials,
- disable TLS verification,
- depend on platform-specific native credential stores unless explicitly
  marked as platform integration tests.

## Explicit exclusions

Do not implement features assigned to later milestones, including any of
the following unless the authoritative Milestone 3 section explicitly
requires them:

- SSE or other streaming proxy support,
- full approval user interface,
- Monaco diff interface,
- dashboard workflows belonging to later milestones,
- MCP proxying,
- uncontrolled or system-wide internet proxying,
- TLS interception or installation of a root CA,
- Tauri desktop packaging,
- Rust components,
- multi-user operation, RBAC, or SSO,
- PostgreSQL or cloud deployment,
- semantic LLM-based classification,
- automatic response rehydration if scheduled for a later milestone.

Do not begin Milestone 4.

## Verification and completion report

After implementation:

1. run all backend and frontend quality gates,
2. run the complete regression suite,
3. run all new Milestone 3 tests,
4. verify the application against the Milestone 3 acceptance criteria,
5. inspect logs, exceptions, and SQLite for prohibited raw data,
6. confirm that no real external provider was contacted,
7. confirm that no later-milestone functionality was introduced.

Create or update a repository file named:

report-milestone-3.md

The report must contain:

1. exact requirements implemented,
2. changed files and their purpose,
3. architecture decisions,
4. detector and policy behavior,
5. exact commands executed,
6. test counts and results,
7. security and privacy verification evidence,
8. failed or skipped checks,
9. known limitations,
10. deviations from the specification,
11. final verdict: PASS, PASS WITH CONDITIONS, or FAIL.

Do not claim that a skipped test passes.
Do not claim manual verification without documenting reproducible commands
and sanitized observed results.
Do not conceal deviations or replace missing evidence with assumptions.
