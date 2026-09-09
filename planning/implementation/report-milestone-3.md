# Milestone 3 Implementation Report

Date: 2026-09-09

## 1. Exact requirements implemented

The complete authoritative Milestone 3 section in
`AgentShield_V1_Specification.md` is:

> ### Milestone 3 – Detectors and Policies
>
> - domain models;
> - secret, PII, and custom-term detectors;
> - policy engine and profiles;
> - request scanning;
> - `ALLOW`, `WARN`, `REDACT`, and `BLOCK`.

This change implements those requirements for the existing non-streaming
OpenAI Responses, OpenAI Chat Completions, and Anthropic Messages proxy
routes:

- provider-independent, immutable finding, detector, scan-context, policy,
  decision, and redaction domain models;
- deterministic built-in secret detection for synthetic OpenAI, Anthropic,
  AWS, GitHub, bearer, JWT, PEM private-key, password-assignment, and
  contextual high-entropy credential patterns;
- structured PII detection plus an injectable Microsoft Presidio adapter for
  configured English and German entity detection;
- validated exact-match and restricted-regex custom-term detection;
- audit, balanced, and strict policy profiles with deterministic rule and
  action precedence;
- selective request-field normalization and scanning before any upstream
  request bytes are sent;
- irreversible request redaction with deterministic overlap handling;
- backend-only enforcement of `ALLOW`, `WARN`, `REDACT`, and `BLOCK`;
- safe detector-failure handling and metadata-only logging.

The implementation also follows requirements elsewhere in the specification
that directly constrain Milestone 3: domain logic is independent of FastAPI;
unknown provider fields are preserved; unsupported multimodal content is
reported and is blocked by strict mode; credentials fail closed; TLS
verification remains enabled; raw payloads and detected values are not logged
or persisted.

## 2. Changed files and purpose

### Backend domain and detector implementation

- `backend/src/agentshield/filtering/models.py`: immutable normalized
  findings, safe locations, severities, scan targets, detector protocol,
  detector failures, and scan results.
- `backend/src/agentshield/filtering/engine.py`: ordered asynchronous detector
  execution, per-detector timeouts, and safe failure normalization.
- `backend/src/agentshield/filtering/detectors/secrets.py`: built-in secret
  patterns, validators, bounded decoding, zero-width normalization,
  contextual entropy checks, and keyed allowlist fingerprints.
- `backend/src/agentshield/filtering/detectors/pii.py`: deterministic
  structured PII detector and Microsoft Presidio adapter.
- `backend/src/agentshield/filtering/detectors/custom_terms.py`: validated
  project-term exact and restricted-regex matching.
- `backend/src/agentshield/filtering/detectors/unsupported.py`: normalized
  findings for unsupported multimodal request parts.
- `backend/src/agentshield/filtering/redaction/service.py`: irreversible,
  right-to-left redaction with deterministic overlap resolution.
- package `__init__.py` files expose the supported domain API.

### Policies and proxy integration

- `backend/src/agentshield/policies/models.py`: four Milestone 3 actions,
  profiles, matching rules, and explainable decisions.
- `backend/src/agentshield/policies/engine.py`: deterministic profile,
  category, severity, rule, and action evaluation.
- `backend/src/agentshield/policies/yaml_io.py`: bounded safe-YAML
  import/export with strict validation.
- `backend/src/agentshield/proxy/scanning.py`: provider-specific textual
  request normalization and offset-safe application of replacements.
- `backend/src/agentshield/proxy/inspection.py`: detector/policy/redaction
  request pipeline and privacy-safe decision logging.
- `backend/src/agentshield/api/dependencies.py`: dependency-injected pipeline
  assembly and stable local fingerprint-key loading.
- `backend/src/agentshield/api/routes/proxy.py`: filtering before upstream
  adapter and credential resolution.
- `backend/src/agentshield/core/config.py`: validated detector, model,
  timeout, profile, custom-term, and allowlist settings.
- `backend/src/agentshield/core/auth.py`: protected generation/loading of the
  separate keyed-fingerprint secret.
- `backend/src/agentshield/core/errors.py`: safe content-blocked Problem
  Details error.
- `backend/src/agentshield/core/logging.py`: sanitizer coverage for the
  fingerprint key and exception-class-only unhandled-error logging.
- `backend/pyproject.toml` and `backend/uv.lock`: locked
  `presidio-analyzer==2.2.364` dependency and transitive dependencies.

### Tests

- New detector, domain, policy, YAML, redaction, normalizer, engine, and proxy
  tests in `backend/tests/test_*detector*.py`,
  `test_filtering_models.py`, `test_policy_engine.py`,
  `test_policy_yaml.py`, `test_redaction.py`,
  `test_request_normalization.py`, and `test_proxy_filtering.py`.
- `backend/tests/conftest.py`: test default disables Presidio model loading;
  Presidio behavior is exercised through injected fakes.
- Existing auth, configuration, and logging tests cover the new safe
  boundaries.

### Documentation and UI wording

- `docs/adr/0008-deterministic-built-in-secret-detector.md`: accepted
  decision to use a deterministic built-in secret detector and Presidio only
  for PII.
- `docs/adr/README.md`: ADR index update.
- `README.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`,
  `SECURITY.md`, `docs/PRIVACY.md`, and `docs/TESTING.md`: implemented
  behavior, boundaries, privacy properties, test strategy, and limitations.
- `frontend/src/pages/DashboardPage.tsx`: wording now reflects irreversible
  Milestone 3 PII redaction rather than later pseudonymization.

There are no database migrations or persistence-model changes.

## 3. Architecture decisions

- A detector returns findings and never chooses a policy action.
- Finding objects contain category, severity, detector identifier/version,
  half-open offsets, confidence, safe metadata, an HMAC fingerprint, and an
  optional replacement. They never retain the matched plaintext.
- `ScanTarget.text` is excluded from representations. Validation and
  configuration errors omit input values.
- Detectors execute in a fixed declared order. Detector exceptions and
  timeouts terminate only that detector boundary and become safe typed failure
  metadata; the policy engine determines the outcome.
- Secret allowlists compare HMAC-SHA256 fingerprints generated with a separate
  local 0600 key. The key and matched values are never persisted to SQLite or
  emitted to logs.
- Presidio is invoked through an adapter and blocking analyzer/model work runs
  outside the async event loop. Production uses explicitly configured local
  spaCy model names. No downloader or network fallback exists.
- Request scanning is provider-aware. It traverses only documented text-bearing
  fields and selected unexpected headers. It preserves unknown root fields and
  all unrelated structural values.
- Redaction deep-copies the parsed payload, selects overlaps deterministically,
  and replaces spans from the end of each text field toward the beginning.
- ADR 0008 records the security-sensitive dependency and detector split.

## 4. Detector and policy behavior

The default processing order is:

1. normalize supported OpenAI or Anthropic request text and unsupported-part
   metadata;
2. detect secrets;
3. detect structured PII;
4. run Presidio PII detection when enabled;
5. detect configured custom terms;
6. report unsupported content;
7. evaluate policy;
8. block, forward unchanged, or apply irreversible redaction;
9. invoke the existing provider adapter only when allowed.

Action precedence is:

```text
BLOCK > REDACT > WARN > ALLOW
```

Findings and conflicting rules are ordered deterministically by action,
explicit rule priority, stable rule identifier, severity, category,
confidence, detector identifier, and location as applicable. Explicit
`ALLOW` rules cannot override credential findings.

- **Audit:** allows non-secret findings and records the balanced-profile action
  as a hypothetical decision. Credentials and credential-detector failures
  still block.
- **Balanced:** blocks secrets, redacts PII, warns for custom terms and
  unsupported content unless an explicit validated rule changes those
  non-secret actions.
- **Strict:** blocks secrets, custom terms, unsupported content, and required
  detector failures; it redacts PII.
- No finding yields `ALLOW`.
- Malformed JSON is rejected before scanning. Oversized requests retain the
  existing bounded-body behavior. Unsupported binary or multimodal parts are
  blocked in strict and clearly reported in balanced/audit.

This audit-profile credential exception resolves a documentation tension:
the profile description is observational, while `AGENTS.md` and
`SECURITY.md` require credentials and required secret-detector failures to
fail closed. The repository precedence rules make the security invariant
authoritative.

## 5. Exact commands executed

### Initial baseline

```bash
cd backend
UV_CACHE_DIR=/tmp/agentshield-uv-cache uv sync --frozen
UV_CACHE_DIR=/tmp/agentshield-uv-cache uv run ruff format --check .
UV_CACHE_DIR=/tmp/agentshield-uv-cache uv run ruff check .
UV_CACHE_DIR=/tmp/agentshield-uv-cache uv run pyright
UV_CACHE_DIR=/tmp/agentshield-uv-cache uv run pytest

cd frontend
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test
pnpm build
UV_CACHE_DIR=/tmp/agentshield-uv-cache pnpm exec playwright test
```

### Dependency and final backend verification

```bash
cd backend
UV_CACHE_DIR=/tmp/agentshield-uv-cache uv lock
UV_CACHE_DIR=/tmp/agentshield-uv-cache uv sync --frozen
UV_CACHE_DIR=/tmp/agentshield-uv-cache uv run ruff format --check .
UV_CACHE_DIR=/tmp/agentshield-uv-cache uv run ruff check .
UV_CACHE_DIR=/tmp/agentshield-uv-cache uv run pyright
UV_CACHE_DIR=/tmp/agentshield-uv-cache uv run pytest

.venv/bin/pytest -q \
  tests/test_custom_term_detector.py \
  tests/test_detector_engine.py \
  tests/test_filtering_models.py \
  tests/test_pii_detectors.py \
  tests/test_policy_engine.py \
  tests/test_policy_yaml.py \
  tests/test_proxy_filtering.py \
  tests/test_redaction.py \
  tests/test_request_normalization.py \
  tests/test_secret_detector.py
```

### Final frontend and static verification

```bash
cd frontend
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm exec playwright test

cd ..
git diff --check
rg -n "from fastapi|import fastapi|sqlalchemy" \
  backend/src/agentshield/filtering backend/src/agentshield/policies
rg -n "verify\\s*=\\s*False" backend/src backend/tests
```

The final `pnpm exec playwright test` command was submitted for approval but
was not executed because automatic approval review rejected the escalation
after the environment usage limit was reached.

## 6. Test counts and results

- Baseline backend regression suite: **90 passed**.
- Final backend regression suite: **150 passed in 1.48 seconds**.
- Dedicated Milestone 3 suite: **55 passed in 0.31 seconds**.
- Final Ruff format check: **76 files already formatted**.
- Final Ruff lint: **passed**.
- Final Pyright strict: **0 errors, 0 warnings, 0 information messages**.
- Final frontend Vitest: **3 passed**.
- Final frontend ESLint, TypeScript check, and production build: **passed**.
- Baseline Playwright before implementation: **1 passed**.
- Final post-implementation Playwright: **not run** because automatic approval
  review rejected the required sandbox escalation.
- Skipped tests: **0 reported** by the executed pytest and Vitest suites.

## 7. Security and privacy verification evidence

- Secret-pattern tests cover every implemented pattern, true and false
  positives, boundaries, Unicode, zero-width characters, URL encoding,
  contextual Base64, entropy, repeated values, and allowlist fingerprints.
- Finding tests prove safe representations, offset validation, immutable
  models, and absence of matched values in validation messages.
- Detector-engine tests prove deterministic order, timeout behavior, safe
  failure codes, and absence of detector exception text.
- Redaction tests cover repeated, adjacent, and overlapping findings and prove
  the original values do not appear in the transformed output.
- Proxy integration tests use injected in-process HTTPX transports. They prove
  blocked OpenAI and Anthropic requests do not reach the provider, redacted
  requests preserve unknown fields, unexpected-header secrets block, and
  synthetic markers are absent from logs, Problem Details responses, and a
  sanitized SQLite dump.
- Auth and logging regression tests prove the fingerprint key is protected and
  sanitized, and arbitrary exception text is not emitted.
- Presidio tests use injected fake analyzers. The global test configuration
  disables local model loading, so tests neither download models nor contact
  a model service.
- All provider contract tests use in-process mock transports and synthetic
  credentials. No real OpenAI or Anthropic endpoint was configured or
  contacted.
- Static searches found no FastAPI or SQLAlchemy import in the filtering or
  policy packages and no disabled TLS verification.
- `git diff --check` reported no whitespace errors. Git emitted only the
  repository's configured LF-to-CRLF conversion warnings.
- No audit row stores raw payloads, findings, or mappings. This milestone does
  not add a finding/audit persistence path.

## 8. Failed or skipped checks

- Initial dependency commands inside the restricted sandbox could not use the
  normal package caches. The exact commands were rerun with approved access and
  completed successfully.
- Initial Playwright attempts inside the sandbox could not start the local
  backend reliably. The approved baseline run passed before implementation.
- The final post-implementation Playwright run is **not run**. Automatic
  approval review rejected the required escalation because the environment
  usage limit had been reached. This report does not count the baseline
  Playwright result as final validation.
- No executed unit or integration test was skipped.

## 9. Known limitations

- PII and secret detection can produce false positives and false negatives and
  cannot guarantee complete identification.
- Presidio language models are deliberately not bundled or downloaded.
  Operators must install the configured English and German spaCy models
  locally. An unavailable analyzer becomes a policy-visible detector failure.
- URL decoding is bounded and preserves offsets for supported ASCII escapes.
  Contextual Base64 inspection is bounded by candidate length and context.
  Obfuscation through arbitrary encodings, homoglyph substitution, or
  cross-field fragmentation may evade deterministic matching.
- Custom regex rules are intentionally restricted in length and syntax. They
  do not support capture groups, backreferences, or arbitrary executable code.
- Unknown provider root fields are preserved but are not recursively scanned
  unless they are documented text-bearing fields.
- The existing 10 MiB request-body limit remains the hard bound. No new
  performance claim is made for requests near that limit.
- Policies can be safely imported/exported, but SQLite-backed policy editing
  and dashboard workflows remain Milestone 5 work.

## 10. Deviations from the specification

There is no intentional deviation from the authoritative Milestone 3 section.

The task prompt also listed `REQUIRE_APPROVAL`, reversible pseudonymization,
session mapping isolation/expiry, and response rehydration as possible expected
scope. The exact implementation order assigns reversible pseudonymization and
rehydration to Milestone 4 and approval to Milestone 5. They were therefore
excluded rather than implemented early. Version-wide tests for those later
features were likewise not added in Milestone 3.

Audit mode still blocks detected credentials and secret-detector failures.
This follows the higher-precedence `AGENTS.md` and security invariants rather
than interpreting “observational” as permission to forward secrets.

## 11. Explicit later-milestone exclusions

This change does not add:

- SSE or other streaming inspection;
- rolling response scanning;
- reversible pseudonymization, mapping storage, expiry, or rehydration;
- `REQUIRE_APPROVAL`, approval queues, Monaco diff, or dashboard workflows;
- audit export workflows or integration installers;
- MCP proxying, a system-wide proxy, TLS interception, or a root CA;
- Tauri, Rust, cloud services, PostgreSQL, RBAC, SSO, or semantic LLM
  classification.

## 12. Final verdict

**PASS WITH CONDITIONS**

The backend Milestone 3 implementation, dedicated tests, full backend
regression suite, frontend unit checks, type checking, linting, and production
build pass. The condition is that the final post-implementation Playwright
suite could not be run after automatic approval review rejected the required
escalation. Presidio also requires operators who enable it to install the
configured local language models; unavailable models follow the documented
profile-specific fail-safe behavior.
