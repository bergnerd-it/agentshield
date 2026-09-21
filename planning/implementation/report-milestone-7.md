# Milestone 7 Code Review Report

**Project:** AgentShield V1

**Milestone:** 7 — Hardening and Documentation

**Review completed:** 2026-09-21

**Status:** Review findings fixed; required local quality gates pass

## Review Scope

The review covered the Milestone 7 implementation against:

- `planning/AgentShield_V1_Specification.md` and the Milestone 7 Definition of Done;
- `AGENTS.md`, `SECURITY.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`,
  `docs/PRIVACY.md`, and `docs/TESTING.md`;
- accepted ADRs, with ADR 0011 added to supersede ADR 0009;
- backend, frontend, demonstration, benchmark, corpus, CI, dependency scanning, and SBOM paths.

## Material Findings and Resolutions

### 1. Management credential exposure and unusable browser authentication

**Finding:** The administration token was accepted from a query parameter by the shared
management authentication dependency. The dashboard used `EventSource` with that token in the
SSE URL and tests persisted it in `localStorage`. After simply removing query authentication,
production UI bootstrap would have had no supported way to obtain the token.

**Resolution:**

- management credentials are accepted only from `Authorization` or `X-AgentShield-Token` headers;
- the dashboard uses Fetch streaming for SSE with a bounded 64 KiB frame buffer, strict UTF-8
  decoding, bounded reconnect backoff, and header authentication;
- a dashboard unlock form validates the administration token and retains it only in module memory;
- browser storage and URL credentials are no longer used;
- management endpoints have regression tests proving query tokens are rejected;
- ADR 0011 records the change and supersedes ADR 0009.

### 2. Response-stream secret evasion and SSE parser fail-open cases

**Finding:** Secret fragments split across JSON SSE delta events were separated by framing JSON
before rolling detection. Invalid UTF-8 could be replacement-decoded, terminal CR handling was
incomplete, and serializer control fields could inject line breaks.

**Resolution:** Logical OpenAI and Anthropic text/tool-call deltas are extracted before rolling
secret scanning. Invalid UTF-8 now terminates parsing, parser errors poison the parser state,
terminal CR is handled as a line ending, and event/id/comment fields are sanitized. Regression
tests cover split secrets, malformed UTF-8, terminal CR, size violations, and framing injection.

### 3. Excessive memory amplification at the 10 MiB request boundary

**Finding:** The original secret-detector identity pass created two tuples of Python integers per
input character. The corrected benchmark exposed a roughly 935 MiB traced-memory peak for a clean
10 MiB request.

**Resolution:** Identity and one-to-one homoglyph normalization no longer allocate per-character
offset maps. Transformed mappings use compact unsigned integer arrays. The measured 10 MiB peak is
now 100.15 MiB on the documented test machine, and a regression test caps ordinary 1 MiB detector
amplification.

### 4. Performance report measured the wrong workloads

**Finding:** The prior memory scenario exercised 1 MiB while describing 10 MiB, streaming TTFB was
reported without subtracting a direct-upstream baseline, and the concurrency mock did not simulate
a slow upstream.

**Resolution:** The benchmark now exercises the exact 10 MiB JSON boundary, rejects 11 MiB with
HTTP 413 before forwarding, subtracts direct mock-provider TTFB, records actual per-request
concurrency latency, and adds a 50 ms upstream delay. `docs/PERFORMANCE.md` was regenerated rather
than hand-edited.

### 5. Presidio attempted runtime model downloads

**Finding:** `NlpEngineProvider.create_engine()` attempted to download missing spaCy models. This
contradicted the documented offline and supply-chain boundary.

**Resolution:** Configured model packages are checked locally before Presidio initialization.
Missing models produce a normal detector-unavailable result, which remains an explicit policy
input; no runtime downloader is invoked. A regression test verifies this path.

### 6. Demo and diagnostics were not reliably offline or deterministic

**Finding:** The turnkey script omitted person detection, did not prove raw values were absent from
the upstream capture, used polling for approval timing, and allowed diagnostic reachability checks
to use real networking. The documented root-level invocation was also inconsistent.

**Resolution:** The demo injects a deterministic local Presidio analyzer, local mock transports,
an in-memory credential store, and deterministic approval synchronization. It verifies raw secret,
person, and confidential-term absence from upstream and audit output. Both documented root-level
commands complete all ten steps.

### 7. Corpus and multi-sink coverage gaps

**Finding:** The split-event corpus case did not contain real fragments, homoglyph evasion was not
implemented, and multi-sink assertions were incomplete for redacted PII.

**Resolution:** The corpus now includes real split fragments and Cyrillic lookalikes. The secret
detector normalizes the supported confusables with correct source offsets. Tests cover upstream,
logs, SQLite, JSON/HTML exports, and response bodies/headers for secrets, plus raw-value absence
across the applicable sinks for redacted PII.

### 8. Integration, diagnostics, and UI reliability issues

**Resolution:**

- integration DB commit failures roll back the SQLAlchemy session and log only the exception class;
- backup names include microseconds to avoid collisions;
- diagnostic port checks are injectable, exception output is sanitized, and unavailable secure
  keyrings no longer claim that an insecure fallback is active;
- audit rows are keyboard-operable and modal focus is initially placed, trapped, restored, and
  dismissible with Escape;
- flaky E2E sleeps and demo polling were replaced with observable readiness or synchronization.

### 9. Supply-chain gate and reporting gaps

**Finding:** The scripts failed under a restricted user cache, SBOM generation emitted an unknown
editable project component and noisy ignored npm diagnostics, and the scanner described moderate
findings as entirely clean. Vitest 3.2.7 and `@vitest/mocker` had a moderate path-traversal advisory.

**Resolution:** Scripts use a repository-local uv cache, validate reproducible production frontend
SBOM output, omit the editable root from the requirements SBOM, and state the actual high/critical
release gate. Vitest was updated to 4.1.11 and the lockfile refreshed. The final Python and npm
scans report no known vulnerabilities.

## Verification Evidence

### Backend

```text
ruff format --check: 116 files formatted
ruff check:            passed
pyright strict:        0 errors, 0 warnings
pytest (sandbox):      333 passed, 2 socket tests skipped
socket test rerun:     6 passed outside the socket sandbox
```

The two skipped cases in the sandbox are included among the six live-socket tests that passed when
loopback binding was permitted. Across those runs, all 335 distinct backend tests passed.

### Frontend

```text
ESLint:                passed
TypeScript:            passed
Vitest 4.1.11:         5 files, 18 tests passed
production build:      passed
Playwright Chromium:   10 tests passed
```

### Demo, Performance, and Supply Chain

```text
10-step offline demo:  passed
benchmark generation:  passed
SBOM generation:       backend and frontend CycloneDX 1.6 JSON generated
dependency scan:       no known Python or npm vulnerabilities
```

Latest local benchmark highlights (Darwin arm64, Python 3.14.7):

- median added request overhead: 3.58 ms (target below 30 ms);
- median added streaming TTFB: 3.83 ms;
- exact 10 MiB request accepted and 11 MiB request rejected with HTTP 413;
- 10 MiB traced-memory peak: 100.15 MiB;
- 15 requests with a simulated 50 ms upstream delay: 186.8 requests/second.

## Residual Limitations

- Results are local measurements, not universal production guarantees.
- Streaming content already delivered before a later secret fragment cannot be retracted; the full
  detected credential is withheld and the stream is terminated, as documented in the architecture.
- Dashboard page reloads intentionally require re-entering the administration token because V1
  does not persist it in browser storage.
- `pip-audit` cannot resolve the local `agentshield` project or the separately distributed
  `en-core-web-lg` model on PyPI; all resolvable Python dependencies were audited.
- AgentShield remains a cooperative loopback proxy and does not control traffic that bypasses it.

## Conclusion

No open Critical, Major, Medium, or Minor findings from this review remain. Milestone 7 is ready for
owner review and merge, subject to the documented Version 1 limitations above.
