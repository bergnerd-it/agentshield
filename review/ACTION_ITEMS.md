# AgentShield Planning Review – Action Items

Companion to `PLANNING_REVIEW.md` (section references in parentheses).
Grouped by the document that has to change. Checkboxes for tracking.

## New ADRs to write (decisions that change interfaces — do before Milestone 3/4)

- [ ] **ADR 0006 – Conversation identity and pseudonym mapping scope** (2.1)
  - Define how a "session"/conversation is identified from stateless agent requests.
  - Require: same original value → same placeholder across all turns of one conversation, including values re-entering via resent history.
  - Define TTL semantics compatible with multi-hour coding sessions.
- [ ] **ADR 0007 – Upstream authentication modes** (2.3)
  - Decide: API-key-substitution only vs. additional OAuth/subscription passthrough mode for Codex ("Sign in with ChatGPT") and Claude Code (subscription).
  - If passthrough: define how the client's provider credential and the local proxy token coexist, and add a threat-model entry.
- [ ] **ADR 0008 – Secrets-detector engine choice** (5.3)
  - Hand-rolled regex set vs. wrapping detect-secrets / gitleaks rules behind the `Detector` interface.

## AgentShield_V1_Specification.md

- [ ] §9: add `POST /proxy/anthropic/v1/messages/count_tokens`, `GET .../models` for both providers; define behavior for unknown `/proxy/...` paths (recommend: block + audit by default) (2.4).
- [ ] §9: state that `count_tokens` carries full prompt content and must be scanned under the same policy (2.4, 3.4).
- [ ] §9/§12: add a section on OpenAI Responses statefulness — `store` rewrite policy (default `false` in balanced/strict), `previous_response_id` handling for scanning and rehydration (2.2).
- [ ] §12.1: switch identifier-class placeholders to identifier-shaped format (`AsInternalClass0001`, case-style preserved); keep angle-bracket format for prose entities; document derived-token limitation (2.5).
- [ ] §12.1: align placeholder examples with the ADR 0005 / T-08 session-namespace requirement (3.9).
- [ ] §12.3/§13.1: change balanced default for NLP-based PII from `REDACT` to `WARN`; keep `REDACT` for high-confidence structured PII; define per-category confidence thresholds per profile (2.6).
- [ ] §11.5: rule that tool *names* are never redacted (warn-only in V1); note symmetric-mapping option as future work (3.4).
- [ ] §14: approval — dedupe pending approvals by fingerprint; keepalive strategy for streaming requests held for approval; raise default timeout (e.g., 5 min); optional local OS notification (2.8).
- [ ] §16.1/§9: proxy endpoints return provider-native error JSON with actionable block reason; RFC 7807 only on management API; define in-stream termination wire format (3.1).
- [ ] §18.4: add scanning latency budget for the NLP path at a realistic payload size; require incremental scanning / scan-result caching for stable conversation prefixes (2.7).
- [ ] §8: per-integration/per-project proxy tokens as the attribution mechanism for rules, audit, and mapping scope (2.9).
- [ ] §5.1: verify Presidio/spaCy/keyring wheel availability for Python 3.14 on all platforms; otherwise pin 3.13 (3.5). Specify the exact spaCy models for de/en, their pinning and offline install (2.7).
- [ ] §7: define config bootstrap (file format + per-OS data directory) (3.6); name the single-instance mechanism (3.7); add `agentshield stop` / `agentshield status` (6.3).
- [ ] §3.1: make Chat Completions a firm requirement instead of "reasonable effort" (5.2).
- [ ] §20: add DoD item — real multi-turn session with an actual coding agent (Codex or Claude Code) through the proxy in `balanced` profile without degradation (5.4).
- [ ] §6: add `docs/PRIVACY.md`, `docs/TESTING.md`, `docs/DEMO.md` to the repo tree (6.1).

## docs/ARCHITECTURE.md

- [ ] §4.5/§4.8: incremental scanning cache and conversation-scoped pseudonym vault (2.1, 2.7).
- [ ] §6: concrete streaming rewrite design — holdback window sizing, delta re-chunking, per-provider event-structure consistency (Anthropic `content_block_delta` indexes, OpenAI sequence numbers), unmodified `usage` fields (3.2).
- [ ] §12: `/health` vs `/ready` distinction; detector warmup behavior (3.10).
- [ ] Note on prompt-cache preservation: sanitized prefixes must be byte-stable across turns (3.3).

## docs/THREAT_MODEL.md

- [ ] New threat: forwarded-but-unscanned auxiliary endpoint as scanning bypass (`count_tokens` class) (4.1).
- [ ] New/extended threat: provider server-side retention via Responses `store: true` — an AgentShield-influenceable control (4.2).
- [ ] New threat/policy dimension: provider-side built-in tools (web search, code interpreter, hosted MCP) performing egress with prompt data; rules should support allowed tool types (4.3).
- [ ] T-17: add swap/paging residual risk (no mlock in Python) (4.4).
- [ ] T-02: name DNS rebinding explicitly so tests cover it (4.5).

## docs/TESTING.md

- [ ] Add test: pseudonym consistency across multi-turn conversation with resent history and rehydrated responses (2.1).
- [ ] Add test: sanitized prefix byte-stability across turns (prompt-cache preservation) (3.3).
- [ ] Add test: pending-approval dedupe on client retry with identical fingerprint (2.8).
- [ ] Add test: unknown `/proxy` path behavior and `count_tokens` policy coverage (2.4).
- [ ] Add contract fixtures for Claude Code startup traffic (`/v1/messages?beta=true`, `anthropic-beta` headers) (2.4).

## Milestones / process

- [ ] Milestone 2: add a manual integration guide (Codex `config.toml` snippet, `ANTHROPIC_BASE_URL` for Claude Code) so the proxy is personally usable before M6 (5.1).
- [ ] Milestone 4/5: consider CLI approval fallback (`agentshield approve <id>`) before the full dashboard approval UI (5.1).

## Housekeeping

- [ ] Decide license before showing the repo to clients (6.4).
- [ ] Fill the SECURITY.md reporting channel before first external viewer (6.5).
- [ ] Mark or remove the superseded German spec in `backup/` (6.6).
- [ ] Remove/replace stale `agentproxy.iml` (6.7).
