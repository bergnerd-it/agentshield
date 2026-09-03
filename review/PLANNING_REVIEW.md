# AgentShield Planning Documents – Technical Review

Review date: 2026-09-03
Scope: all documents in `planning/` (specification, AGENTS.md, README, SECURITY.md, docs/, ADRs)
Focus, as requested: functionality first, technical correctness second, wording ignored.

Severity legend:

- **[CRITICAL]** – will break core functionality or invalidate a core promise if not addressed before/during implementation.
- **[HIGH]** – significant functional or technical gap; will surface during implementation and force unplanned design decisions.
- **[MEDIUM]** – should be fixed in the docs; cheap now, expensive later.
- **[LOW]** – polish, consistency, nice-to-have.

---

## 1. Overall Assessment

The documentation set is unusually good for a pre-implementation project. In particular:

- The **honest boundary** ("cooperative proxy, no claim about bypass traffic") is consistently maintained across all documents. This is the single most important property for a security reference project and it is done right.
- Detector/policy separation, fail-closed semantics, the threat model (T-01…T-20), the leak-test discipline, and the privacy model are coherent and mutually consistent.
- Milestones, Definition of Done, and the demo script give an implementable path.

The main weaknesses are **not** in the security model. They are in the **operational reality of proxying real coding agents**: conversation statefulness, authentication modes agents actually use, endpoint coverage, latency of NLP scanning on large code contexts, and the practicality of redaction/pseudonymization on source code. These are exactly the areas where the product will succeed or fail in daily personal use, and they are currently under-specified.

---

## 2. Critical Functional Gaps

### 2.1 [CRITICAL] No definition of "session"/conversation identity → pseudonymization cannot work consistently

The spec (§12), ADR 0005, and PRIVACY.md all scope pseudonym mappings "per session" and "per project", but **no document defines how a session is identified** from the stateless HTTP requests a coding agent sends.

Why this breaks functionality:

- Coding agents resend the whole conversation history on every turn. After AgentShield rehydrates a response for the agent, the agent's *next* request contains the original value again (e.g., `GreenfieldGrantService`). If turn 2 gets a *different* placeholder than turn 1 (new "session"), the provider sees two different placeholders for the same entity within what it perceives as one conversation → degraded/incorrect completions.
- Conversely, if the mapping TTL expires mid-conversation, turn N+1 either re-pseudonymizes inconsistently or rehydration of older placeholders embedded in resent history fails ("preserve unknown placeholders and warn" per spec §12.2) — the provider then sees a mix of placeholders and raw values.

What is needed in the spec:

1. A concrete session-identity mechanism. Realistic options: (a) fingerprint of the conversation prefix (message history hash chain), (b) per-integration/per-project proxy tokens plus time-window heuristics, (c) treat the *project* as the mapping scope with a much longer TTL, accepting the ADR 0005 "global stable pseudonyms permit correlation" trade-off at project granularity.
2. Required behavior: **the same original value within one conversation must map to the same placeholder across turns**, including values re-entering via resent history.
3. TTL semantics relative to conversation length (a coding session is often hours; a 15-minute TTL would break every long session).
4. Interaction with OpenAI Responses API statefulness (see 2.2), where history is *not* resent.

This is the largest functional design gap in the whole plan. Recommendation: resolve it in a dedicated ADR (e.g., "0006 – Conversation identity and mapping scope") **before Milestone 4**.

### 2.2 [CRITICAL] OpenAI Responses API statefulness (`store`, `previous_response_id`) is not addressed

The Responses API is stateful by default (`store: true`), and clients (including Codex) can chain turns via `previous_response_id` instead of resending history. Consequences the spec ignores:

- **Privacy:** with `store: true` the provider retains the conversation server-side. For a privacy product this is the elephant in the room. AgentShield should offer a policy option (arguably the default in `balanced`/`strict`) to **rewrite `store` to `false`** — but note spec §11.5 currently forbids modifying provider control fields without an explicit rule, so this needs an explicit built-in rule.
- **Scanning:** with `previous_response_id`, a request no longer contains the whole history. Per-request scanning still works for the *new* content, but pseudonym consistency (2.1) must handle the case where earlier turns live only server-side.
- **Rehydration:** placeholders from earlier turns can come back in later responses even though the current request never contained them — the mapping lookup must span the conversation, not the request.

Add a dedicated section to the spec (§9 or §12) and cover it in THREAT_MODEL (this is a data-retention path that bypasses the "minimize retention" story — retention happens *at the provider* by default).

### 2.3 [CRITICAL] Agent authentication reality: subscription/OAuth mode does not fit the "substitute API key from keychain" model

The credential model (spec §8: agent gets a local proxy token; backend substitutes real provider API key from the OS keychain) is only valid for **API-key billing**. In practice:

- **Codex** is predominantly used with "Sign in with ChatGPT" (subscription). A custom `model_providers` entry with `requires_openai_auth = true` will route through a proxy **but sends the user's OAuth token**, which contradicts §8 ("local credentials never forwarded upstream" / substitution model) — here the *client's* credential IS the upstream credential and must be passed through.
- **Claude Code** with a Claude subscription behaves similarly (OAuth tokens, not `x-api-key`).

The spec must explicitly pick one of:

1. **V1 supports API-key mode only.** Document loudly that subscription-authenticated agents are out of scope (this materially limits personal usefulness — if you use Codex/Claude Code on a subscription, V1 won't mediate your main traffic).
2. **Add a "credential passthrough" mode** per provider: the client's own Authorization/OAuth token is forwarded verbatim, AgentShield never stores it, and the local-proxy-token layer is still used to authenticate the agent to AgentShield (double auth: proxy token in a custom header, provider token passed through). This requires new rules in §8/§9.1 (currently "never forward local authentication headers" without defining how to distinguish the passthrough credential) and a threat-model entry.

Given the target of *personal use with Codex and Claude Code*, option 2 is likely required. Right now the docs implicitly promise integrations that the credential model cannot serve.

### 2.4 [HIGH] Proxy endpoint surface is too small — agents will break and users will bypass

Spec §9 lists only three POST endpoints. Real agent traffic includes more; if the proxy 404s auxiliary calls, agents degrade or fail, which drives exactly the bypass behavior the threat model (T-01) fears and violates Security Objective #5 ("preserve provider protocol behavior sufficiently that users do not bypass the proxy").

Minimum additional endpoints to specify:

- `POST /proxy/anthropic/v1/messages/count_tokens` — Claude Code calls this (optional but routine). Decide: forward (it contains the same prompt content → must be scanned too, or at least must be covered by the same policy!) or emulate.
- `GET /proxy/openai/v1/models` and `GET /proxy/anthropic/v1/models` — many clients list models at startup.
- Claude Code startup traffic (`/v1/messages?beta=true` probe) and forwarded `anthropic-beta` / `anthropic-version` headers (the header part is covered generically; the probe path is not).

Also missing: **a defined behavior for unknown paths under `/proxy/...`** — pass through, block, or block-with-audit-event? For a security product this must be an explicit policy (recommend: block by default in `strict`, configurable passthrough for GET-only metadata endpoints elsewhere; always audited). Note the subtle trap: `count_tokens` carries full prompt content — if it is passed through unscanned, it is a **complete scanning bypass channel**. This deserves its own threat-model entry.

### 2.5 [HIGH] Placeholder format is wrong for source-code identifiers

Spec §12.1 mandates `<AS:INTERNAL_CLASS:0001>`-style placeholders. For prose this is fine. For **code identifiers** it is functionally harmful:

- Replacing `GreenfieldGrantService` with `<AS:INTERNAL_CLASS:0001>` inside Java/Python source produces syntactically invalid code. The LLM's ability to reason about, refactor, or extend that code collapses; it may also "helpfully" rename or reformat the placeholder, defeating exact-match rehydration (ADR 0005 already admits "an LLM may alter a placeholder" but offers no mitigation).
- The model will generate derived identifiers (`<AS:INTERNAL_CLASS:0001>Impl`, getters, imports) that cannot be rehydrated by exact matching.

Recommendation: use **identifier-shaped placeholders** for identifier-class data (e.g., `AsInternalClass0001`, matching the case-style of the original: `asInternalClass0001` for camelCase variables, `AS_INTERNAL_CLASS_0001` for constants), keeping the angle-bracket format for prose entities (person names, orgs). Also specify a **derived-token strategy**: at minimum document that derivatives are not rehydrated; better, rehydrate longest-match placeholder prefixes/suffixes conservatively. This belongs in spec §12 and ADR 0005.

### 2.6 [HIGH] Balanced-profile default "pseudonymize PII" will mangle source code and destroy trust

Coding-agent payloads are dominated by source code, diffs, logs, and file listings. Running Presidio-style NER over code yields heavy false positives (identifiers that look like names, emails in commit history/license headers, IPs in test fixtures and docs, UUIDs, high-entropy strings in lockfiles). With `balanced` defaulting to `REDACT` for PII (spec §12.3, §13.1):

- Ordinary requests get silently rewritten; generated patches may come back with placeholders sprinkled into unrelated code.
- Users will experience it as "the proxy corrupts my prompts" and disable it (T-07's own predicted outcome).

Recommendations:

1. Make `balanced` default to **`WARN` for NLP-based PII findings** and `REDACT` only for high-confidence structured PII (email, IBAN, phone with strict patterns). Reserve blanket PII redaction for `strict`.
2. Specify per-category **confidence thresholds** as part of the profile definitions (the Finding model has `confidence`, but no document says how profiles use it — this is a real spec hole: what threshold triggers action?).
3. Add a first-run "observe mode" recommendation: run `audit` profile for N days, review findings, then tighten. This is also a good customer-demo narrative.

### 2.7 [HIGH] Latency: the 30 ms target and Presidio cannot coexist on realistic payloads, and the spec doesn't resolve the tension

Spec §18.4 targets <30 ms median overhead "without a heavy NLP detector", but the default `balanced` profile requires PII detection (Presidio) on every request. Coding agents routinely send 50–500 KB of context per request (Claude Code often more). Presidio/spaCy on that volume costs *seconds*, not milliseconds, per request — on every turn, because the whole history is resent.

The docs acknowledge "offload blocking NLP from the event loop" (ADR 0001) but never address **throughput/latency of scanning itself**. Needed in the spec:

1. An explicit latency budget for the NLP path (e.g., "balanced profile p50 ≤ X ms at 200 KB payload") — currently untestable.
2. **Incremental scanning:** conversation prefixes are stable across turns; cache scan results keyed by (normalization version, content fingerprint) per message/block so only new content is NLP-scanned. This single design decision determines whether the tool is usable daily. It should be in ARCHITECTURE.md §4.5 and the spec.
3. Presidio operational details: which spaCy models (de + en), model download/pinning strategy (offline install, supply-chain), memory footprint. TESTING.md tests Presidio latency but nothing specifies which models exist. This also matters for the "German and English" requirement — Presidio's German support needs an explicit model choice and quality validation.

### 2.8 [HIGH] Approval flow vs. real agent HTTP clients — holding a request 60 s will cause client timeouts and duplicate submissions

Spec §14 holds the request while awaiting approval (default 60 s). Unaddressed realities:

- Agent SDKs have their own connect/read timeouts and retry logic; a held non-streaming request may be retried by the client (Anthropic SDK retries on timeout), creating **multiple pending approvals for the same logical request** — the fingerprint binding helps dedupe, but the spec should require it explicitly ("identical fingerprint while pending → attach to existing approval, don't create a second one").
- For **streaming requests**, holding without sending anything means no SSE bytes flow; some clients time out on time-to-first-byte. Specify a keepalive strategy (e.g., SSE comment lines/`ping` events are format-compatible for Anthropic; for OpenAI decide explicitly) or document that approvals force non-streaming behavior for that request.
- What error does the agent get on deny/timeout? See 3.1 — it must be a provider-shaped error, ideally with text the agent will surface to the user ("blocked by AgentShield policy X, open dashboard at 127.0.0.1:8765"). This is a big usability lever and costs nothing.

Also: 60 s is far too short for a human who is not staring at the dashboard. For personal use recommend a larger default (5 min) plus an optional local OS notification (macOS `osascript`/`terminal-notifier`) — small, no cloud, huge usability gain. Currently notifications are only "dashboard SSE/WebSocket", which assumes the dashboard is open.

### 2.9 [MEDIUM] Attribution of requests to agent/project is assumed but never designed

Policy rules (§13.2) and audit records (§15.1) reference "agent" and "project", but no mechanism defines how a request is attributed. Recommendation: issue **distinct proxy tokens per integration/project** (the `configure codex` flow naturally installs a dedicated token). This gives attribution for rules, audit, and pseudonym scoping (helps 2.1) with zero protocol changes. Should be specified in §8.

---

## 3. Technical Issues and Under-specified Behaviors

### 3.1 [HIGH] Error responses on proxy endpoints must be provider-shaped, not RFC 7807

Spec §16.1 mandates one Problem Details format; ARCHITECTURE.md's lifecycle returns a "safe structured error" on block. If proxy endpoints return RFC 7807 to an OpenAI/Anthropic SDK, the SDK raises a generic parse/HTTP error and the agent shows a useless message, possibly retries. Specify: **proxy endpoints emit provider-native error JSON** (OpenAI `{"error": {...}}` / Anthropic `{"type": "error", "error": {...}}`) with a clear human-readable block reason; Problem Details is for the management API only. For streaming, specify the in-stream termination shape (provider-conform `error` event vs. connection abort) — currently "terminate the stream" (spec §9.2) leaves the wire format undefined, and agents differ in how they surface each.

### 3.2 [HIGH] Response-side redaction/rehydration in SSE streams needs a concrete design, not just "rolling buffer"

Rehydrating `<AS:PERSON:0001>` in a stream where the placeholder is split across 3 `text_delta` events requires holding back and **rewriting deltas** — changing chunk boundaries, event counts, and possibly indexes. The docs require both "preserve valid SSE framing and event order" and rolling-scan enforcement, but never state that **delta content will be re-chunked**, nor how provider-specific event structure (Anthropic `content_block_delta` indexes, OpenAI Responses `output_text.delta` sequence numbers) is kept consistent after rewriting. This is one of the trickiest implementation areas; a short design section (holdback = max placeholder length, re-emission strategy, per-provider notes) belongs in ARCHITECTURE.md §6 before Milestone 4. Also specify interaction with `usage`/token-count fields that no longer match modified content (harmless but should be documented as intentionally unmodified).

### 3.3 [MEDIUM] Redaction invalidates provider prompt caching — cost/latency consequence undocumented

Anthropic `cache_control` and OpenAI automatic prompt caching depend on byte-stable prefixes. Consistent pseudonymization (same placeholder each turn) *preserves* caching; inconsistent mapping (2.1) or confidence-flapping detectors *destroy* it, multiplying cost and latency. Worth an explicit note in the spec/ARCHITECTURE and a test idea: "stable payloads produce byte-identical sanitized prefixes across turns."

### 3.4 [MEDIUM] `count_tokens`-class side channels and tool definitions

Two content paths that carry prompt data but are easy to forget:

- `count_tokens` (see 2.4) — full message content, must be policy-covered.
- **Tool definitions** (`tools` array with names/descriptions/JSON schemas) often contain internal API and domain vocabulary. Spec §11.5 says "recursively inspect all relevant text fields", which technically covers this, but redacting tool *names* breaks tool-call round-trips (the response references the tool by name and the client dispatches on it). Specify: tool names are scan-visible but **never redacted** (or redacted only with reversible mapping applied symmetrically to response tool-call names — complex; recommend "warn-only" for V1).

### 3.5 [MEDIUM] Python 3.14 pin is risky for the NLP stack

Presidio → spaCy → thinc/numpy binary wheels historically lag new CPython releases. Before committing, verify current wheel availability for 3.14 on macOS/Linux/Windows; otherwise specify "3.13, upgrade when the NLP stack supports 3.14". A one-line change in the spec/ADR 0001 now avoids a Milestone-3 surprise. (Same class of check: `keyring` backends on all three platforms.)

### 3.6 [MEDIUM] Configuration bootstrap is undefined

SQLite is the source of truth for policies/settings, but bootstrap values (port, data directory, database location itself, dev mode) cannot live in the database. No document defines the config file format/location or the per-OS data directory (macOS `~/Library/Application Support/AgentShield`, Linux XDG, Windows `%APPDATA%`). Small spec section needed; also feeds `agentshield doctor` and the demo "clean temporary data directory".

### 3.7 [MEDIUM] Single-instance behavior is required but no mechanism is named

Spec §7.2 "repeated `start` calls must not create competing instances" — specify the mechanism (port bind as the natural lock + health-check handshake to distinguish "ours" from "foreign process on 8765"). Otherwise implementers improvise pidfiles that break after crashes.

### 3.8 [LOW] Management API list is missing endpoints implied elsewhere

§16.1 lacks: the SSE/WebSocket notification channel required by §14 (approvals push), detector configuration mutation (only `GET /detectors`), policy delete/disable, custom-terms YAML import/export endpoints (§11.4), and integration endpoints backing the whole Integrations UI page (§16.2). Either add them or mark the list explicitly non-exhaustive with a pointer to the OpenAPI spec as canonical.

### 3.9 [LOW] Spec §12.1 placeholder examples contradict ADR 0005 / T-08

ADR 0005 and THREAT_MODEL T-08 require a session namespace/nonce in placeholders; §12.1's examples (`<AS:PERSON:0001>`) have none. Align the examples (e.g., `<AS:PERSON:k7f3:0001>`) — implementers copy examples, not constraints. (And revisit the format entirely per 2.5.)

### 3.10 [LOW] "Block if a required detector is unavailable" needs a startup story

Strict profile blocks when a required detector is down — correct. But Presidio cold-start (model load) can take many seconds; define whether requests during warmup are queued, blocked, or the service delays readiness (recommend: readiness gate — `/health` vs `/ready` distinction, which also belongs in §16.1).

---

## 4. Threat Model — Additions Worth Making

The threat model is strong. Missing or worth strengthening:

1. **[MEDIUM] Unproxied auxiliary endpoints as scanning bypass** (the `count_tokens` problem, 2.4). Distinct from T-01 (which is about the agent not using the proxy at all): here the agent *uses* the proxy and content still escapes scanning through a forwarded-but-unscanned route. Deserves its own entry or an explicit extension of T-01.
2. **[MEDIUM] Provider server-side retention** (Responses `store: true`, provider logging/training) — currently only PRIVACY.md §9 mentions provider retention as "external". Given `store: true` is the *default* the proxy would forward, it's an AgentShield-influenceable control, not purely external (see 2.2).
3. **[MEDIUM] Provider-side built-in tools** (Responses API `web_search`, code interpreter, MCP connectors): when enabled in a request, the *provider* performs egress/processing with the prompt data beyond simple completion. A policy dimension "allowed tool types" (rules already cover model/provider/endpoint — add tool type) would be cheap and genuinely useful; T-16 is adjacent but only covers inbound instructions.
4. **[LOW] Memory exposure of the pseudonym vault** — T-17 mentions memory inspection; add swap/paging as residual (Python cannot mlock; state it).
5. **[LOW] DNS rebinding** is implicitly covered by Host validation (T-02); name it explicitly so the test suite includes a rebinding case.

---

## 5. Scope and Milestones — What I Would Do Differently

### 5.1 [HIGH] Define a "personal MVP" cut inside the milestones

For the stated dual goal (daily personal use + client reference), the current 7 milestones front-load infrastructure and defer the two things personal use needs most: agent integration (M6) and approvals (M5). Until M6 you cannot comfortably point Codex/Claude Code at the proxy; until M5 nothing interactive works. Suggested adjustments:

- Move a **minimal manual integration guide** (env vars/config snippets for Codex + Claude Code, no adapters/rollback machinery) into Milestone 2. It's documentation, not code, and makes the proxy usable from week one — generating real-world feedback for detectors long before M6.
- Consider a **CLI/log-based approval fallback** (approve via `agentshield approve <id>` or the dashboard) earlier than full M5 UI polish.
- HTML audit export, Monaco diff, and TanStack Table polish are demo assets, not personal-use assets; they can safely stay late or slip.

### 5.2 [MEDIUM] Chat Completions "where reasonable effort" is the wrong hedge

§3.1 includes Chat Completions "where this can be added with reasonable effort". In practice Chat Completions is the *simplest* of the three protocols and the most common denominator for third-party tools (and for pointing other agents at the proxy). Make it a firm requirement — the hedge should apply to *Responses API statefulness edge cases* instead, which are genuinely hard (2.2).

### 5.3 [MEDIUM] Detector engine: plan for an established secrets scanner instead of hand-rolled regexes only

§11.2 hand-specifies secret patterns. Consider wrapping an existing engine (e.g., detect-secrets or gitleaks rule sets) behind the `Detector` interface: battle-tested patterns, maintained upstream, and a better story to show clients ("we integrate standard scanners") than bespoke regexes. Keep the bespoke layer for provider-key patterns and custom terms. This is an ADR-worthy decision either way.

### 5.4 [LOW] Sequencing risk in Definition of Done #14 vs. reality

DoD is fine, but add one item: **"a real coding agent (Codex or Claude Code) has completed a real multi-turn session through the proxy with `balanced` profile without functional degradation."** All current DoD items are mock-based; nothing forces the plan to confront real-agent behavior (auth modes, extra endpoints, timeouts, caching) before declaring V1 done. This single acceptance criterion would have surfaced most issues in section 2.

---

## 6. Smaller Gaps and Inconsistencies

1. **[LOW]** Spec §6 repo tree omits `docs/PRIVACY.md`, `docs/TESTING.md`, `docs/DEMO.md`, which exist and are referenced by README/AGENTS.md. Add them to the tree.
2. **[LOW]** README "Intended Local Development Commands" uses `uv run agentshield start` from `backend/`, spec §7.2 presents global `agentshield start` — clarify that the CLI is the packaged entry point and the `backend/` variant is dev-mode.
3. **[LOW]** `agentshield stop` / `agentshield status` CLI commands are missing from §7.2 (doctor exists, but no way to stop a background service or query it from the shell).
4. **[LOW]** License is explicitly deferred (README §License) — fine, but for "show to potential clients" set a decision deadline; an unlicensed public repo blocks any client evaluation legally.
5. **[LOW]** SECURITY.md placeholder reporting channel — same: fill before the first client sees the repo.
6. **[LOW]** The old German spec in `backup/` is superseded; consider deleting or clearly marking it to avoid an agent (per AGENTS.md reading rules) or a client picking up stale requirements.
7. **[LOW]** `agentproxy.iml` at repo root points at a `.venv` in a different project (`agentproxy`); stale IDE config, cosmetic.
8. **[LOW]** THREAT_MODEL review triggers and ADR README are good; add a `docs/adr/0006+` placeholder list for the decisions this review shows are still open (session identity, credential passthrough, secrets-scanner choice, placeholder format).

---

## 7. What Is Good and Should Not Change

Explicitly, to prevent well-meaning "improvements" later:

- Cooperative reverse proxy instead of TLS interception (ADR 0003) — right call for V1; do not let bypass-prevention pressure reintroduce MITM.
- Fail-closed table in ARCHITECTURE §9 — keep it verbatim as acceptance criteria.
- Never-rehydrate-secrets invariant and the leak-test corpus discipline (TESTING §3–4) — this is the differentiating engineering quality of the project.
- SQLite + Alembic + no cloud dependencies — correct for scope.
- Honest non-claims (no GDPR claim, no full-egress claim) — keep them in every client-facing artifact.

---

## 8. Priority Summary

Resolve **before Milestone 3/4 design work** (they change interfaces):

1. Session/conversation identity + cross-turn pseudonym consistency (2.1) — new ADR.
2. Responses API statefulness / `store` policy (2.2).
3. Credential passthrough vs API-key-only decision (2.3) — new ADR.
4. Endpoint surface incl. `count_tokens` and unknown-path policy (2.4).
5. Identifier-safe placeholder format (2.5) — amend ADR 0005.

Resolve **in the spec text now** (cheap edits, avoid implementation drift):

6. Provider-shaped proxy errors (3.1); streaming rewrite design note (3.2).
7. Balanced-profile PII default → WARN + confidence thresholds (2.6).
8. Scanning latency budget + incremental scan cache (2.7).
9. Approval/timeout/keepalive/dedupe semantics + longer default + OS notification (2.8).
10. Per-integration proxy tokens for attribution (2.9); config bootstrap (3.6); Python version verification (3.5).

Everything in sections 4–6 can follow opportunistically.
