Implement Milestone 5 of AgentShield according to the authoritative repository specification.

You are continuing work performed by other agents. Do not assume access to their conversations, and do not treat completion reports as proof of correctness.

1. Read the project instructions

Locate and read:
- AGENTS.md and applicable directory-specific instructions
- AgentShield_V1_Specification.md
- README.md
- architecture, threat model, privacy, security, and testing documentation
- accepted ADRs
- report-milestone-4.md
- review-milestone-4.md and subsequent remediation/review reports
- relevant repository-native issue and task records

Resolve actual paths from the repository.

Identify the exact Milestone 5 requirements and acceptance criteria. The expected scope is the local React dashboard and approval workflows, but the repository specification takes precedence.

Do not silently expand scope or change requirements.

2. Verify the Milestone 4 baseline

Inspect the current commit, branch, working tree, and configured development environment. Preserve existing changes.

Run the repository’s required backend and frontend quality gates. Distinguish application failures from environment limitations.

Specifically verify the disposition of these previous review findings:
- dropped holdback text in streaming rehydration,
- provider-correct flushing before completion events,
- missing Responses API rehydration integration tests,
- missing tool-argument JSON rehydration tests,
- missing backpressure tests,
- missing latency instrumentation,
- missing safe warnings for unresolved placeholders,
- missing streaming threat-model documentation,
- insufficient evidence concerning credentials split across chunks.

Check that tool-argument tests cover quotes, backslashes, newlines, Unicode, and fragmented placeholders. Verify that leak-prevention claims match bytes actually delivered to the client.

Do not require optional style changes as acceptance gates.

If functional/security blockers remain, or required gates lack passing evidence or an explicitly approved deferral, report them and stop. Do not silently repair Milestone 4 as part of Milestone 5.

3. Plan first

Produce a concise implementation plan containing:
- the exact Milestone 5 requirements,
- affected frontend and backend modules,
- API contracts and approval state transitions,
- handling of sensitive data in the UI,
- live-update and reconnect behavior,
- requirement-to-test mapping,
- explicit exclusions and unresolved decisions.

Stop after presenting the plan. Wait for my approval before implementation.

4. Implement the approved scope

Use the existing architecture, dependencies, design conventions, and generated API-client workflow. Avoid unrelated refactoring and dependency upgrades.

Implement the following only to the extent required by Milestone 5.

Dashboard:
- Real backend-connected views for requests, findings, decisions, and approvals.
- Relevant filtering, sorting, pagination, and request details.
- Clear loading, empty, disconnected, expired, and error states.
- Accurate distinction between pending, allowed, redacted, blocked, cancelled,
  failed, and completed requests where supported.
- Live updates using the project’s chosen mechanism.
- Reconnection and authoritative state refresh without duplicate entries
  or silently missed approval decisions.

Sensitive-content preview:
- Provide the specified original-versus-redacted comparison, using Monaco
  if required by the specification.
- Retrieve sensitive content only through authorized backend endpoints.
- Keep raw content out of URLs, browser storage, service-worker caches,
  analytics, console logs, and error reports.
- Bound in-memory retention and clear sensitive previews when they expire,
  the user leaves the view, or access ends.
- Do not expose provider credentials or secret values merely to make a
  preview convenient. Follow the specification’s masking rules.
- Render untrusted content as inert text; never execute or render it as
  trusted HTML.
- Handle large payloads without freezing the interface.

Approval workflow:
- Enforce authorization and all policy decisions in the backend.
- Implement explicit, atomic approval state transitions.
- Bind each approval to the exact request content, destination, project,
  session, and applicable policy context required by the specification.
- Prevent a changed request from reusing an earlier approval.
- Handle simultaneous decisions from multiple tabs without duplicate
  upstream dispatch.
- Enforce expiry and deny-by-default behavior on timeout.
- Release pending resources when the client disconnects or the request
  is cancelled.
- Reject stale or replayed decisions safely.
- Ensure UI button disabling is never the only protection against races.
- Do not allow approval to override non-overridable BLOCK rules or other
  security invariants.
- Do not transmit request content upstream before approval is valid.
- Follow the specified behavior for policy changes while approval is pending.
- Keep audit records dataminimal and free of raw payloads.

Local application security:
- Preserve separate management, proxy, and upstream authentication.
- Preserve Host/Origin validation, applicable CSRF protections, restrictive
  CORS, TLS verification, and loopback defaults.
- Never place upstream provider credentials in frontend code or responses.
- Do not introduce unauthenticated live-update or preview endpoints.
- Preserve non-streaming and streaming behavior from earlier milestones.

Usability:
- Explain why a request needs approval and what each available action does.
- Show timeouts and expired decisions clearly.
- Support keyboard navigation, accessible labels, focus management, and
  readable contrast.
- Never display optimistic “approved” or “sent” status before the backend
  confirms that state.

If an important behavior is unspecified, explain the options and request
a decision rather than inventing a weaker security boundary.

5. Test meaningful behavior

Add appropriate backend, frontend, integration, and Playwright tests.

Cover:
- dashboard rendering with real backend responses,
- request filtering, pagination, and detail views where implemented,
- preview masking and safe rendering of hostile text,
- approval, rejection, expiry, and cancellation,
- simultaneous decisions and repeated submissions,
- stale approvals and changed payloads,
- unauthorized preview, decision, and live-update access,
- no upstream transmission before approval,
- no duplicate dispatch after races or retries,
- reconnect behavior and state reconciliation,
- bounded pending-request and preview retention,
- absence of sensitive data in logs and persisted browser storage,
- regressions in request filtering, authentication separation,
  non-streaming forwarding, streaming, and rehydration.

Use synthetic data and local mock providers only. Do not call real LLM
providers or use production credentials.

Do not substitute screenshots or mocked frontend-only tests for end-to-end
approval verification.

6. Verify and report

Run all required quality gates and regression tests. Record exact commands,
results, and any skipped or blocked checks.

Update the relevant architecture, threat-model, privacy, usage, and testing
documentation. Maintain the existing repository-native task records.

Create report-milestone-5.md containing:
- tested commit and working-tree state,
- requirements implemented and their verification evidence,
- changed files and architecture decisions,
- approval lifecycle and security controls,
- test commands, counts, exit codes, and results,
- reproducible local demo instructions,
- known limitations and explicitly approved deviations,
- verdict: PASS, PASS WITH CONDITIONS, or FAIL.

Do not claim skipped checks passed or infer full security from test counts.
Do not weaken tests or requirements to obtain a passing result.

Do not begin Milestone 6. Do not commit, push, merge, or deploy without
explicit authorization.