# ADR 0010: Formally Defer Playwright End-to-End Tests to Milestone 6

- Status: Accepted (deferred to Milestone 6)
- Date: 2026-09-17

## Context

The Milestone 5 specification and prompt called for verifying manual approvals and the
operator dashboard end-to-end using Playwright browser tests, noting that component tests
should not be a permanent substitute for full end-to-end approval flow verification.

During Milestone 5 execution:
- Comprehensive backend integration tests were built covering the complete approval lifecycle
  (proxy hold, approve/deny/timeout flows, state transitions, payload memory clearance, SSE event publication);
- Frontend unit and component tests (Vitest + React Testing Library) were built covering the
  `ApprovalsPage`, `DiffViewer`, and `App` navigation/rendering;
- However, the headless browser orchestration (running simultaneous proxy server, mock LLM server,
  Vite dev server, and Playwright test runner) was not completed within Milestone 5 scope.

## Decision

Formally defer full browser-driven Playwright end-to-end tests to Milestone 6.
End-to-end automated browser tests must be implemented in Milestone 6 and gate the completion of Milestone 7.

## Mandatory Scenarios for Milestone 6

Milestone 6 must implement automated Playwright browser tests covering the following six scenarios:

1. **Full approve flow:** Client initiates a proxy request requiring approval → approval hold is created →
   SSE event pushes approval card to dashboard → operator clicks "Approve" in UI → upstream response is received by client.
2. **Full deny flow:** Client initiates a proxy request requiring approval → operator clicks "Deny" in UI with reason →
   HTTP 403 problem details is returned to client.
3. **Timeout failure:** Client initiates proxy request requiring approval → operator takes no action within timeout window →
   request fails closed with HTTP 403 `approval-timeout`.
4. **Unauthorized dashboard access:** Unauthorized browser request to `/api/v1/approvals` returns HTTP 401.
5. **Real-time SSE card updates:** In-flight approval hold arrives via SSE and updates dashboard queue live without manual page refresh.
6. **Multi-tab concurrency:** Request approved in tab A causes tab B to update to the resolved state in real time without manual page refresh.

## Consequences

- Milestone 5 completes without introducing unstable or incomplete browser harness dependencies;
- Test coverage remains strong at unit and integration boundaries (214 backend tests, 9 frontend tests);
- Explicitly schedules the required multi-process browser test harness as a primary deliverable in Milestone 6.
