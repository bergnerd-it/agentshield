# ADR 0009: Accept Admin Token in Query Parameter for SSE Stream

- Status: Accepted
- Date: 2026-09-17

## Context

Milestone 5 introduces real-time Server-Sent Events (SSE) via `GET /api/v1/events/stream`
to push pending approval requests and live audit updates to the dashboard frontend.
Security rules (AGENTS.md §4) state that secrets and credentials must not be passed in URLs.

However, the standard browser `EventSource` API does not permit setting custom HTTP request
headers (such as `Authorization: Bearer <token>`). While custom `fetch`-based SSE polyfills
exist, native `EventSource` provides automatic reconnection and browser lifecycle integration.

The dashboard runs strictly on the local loopback interface (`127.0.0.1:8765`). The admin token
is a local loopback access control token, not an upstream provider API key or secret. The backend
authentication dependency (`require_admin_auth`) already inspects `token` query parameter as a
fallback specifically for `/api/v1/events/stream`.

## Decision

Accept passing the local admin token as a query parameter (`?token=...`) exclusively for the
`GET /api/v1/events/stream` SSE endpoint.

All other control-plane and management API routes (approvals, policies, settings, audit inspection)
must strictly continue requiring standard `Authorization: Bearer <token>` HTTP request headers.

## Consequences

### Positive

- Enables native browser `EventSource` usage without heavy third-party polyfills or custom stream readers;
- Maintains clean real-time notifications for approval holds and audit events;
- Confines query-parameter authentication to a single dedicated streaming route.

### Negative

- The admin token appears in local HTTP access logs (if enabled), browser history, and browser DevTools Network inspect URLs;
- Creates a documented architectural deviation from the strict "no secrets in URLs" guideline.

## Mitigation & Future Considerations

- AgentShield binds only to `127.0.0.1` by default, preventing external network exposure of the URL;
- Local access logging must not retain or expose query string tokens in persistent disk logs;
- For future versions, consider implementing a short-lived, single-use ticket/session exchange endpoint
  (`POST /api/v1/events/session` via `Authorization: Bearer` returning a short-lived ticket for the SSE stream URL).
