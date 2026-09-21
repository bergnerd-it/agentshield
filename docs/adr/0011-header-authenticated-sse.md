# ADR 0011: Use Header-Authenticated Fetch Streaming for Management SSE

- Status: Accepted
- Date: 2026-09-21
- Supersedes: ADR 0009

## Context

ADR 0009 allowed the long-lived management token in the SSE query string to accommodate the
browser `EventSource` API. That exception conflicts with the Version 1 invariant that tokens never
appear in URLs and exposes the token to browser history, development tools, and access logs. The
shared authentication dependency also made the query credential available to management routes
beyond the intended SSE endpoint.

## Decision

The dashboard consumes `/api/v1/events/stream` with the browser Fetch streaming API and sends the
management token only in the `Authorization` header. The backend accepts management credentials
only from `Authorization` or `X-AgentShield-Token` headers. No management endpoint accepts a token
query parameter.

The frontend parses bounded SSE frames incrementally and reconnects with bounded exponential
backoff. An unlock form validates the administration token and retains it only in module memory for
the page lifetime. The dashboard does not read or write management credentials in browser storage.

## Consequences

- Management credentials no longer appear in URLs.
- The dashboard owns reconnect and SSE parsing behavior instead of native `EventSource`.
- Page reloads require the local session/bootstrap mechanism to supply the token again; durable
  browser credential storage remains prohibited.
- Backend tests verify that query credentials are rejected on SSE and all other management routes.
