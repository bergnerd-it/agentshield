# ADR 0002: Use React, TypeScript, and Vite for the Frontend

- Status: Accepted
- Date: 2026-09-03

## Context

AgentShield needs a local dashboard for live traffic, findings, diffs, approvals, policies, integration configuration, and audit export. Server-side rendering and public search indexing provide no value for this application.

Candidate approaches included Angular, Vue, Svelte, React with Next.js, a server-rendered Python UI, and Electron or Tauri from the start.

## Decision

Use React 19 with TypeScript strict mode and Vite as a client-side single-page application. Use TanStack Query for server state, TanStack Table for event tables, and Monaco Editor for sanitized payload and diff views.

In production, the Python backend serves the built frontend from the same loopback origin. Do not introduce Next.js, server-side rendering, Electron, or Tauri in Version 1.

## Rationale

- React and TypeScript are current, recognizable technologies for a customer-facing reference project.
- Vite provides a simple development and production build without an unnecessary application server.
- A single-page application matches the local management use case.
- Same-origin production delivery simplifies the security model.
- The frontend can later be embedded unchanged in Tauri.

## Consequences

### Positive

- strong component and tooling ecosystem;
- reusable frontend for browser and later desktop packaging;
- strict typing through a generated OpenAPI client;
- suitable libraries for tables, live state, and source diffs.

### Negative

- requires a separate JavaScript toolchain;
- browser security behavior must be considered even on loopback;
- Monaco increases bundle size;
- client state must be handled carefully to avoid retaining confidential content.

## Constraints

- Never store raw content or secrets in browser storage.
- Default every code or payload view to sanitized content.
- Use the generated API client instead of handwritten DTO copies.
- Treat all frontend authorization as advisory; backend enforcement is mandatory.
- Keep wildcard CORS disabled.

## Revisit When

- desktop distribution and OS integration become a committed milestone;
- offline browser limitations block required functionality;
- accessibility or bundle-size measurements show the selected libraries are unsuitable.
