# ADR 0001: Use Python and FastAPI for the Version 1 Backend

- Status: Accepted
- Date: 2026-09-03

## Context

AgentShield requires asynchronous HTTP proxying, provider-compatible APIs, schema validation, an OpenAPI contract, PII and text-analysis integrations, local persistence, and a rapid implementation path suitable for a reference project.

Candidate approaches included Java with Spring Boot, TypeScript with Node.js, Go, Rust, and Python.

## Decision

Use Python 3.14 with FastAPI, Pydantic, Uvicorn, and HTTPX for the Version 1 backend. Use `uv` for environment and dependency management. Keep policy, detector, redaction, and audit domain logic independent of FastAPI.

## Rationale

- Python has strong libraries for PII detection, NLP, and security-oriented text processing.
- FastAPI provides async request handling, streaming support, validation, and OpenAPI generation.
- Pydantic provides typed API and configuration boundaries.
- HTTPX supports asynchronous upstream communication and test transports.
- Python enables fast iteration while the product boundary and detector behavior are still evolving.
- Framework-independent domain interfaces preserve the option of moving the latency-sensitive data plane to Rust or Go later.

## Consequences

### Positive

- rapid feature development;
- direct integration with Presidio and Python analysis libraries;
- generated OpenAPI client for the frontend;
- accessible codebase for security experiments and customer demonstrations.

### Negative

- cross-platform standalone packaging is harder than with a single compiled binary;
- CPU-heavy detectors can block the event loop unless isolated;
- Python does not itself provide a hardened network or process-isolation boundary;
- careful dependency and interpreter management is required.

## Constraints

- Use async I/O on the proxy path.
- Offload blocking or CPU-heavy detector work from the event loop.
- Use bounded concurrency and buffers.
- Keep security domain logic free of FastAPI imports.
- Do not use Python's convenience as a reason to implement TLS interception or OS enforcement in Version 1.

## Revisit When

- measured proxy overhead cannot meet requirements;
- a privileged or hardened process boundary is introduced;
- desktop distribution requires a single small binary;
- streaming or connection concurrency becomes a demonstrated bottleneck.

A future Rust data-plane sidecar may supersede part of this decision without replacing the Python control plane.
