# ADR 0003: Use a Cooperative Reverse Proxy Instead of TLS Interception

- Status: Accepted
- Date: 2026-09-03

## Context

AgentShield aims to inspect coding-agent traffic to LLM providers. Possible designs include:

1. a provider-compatible reverse proxy configured as the agent's API base URL;
2. an HTTP forward proxy with TLS interception and a local root CA;
3. OS firewall or sandbox enforcement;
4. agent-specific plugins or SDK instrumentation.

TLS interception and network enforcement substantially increase platform privileges, certificate risk, compatibility complexity, and legal or organizational deployment concerns.

## Decision

Version 1 is a cooperative provider-compatible reverse proxy. Codex, Claude Code, or another supported agent must be configured to use AgentShield's local endpoint. AgentShield creates its own verified TLS connection to the selected upstream provider.

Version 1 does not install a root CA, decrypt arbitrary HTTPS, modify the OS firewall, or claim to block direct egress outside its routes.

## Rationale

- Full request bodies can be inspected without breaking provider TLS.
- Provider-specific protocol semantics are explicit and testable.
- Installation requires no privileged certificate or firewall modification.
- The boundary is understandable and suitable for an initial reference implementation.
- Security claims can be precise and verifiable.

## Consequences

### Positive

- materially lower platform and certificate risk;
- simpler macOS, Linux, and Windows portability;
- full visibility into supported provider payloads and streaming events;
- easier local testing with mock providers.

### Negative

- a coding agent with direct network access can bypass AgentShield;
- each provider protocol needs an adapter;
- hard-coded or unsupported endpoints cannot be intercepted transparently;
- configuration drift can disable mediation.

## Required Mitigations

- configuration adapters with preview, backup, validation, and rollback;
- `agentshield doctor` verifies the configured path;
- persistent UI and documentation warning about direct egress;
- no marketing or compliance claim of system-wide enforcement;
- later enforced-egress work requires a new threat model and ADR.

## Rejected for Version 1

- TLS man-in-the-middle interception;
- custom root-CA installation;
- packet capture as a content-inspection mechanism;
- silent modification of system proxy settings;
- firewall rules applied without an explicit later design.

## Revisit When

A customer requirement explicitly demands bypass-resistant egress control and provides the authority, deployment model, certificate policy, and supported-platform constraints needed to implement it safely.
