# AgentShield

> Local inspection and policy enforcement for coding-agent LLM traffic.

AgentShield is a local security proxy intended to show and control which data a coding agent sends to an external LLM provider. It detects credentials, personal data, and project-specific confidential terms and then applies a configurable action: allow, warn, redact, require manual approval, or block.

## Project Status

AgentShield has implemented Milestones 1 through 3. The current backend supports
the non-streaming OpenAI Responses, OpenAI Chat Completions, and Anthropic
Messages proxy routes plus request-side secret, PII, custom-term, unsupported
content, policy, and irreversible-redaction processing.

Streaming, response scanning, reversible pseudonymization and rehydration,
approval workflows, the complete dashboard, audit export, and coding-agent
integration management remain planned for later milestones. The documentation
in this repository defines the complete Version 1 target and does not imply that
those later features are implemented.

## Version 1 Boundary

Version 1 is a **cooperative reverse proxy** for explicitly configured OpenAI- and Anthropic-compatible endpoints.

```text
Coding agent -> AgentShield -> approved LLM provider
```

It does not transparently intercept TLS and does not guarantee control of direct network connections that bypass AgentShield. Full internet-egress enforcement, MCP proxying, sandboxing, and OS firewall integration are future work.

## Planned Version 1 Capabilities

- OpenAI Responses and Anthropic Messages proxy endpoints;
- non-streaming and SSE streaming;
- secret, PII, and custom-term detection;
- deterministic policy evaluation;
- reversible pseudonymization for eligible data classes;
- secrets that are blocked and never rehydrated;
- local manual approval;
- privacy-preserving audit events and exports;
- local React dashboard;
- Codex and Claude Code configuration assistance;
- macOS support with portable implementation for Linux and Windows.

## Technology

- Python 3.14, FastAPI, Pydantic, HTTPX;
- SQLAlchemy, Alembic, and SQLite;
- React 19, TypeScript, Vite, and TanStack Query;
- `uv` and pnpm with committed lockfiles;
- Ruff, Pyright, pytest, Vitest, and Playwright.

## Documentation

- [Version 1 Specification](AgentShield_V1_Specification.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Privacy Model](docs/PRIVACY.md)
- [Security Policy](SECURITY.md)
- [Testing Strategy](docs/TESTING.md)
- [Local Demonstration](docs/DEMO.md)
- [Architecture Decisions](docs/adr/)
- [Instructions for Coding Agents](AGENTS.md)

## Development Sequence

Implementation proceeds by milestone. Do not ask an automated coding agent to implement all milestones in one run.

1. Foundation
2. Non-streaming LLM proxy
3. Detectors and policies
4. Streaming and rehydration
5. Dashboard and approval
6. Audit and integrations
7. Hardening and documentation

The authoritative acceptance criteria are in the Version 1 specification.

## Intended Local Development Commands

These commands become authoritative once Milestone 1 has bootstrapped the repository:

```bash
cd backend
uv sync
uv run agentshield start
```

```bash
cd frontend
pnpm install
pnpm dev
```

Production mode will serve the built frontend from the backend on loopback only:

```text
http://127.0.0.1:8765
```

## Security Notice

AgentShield reduces risk but cannot guarantee that every sensitive value will be detected. It does not establish GDPR compliance by itself. Never treat audit mode as enforcement, and do not grant a coding agent unrestricted direct egress if bypass prevention is required.

See [SECURITY.md](SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before using AgentShield with confidential source code.

Microsoft Presidio integration is available for configured English and German
person and organization detection. AgentShield never downloads language models
at runtime or in tests. If the configured local NLP models are unavailable, the
failure is an explicit policy input: strict mode blocks, balanced mode warns,
and a required secret-detector failure blocks in every profile. PII detection is
inherently incomplete and can produce false positives and false negatives.

## License

The license must be selected before public distribution. Do not add a license without an explicit project-owner decision.
