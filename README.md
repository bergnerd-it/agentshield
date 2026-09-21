# AgentShield

> Local inspection and policy enforcement for coding-agent LLM traffic.

AgentShield is a local security proxy intended to show and control which data a coding agent sends to an external LLM provider. It detects credentials, personal data, and project-specific confidential terms and then applies a configurable action: allow, warn, redact, require manual approval, or block.

## Project Status

**Version 1 Complete (Milestones 1 through 7)**.

AgentShield Version 1 delivers a complete, local, deterministic security proxy for coding agents:
- **Proxy Endpoints**: Non-streaming and SSE streaming for OpenAI Responses, OpenAI Chat Completions, and Anthropic Messages.
- **Data Protection**: Request-side detection of secrets (API keys, tokens, private keys), PII (English & German names, emails, phones, IBANs, IP addresses), custom confidential terms, and unsupported multimodal payloads.
- **Deterministic Policies**: Hierarchical action precedence (`BLOCK > REQUIRE_APPROVAL > REDACT > WARN > ALLOW`) across `strict`, `balanced`, and `audit` profiles.
- **Reversible Pseudonymization**: In-memory TTL-bounded vaulting for eligible categories (`PII_*`, `CUSTOM_TERM`), bidirectional streaming holdback, and seamless rehydration of exact issued placeholders in assistant responses. Secrets are permanently blocked and never stored or rehydrated.
- **Human-in-the-Loop Approvals**: In-flight hold coordinator, live SSE broadcasting to the web dashboard, masked diff preview, client disconnect polling, and fail-closed timeouts.
- **Safe Auditing & Integration Management**: SQLite-backed audit trails, HTML & JSON exports with strict safe metadata allowlists, zero-raw-payload persistence, and atomic configuration adapters for Codex and Claude Code with rollback.
- **Hardening & Supply Chain**: Declarative synthetic attack corpus with multi-sink zero-leak tests, latency benchmarking (<30ms median SLA), CycloneDX JSON SBOM generation, and dependency vulnerability scanning.

## Version 1 Boundary & Notice

> [!IMPORTANT]
> **Cooperative Reverse Proxy**: Version 1 mediates only traffic that coding agents are explicitly configured to route through its loopback endpoints (`127.0.0.1:8765`). It does **not** transparently intercept network traffic, modify OS routing tables, install kernel firewalls, or prevent direct external egress from arbitrary processes on the host. Strong bypass prevention requires process-level sandboxing or network namespace isolation.

```text
Coding Agent (Configured) -> AgentShield (127.0.0.1:8765) -> Approved LLM Provider
```

## Quickstart

### Prerequisites
- Python `>= 3.14` and `uv`
- Node.js `>= 20` and `pnpm`

### 1. Bootstrap and Build
```bash
# Build frontend static assets
cd frontend
pnpm install --frozen-lockfile
pnpm build

# Start AgentShield backend on loopback
cd ../backend
uv sync --frozen
uv run agentshield start
```

Open your browser at `http://127.0.0.1:8765` to view the AgentShield Management Dashboard.

### 2. Run the Turnkey Local Demonstration
You can run the complete 10-step customer demonstration against a local in-memory mock provider without real LLM credentials or internet egress:

```bash
# Interactive mode (step-by-step walkthrough)
uv run scripts/run_demo.py

# Automated mode
uv run scripts/run_demo.py --auto
```

See [docs/DEMO.md](docs/DEMO.md) for full step-by-step details, curl snippets, and reset commands.

### 3. Diagnose Installation
```bash
uv run agentshield doctor
```

## Technology

- Python 3.14, FastAPI, Pydantic, HTTPX;
- SQLAlchemy, Alembic, and SQLite;
- React 19, TypeScript, Vite, and TanStack Query;
- `uv` and pnpm with committed lockfiles;
- CycloneDX SBOM generation and dependency vulnerability scanning;
- Ruff, Pyright, pytest, Vitest, and Playwright.

## Documentation

- [Version 1 Specification](planning/AgentShield_V1_Specification.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Privacy Model](docs/PRIVACY.md)
- [Performance & SLA Report](docs/PERFORMANCE.md)
- [Security Policy](SECURITY.md)
- [Testing Strategy](docs/TESTING.md)
- [Local Demonstration](docs/DEMO.md)
- [Architecture Decisions](docs/adr/)
- [Instructions for Coding Agents](AGENTS.md)

## Development Sequence

All milestones of Version 1 are complete:
- [x] Milestone 1: Foundation
- [x] Milestone 2: Non-streaming LLM proxy
- [x] Milestone 3: Detectors and policies
- [x] Milestone 4: Streaming and rehydration
- [x] Milestone 5: Dashboard and approval
- [x] Milestone 6: Audit and integrations
- [x] Milestone 7: Hardening and documentation

## Quality Gates

To verify code quality across backend and frontend:

```bash
# Backend Quality Gates
cd backend
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest

# Frontend Quality Gates
cd ../frontend
pnpm lint
pnpm typecheck
pnpm test -- --run
pnpm exec playwright test

# Supply Chain & SBOM Quality Gates
cd ..
./scripts/scan_dependencies.sh
./scripts/generate_sbom.sh
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
