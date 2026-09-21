# Security Policy

## Project Status

AgentShield Version 1.0.0 is the active release line. It implements the complete Version 1 Specification covering deterministic data-protection policies, secret blocking, PII pseudonymization, manual approvals, and safe auditing.

## Supported Versions

| Version | Supported | Security Fix Policy |
| :--- | :--- | :--- |
| `1.0.x` | Yes | Active maintenance, security patches, and dependency updates |
| `< 1.0.0` | No | Pre-release milestones; upgrade to 1.0.0+ |

## Reporting a Vulnerability

A private reporting channel must be defined before public release. Until then, do not publish a vulnerability containing exploit details or sensitive test data in a public issue. Contact the project owner through the private channel used to provide access to the repository.

The final public repository must replace this paragraph with a concrete security contact or private vulnerability-reporting mechanism.

Include when possible:

- affected version or commit;
- platform and configuration;
- reproducible steps using synthetic data;
- expected and observed result;
- security impact;
- suggested mitigation, if known.

Never include real provider keys, customer source code, personal data, or production prompts in a report.

## Security Boundary

Version 1 protects only traffic explicitly routed through AgentShield's supported proxy endpoints. It does not enforce system-wide egress and cannot prevent a coding agent from using another network path when the operating system permits it.

See `docs/THREAT_MODEL.md` for the complete boundary and residual risks.

## Mandatory Security Invariants

- TLS verification is always enabled for upstream providers.
- Provider credentials remain in the native credential store.
- Local proxy credentials are never forwarded upstream.
- Management and proxy credentials are separate.
- Raw prompts and responses are not persisted by default.
- Detected secret values are never persisted.
- Secrets are blocked and never rehydrated.
- Required detector failure is never silently interpreted as a clean result.
- State-changing management operations require authentication.
- Production binds to loopback by default.
- Wildcard CORS is prohibited.
- Automated tests do not contact external providers.

## Secure Configuration

For confidential work:

1. use the `strict` profile;
2. configure only approved providers and models;
3. confirm all required detectors are healthy;
4. keep external telemetry disabled;
5. keep diagnostic payload retention disabled;
6. run `agentshield doctor` after integration changes;
7. independently restrict direct agent egress if bypass prevention is required;
8. review provider contracts and data-processing terms separately.

Audit mode observes but does not enforce content decisions. It must not be used as a substitute for protection.

The fail-closed credential invariant also applies in audit mode: a detected
secret or unavailable required secret detector blocks the request. Audit mode is
observational for non-secret content findings.

Presidio person and organization recognition requires locally installed,
configured English and German NLP models. AgentShield does not download models
at runtime. Confirm detector health before relying on strict mode; strict mode
blocks when a required detector is unavailable. Custom regular expressions use
a restricted, bounded subset without groups or backreferences and are executed
off the async request loop.

## Credential Handling

- Store provider credentials only through the credential-store abstraction.
- Do not expose a “show secret” UI.
- Do not place credentials in URLs, SQLite, YAML, shell history examples, screenshots, tests, or logs.
- Use separate credentials per provider and environment where possible.
- Rotate a credential immediately if a test indicates it may have crossed the proxy boundary unexpectedly.
- Custom endpoints must never receive credentials issued for another provider.

## Logging and Telemetry

The default log schema uses an allowlist and may include event IDs, provider name, model name, endpoint class, sizes, timing, finding categories, decision, and safe error class.

It must not include:

- authorization headers;
- cookies or local tokens;
- raw prompts or responses;
- detected values;
- reversible mappings;
- provider exception bodies unless safely normalized;
- filesystem contents or environment-variable dumps.

External telemetry exporters are disabled by default. Enabling one requires a threat-model update and explicit documentation of exported fields and destination.

## Diagnostic Mode

Diagnostic mode is disabled by default. If implemented, it must:

- require explicit activation and show a persistent warning;
- have a short maximum lifetime and expire automatically;
- redact credentials regardless of configuration;
- store files with restrictive permissions;
- provide immediate cleanup;
- record activation and expiration without retaining the reason text if it may be sensitive.

## Dependency Security & Supply-Chain Integrity
 
- Commit Python (`uv.lock`) and JavaScript (`pnpm-lock.yaml`) lockfiles.
- Run automated vulnerability scanning in CI (`scripts/scan_dependencies.sh`) via `pip-audit` for Python and `pnpm audit --audit-level=high` for Node.
- Generate standard CycloneDX JSON Software Bill of Materials (SBOM) for backend and frontend release artifacts (`scripts/generate_sbom.sh`) into `dist/sbom/`.
- Validate that dependencies contain zero high or critical severity vulnerabilities before tagging releases.
- Review networking, parser, authentication, credential-store, cryptography, and detector dependency updates manually.
- Do not run unpinned remote scripts in CI.
- Do not publish a release containing known unreviewed critical vulnerabilities.

## Release Security Checklist

- All quality gates in `docs/TESTING.md` pass.
- Synthetic-secret leak tests pass across logs, SQLite, exports, API responses, and UI.
- Threat model is current.
- Debug mode and external telemetry are off in release configuration.
- Provider endpoint defaults use HTTPS.
- Credential-store behavior has been tested on every supported platform.
- Build inputs are locked and an SBOM is generated.
- Release artifacts are checksummed; signing and notarization are required once desktop packages are distributed.
- Documentation contains the direct-egress limitation and no unsupported compliance claim.

## Legal and Compliance Notice

AgentShield is a technical safeguard. Its use does not itself make an organization compliant with the GDPR, AI Act, contractual confidentiality obligations, or customer security policies. Legal basis, provider contracts, data-processing agreements, retention, access control, and organizational measures remain deployment-specific responsibilities.
