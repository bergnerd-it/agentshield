# Privacy Model

Status: Version 1 design baseline

## 1. Principle

AgentShield follows data minimization: inspect content in memory, enforce policy, and retain only the metadata necessary to explain and operate the control.

## 2. Data Categories

| Category | Example | Default handling |
| --- | --- | --- |
| Provider credential | API key | Native credential store only |
| Local credential | Proxy or management token | Native credential store or protected local secret storage |
| Request content | Prompt, code, tool result | Process in memory; do not persist by default |
| Response content | Text, code, tool call | Stream/process in memory; do not persist by default |
| Detected secret | Token or password value | Block; never persist or rehydrate |
| Reversible value | Name or internal identifier | Short-lived protected mapping |
| Finding metadata | Category, detector, confidence | Sanitized audit storage |
| Finding fingerprint key | Local HMAC key | Restricted local file; never logged or exported |
| Policy | Rule and action | Versioned SQLite storage |
| Integration backup | Previous agent configuration | Local, restrictive permissions, bounded retention |

## 3. Default Data Flow

1. The coding agent sends a request to loopback.
2. AgentShield parses and scans it in memory.
3. The policy engine produces a decision.
4. A blocked request never reaches the provider.
5. A redacted request is validated and sent to the configured provider.
6. The provider response is scanned and eligible placeholders may be rehydrated.
7. AgentShield stores sanitized event metadata, not the complete exchange.

## 4. Retention

Initial defaults:

- raw requests and responses: not retained;
- detected secret values: not retained;
- pseudonym mappings: memory only with a bounded configurable TTL;
- approval previews: memory only until terminal state plus a short cleanup grace period;
- audit metadata: 30 days, configurable;
- integration backups: retain the latest successful backup per integration until rollback or explicit cleanup;
- diagnostic artifacts: disabled; if enabled, short explicit TTL and manual cleanup.

Retention changes must be visible in the UI and documented. Reducing retention should not require a migration that exposes deleted content.

## 5. Fingerprints

Fingerprints support request correlation without retaining raw content. A plain SHA-256 hash of predictable content can permit dictionary attacks. Where this matters, use a versioned keyed digest with a locally protected key and record only the digest and normalization version.

Fingerprints must not be used as reversible pseudonyms.

Milestone 3 uses a separate 256-bit local key stored with restrictive file
permissions to create HMAC-SHA-256 finding fingerprints. Findings never retain
the detected source value. A configured secret exclusion stores only one of
these keyed fingerprints; it cannot contain plaintext secret material.

## 6. Pseudonymization

- Reversible mappings are scoped by project and session.
- Placeholders include a collision-resistant session namespace.
- Only explicit eligible categories enter the mapping.
- Credentials and secrets never enter the mapping.
- Mappings expire and are removed.
- Exact issued placeholders only are eligible for rehydration.
- Audit records contain category and count, not the mapping.

Pseudonymization reduces disclosure but is not anonymization. A provider may infer information from surrounding source code or context.

## 7. UI Privacy

- Sanitized content is the default view.
- Raw content is never rendered when it contains a blocked secret.
- Content views must not be placed in browser local storage, session storage, analytics, or URLs.
- Copy operations must reflect what the user is copying and should warn if unsanitized content is available.
- Closing or refreshing the page must not extend in-memory retention.

## 8. Exports & Safe Metadata Serialization

JSON and HTML audit exports exclude raw content by default. The audit service serializes event metadata using an explicit, non-bypassable key allowlist (`_SAFE_METADATA_KEYS`):

- `model`, `provider`, `action`, `profile`, `policy_version`, `status_code`, `latency_ms`, `tokens_in`, `tokens_out`, `findings_count`, `rule_ids`, `finding_categories`.

Any arbitrary internal or runtime metadata keys not present in the allowlist are strictly dropped before persisting to SQLite, rendering in the live events API (`/api/v1/events`), or writing to export artifacts.

Each audit export explicitly includes:

- time range;
- active filters;
- policy versions represented;
- whether diagnostic content was included;
- generation timestamp.

Zero raw prompts, LLM responses, or detected secret values are ever written to the audit database or export artifacts. Exports are ordinary files after creation. The user is responsible for their storage and sharing. AgentShield informs operators that event metadata may still indicate organizational activity.

## 9. External Processing

Only a request allowed by policy is sent to the configured provider. AgentShield does not control the provider's retention or training behavior. Provider selection, contracts, regional processing, and data-processing agreements remain external deployment decisions.

External telemetry is disabled by default. Adding any telemetry destination requires documenting exact fields, purpose, retention, and opt-in behavior.

## 10. Data Subject and Administrative Operations

Version 1 is a single-user local tool, not a system of record for people. Nevertheless, it should support:

- deleting audit events by retention cleanup;
- clearing pseudonym mappings immediately;
- deleting diagnostic artifacts;
- removing integration backups;
- exporting configuration and audit metadata.

Operations must not claim to delete data already sent to an external provider.

## 11. Privacy Verification

Automated tests must seed unique synthetic markers and verify their absence from:

- logs;
- SQLite tables;
- audit exports;
- management API responses;
- frontend DOM and browser storage;
- crash and validation error output.

Any leak test failure blocks release.

Milestone 3 request tests also verify blocked synthetic values are absent from
mock-provider captures, local error responses, captured logs, and SQLite dumps.
Reversible mapping, response rehydration, and audit export verification remain
attached to the milestones that implement those data paths.
