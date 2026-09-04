# ADR 0004: Use SQLite and Privacy-Preserving Audit Records

- Status: Accepted
- Date: 2026-09-03

## Context

Version 1 is a local single-user application. It needs settings, versioned policies, detector configuration, approval metadata, integration-backup metadata, and audit events. Requiring an external database would complicate installation and offer little benefit for the initial scope.

The audit capability must explain decisions without creating a second repository of confidential prompts and source code.

## Decision

Use SQLite with SQLAlchemy 2 and Alembic as the Version 1 runtime store. Enable WAL mode, restrictive file permissions, bounded busy handling, and explicit transactions.

Audit records store sanitized metadata, categories, counts, policy version, decisions, timings, sizes, and protected fingerprints. Raw prompts, full responses, provider credentials, detected secret values, and long-lived pseudonym mappings are excluded by default.

## Rationale

- no external service is needed;
- SQLite is portable across target platforms;
- transactional policy versions and approval state are available;
- migrations provide a professional evolution path;
- data minimization reduces breach impact and supports the product's purpose.

## Consequences

### Positive

- simple local installation and backup;
- deterministic tests using temporary databases;
- strong fit for a single-user workload;
- straightforward retention cleanup and audit export.

### Negative

- not suitable for central multi-user deployment without redesign;
- local processes with the same filesystem permissions may access or tamper with the database;
- write concurrency requires explicit handling;
- metadata may still be confidential.

## Constraints

- Provider credentials never enter SQLite.
- Raw payload retention is disabled by default.
- Audit serialization uses an allowlist.
- Retention cleanup is testable and bounded.
- Policy decisions reference immutable policy versions.
- Diagnostic retention, if added, uses separate explicit controls and automatic expiry.
- Migrations must work from an empty database and from every supported released schema.

## Revisit When

- central team management becomes a committed requirement;
- concurrent write load exceeds measured SQLite capability;
- remote access, RBAC, or high-availability requirements are introduced.

At that point PostgreSQL may become appropriate, but privacy-preserving audit semantics remain unchanged.
