# ADR 0005: Use Bounded Reversible Pseudonymization for Eligible Data

- Status: Accepted
- Date: 2026-09-03

## Context

Irreversible redaction protects data but can make generated code unusable. For example, if an internal Java class name is replaced before the LLM call, the response may need to restore that exact identifier before returning to the coding agent.

Applying the same mechanism to credentials would be dangerous because a model could cause a secret to be inserted into generated output.

## Decision

Use typed, collision-resistant, project- and session-scoped placeholders for explicitly eligible data classes. Maintain a short-lived mapping locally and rehydrate only exact placeholders that AgentShield issued in that active scope.

Credentials, passwords, tokens, private keys, and other secret classes are never eligible for reversible mapping or rehydration.

## Rationale

- preserves usefulness of generated code involving protected identifiers;
- avoids sending the original value to the provider;
- supports consistent replacements inside one request or session;
- creates a clear hard boundary between pseudonymizable context and non-recoverable secrets.

## Consequences

### Positive

- safer handling of names and internal identifiers without breaking results;
- explainable before/after diff;
- deterministic, testable rehydration behavior.

### Negative

- mappings are sensitive during their lifetime;
- placeholder collisions and injection require explicit defense;
- an LLM may alter a placeholder, preventing rehydration;
- surrounding context may still reveal information.

## Constraints

- Include a collision-resistant session namespace in issued placeholders.
- Check input for collisions before issuing a placeholder.
- Different original values never share a placeholder in the same scope.
- Replace only exact issued placeholders.
- Never guess after expiry or for a modified placeholder.
- Use memory-only mappings by default with bounded TTL and cleanup.
- Never write mappings to audit records or ordinary logs.
- Test cross-session isolation, concurrency, collision, injection, expiry, and Unicode behavior.

## Rejected Alternatives

- irreversible replacement for every internal identifier, because it breaks code usability;
- reversible storage of secrets, because it enables unsafe reinsertion;
- global stable pseudonyms, because they permit cross-project correlation;
- LLM-assisted rehydration, because it is not deterministic or safe.

## Revisit When

Persistent mappings, collaboration, team policy, or long-running cross-session workflows become requirements. Any persistence requires a dedicated key-management and privacy design.
