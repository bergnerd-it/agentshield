# ADR 0008: Use a Deterministic Built-In Secret Detector

- Status: Accepted
- Date: 2026-09-09

## Context

Milestone 3 requires deterministic detection of provider keys, AWS credentials,
GitHub tokens, bearer tokens, JWTs, private keys, password assignments, and
contextual high-entropy values. The planning review asked whether AgentShield
should wrap a general secrets scanner or maintain focused rules behind its own
`Detector` interface.

A general scanner would add a highly privileged dependency and a much larger,
changing rule corpus. It would also make offsets, safe representations,
normalization bounds, and false-positive behavior less directly controlled by
AgentShield. Microsoft Presidio is separately required by the Version 1
specification for PII.

## Decision

Implement the Milestone 3 secret families with reviewed standard-library regular
expressions, explicit validation, contextual entropy checks, and bounded URL,
zero-width, and Base64 normalization. Keep these rules behind the shared async
`Detector` contract so a mature scanner can be evaluated later without changing
policy or provider adapters.

Use keyed SHA-256 fingerprints for exclusions. The HMAC key is a separate local
0600-protected value; exclusions never store detected plaintext. Secrets always
produce fail-closed policy behavior and never receive replacement proposals.

Add `presidio-analyzer` only for the specification-required PII adapter. Its
resolved package metadata identifies an MIT license and Python 3.14 support. NLP
model packages are not downloaded by application tests or implicitly by
AgentShield.

## Consequences

### Positive

- exact offsets and safe finding metadata remain under local control;
- the scanner is deterministic, offline, and straightforward to test;
- the dependency attack surface stays smaller than a second general scanner;
- provider adapters and policy logic remain independent of rule implementation.

### Negative

- AgentShield owns maintenance of the initial secret signatures;
- the rule set is narrower than mature general-purpose scanners;
- obfuscated, split, encrypted, or novel secret formats can remain undetected;
- false-positive and attack corpora require continued review.

## Constraints

- Every pattern requires positive, negative, boundary, encoding, and
  false-positive tests.
- Normalization passes and Base64 candidate counts remain bounded.
- Detected values never enter findings, logs, errors, SQLite, or audit data.
- A scanner replacement requires supply-chain review and must preserve the
  `Detector` contract and fail-closed secret semantics.

## Revisit When

- the required secret corpus materially exceeds the maintainable built-in rules;
- measured false negatives justify an additional dependency;
- a candidate scanner can return exact offsets without retaining or logging
  detected values.
