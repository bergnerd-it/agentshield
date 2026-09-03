# Local Customer Demonstration

Status: target Version 1 demo  
Purpose: demonstrate the product without external LLM calls, real credentials, personal data, or customer code

## 1. Demo Message

AgentShield provides a visible local control point between a coding agent and an LLM provider. It can detect sensitive data before transmission, apply deterministic policy, request a human decision, and produce an audit record without retaining the confidential payload.

The demo must also state the boundary honestly: Version 1 controls only requests configured to pass through AgentShield.

## 2. Prerequisites

- completed Version 1 local build;
- local mock provider included with the repository;
- clean temporary AgentShield data directory;
- fake credential-store adapter enabled only for the demo environment;
- browser supported by Playwright or the local desktop environment;
- no external provider credentials configured.

Replace this section with exact commands after Milestone 1 defines the executable entry points.

## 3. Demo Data

Use fictional values only:

```text
Person: Erika Example
Organization: Alpine Example GmbH
Internal project: GREENFIELD_DEMO
Internal Java class: GreenfieldGrantService
Synthetic key: use a corpus value explicitly marked invalid
```

Do not paste a live credential, real customer name, real source file, or production endpoint during the demonstration.

## 4. Script

### Step 1 – Start the Environment

Start the mock provider and AgentShield. Open the dashboard and show:

- loopback endpoint;
- healthy detector status;
- selected `balanced` profile;
- mock provider destination;
- warning that direct egress is not enforced.

### Step 2 – Allow a Normal Request

Send a small ordinary coding request. Show that:

- the request is classified as `ALLOW`;
- the mock provider receives it;
- the response returns normally;
- audit stores metadata and timing only.

### Step 3 – Block a Secret

Send a prompt containing the designated synthetic API-key pattern. Show that:

- AgentShield reports the detector and category;
- action is `BLOCK`;
- the mock provider received no request;
- the UI, logs, SQLite, and audit export do not contain the original value.

Never reveal the complete test value in the UI during the customer demonstration.

### Step 4 – Pseudonymize PII and an Internal Identifier

Send a request containing the fictional person, organization, and Java class. Show the Monaco before/after view:

```text
Erika Example                -> <AS:PERSON:...>
Alpine Example GmbH          -> <AS:ORGANIZATION:...>
GreenfieldGrantService       -> <AS:INTERNAL_CLASS:...>
```

Show the sanitized request captured by the mock provider. Then show an eligible placeholder returned by the provider and correctly rehydrated for the coding agent.

Explain that credentials are never eligible for this mechanism.

### Step 5 – Require Approval

Trigger a project rule with `REQUIRE_APPROVAL` and show:

- the request is not yet visible at the provider;
- the pending approval, masked findings, and countdown appear in the UI;
- approval is bound to that request fingerprint;
- the provider receives the request only after approval.

Repeat with a denial or timeout if time permits.

### Step 6 – Show Streaming

Request a mock SSE response. Show incremental output and the measured proxy overhead. If available, use a separate safe scenario to show stream termination after an enforceable response finding.

Explain that content already delivered before a later finding cannot be recalled.

### Step 7 – Export Audit Evidence

Export a standalone HTML report and show:

- event timeline;
- provider and model metadata;
- finding categories and counts;
- actions and policy versions;
- latency;
- absence of raw prompts and detected values.

### Step 8 – Diagnose the Installation

Run:

```bash
agentshield doctor
```

Show configuration, credential-store, database, detector, frontend, and provider-route checks. Point out the direct-egress warning.

## 5. Expected Evidence

The demo is successful when:

- allowed requests reach the mock provider;
- blocked requests do not;
- the original synthetic secret is absent from all persistent artifacts;
- pseudonymization preserves request usefulness;
- approval occurs before provider contact;
- policy version and decision are auditable;
- all external network access remains disabled.

## 6. Reset

Provide one documented command that removes only the temporary demo data directory and fake demo credentials. It must resolve and display the exact target before deletion and must refuse broad paths such as a home directory or workspace root.

Do not make the demo cleanup command suitable for deleting real user configuration.

## 7. Suggested Customer Discussion

After the technical flow, discuss:

- deployment-specific provider approval;
- project-specific confidential terms;
- false-positive tuning;
- retention and audit requirements;
- the difference between cooperative proxying and enforced egress;
- later MCP and sandbox integration;
- why a technical control complements rather than replaces contractual and organizational safeguards.
