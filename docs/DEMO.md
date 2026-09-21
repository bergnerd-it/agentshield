# Local Customer Demonstration Walkthrough

Status: Version 1 Release Candidate Demo  
Purpose: Demonstrate AgentShield capabilities end-to-end without external LLM calls, real credentials, personal data, or customer code.

## 1. Demo Overview

AgentShield provides a visible local control point between coding agents (such as Claude Code or Codex) and external LLM providers. It inspects prompts and responses before network dispatch, enforces deterministic data-protection policies, supports in-memory human-in-the-loop approvals, and emits privacy-preserving audit logs without retaining confidential payloads.

> [!IMPORTANT]
> **Cooperative Proxy Boundary Notice**: Version 1 inspects only traffic explicitly routed through AgentShield endpoints (`127.0.0.1:8765`). It does not transparently intercept network traffic, install OS firewalls, or prevent direct external egress from arbitrary local processes.

---

## 2. Prerequisites & Setup

- Python `>= 3.14` and `uv` installed.
- Node.js `>= 20` and `pnpm` installed.
- Zero external provider credentials or cloud connectivity required (operates 100% against local loopback mock providers).
- Synthetic test data only.

### Starting the Demonstration Runner

AgentShield provides a turnkey runner that sets up an isolated demo sandbox, runs the mock LLM server, and guides the operator through each verification step:

```bash
# Interactive mode (pauses between steps for operator discussion and UI inspection)
uv run scripts/run_demo.py

# Automated mode (runs all 10 steps sequentially with programmatic assertions)
uv run scripts/run_demo.py --auto
```

To run the automated scenario test via pytest:
```bash
cd backend
uv run pytest tests/test_demo_scenario.py -v
```

---

## 3. Synthetic Demonstration Data

The demonstration relies exclusively on synthetic, fictional data:

| Entity Type | Synthetic Sample | Intended Policy Handling |
| :--- | :--- | :--- |
| **Clean Code** | QuickSort function in Python | `ALLOW` (Forwarded to provider) |
| **API Key Secret** | `sk-proj-DEMOONLYfakekey1234567890abcdefghijklmnopqrstuvwxyz` | `BLOCK` (HTTP 403, Upstream non-receipt) |
| **PII Person** | Erika Mustermann | `REDACT` (Pseudonymized into `<AS:PERSON:...>`) |
| **Internal Term** | `GreenfieldGrantService` | `REDACT` (Pseudonymized into `<AS:TERM:...>`) |
| **Privileged Action** | `HIGH_RISK_OP` | `REQUIRE_APPROVAL` (In-flight hold in dashboard) |

---

## 4. Step-by-Step Scenario Walkthrough

### Step 1 – Initialize & Verify Service
AgentShield initializes on loopback `127.0.0.1:8765` using an isolated temporary data directory.
- Checks service health at `GET /health`.
- Returns `{"status": "healthy", "version": "1.0.0"}` with HTTP 200.

### Step 2 – Start Local Mock Provider
The in-memory OpenAI and Anthropic provider simulator starts on loopback.
- Captures all outbound requests for validation.
- Emulates upstream provider responses with zero token charges or external network access.

### Step 3 – Verify Active Profile
The proxy queries `GET /api/v1/settings` with the local admin token.
- Asserts active profile is `balanced`.
- Displays action precedence: `BLOCK > REQUIRE_APPROVAL > REDACT > WARN > ALLOW`.

### Step 4 – Send Normal Request (Clean Code)
A clean request is sent through the proxy endpoint:
```bash
curl -X POST http://127.0.0.1:8765/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer <PROXY_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Write a quicksort function in Python."}]
  }'
```
- **Result**: HTTP 200 OK.
- **Verification**: Mock provider captures exactly 1 request. Event recorded in audit log with category `ALLOW`.

### Step 5 – Block Synthetic Secret
A prompt containing an API key credential is submitted:
```bash
curl -X POST http://127.0.0.1:8765/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer <PROXY_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Fix API connection using sk-proj-DEMOONLYfakekey1234567890abcdefghijklmnopqrstuvwxyz"}]
  }'
```
- **Result**: HTTP 403 Forbidden with RFC 9457 Problem Details (`urn:agentshield:error:policy-blocked`).
- **Verification**: Mock provider requests count remains 1 (request was dropped locally before upstream contact). Original secret is completely absent from database tables, exports, and logs.

### Step 6 – Pseudonymize Sensitive Terms & PII
A prompt containing a person's name and internal class name is submitted:
```bash
curl -X POST http://127.0.0.1:8765/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer <PROXY_TOKEN>" \
  -H "x-session-id: demo-sess-customer" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Review access request for Erika Mustermann on GreenfieldGrantService internal database."}]
  }'
```
- **Result**: HTTP 200 OK.
- **Verification**: Upstream mock provider receives transformed prompt:
  `Review access request for <AS:PERSON:demo-sess:0001> on <AS:TERM:demo-sess:0001> internal database.`
- Original confidential terms are stored in temporary in-memory vault with bounded TTL (3600s).

### Step 7 – Response Rehydration
The upstream mock provider responds citing the placeholder:
`Confirmed architecture analysis for: <AS:TERM:demo-sess:0001>`.
- The streaming/response pipeline scans the placeholder and seamlessly rehydrates it in memory:
  `Confirmed architecture analysis for: GreenfieldGrantService`.
- The coding agent receives the fully intelligible response while the LLM provider never saw the internal identifier.
- **Invariant**: Secrets and passwords are never eligible for rehydration.

### Step 8 – In-Flight Hold & Manual Approval
A prompt matching a `REQUIRE_APPROVAL` custom term is submitted:
```bash
curl -X POST http://127.0.0.1:8765/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer <PROXY_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Run critical operation HIGH_RISK_OP"}]
  }'
```
- Outbound request halts before upstream transmission.
- Appears in Management Dashboard `/approvals` with masked diff and countdown timer.
- Security officer grants approval via Management API:
  `POST /api/v1/approvals/<APPROVAL_ID>/approve`
- Upstream request completes, returning HTTP 200 to the client. If client disconnected or timer expired (60s), the request would fail closed.

### Step 9 – Audit Export Verification
The operator exports the audit log:
```bash
curl -X POST http://127.0.0.1:8765/api/v1/audit/export \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"format": "json"}'
```
- **Verification**: Validates JSON export artifact against synthetic secrets. Demonstrates 100% absence of `sk-proj-DEMOONLYfakekey...`, raw prompts, and raw responses.

### Step 10 – System Diagnostics (`agentshield doctor`)
The diagnostic health check verifies local security posture:
```bash
agentshield doctor
```
- Displays checks:
  - `[✓] runtime                   : OK     (Python 3.14.7)`
  - `[✓] data_directory            : OK     (Writable: ...)`
  - `[✓] database                  : OK     (Connected, Alembic schema current)`
  - `[✓] credential_store          : OK     (Secure backend available)`
  - `[✓] detectors                 : OK     (All 4 detectors healthy)`
  - `[✓] frontend                  : OK     (Static bundle built & ready)`
  - `[✓] agent_codex               : OK     (Configured to 127.0.0.1:8765)`
- Displays the mandatory cooperative proxy warning banner.

---

## 5. Environment Reset

To safely reset and clean up temporary demonstration data without risking real user configurations, use `scripts/reset_demo.py`:

```bash
python3 scripts/reset_demo.py
```

### Safety Guards in `reset_demo.py`:
1. Refuses broad paths (`/`, `~`, CWD, parent directory).
2. Deletes only directories explicitly named with the demo prefix (`.agentshield-demo*` or `agentshield-demo*`).
3. Does not modify or delete normal user configuration in `~/Library/Application Support/AgentShield` or `~/.config/agentshield`.

---

## 6. Suggested Customer Discussion

After the technical flow, discuss:
- Deployment-specific provider approval workflows.
- Project-specific confidential terms and custom rulesets.
- False-positive tuning and audit mode vs balanced vs strict enforcement.
- Retention policies and audit export requirements.
- The fundamental distinction between cooperative reverse proxying and OS-level network isolation.
- Future roadmap (MCP inspection, process sandboxing, centralized policy distribution).
- Why technical controls complement rather than replace contractual and organizational data-protection safeguards.
