# Tracked Issues & Upstream Dependencies

This document tracks upstream library warnings, known vendor deprecations, and their resolution status.

---

### ISSUE-001: Starlette / FastAPI TestClient Deprecation Warnings

#### 1. Description & Exact Warning Output
When executing tests via `fastapi.testclient.TestClient` or `starlette.testclient.TestClient`, the following deprecation warnings are emitted by the test runner:

```text
fastapi/testclient.py:1: StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.
  warnings.warn(

starlette/testclient.py:53: DeprecationWarning: The anyio.abc.BlockingPortal alias is deprecated, use anyio.from_thread.BlockingPortal instead.
  portal = anyio.abc.BlockingPortal()
```

#### 2. Affected Dependency Versions
- `fastapi`: 0.115.0+ (and 0.141.x+)
- `starlette`: 0.45.0+ / 1.6.0+
- `httpx`: 0.28.1+
- `anyio`: 4.8.0+ / 4.15.0+

#### 3. Root Cause Analysis
- **`StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated`**:
  Starlette's `testclient.py` includes a forward-looking deprecation notice regarding future transport layers (`httpx2`). At runtime, standard `httpx` remains the official stable synchronous/asynchronous HTTP client for FastAPI test suites.
- **`DeprecationWarning: The anyio.abc.BlockingPortal alias is deprecated`**:
  Starlette's internal test client implementation instantiates AnyIO's blocking portal via the legacy import path `anyio.abc.BlockingPortal` rather than `anyio.from_thread.BlockingPortal`.

#### 4. Resolution & Mitigation
- **Mitigation in AgentShield**: Configured scoped warning filters under `[tool.pytest.ini_options]` in `backend/pyproject.toml` so that these non-fatal third-party test fixtures do not obscure genuine application warnings or fail strict CI builds.
- **Upstream Resolution**: Upstream Starlette issue tracking modern portal imports and client transport updates in future minor releases. No action is required within AgentShield production code, as `TestClient` is strictly a test-time dependency and is never executed in production.
