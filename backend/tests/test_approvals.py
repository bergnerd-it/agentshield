import asyncio
from collections.abc import AsyncGenerator
from uuid import uuid4

import httpx
import pytest

from agentshield.api.app import create_app
from agentshield.api.dependencies import (
    get_approval_manager,
    get_credential_store,
    get_forward_client,
    get_inspection_pipeline,
    reset_approval_manager,
)
from agentshield.approvals.manager import ApprovalManager
from agentshield.approvals.models import ApprovalStatus
from agentshield.core.auth import get_or_create_proxy_token
from agentshield.core.config import Settings
from agentshield.core.credentials import InMemoryCredentialStore
from agentshield.core.errors import ConflictError, NotFoundError
from agentshield.filtering.detectors.custom_terms import CustomTermDetector, CustomTermRule
from agentshield.filtering.detectors.pii import StructuredPiiDetector
from agentshield.filtering.detectors.secrets import SecretDetector
from agentshield.filtering.detectors.unsupported import UnsupportedContentDetector
from agentshield.filtering.engine import DetectorEngine
from agentshield.filtering.models import (
    DetectionReport,
    Finding,
    FindingCategory,
    FindingLocation,
    ScanContext,
    ScanDirection,
    Severity,
)
from agentshield.policies.engine import PolicyEngine
from agentshield.policies.models import PolicyAction, PolicyProfile, PolicyRule
from agentshield.proxy.client import ProxyForwardClient
from agentshield.proxy.inspection import RequestInspectionPipeline
from tests.mock_providers import MockOpenAIServer


def _build_test_pipeline(
    profile: PolicyProfile = PolicyProfile.BALANCED,
    rules: tuple[PolicyRule, ...] = (),
    custom_rules: tuple[CustomTermRule, ...] = (),
) -> RequestInspectionPipeline:
    key = b"approval-test-fingerprint-key"
    return RequestInspectionPipeline(
        detector_engine=DetectorEngine(
            (
                SecretDetector(fingerprint_key=key),
                StructuredPiiDetector(fingerprint_key=key),
                CustomTermDetector(fingerprint_key=key, rules=custom_rules),
                UnsupportedContentDetector(fingerprint_key=key),
            ),
            timeout_seconds=1.0,
        ),
        policy_engine=PolicyEngine(profile, rules=rules),
        header_secret_detector=SecretDetector(fingerprint_key=key),
    )


def test_policy_engine_require_approval_precedence() -> None:
    """Verify action precedence BLOCK > REQUIRE_APPROVAL > REDACT > WARN > ALLOW."""
    engine = PolicyEngine(
        PolicyProfile.BALANCED,
        rules=(
            PolicyRule(
                id="rule-approval",
                action=PolicyAction.REQUIRE_APPROVAL,
                category=FindingCategory.PII_EMAIL,
            ),
        ),
    )
    context = ScanContext(
        provider="openai",
        endpoint="/v1/chat/completions",
        direction=ScanDirection.REQUEST,
        targets=(),
    )
    email_finding = Finding(
        id=uuid4(),
        category=FindingCategory.PII_EMAIL,
        severity=Severity.HIGH,
        detector_id="structured-pii",
        detector_version="1.0",
        confidence=1.0,
        location=FindingLocation(path=("messages", 0, "content")),
        fingerprint="a" * 64,
    )
    report = DetectionReport(findings=(email_finding,))
    decision = engine.evaluate(context, report)
    assert decision.action == PolicyAction.REQUIRE_APPROVAL


def test_secret_finding_never_overridden_by_approval_rule() -> None:
    """Security Invariant: secrets always BLOCK, even if a rule matches REQUIRE_APPROVAL."""
    engine = PolicyEngine(
        PolicyProfile.BALANCED,
        rules=(
            PolicyRule(
                id="override-rule",
                action=PolicyAction.REQUIRE_APPROVAL,
                category=FindingCategory.SECRET_API_KEY,
            ),
        ),
    )
    context = ScanContext(
        provider="openai",
        endpoint="/v1/chat/completions",
        direction=ScanDirection.REQUEST,
        targets=(),
    )
    secret_finding = Finding(
        id=uuid4(),
        category=FindingCategory.SECRET_API_KEY,
        severity=Severity.CRITICAL,
        detector_id="secret-patterns",
        detector_version="1.0",
        confidence=1.0,
        location=FindingLocation(path=("messages", 0, "content")),
        fingerprint="b" * 64,
    )
    report = DetectionReport(findings=(secret_finding,))
    decision = engine.evaluate(context, report)
    assert decision.action == PolicyAction.BLOCK


@pytest.mark.asyncio
async def test_approval_manager_state_machine() -> None:
    """Verify atomic state transitions and conflict detection in ApprovalManager."""
    manager = ApprovalManager()
    req = manager.create_request(
        request_fingerprint="abc123hash",
        policy_version="v1",
        provider="openai",
        model="gpt-4o",
        endpoint="/v1/chat/completions",
        timeout_seconds=5.0,
    )
    assert req.status == ApprovalStatus.PENDING
    assert req.remaining_seconds > 0.0

    # First approve succeeds
    approved = await manager.approve(req.id, reason="Operator verified")
    assert approved.status == ApprovalStatus.APPROVED
    assert approved.decided_at is not None
    assert approved.decision_reason == "Operator verified"

    # Second approve raises 409 Conflict
    with pytest.raises(ConflictError):
        await manager.approve(req.id, reason="Duplicate")

    # Deny on approved raises 409 Conflict
    with pytest.raises(ConflictError):
        await manager.deny(req.id, reason="Contradicting")

    # Unknown ID raises 404
    with pytest.raises(NotFoundError):
        await manager.approve("non-existent-id")


@pytest.mark.asyncio
async def test_approval_manager_timeout_expiry() -> None:
    """Verify timeout leads to EXPIRED state."""
    manager = ApprovalManager()
    req = manager.create_request(
        request_fingerprint="timeout-fp",
        policy_version="v1",
        provider="openai",
        model="gpt-4o",
        endpoint="/v1/chat/completions",
        timeout_seconds=0.2,
    )

    status = await manager.wait_for_decision(req.id, timeout_seconds=0.2)
    assert status == ApprovalStatus.EXPIRED
    req_after = manager.get_request(req.id)
    assert req_after is not None
    assert req_after.status == ApprovalStatus.EXPIRED


@pytest.mark.asyncio
async def test_approval_manager_disconnect_cancellation() -> None:
    """Verify client disconnect leads to CANCELLED state."""
    manager = ApprovalManager()
    req = manager.create_request(
        request_fingerprint="disconnect-fp",
        policy_version="v1",
        provider="openai",
        model="gpt-4o",
        endpoint="/v1/chat/completions",
        timeout_seconds=5.0,
    )

    async def is_disconnected() -> bool:
        return True

    status = await manager.wait_for_decision(
        req.id,
        timeout_seconds=5.0,
        is_client_disconnected=is_disconnected,
    )
    assert status == ApprovalStatus.CANCELLED
    req_after = manager.get_request(req.id)
    assert req_after is not None
    assert req_after.status == ApprovalStatus.CANCELLED


@pytest.fixture
async def approval_test_env(
    test_settings: Settings,
) -> AsyncGenerator[tuple[httpx.AsyncClient, MockOpenAIServer, ApprovalManager, Settings]]:
    test_settings.approval_timeout_seconds = 2.0
    manager = ApprovalManager()
    reset_approval_manager(manager)

    mock = MockOpenAIServer()
    upstream = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock.app),  # pyright: ignore[reportArgumentType]
        base_url=test_settings.openai_upstream_base_url,
    )
    forwarder = ProxyForwardClient(settings=test_settings, client=upstream)

    # Policy rule: custom term "ProjectFalcon" requires approval
    rule = PolicyRule(
        id="falcon-approval-rule",
        action=PolicyAction.REQUIRE_APPROVAL,
        category=FindingCategory.CUSTOM_TERM,
    )
    custom_rule = CustomTermRule(
        id="falcon-rule",
        pattern="ProjectFalcon",
        default_action=PolicyAction.REQUIRE_APPROVAL,
    )
    pipeline = _build_test_pipeline(
        profile=PolicyProfile.BALANCED,
        rules=(rule,),
        custom_rules=(custom_rule,),
    )

    app = create_app(test_settings)
    app.dependency_overrides[get_forward_client] = lambda: forwarder
    app.dependency_overrides[get_credential_store] = lambda: InMemoryCredentialStore(
        initial_keys={"openai": "sk-synth-provider-only-1234567890"}
    )
    app.dependency_overrides[get_inspection_pipeline] = lambda: pipeline
    app.dependency_overrides[get_approval_manager] = lambda: manager

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # pyright: ignore[reportArgumentType]
        base_url="http://127.0.0.1:8765",
    ) as client:
        yield client, mock, manager, test_settings

    reset_approval_manager(None)


@pytest.mark.asyncio
async def test_proxy_hold_and_approve_flow(
    approval_test_env: tuple[httpx.AsyncClient, MockOpenAIServer, ApprovalManager, Settings],
) -> None:
    """Verify that a request is held, and approving it allows it to forward upstream."""
    client, mock, manager, settings = approval_test_env
    proxy_token = get_or_create_proxy_token(settings.effective_proxy_token_path)

    async def approve_background() -> None:
        # Wait until hold appears
        for _ in range(30):
            await asyncio.sleep(0.05)
            pending = manager.list_requests(status=ApprovalStatus.PENDING)
            if pending:
                req_id = pending[0].id
                # Check that provider mock has received 0 requests while pending
                assert len(mock.recorded_requests) == 0
                # Approve via manager
                await manager.approve(req_id, reason="Approved by security officer")
                break

    task = asyncio.create_task(approve_background())

    # Send proxy request containing term that triggers REQUIRE_APPROVAL
    resp = await client.post(
        "/proxy/openai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {proxy_token}",
            "Content-Type": "application/json",
            "X-Agent-ID": "test-agent",
        },
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "ProjectFalcon specs."}],
        },
    )
    await task

    assert resp.status_code == 200
    assert len(mock.recorded_requests) == 1
    # Verify mock received the request
    body_received = mock.recorded_requests[0].body.decode("utf-8")
    assert "ProjectFalcon" in body_received


@pytest.mark.asyncio
async def test_proxy_hold_and_deny_flow(
    approval_test_env: tuple[httpx.AsyncClient, MockOpenAIServer, ApprovalManager, Settings],
) -> None:
    """Verify that denying an in-flight hold blocks the request and stops upstream transmission."""
    client, mock, manager, settings = approval_test_env
    proxy_token = get_or_create_proxy_token(settings.effective_proxy_token_path)

    async def deny_background() -> None:
        for _ in range(30):
            await asyncio.sleep(0.05)
            pending = manager.list_requests(status=ApprovalStatus.PENDING)
            if pending:
                req_id = pending[0].id
                assert len(mock.recorded_requests) == 0
                await manager.deny(req_id, reason="Policy violation")
                break

    task = asyncio.create_task(deny_background())

    resp = await client.post(
        "/proxy/openai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {proxy_token}",
            "Content-Type": "application/json",
        },
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Confidential ProjectFalcon data"}],
        },
    )
    await task

    assert resp.status_code == 403
    problem = resp.json()
    assert problem["type"] == "urn:agentshield:error:approval-denied"
    assert len(mock.recorded_requests) == 0


@pytest.mark.asyncio
async def test_proxy_hold_timeout_fails_closed(
    approval_test_env: tuple[httpx.AsyncClient, MockOpenAIServer, ApprovalManager, Settings],
) -> None:
    """Verify that approval timeout denies by default and provider is never contacted."""
    client, mock, _manager, settings = approval_test_env
    settings.approval_timeout_seconds = 0.3  # Short timeout for fast test
    proxy_token = get_or_create_proxy_token(settings.effective_proxy_token_path)

    resp = await client.post(
        "/proxy/openai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {proxy_token}",
            "Content-Type": "application/json",
        },
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "ProjectFalcon secrets waiting for operator"}],
        },
    )

    assert resp.status_code == 403
    problem = resp.json()
    assert problem["type"] == "urn:agentshield:error:approval-timeout"
    assert len(mock.recorded_requests) == 0
