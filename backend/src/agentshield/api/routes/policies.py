"""FastAPI routes for security policy management and detector inspection."""

import json
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from agentshield.api.dependencies import (
    get_current_settings,
    get_policy_repository,
    require_admin_auth,
)
from agentshield.core.config import Settings
from agentshield.core.errors import NotFoundError
from agentshield.persistence.models import SecurityPolicy
from agentshield.persistence.repository import PolicyRepository

router = APIRouter(prefix="/api/v1", tags=["Policies & Detectors"])


class PolicyRuleDTO(BaseModel):
    """Rule definition within a security policy."""

    id: str
    action: str = Field(description="ALLOW, WARN, REDACT, REQUIRE_APPROVAL, or BLOCK")
    priority: int = 0
    category: str | None = None
    minimum_severity: str | None = None
    detector_id: str | None = None
    provider: str | None = None
    model: str | None = None
    endpoint: str | None = None
    direction: str | None = None
    agent: str | None = None
    project: str | None = None


class PolicySummaryResponse(BaseModel):
    """Summary of a stored security policy."""

    id: str
    name: str
    profile: str
    is_active: bool
    version: str
    rule_count: int
    created_at: str
    updated_at: str


class PolicyDetailResponse(BaseModel):
    """Detailed security policy configuration."""

    id: str
    name: str
    profile: str
    is_active: bool
    version: str
    rules: list[PolicyRuleDTO]
    created_at: str
    updated_at: str


class PolicyListResponse(BaseModel):
    """Listing of security policies and active rules."""

    active_profile: str
    effective_precedence: list[str]
    policies: list[PolicySummaryResponse]
    rules: list[PolicyRuleDTO]


class PolicyCreateRequest(BaseModel):
    """Payload to create or import a new policy."""

    name: str = Field(min_length=1, max_length=128)
    profile: str = Field(pattern="^(audit|balanced|strict)$")
    version: str = Field(default="v1", max_length=32)
    is_active: bool = True
    rules: list[PolicyRuleDTO] = Field(default_factory=list)


class PolicyUpdateRequest(BaseModel):
    """Payload to update an existing policy."""

    name: str | None = Field(default=None, max_length=128)
    is_active: bool | None = None
    rules: list[PolicyRuleDTO] | None = None


class DetectorInfo(BaseModel):
    """Status and metadata of an active security detector."""

    id: str
    name: str
    version: str
    description: str
    enabled: bool
    supported_categories: list[str]
    is_blocking_only: bool = False


class DetectorListResponse(BaseModel):
    """Registered detector statuses and capabilities."""

    detectors: list[DetectorInfo]


def _to_rules(rules_json: str) -> list[PolicyRuleDTO]:
    try:
        raw_list = json.loads(rules_json)
        return [PolicyRuleDTO(**item) for item in raw_list]
    except Exception:
        return []


def _to_summary(p: SecurityPolicy) -> PolicySummaryResponse:
    rules = _to_rules(p.rules_json)
    return PolicySummaryResponse(
        id=p.id,
        name=p.name,
        profile=p.profile,
        is_active=p.is_active,
        version=p.version,
        rule_count=len(rules),
        created_at=p.created_at.isoformat(),
        updated_at=p.updated_at.isoformat(),
    )


def _to_detail(p: SecurityPolicy) -> PolicyDetailResponse:
    return PolicyDetailResponse(
        id=p.id,
        name=p.name,
        profile=p.profile,
        is_active=p.is_active,
        version=p.version,
        rules=_to_rules(p.rules_json),
        created_at=p.created_at.isoformat(),
        updated_at=p.updated_at.isoformat(),
    )


@router.get(
    "/policies",
    response_model=PolicyListResponse,
    summary="List policies and active profile rules",
    description="Retrieve available security policies and currently effective rule precedence.",
)
async def list_policies(
    _admin: Annotated[str, Depends(require_admin_auth)],
    repo: Annotated[PolicyRepository, Depends(get_policy_repository)],
    settings: Annotated[Settings, Depends(get_current_settings)],
    profile: str | None = None,
) -> PolicyListResponse:
    policies = repo.list_policies(profile=profile)
    active_policy = repo.get_active_policy_by_profile(settings.profile)
    active_rules: list[PolicyRuleDTO] = []
    if active_policy:
        active_rules = _to_rules(active_policy.rules_json)

    return PolicyListResponse(
        active_profile=settings.profile,
        effective_precedence=["BLOCK", "REQUIRE_APPROVAL", "REDACT", "WARN", "ALLOW"],
        policies=[_to_summary(p) for p in policies],
        rules=active_rules,
    )


@router.post(
    "/policies",
    response_model=PolicyDetailResponse,
    summary="Create or import policy",
    description="Store a new versioned security policy configuration.",
)
async def create_policy(
    body: PolicyCreateRequest,
    _admin: Annotated[str, Depends(require_admin_auth)],
    repo: Annotated[PolicyRepository, Depends(get_policy_repository)],
) -> PolicyDetailResponse:
    policy_id = f"pol_{uuid4().hex[:12]}"
    rules_json = json.dumps([r.model_dump() for r in body.rules])
    policy = SecurityPolicy(
        id=policy_id,
        name=body.name,
        profile=body.profile,
        is_active=body.is_active,
        version=body.version,
        rules_json=rules_json,
    )
    repo.save_policy(policy)
    return _to_detail(policy)


@router.put(
    "/policies/{policy_id}",
    response_model=PolicyDetailResponse,
    summary="Update existing policy",
    description="Update rules or activation status of a security policy.",
)
async def update_policy(
    policy_id: str,
    body: PolicyUpdateRequest,
    _admin: Annotated[str, Depends(require_admin_auth)],
    repo: Annotated[PolicyRepository, Depends(get_policy_repository)],
) -> PolicyDetailResponse:
    policy = repo.get_policy(policy_id)
    if policy is None:
        raise NotFoundError(f"Security policy '{policy_id}' not found")

    if body.name is not None:
        policy.name = body.name
    if body.is_active is not None:
        policy.is_active = body.is_active
    if body.rules is not None:
        policy.rules_json = json.dumps([r.model_dump() for r in body.rules])

    repo.save_policy(policy)
    return _to_detail(policy)


@router.get(
    "/detectors",
    response_model=DetectorListResponse,
    summary="List active detectors",
    description="List active security detectors and their detection capabilities.",
)
async def list_detectors(
    _admin: Annotated[str, Depends(require_admin_auth)],
    settings: Annotated[Settings, Depends(get_current_settings)],
) -> DetectorListResponse:
    detectors: list[DetectorInfo] = [
        DetectorInfo(
            id="secret-patterns",
            name="Built-in Secret Detector",
            version="1.0.0",
            description=(
                "Detects API keys, tokens, private keys, and cloud credentials. "
                "Secrets always fail closed."
            ),
            enabled=True,
            supported_categories=["SECRET_API_KEY", "SECRET_TOKEN", "SECRET_KEY"],
            is_blocking_only=True,
        ),
        DetectorInfo(
            id="structured-pii",
            name="Structured PII Detector",
            version="1.0.0",
            description=(
                "Detects structured personal information such as IP addresses, "
                "emails, and phone numbers."
            ),
            enabled=True,
            supported_categories=["PII_EMAIL", "PII_IP_ADDRESS", "PII_PHONE"],
        ),
        DetectorInfo(
            id="presidio-pii",
            name="Presidio Named Entity Recognizer",
            version="1.0.0",
            description="NLP-based personal name and organization entity extraction.",
            enabled=settings.presidio_enabled,
            supported_categories=["PII_PERSON", "PII_ORGANIZATION"],
        ),
        DetectorInfo(
            id="custom-terms",
            name="Custom Term & Pattern Detector",
            version="1.0.0",
            description="User-configured regex and exact matches for confidential terms.",
            enabled=len(settings.custom_terms) > 0,
            supported_categories=["CUSTOM_TERM"],
        ),
        DetectorInfo(
            id="unsupported-content",
            name="Unsupported Content Detector",
            version="1.0.0",
            description="Detects binary, multipart, and malformed payload bodies.",
            enabled=True,
            supported_categories=["UNSUPPORTED_CONTENT"],
        ),
    ]
    return DetectorListResponse(detectors=detectors)
