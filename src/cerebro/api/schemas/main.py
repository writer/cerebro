"""Pydantic schemas for API requests and responses."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# Organization schemas
class OrganizationCreate(BaseModel):
    name: str = Field(..., description="Organization name")


class OrganizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    org_id: UUID
    name: str
    created_at: datetime


# Account schemas
class AccountCreate(BaseModel):
    org_id: UUID
    provider: str = Field(
        ..., description="Provider name (github, aws, gcp, google_workspace)"
    )
    external_id: str = Field(..., description="Provider-specific account ID")
    display_name: str | None = None


class AccountResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    account_id: UUID
    org_id: UUID
    provider: str
    external_id: str
    display_name: str | None


# Resource schemas
class ResourceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    resource_id: UUID
    account_id: UUID
    provider: str
    resource_type: str
    external_id: str
    name: str | None
    parent_external_id: str | None
    created_at: datetime


# Principal schemas
class PrincipalResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    principal_id: UUID
    account_id: UUID
    provider: str
    principal_type: str
    external_id: str
    email: str | None
    display_name: str | None
    is_human: bool | None


# Rule schemas
class RuleCreate(BaseModel):
    name: str
    description: str | None = None
    provider: list[str] = Field(..., description="List of applicable providers")
    resource_types: list[str] | None = None
    expression_lang: str = Field(
        default="cel", description="Expression language (cel, sql, rego)"
    )
    expression: str = Field(..., description="Rule expression")
    severity: str = Field(..., description="Severity level")
    policy_id: UUID | None = None
    cwe: list[str] | None = None
    cis: list[str] | None = None
    nist_800_53: list[str] | None = None
    mitre_attack: list[str] | None = None


class RuleResponse(BaseModel):
    rule_id: UUID
    policy_id: UUID | None
    name: str
    description: str | None
    provider: list[str]
    resource_types: list[str] | None
    expression_lang: str
    expression: str
    severity: str
    cwe: list[str] | None
    cis: list[str] | None
    nist_800_53: list[str] | None
    mitre_attack: list[str] | None
    version: int
    is_active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


# Finding schemas
class FindingResponse(BaseModel):
    finding_id: UUID
    org_id: UUID
    account_id: UUID
    provider: str
    rule_id: UUID
    rule_version: int
    resource_id: UUID | None
    principal_id: UUID | None
    first_seen: datetime
    last_seen: datetime
    status: str
    severity: str
    fingerprint: str
    title: str
    summary: str | None
    evidence: dict[str, Any] | None
    model_config = ConfigDict(from_attributes=True)


class FindingPageResponse(BaseModel):
    items: list[FindingResponse]
    next_cursor: str | None = None
    freshness: dict[str, Any] | None = None
    warnings: list[str] = Field(default_factory=list)


class FindingUpdate(BaseModel):
    status: str | None = None


class FindingStats(BaseModel):
    total: int
    by_status: dict[str, int]
    by_severity: dict[str, int]
    by_provider: dict[str, int]


# Collection schemas
class CollectionRequest(BaseModel):
    providers: list[str] | None = None
    resource_types: list[str] | None = None


class CollectionResponse(BaseModel):
    organization: str
    accounts_processed: int
    duration_seconds: float
    errors: list[str]
    summary: dict[str, Any]


# Config snapshot schemas
class ConfigSnapshotResponse(BaseModel):
    snapshot_id: UUID
    resource_id: UUID
    captured_at: datetime
    normalized_config: dict[str, Any]
    collector_version: str
    model_config = ConfigDict(from_attributes=True)


# Policy schemas
class PolicyCreate(BaseModel):
    name: str
    description: str | None = None
    framework: str | None = None


class PolicyResponse(BaseModel):
    policy_id: UUID
    org_id: UUID
    name: str
    description: str | None
    framework: str | None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)
