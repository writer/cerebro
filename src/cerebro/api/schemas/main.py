"""Pydantic schemas for API requests and responses."""

from typing import Any, Dict, List, Optional
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, Field


# Base schemas
class BaseResponse(BaseModel):
    """Base response schema."""
    success: bool = True
    message: Optional[str] = None


# Organization schemas
class OrganizationCreate(BaseModel):
    name: str = Field(..., description="Organization name")


class OrganizationResponse(BaseModel):
    org_id: UUID
    name: str
    created_at: datetime

    class Config:
        from_attributes = True


# Account schemas
class AccountCreate(BaseModel):
    org_id: UUID
    provider: str = Field(..., description="Provider name (github, aws, gcp, google_workspace)")
    external_id: str = Field(..., description="Provider-specific account ID")
    display_name: Optional[str] = None


class AccountResponse(BaseModel):
    account_id: UUID
    org_id: UUID
    provider: str
    external_id: str
    display_name: Optional[str]

    class Config:
        from_attributes = True


# Resource schemas
class ResourceResponse(BaseModel):
    resource_id: UUID
    account_id: UUID
    provider: str
    resource_type: str
    external_id: str
    name: Optional[str]
    parent_external_id: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


# Principal schemas
class PrincipalResponse(BaseModel):
    principal_id: UUID
    account_id: UUID
    provider: str
    principal_type: str
    external_id: str
    email: Optional[str]
    display_name: Optional[str]
    is_human: Optional[bool]

    class Config:
        from_attributes = True


# Rule schemas
class RuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    provider: List[str] = Field(..., description="List of applicable providers")
    resource_types: Optional[List[str]] = None
    expression_lang: str = Field(default="cel", description="Expression language (cel, sql, rego)")
    expression: str = Field(..., description="Rule expression")
    severity: str = Field(..., description="Severity level")
    policy_id: Optional[UUID] = None
    cwe: Optional[List[str]] = None
    cis: Optional[List[str]] = None
    nist_800_53: Optional[List[str]] = None
    mitre_attack: Optional[List[str]] = None


class RuleResponse(BaseModel):
    rule_id: UUID
    policy_id: Optional[UUID]
    name: str
    description: Optional[str]
    provider: List[str]
    resource_types: Optional[List[str]]
    expression_lang: str
    expression: str
    severity: str
    cwe: Optional[List[str]]
    cis: Optional[List[str]]
    nist_800_53: Optional[List[str]]
    mitre_attack: Optional[List[str]]
    version: int
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# Finding schemas
class FindingResponse(BaseModel):
    finding_id: UUID
    org_id: UUID
    account_id: UUID
    provider: str
    rule_id: UUID
    rule_version: int
    resource_id: Optional[UUID]
    principal_id: Optional[UUID]
    first_seen: datetime
    last_seen: datetime
    status: str
    severity: str
    fingerprint: str
    title: str
    summary: Optional[str]
    evidence: Optional[Dict[str, Any]]

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    

class FindingStats(BaseModel):
    total: int
    by_status: Dict[str, int]
    by_severity: Dict[str, int]
    by_provider: Dict[str, int]


# Collection schemas
class CollectionRequest(BaseModel):
    providers: Optional[List[str]] = None
    resource_types: Optional[List[str]] = None


class CollectionResponse(BaseModel):
    organization: str
    accounts_processed: int
    duration_seconds: float
    errors: List[str]
    summary: Dict[str, Any]


# Config snapshot schemas
class ConfigSnapshotResponse(BaseModel):
    snapshot_id: UUID
    resource_id: UUID
    captured_at: datetime
    normalized_config: Dict[str, Any]
    collector_version: str

    class Config:
        from_attributes = True


# Policy schemas
class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    framework: Optional[str] = None


class PolicyResponse(BaseModel):
    policy_id: UUID
    org_id: UUID
    name: str
    description: Optional[str]
    framework: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
