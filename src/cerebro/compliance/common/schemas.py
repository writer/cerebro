"""
Schema factory functions for compliance operations.

Provides reusable Pydantic schema generators for common patterns
in compliance operations, following Vanta MCP patterns.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from .descriptions import (
    AUTOMATION_LEVEL_DESCRIPTION,
    COMPLIANCE_STATUS_DESCRIPTION,
    CONTROL_ID_DESCRIPTION,
    FRAMEWORK_ID_DESCRIPTION,
    INCLUDE_EVIDENCE_DESCRIPTION,
    INCLUDE_REMEDIATION_DESCRIPTION,
    LIMIT_DESCRIPTION,
    OFFSET_DESCRIPTION,
    ORGANIZATION_ID_DESCRIPTION,
    PAGE_CURSOR_DESCRIPTION,
    PAGE_SIZE_DESCRIPTION,
    PERIOD_END_DESCRIPTION,
    PERIOD_START_DESCRIPTION,
    REPORT_FORMAT_DESCRIPTION,
)


def create_pagination_schema() -> type[BaseModel]:
    """Creates a schema with only pagination parameters."""

    class PaginationSchema(BaseModel):
        page_size: int | None = Field(
            default=25, description=PAGE_SIZE_DESCRIPTION, ge=1, le=100
        )
        page_cursor: str | None = Field(
            default=None, description=PAGE_CURSOR_DESCRIPTION
        )
        offset: int | None = Field(default=0, description=OFFSET_DESCRIPTION, ge=0)
        limit: int | None = Field(
            default=25, description=LIMIT_DESCRIPTION, ge=1, le=100
        )

    return PaginationSchema


def create_id_schema(param_name: str, description: str) -> type[BaseModel]:
    """Creates a schema with a single ID parameter."""

    class IdSchema(BaseModel):
        pass

    # Dynamically add the ID field
    IdSchema.__annotations__ = {param_name: str}

    setattr(IdSchema, param_name, Field(..., description=description))

    return IdSchema


def create_id_with_pagination_schema(
    param_name: str, description: str
) -> type[BaseModel]:
    """Creates a schema with an ID parameter plus pagination."""

    class IdWithPaginationSchema(BaseModel):
        page_size: int | None = Field(
            default=25, description=PAGE_SIZE_DESCRIPTION, ge=1, le=100
        )
        page_cursor: str | None = Field(
            default=None, description=PAGE_CURSOR_DESCRIPTION
        )
        offset: int | None = Field(default=0, description=OFFSET_DESCRIPTION, ge=0)
        limit: int | None = Field(
            default=25, description=LIMIT_DESCRIPTION, ge=1, le=100
        )

    # Dynamically add the ID field
    IdWithPaginationSchema.__annotations__[param_name] = str
    setattr(IdWithPaginationSchema, param_name, Field(..., description=description))

    return IdWithPaginationSchema


def create_filter_schema(custom_fields: dict[str, Any] | None = None) -> type[BaseModel]:
    """Creates a base schema that can be extended with custom fields."""

    class FilterSchema(BaseModel):
        page_size: int | None = Field(
            default=25, description=PAGE_SIZE_DESCRIPTION, ge=1, le=100
        )
        page_cursor: str | None = Field(
            default=None, description=PAGE_CURSOR_DESCRIPTION
        )
        offset: int | None = Field(default=0, description=OFFSET_DESCRIPTION, ge=0)
        limit: int | None = Field(
            default=25, description=LIMIT_DESCRIPTION, ge=1, le=100
        )

    # Add custom fields if provided
    if custom_fields:
        for field_name, field_config in custom_fields.items():
            if isinstance(field_config, dict):
                field_type = field_config.get("type", str)
                field_default = field_config.get("default", None)
                field_description = field_config.get("description", "")

                FilterSchema.__annotations__[field_name] = field_type
                setattr(
                    FilterSchema,
                    field_name,
                    Field(field_default, description=field_description),
                )

    return FilterSchema


def create_compliance_request_schema() -> type[BaseModel]:
    """Creates a schema for compliance evidence generation requests."""

    class ComplianceRequestSchema(BaseModel):
        organization_id: str = Field(..., description=ORGANIZATION_ID_DESCRIPTION)
        framework_id: str = Field(..., description=FRAMEWORK_ID_DESCRIPTION)
        period_start: datetime | None = Field(
            None, description=PERIOD_START_DESCRIPTION
        )
        period_end: datetime | None = Field(None, description=PERIOD_END_DESCRIPTION)
        control_ids: list[str] | None = Field(
            None, description="Specific controls to assess"
        )
        include_evidence: bool = Field(False, description=INCLUDE_EVIDENCE_DESCRIPTION)
        include_remediation: bool = Field(
            True, description=INCLUDE_REMEDIATION_DESCRIPTION
        )
        report_format: str = Field("json", description=REPORT_FORMAT_DESCRIPTION)

    return ComplianceRequestSchema


def create_framework_filter_schema() -> type[BaseModel]:
    """Creates a schema for filtering compliance frameworks."""

    custom_fields = {
        "automation_level": {
            "type": Optional[str],
            "default": None,
            "description": AUTOMATION_LEVEL_DESCRIPTION,
        },
        "framework_matches_any": {
            "type": Optional[list[str]],
            "default": None,
            "description": "List of framework names to match against",
        },
    }

    return create_filter_schema(custom_fields)


def create_control_filter_schema() -> type[BaseModel]:
    """Creates a schema for filtering compliance controls."""

    custom_fields = {
        "framework_id": {
            "type": Optional[str],
            "default": None,
            "description": FRAMEWORK_ID_DESCRIPTION,
        },
        "category": {
            "type": Optional[str],
            "default": None,
            "description": "Filter by control category",
        },
        "automation_level": {
            "type": Optional[str],
            "default": None,
            "description": AUTOMATION_LEVEL_DESCRIPTION,
        },
        "compliance_status": {
            "type": Optional[str],
            "default": None,
            "description": COMPLIANCE_STATUS_DESCRIPTION,
        },
    }

    return create_filter_schema(custom_fields)


def create_evidence_filter_schema() -> type[BaseModel]:
    """Creates a schema for filtering compliance evidence."""

    custom_fields = {
        "control_id": {
            "type": Optional[str],
            "default": None,
            "description": CONTROL_ID_DESCRIPTION,
        },
        "evidence_type": {
            "type": Optional[str],
            "default": None,
            "description": "Filter by evidence type",
        },
        "collected_since": {
            "type": Optional[datetime],
            "default": None,
            "description": "Filter evidence collected since this date",
        },
        "status": {
            "type": Optional[str],
            "default": None,
            "description": "Filter by evidence status",
        },
    }

    return create_filter_schema(custom_fields)


# Standard schemas that can be reused
PaginationSchema = create_pagination_schema()
OrganizationIdSchema = create_id_schema("organization_id", ORGANIZATION_ID_DESCRIPTION)
FrameworkIdSchema = create_id_schema("framework_id", FRAMEWORK_ID_DESCRIPTION)
ControlIdSchema = create_id_schema("control_id", CONTROL_ID_DESCRIPTION)
ComplianceRequestSchema = create_compliance_request_schema()
FrameworkFilterSchema = create_framework_filter_schema()
ControlFilterSchema = create_control_filter_schema()
EvidenceFilterSchema = create_evidence_filter_schema()
