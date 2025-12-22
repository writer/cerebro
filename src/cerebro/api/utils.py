"""Common utilities for API routers to reduce code duplication."""

from typing import Any, Dict, List, Optional, Type, TypeVar
from uuid import UUID
from fastapi import HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import DeclarativeBase
from pydantic import BaseModel

T = TypeVar("T", bound=DeclarativeBase)
ResponseT = TypeVar("ResponseT", bound=BaseModel)


class StandardFilters:
    """Common filter parameters for list endpoints."""

    def __init__(
        self,
        skip: int = Query(0, ge=0, description="Number of items to skip"),
        limit: int = Query(
            100, ge=1, le=1000, description="Maximum number of items to return"
        ),
        account_id: Optional[UUID] = Query(None, description="Filter by account ID"),
        provider: Optional[str] = Query(None, description="Filter by provider"),
    ):
        self.skip = skip
        self.limit = limit
        self.account_id = account_id
        self.provider = provider


async def get_entity_by_id_or_404(
    db: AsyncSession,
    model: Type[T],
    entity_id: UUID,
    error_message: Optional[str] = None,
) -> T:
    """Get an entity by ID or raise 404 if not found."""
    entity = await db.get(model, entity_id)
    if not entity:
        message = error_message or f"{model.__name__} not found"
        raise HTTPException(status_code=404, detail=message)
    return entity


def build_filtered_query(
    model: Type[T],
    filters: StandardFilters,
    additional_filters: Optional[Dict[str, Any]] = None,
):
    """Build a filtered SQLAlchemy query with standard filters."""
    stmt = select(model)

    # Apply standard filters
    if filters.account_id:
        stmt = stmt.where(getattr(model, "account_id", None) == filters.account_id)
    if filters.provider:
        stmt = stmt.where(getattr(model, "provider", None) == filters.provider)

    # Apply additional filters
    if additional_filters:
        for field, value in additional_filters.items():
            if value is not None:
                stmt = stmt.where(getattr(model, field, None) == value)

    return stmt.offset(filters.skip).limit(filters.limit)


async def paginated_list(
    db: AsyncSession,
    model: Type[T],
    filters: StandardFilters,
    additional_filters: Optional[Dict[str, Any]] = None,
    order_by_field: str = "created_at",
    order_desc: bool = True,
) -> List[T]:
    """Execute a paginated list query with standard filters."""
    stmt = build_filtered_query(model, filters, additional_filters)

    # Add ordering
    order_field = getattr(model, order_by_field, None)
    if order_field is not None:
        if order_desc:
            stmt = stmt.order_by(order_field.desc())
        else:
            stmt = stmt.order_by(order_field)

    result = await db.scalars(stmt)
    return list(result)


class StandardResponses:
    """Standard HTTP response patterns."""

    @staticmethod
    def not_found(entity_type: str) -> HTTPException:
        """Standard 404 response."""
        return HTTPException(status_code=404, detail=f"{entity_type} not found")

    @staticmethod
    def bad_request(message: str) -> HTTPException:
        """Standard 400 response."""
        return HTTPException(status_code=400, detail=message)

    @staticmethod
    def forbidden(message: str = "Forbidden") -> HTTPException:
        """Standard 403 response."""
        return HTTPException(status_code=403, detail=message)

    @staticmethod
    def internal_error(message: str = "Internal server error") -> HTTPException:
        """Standard 500 response."""
        return HTTPException(status_code=500, detail=message)


def validate_uuid_or_400(uuid_str: str, field_name: str = "ID") -> UUID:
    """Validate UUID string or raise 400 error."""
    try:
        return UUID(uuid_str)
    except ValueError:
        raise StandardResponses.bad_request(f"Invalid {field_name} format")


def handle_database_error(e: Exception, operation: str = "database operation"):
    """Handle common database errors with appropriate HTTP responses."""
    error_msg = str(e).lower()

    if "foreign key" in error_msg:
        raise StandardResponses.bad_request("Referenced entity not found")
    elif "unique constraint" in error_msg:
        raise StandardResponses.bad_request("Entity already exists")
    elif "not null constraint" in error_msg:
        raise StandardResponses.bad_request("Required field missing")
    else:
        # Log the full error for debugging
        import logging

        logger = logging.getLogger(__name__)
        logger.error(f"Database error during {operation}: {e}")
        raise StandardResponses.internal_error(f"Failed to complete {operation}")
