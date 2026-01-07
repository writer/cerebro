"""Standardized pagination for Cerebro API.

This module provides consistent cursor-based pagination across all endpoints.
"""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any, Generic, TypeVar
from uuid import UUID

from fastapi import Query, Response
from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginationParams(BaseModel):
    """Standard pagination parameters."""

    cursor: str | None = Field(
        None,
        description="Opaque cursor for pagination. Use the value from next_cursor or prev_cursor.",
    )
    limit: int = Field(
        50,
        ge=1,
        le=1000,
        description="Maximum number of items to return (1-1000).",
    )
    sort_by: str | None = Field(
        None,
        description="Field to sort by (e.g., 'created_at', '-updated_at' for descending).",
    )


class PaginationMeta(BaseModel):
    """Pagination metadata included in responses."""

    total: int | None = Field(
        None,
        description="Total number of items (only included when available).",
    )
    limit: int = Field(..., description="Maximum items per page.")
    has_more: bool = Field(..., description="Whether there are more items after this page.")
    next_cursor: str | None = Field(
        None,
        description="Cursor to fetch the next page. Null if no more pages.",
    )
    prev_cursor: str | None = Field(
        None,
        description="Cursor to fetch the previous page. Null if on first page.",
    )


class PaginatedResponse(BaseModel, Generic[T]):
    """Standard paginated response envelope."""

    items: list[T] = Field(..., description="List of items in this page.")
    pagination: PaginationMeta = Field(..., description="Pagination metadata.")


class CursorData(BaseModel):
    """Internal cursor data structure."""

    # Primary key field and value for cursor position
    pk_field: str = "id"
    pk_value: Any

    # Sort field and value (if different from pk)
    sort_field: str | None = None
    sort_value: Any | None = None
    sort_desc: bool = False

    # Direction
    direction: str = "next"  # "next" or "prev"


def encode_cursor(data: CursorData) -> str:
    """Encode cursor data to an opaque string."""
    # Serialize to JSON, then base64 encode
    json_str = data.model_dump_json()
    return base64.urlsafe_b64encode(json_str.encode()).decode()


def decode_cursor(cursor: str) -> CursorData | None:
    """Decode cursor string back to cursor data."""
    try:
        json_str = base64.urlsafe_b64decode(cursor.encode()).decode()
        return CursorData.model_validate_json(json_str)
    except Exception:
        return None


def create_next_cursor(
    last_item: Any,
    pk_field: str = "id",
    sort_field: str | None = None,
    sort_desc: bool = False,
) -> str | None:
    """Create a cursor pointing to the next page after the last item."""
    if last_item is None:
        return None

    pk_value = getattr(last_item, pk_field, None)
    if pk_value is None:
        return None

    # Handle UUID serialization
    if isinstance(pk_value, UUID):
        pk_value = str(pk_value)
    elif isinstance(pk_value, datetime):
        pk_value = pk_value.isoformat()

    sort_value = None
    if sort_field and sort_field != pk_field:
        sort_value = getattr(last_item, sort_field, None)
        if isinstance(sort_value, UUID):
            sort_value = str(sort_value)
        elif isinstance(sort_value, datetime):
            sort_value = sort_value.isoformat()

    cursor_data = CursorData(
        pk_field=pk_field,
        pk_value=pk_value,
        sort_field=sort_field,
        sort_value=sort_value,
        sort_desc=sort_desc,
        direction="next",
    )
    return encode_cursor(cursor_data)


def create_prev_cursor(
    first_item: Any,
    pk_field: str = "id",
    sort_field: str | None = None,
    sort_desc: bool = False,
) -> str | None:
    """Create a cursor pointing to the previous page before the first item."""
    if first_item is None:
        return None

    pk_value = getattr(first_item, pk_field, None)
    if pk_value is None:
        return None

    # Handle UUID serialization
    if isinstance(pk_value, UUID):
        pk_value = str(pk_value)
    elif isinstance(pk_value, datetime):
        pk_value = pk_value.isoformat()

    sort_value = None
    if sort_field and sort_field != pk_field:
        sort_value = getattr(first_item, sort_field, None)
        if isinstance(sort_value, UUID):
            sort_value = str(sort_value)
        elif isinstance(sort_value, datetime):
            sort_value = sort_value.isoformat()

    cursor_data = CursorData(
        pk_field=pk_field,
        pk_value=pk_value,
        sort_field=sort_field,
        sort_value=sort_value,
        sort_desc=sort_desc,
        direction="prev",
    )
    return encode_cursor(cursor_data)


def paginate(
    items: list[T],
    limit: int,
    pk_field: str = "id",
    sort_field: str | None = None,
    sort_desc: bool = False,
    total: int | None = None,
    cursor: str | None = None,
) -> PaginatedResponse[T]:
    """
    Create a paginated response from a list of items.

    Args:
        items: List of items (should be limit + 1 to detect has_more)
        limit: Requested page size
        pk_field: Primary key field name for cursor creation
        sort_field: Sort field name (if different from pk)
        sort_desc: Whether sorting is descending
        total: Total count (optional, expensive for large datasets)
        cursor: Current cursor being used

    Returns:
        PaginatedResponse with items and pagination metadata
    """
    has_more = len(items) > limit
    page_items = items[:limit] if has_more else items

    next_cursor = None
    prev_cursor = None

    if page_items:
        if has_more:
            next_cursor = create_next_cursor(
                page_items[-1], pk_field, sort_field, sort_desc
            )

        # Only create prev_cursor if we're not on the first page
        if cursor:
            prev_cursor = create_prev_cursor(
                page_items[0], pk_field, sort_field, sort_desc
            )

    return PaginatedResponse(
        items=page_items,
        pagination=PaginationMeta(
            total=total,
            limit=limit,
            has_more=has_more,
            next_cursor=next_cursor,
            prev_cursor=prev_cursor,
        ),
    )


def add_pagination_headers(
    response: Response,
    pagination: PaginationMeta,
    base_url: str,
) -> None:
    """
    Add RFC 5988 Link headers for pagination.

    Args:
        response: FastAPI Response object
        pagination: Pagination metadata
        base_url: Base URL for the endpoint
    """
    links = []

    if pagination.next_cursor:
        next_url = f"{base_url}?cursor={pagination.next_cursor}&limit={pagination.limit}"
        links.append(f'<{next_url}>; rel="next"')

    if pagination.prev_cursor:
        prev_url = f"{base_url}?cursor={pagination.prev_cursor}&limit={pagination.limit}"
        links.append(f'<{prev_url}>; rel="prev"')

    # First page link (no cursor)
    first_url = f"{base_url}?limit={pagination.limit}"
    links.append(f'<{first_url}>; rel="first"')

    if links:
        response.headers["Link"] = ", ".join(links)

    # Add total count header if available
    if pagination.total is not None:
        response.headers["X-Total-Count"] = str(pagination.total)

    # Add has-more header for easy checking
    response.headers["X-Has-More"] = str(pagination.has_more).lower()


# FastAPI dependency for pagination parameters
def get_pagination_params(
    cursor: str | None = Query(
        None,
        description="Opaque cursor from previous response",
        example="eyJwa19maWVsZCI6ImlkIiwicGtfdmFsdWUiOiIxMjM0NSJ9",
    ),
    limit: int = Query(
        50,
        ge=1,
        le=1000,
        description="Maximum items per page",
    ),
    sort: str | None = Query(
        None,
        description="Sort field (prefix with - for descending)",
        example="-created_at",
    ),
) -> PaginationParams:
    """FastAPI dependency for standard pagination parameters."""
    return PaginationParams(
        cursor=cursor,
        limit=limit,
        sort_by=sort,
    )
