"""Database type compatibility layer for cross-database support."""

import json

from sqlalchemy import JSON, String, TypeDecorator
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.engine import Dialect


class JSONType(TypeDecorator):
    """
    Cross-database JSON type that uses JSONB for PostgreSQL and JSON for others.

    This allows the same code to work with both PostgreSQL (production)
    and SQLite (testing) databases.
    """

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect):
        """Load the appropriate type for the dialect."""
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(JSONB())
        else:
            return dialect.type_descriptor(JSON())


class ArrayType(TypeDecorator):
    """
    Cross-database array type that uses ARRAY for PostgreSQL and JSON for others.

    For SQLite and other databases that don't support native arrays,
    arrays are stored as JSON and converted back to lists on retrieval.
    """

    impl = JSON
    cache_ok = True

    def __init__(self, item_type=String, **kwargs):
        self.item_type = item_type
        super().__init__(**kwargs)

    def load_dialect_impl(self, dialect: Dialect):
        """Load the appropriate type for the dialect."""
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(ARRAY(self.item_type))
        else:
            return dialect.type_descriptor(JSON())

    def process_bind_param(self, value, dialect):
        """Process values being sent to the database."""
        if value is None:
            return None
        if dialect.name == 'postgresql':
            return value
        else:
            # For non-PostgreSQL, store as JSON
            return json.dumps(value) if value is not None else None

    def process_result_value(self, value, dialect):
        """Process values being returned from the database."""
        if value is None:
            return None
        if dialect.name == 'postgresql':
            return value
        else:
            # For non-PostgreSQL, parse from JSON
            if isinstance(value, str):
                return json.loads(value)
            return value