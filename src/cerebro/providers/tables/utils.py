"""Utility functions for provider tables."""

import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


def parse_timestamp_safely(
    timestamp_str: Optional[str], provider: str = "unknown"
) -> Optional[datetime]:
    """
    Parse timestamp string safely with proper error handling.

    Args:
        timestamp_str: Timestamp string to parse
        provider: Provider name for error logging context

    Returns:
        Parsed datetime or None if parsing fails
    """
    if not timestamp_str:
        return None

    try:
        # Handle ISO format with Z timezone
        if timestamp_str.endswith("Z"):
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))

        # Try direct ISO parsing
        return datetime.fromisoformat(timestamp_str)

    except (ValueError, AttributeError) as e:
        logger.warning(f"Failed to parse {provider} timestamp '{timestamp_str}': {e}")
        return None
    except Exception as e:
        logger.error(
            f"Unexpected error parsing {provider} timestamp '{timestamp_str}': {e}"
        )
        return None


def validate_string_input(
    input_str: Optional[str], field_name: str, max_length: int = 255
) -> Optional[str]:
    """
    Validate and sanitize string input safely.

    Args:
        input_str: Input string to validate
        field_name: Field name for error context
        max_length: Maximum allowed length

    Returns:
        Validated string or None if validation fails
    """
    if not input_str:
        return None

    try:
        # Strip whitespace and check length
        cleaned = input_str.strip()
        if len(cleaned) > max_length:
            logger.warning(
                f"{field_name} exceeds max length ({len(cleaned)} > {max_length}): {cleaned[:50]}..."
            )
            return cleaned[:max_length]

        return cleaned

    except (AttributeError, TypeError) as e:
        logger.error(f"Invalid {field_name} type: {type(input_str)} - {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error validating {field_name}: {e}")
        return None


def safe_int_conversion(value, field_name: str, default: int = 0) -> int:
    """
    Safely convert value to integer.

    Args:
        value: Value to convert
        field_name: Field name for error context
        default: Default value if conversion fails

    Returns:
        Integer value or default if conversion fails
    """
    if value is None:
        return default

    try:
        return int(value)
    except (ValueError, TypeError) as e:
        logger.warning(f"Failed to convert {field_name} to int: {value} - {e}")
        return default
    except Exception as e:
        logger.error(f"Unexpected error converting {field_name} to int: {value} - {e}")
        return default


def safe_bool_conversion(value, field_name: str, default: bool = False) -> bool:
    """
    Safely convert value to boolean.

    Args:
        value: Value to convert
        field_name: Field name for error context
        default: Default value if conversion fails

    Returns:
        Boolean value or default if conversion fails
    """
    if value is None:
        return default

    try:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "1", "yes", "on")
        return bool(value)
    except Exception as e:
        logger.warning(f"Failed to convert {field_name} to bool: {value} - {e}")
        return default
