"""
Simple event system for Cerebro.

Provides basic event emission for logging and monitoring.
"""

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


def emit_event(event_type: str, data: Dict[str, Any]) -> None:
    """
    Emit an event for logging/monitoring purposes.
    
    Args:
        event_type: Type of event (e.g., "table_registered", "query_executed")
        data: Event data dictionary
    """
    logger.info(f"Event: {event_type}", extra={"event_data": data})
