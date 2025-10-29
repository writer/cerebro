"""Central logging configuration for Cerebro."""

from __future__ import annotations

import logging
from typing import Optional

import structlog

_configured = False


def configure_structlog(level: Optional[int] = None) -> None:
    """Configure structlog for application-wide logging.

    Parameters
    ----------
    level:
        Optional logging level override.  When omitted the value from
        :mod:`cerebro.core.config.settings` is used.
    """

    global _configured
    if _configured:
        return

    from cerebro.core.config import settings

    level_value = level if level is not None else getattr(logging, settings.log_level.upper(), logging.INFO)
    log_format = (settings.log_format or "json").lower()

    if log_format == "json":
        logging.basicConfig(level=level_value)
        processors = [
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    else:
        logging.basicConfig(
            level=level_value,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
        processors = [
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.dev.ConsoleRenderer(colors=False),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level_value),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    _configured = True
