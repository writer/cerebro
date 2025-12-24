"""
Provider-specific table implementations for the query engine.

Each provider implements SecurityTable instances that expose their
resources as queryable SQL tables.
"""

# ruff: noqa: F403

from .aws_tables import *
from .gcp_tables import *
from .github_tables import *
from .m365_tables import *
from .okta_tables import *

__all__ = ["register_all_provider_tables"]


def register_all_provider_tables():
    """Register all provider tables with the query engine - hardened against import failures."""
    import importlib
    import logging

    logger = logging.getLogger(__name__)

    registration_functions = [
        ("aws_tables", "register_aws_tables"),
        ("okta_tables", "register_okta_tables"),
        ("github_tables", "register_github_tables"),
        ("gcp_tables", "register_gcp_tables"),
        ("m365_tables", "register_m365_tables"),
    ]

    successful_registrations = 0

    for module_name, function_name in registration_functions:
        try:
            module = importlib.import_module(f".{module_name}", package=__name__)
            register_func = getattr(module, function_name, None)

            if register_func and callable(register_func):
                register_func()
                successful_registrations += 1
                logger.info(f"Successfully registered {module_name} tables")
            else:
                logger.warning(
                    f"Registration function {function_name} not found in {module_name}"
                )

        except ImportError as e:
            logger.warning(f"Failed to import {module_name}: {e}")
        except Exception as e:
            logger.error(f"Failed to register {module_name} tables: {e}")

    logger.info(
        f"Successfully registered {successful_registrations}/{len(registration_functions)} provider table modules"
    )
