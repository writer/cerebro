"""
Provider-specific table implementations for the query engine.

Each provider implements SecurityTable instances that expose their
resources as queryable SQL tables.
"""

from .aws_tables import *
from .okta_tables import *
from .github_tables import *

__all__ = ['register_all_provider_tables']


def register_all_provider_tables():
    """Register all provider tables with the query engine."""
    from .aws_tables import register_aws_tables
    from .okta_tables import register_okta_tables
    from .github_tables import register_github_tables
    
    register_aws_tables()
    register_okta_tables() 
    register_github_tables()
