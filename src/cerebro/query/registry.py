"""
Table registry for the query engine.

Manages registration and discovery of security tables across all providers.
Inspired by Steampipe's plugin registration pattern.
"""

from typing import Dict, List, Optional, Type
import logging
from collections import defaultdict

from .table import SecurityTable
from ..core.events import emit_event

logger = logging.getLogger(__name__)


class TableRegistry:
    """
    Central registry for all security tables across providers.
    
    Provides table discovery, registration, and lookup functionality.
    Similar to Steampipe's TableMap pattern.
    """
    
    def __init__(self):
        self._tables: Dict[str, SecurityTable] = {}
        self._tables_by_provider: Dict[str, List[str]] = defaultdict(list)
        self._table_aliases: Dict[str, str] = {}
        
    def register_table(self, table: SecurityTable, aliases: Optional[List[str]] = None) -> None:
        """
        Register a security table with the query engine.
        
        Args:
            table: SecurityTable instance to register
            aliases: Optional list of alternative names for the table
        """
        table_name = table.name
        
        # Check for duplicate registration
        if table_name in self._tables:
            logger.warning(f"Table {table_name} already registered, overwriting")
        
        # Register the table
        self._tables[table_name] = table
        
        # Track by provider if it's a provider table
        if hasattr(table, 'provider_name'):
            provider_name = table.provider_name
            self._tables_by_provider[provider_name].append(table_name)
            
        # Register aliases
        if aliases:
            for alias in aliases:
                self._table_aliases[alias] = table_name
                
        logger.info(f"Registered security table: {table_name}")
        emit_event("table_registered", {"table_name": table_name, "provider": getattr(table, 'provider_name', 'unknown')})
    
    def unregister_table(self, table_name: str) -> bool:
        """
        Unregister a table from the registry.
        
        Returns True if table was found and removed.
        """
        if table_name not in self._tables:
            return False
            
        table = self._tables[table_name]
        
        # Remove from main registry
        del self._tables[table_name]
        
        # Remove from provider tracking
        if hasattr(table, 'provider_name'):
            provider_name = table.provider_name
            if table_name in self._tables_by_provider[provider_name]:
                self._tables_by_provider[provider_name].remove(table_name)
                
        # Remove aliases
        aliases_to_remove = [alias for alias, target in self._table_aliases.items() if target == table_name]
        for alias in aliases_to_remove:
            del self._table_aliases[alias]
            
        logger.info(f"Unregistered security table: {table_name}")
        emit_event("table_unregistered", {"table_name": table_name})
        return True
    
    def get_table(self, table_name: str) -> Optional[SecurityTable]:
        """
        Get a registered table by name or alias.
        """
        # Try direct lookup first
        if table_name in self._tables:
            return self._tables[table_name]
            
        # Try alias lookup
        if table_name in self._table_aliases:
            actual_name = self._table_aliases[table_name]
            return self._tables.get(actual_name)
            
        return None
    
    def list_tables(self, provider: Optional[str] = None) -> List[str]:
        """
        List all registered table names, optionally filtered by provider.
        """
        if provider:
            return self._tables_by_provider.get(provider, [])
        
        return list(self._tables.keys())
    
    def list_providers(self) -> List[str]:
        """List all providers that have registered tables."""
        return list(self._tables_by_provider.keys())
    
    def get_table_info(self, table_name: str) -> Optional[Dict]:
        """
        Get detailed information about a table.
        """
        table = self.get_table(table_name)
        if not table:
            return None
            
        return {
            "name": table.name,
            "description": table.description,
            "provider": getattr(table, 'provider_name', 'unknown'),
            "columns": [
                {
                    "name": col.name,
                    "type": col.type.value,
                    "description": col.description,
                    "required": col.required,
                    "filterable": col.filterable,
                }
                for col in table.columns
            ],
            "indexes": [
                {
                    "name": idx.name,
                    "columns": idx.columns,
                    "unique": idx.unique,
                }
                for idx in table.indexes
            ],
        }
    
    def find_tables_by_pattern(self, pattern: str) -> List[str]:
        """
        Find tables matching a pattern (supports wildcards).
        
        Examples:
        - "aws_*" -> all AWS tables
        - "*_user" -> all user tables
        - "*alert*" -> all tables containing 'alert'
        """
        import fnmatch
        
        matching_tables = []
        for table_name in self._tables.keys():
            if fnmatch.fnmatch(table_name, pattern):
                matching_tables.append(table_name)
                
        return matching_tables
    
    def get_schema_summary(self) -> Dict:
        """
        Get a summary of all registered tables and their schemas.
        
        Useful for query planning and introspection.
        """
        summary = {
            "total_tables": len(self._tables),
            "providers": list(self._tables_by_provider.keys()),
            "tables_by_provider": dict(self._tables_by_provider),
            "tables": {}
        }
        
        for table_name, table in self._tables.items():
            summary["tables"][table_name] = {
                "columns": len(table.columns),
                "filterable_columns": len([c for c in table.columns if c.filterable]),
                "provider": getattr(table, 'provider_name', 'unknown'),
                "description": table.description,
            }
            
        return summary
    
    def validate_query_tables(self, table_names: List[str]) -> Dict[str, List[str]]:
        """
        Validate that all referenced table names exist.
        
        Returns dict with 'valid' and 'invalid' lists.
        """
        valid_tables = []
        invalid_tables = []
        
        for table_name in table_names:
            if self.get_table(table_name):
                valid_tables.append(table_name)
            else:
                invalid_tables.append(table_name)
                
        return {
            "valid": valid_tables,
            "invalid": invalid_tables,
        }


# Global registry instance
_global_registry = TableRegistry()


def get_registry() -> TableRegistry:
    """Get the global table registry instance."""
    return _global_registry


def register_table(table: SecurityTable, aliases: Optional[List[str]] = None) -> None:
    """Register a table with the global registry."""
    _global_registry.register_table(table, aliases)


def get_table(table_name: str) -> Optional[SecurityTable]:
    """Get a table from the global registry."""
    return _global_registry.get_table(table_name)


def list_tables(provider: Optional[str] = None) -> List[str]:
    """List tables from the global registry."""
    return _global_registry.list_tables(provider)


# Decorator for automatic table registration
def security_table(name: Optional[str] = None, aliases: Optional[List[str]] = None):
    """
    Decorator to automatically register a SecurityTable class.
    
    Usage:
        @security_table(aliases=['alerts'])
        class CrowdStrikeAlertTable(SecurityTable):
            ...
    """
    def decorator(cls: Type[SecurityTable]):
        def register_instance(*args, **kwargs):
            instance = cls(*args, **kwargs)
            if name:
                instance.name = name
            register_table(instance, aliases)
            return instance
        return register_instance
    return decorator


# Context manager for bulk table operations
class TableRegistrationContext:
    """Context manager for bulk table registration/unregistration."""
    
    def __init__(self):
        self._registered_tables = []
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Cleanup on error
        if exc_type:
            for table_name in self._registered_tables:
                _global_registry.unregister_table(table_name)
                
    def register_table(self, table: SecurityTable, aliases: Optional[List[str]] = None):
        """Register a table within this context."""
        register_table(table, aliases)
        self._registered_tables.append(table.name)
