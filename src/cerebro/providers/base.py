"""Base provider class and common interfaces."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, AsyncGenerator
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID
import logging

logger = logging.getLogger(__name__)


class ProviderError(Exception):
    """Base exception for provider errors."""
    pass


@dataclass
class ResourceInfo:
    """Information about a discovered resource."""
    external_id: str
    name: Optional[str]
    resource_type: str
    parent_external_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class PrincipalInfo:
    """Information about a discovered principal."""
    external_id: str
    principal_type: str  # user, group, service_account, app, role
    email: Optional[str] = None
    display_name: Optional[str] = None
    is_human: Optional[bool] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class ConfigurationSnapshot:
    """Configuration snapshot for a resource."""
    resource_external_id: str
    captured_at: datetime
    normalized_config: Dict[str, Any]
    raw_config: Optional[Dict[str, Any]] = None


@dataclass
class IamPermission:
    """IAM permission edge."""
    principal_external_id: str
    resource_external_id: Optional[str]
    permission: str
    via: Optional[str] = None
    effective_at: datetime = None
    expires_at: Optional[datetime] = None
    is_admin: bool = False


class BaseProvider(ABC):
    """Base class for all providers."""
    
    def __init__(self, account_id: UUID, **kwargs):
        """Initialize provider."""
        self.account_id = account_id
        self.provider_name = self.name
        self._client = None
        
    @property
    @abstractmethod
    def name(self) -> str:
        """Get the provider name (e.g., 'github', 'aws', 'gcp')."""
        pass
    
    @abstractmethod
    async def authenticate(self) -> bool:
        """Authenticate with the provider."""
        pass
    
    @abstractmethod
    async def discover_resources(
        self, 
        resource_types: Optional[List[str]] = None
    ) -> AsyncGenerator[ResourceInfo, None]:
        """Discover resources from the provider."""
        pass
    
    @abstractmethod
    async def discover_principals(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover principals (users, groups, etc.) from the provider."""
        pass
    
    @abstractmethod
    async def get_resource_configuration(
        self, 
        resource: ResourceInfo
    ) -> ConfigurationSnapshot:
        """Get the current configuration for a resource."""
        pass
    
    @abstractmethod
    async def discover_iam_edges(
        self,
        resource: Optional[ResourceInfo] = None
    ) -> AsyncGenerator[IamPermission, None]:
        """Discover IAM permissions/edges."""
        pass
    
    async def test_connection(self) -> bool:
        """Test connection to the provider."""
        try:
            return await self.authenticate()
        except Exception as e:
            logger.error(f"Connection test failed for {self.provider_name}: {e}")
            return False
    
    async def get_account_info(self) -> Dict[str, Any]:
        """Get account information."""
        return {
            "provider": self.name,
            "account_id": str(self.account_id),
        }
    
    def normalize_resource_type(self, raw_type: str) -> str:
        """Normalize resource type name."""
        return f"{self.name}.{raw_type.lower()}"
    
    def normalize_permission(self, permission: str) -> str:
        """Normalize permission name."""
        return permission.lower()
