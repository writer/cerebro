"""Base provider class and common interfaces.

Provider adapters implement this contract to surface resources, principals, and
permissions in a way that the collector understands.  The support structures
defined here smooth out cross‑provider behaviour: dataclasses describe the
entities we persist, while helpers such as :func:`authenticated_method` and
``AuthenticationMixin`` ensure consistent authentication flow.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, AsyncGenerator
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID
import logging
import asyncio
from functools import wraps

logger = logging.getLogger(__name__)


def authenticated_method(func):
    """Decorator ensuring the provider is authenticated before executing a method."""

    @wraps(func)
    async def wrapper(self, *args, **kwargs):
        if not self._is_authenticated:
            await self.authenticate()
        return await func(self, *args, **kwargs)

    return wrapper


class ProviderError(Exception):
    """Base exception for provider errors."""

    pass


class AuthenticationMixin:
    """Mixin providing common authentication patterns for providers.

    Example usage in a provider:

    class MyProvider(BaseProvider):
        async def authenticate(self) -> bool:
            def _auth_impl():
                # Your authentication logic here
                self.client = SomeAPIClient(self.credentials)
                # Test the connection
                self.client.get_account_info()
                return True

            return await self.safe_authenticate(_auth_impl)
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._is_authenticated = False
        self._auth_lock = asyncio.Lock()

    async def safe_authenticate(self, auth_func, *args, **kwargs) -> bool:
        """Common authentication pattern with error handling and logging."""
        async with self._auth_lock:
            if self._is_authenticated:
                return True

            try:
                logger.info(f"Authenticating with {self.name} provider")
                success = await self._run_auth_operation(auth_func, *args, **kwargs)

                if success:
                    self._is_authenticated = True
                    logger.info(f"Successfully authenticated with {self.name}")
                    return True
                else:
                    logger.error(f"Authentication failed with {self.name}")
                    return False

            except ProviderError:
                # Re-raise provider errors as-is
                raise
            except Exception as e:
                logger.error(f"Unexpected error during {self.name} authentication: {e}")
                raise ProviderError(f"Authentication failed: {e}")

    async def _run_auth_operation(self, auth_func, *args, **kwargs):
        """Run authentication operation in executor if needed."""
        if asyncio.iscoroutinefunction(auth_func):
            return await auth_func(*args, **kwargs)
        else:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, auth_func, *args, **kwargs)

    def reset_authentication(self):
        """Reset authentication state (useful for credential rotation)."""
        self._is_authenticated = False


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


class BaseProvider(AuthenticationMixin, ABC):
    """Base class for concrete provider implementations."""

    def __init__(self, account_id: UUID, **kwargs):
        """Initialize provider."""
        super().__init__(**kwargs)
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
    @authenticated_method
    async def discover_resources(
        self, resource_types: Optional[List[str]] = None
    ) -> AsyncGenerator[ResourceInfo, None]:
        """Discover resources from the provider."""
        pass

    @abstractmethod
    @authenticated_method
    async def discover_principals(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover principals (users, groups, etc.) from the provider."""
        pass

    @abstractmethod
    @authenticated_method
    async def get_resource_configuration(
        self, resource: ResourceInfo
    ) -> ConfigurationSnapshot:
        """Get the current configuration for a resource."""
        pass

    @abstractmethod
    @authenticated_method
    async def discover_iam_edges(
        self, resource: Optional[ResourceInfo] = None
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
