"""Provider plugin registry system."""

from typing import Dict, Type, List, Any, Optional, Callable
import logging
import importlib
import pkgutil

from cerebro.domain.ports import ProviderPort

logger = logging.getLogger(__name__)


class ProviderRegistry:
    """Registry for provider plugins."""

    def __init__(self):
        """Initialize provider registry."""
        self._providers: Dict[str, Type[ProviderPort]] = {}
        self._factories: Dict[str, Callable] = {}

    def register(
        self,
        name: str,
        provider_class: Type[ProviderPort],
        factory: Optional[Callable] = None,
    ) -> None:
        """Register a provider class."""
        if name in self._providers:
            logger.warning(f"Provider {name} already registered, overriding")

        self._providers[name] = provider_class
        if factory:
            self._factories[name] = factory

        logger.info(f"Registered provider: {name}")

    def get_provider_class(self, name: str) -> Type[ProviderPort]:
        """Get provider class by name."""
        if name not in self._providers:
            raise ValueError(f"Unknown provider: {name}")

        return self._providers[name]

    def create_provider(self, name: str, **kwargs) -> ProviderPort:
        """Create provider instance."""
        if name not in self._providers:
            raise ValueError(f"Unknown provider: {name}")

        if name in self._factories:
            # Use custom factory
            return self._factories[name](**kwargs)
        else:
            # Use default constructor
            provider_class = self._providers[name]
            return provider_class(**kwargs)

    def list_providers(self) -> List[str]:
        """List all registered providers."""
        return list(self._providers.keys())

    def get_provider_info(self, name: str) -> Dict[str, Any]:
        """Get provider information."""
        if name not in self._providers:
            raise ValueError(f"Unknown provider: {name}")

        provider_class = self._providers[name]

        return {
            "name": name,
            "class": provider_class.__name__,
            "module": provider_class.__module__,
            "doc": provider_class.__doc__,
            "has_factory": name in self._factories,
        }

    def auto_discover_providers(self, package_name: str = "cerebro.providers") -> int:
        """Auto-discover providers in a package."""
        discovered = 0

        try:
            package = importlib.import_module(package_name)

            # Walk through all modules in the package
            for importer, modname, ispkg in pkgutil.walk_packages(
                package.__path__, package.__name__ + "."
            ):
                try:
                    module = importlib.import_module(modname)

                    # Look for classes that implement ProviderPort
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)

                        if (
                            isinstance(attr, type)
                            and hasattr(attr, "name")
                            and callable(getattr(attr, "authenticate", None))
                        ):

                            # Try to get provider name
                            try:
                                instance: Any = object.__new__(attr)  # type: ignore[type-var]
                                provider_name = instance.name
                                self.register(provider_name, attr)
                                discovered += 1
                            except Exception as e:
                                logger.debug(
                                    f"Could not auto-register {attr_name}: {e}"
                                )

                except ImportError as e:
                    logger.debug(f"Could not import {modname}: {e}")

        except ImportError as e:
            logger.warning(f"Could not discover providers in {package_name}: {e}")

        logger.info(f"Auto-discovered {discovered} providers")
        return discovered


# Global registry instance
provider_registry = ProviderRegistry()


def register_provider(name: Optional[str] = None, factory: Optional[Callable] = None):
    """Decorator to register a provider class.

    Usage:
        @register_provider("github")
        class GitHubProvider:
            ...

        @register_provider("aws", factory=create_aws_provider)
        class AWSProvider:
            ...
    """

    def decorator(cls: Type[ProviderPort]) -> Type[ProviderPort]:
        provider_name = name
        if provider_name is None:
            # Try to get name from class
            if hasattr(cls, "name"):
                try:
                    instance = cls.__new__(cls)
                    provider_name = instance.name
                except Exception:
                    provider_name = cls.__name__.lower().replace("provider", "")
            else:
                provider_name = cls.__name__.lower().replace("provider", "")

        provider_registry.register(provider_name, cls, factory)
        return cls

    return decorator


def get_provider_registry() -> ProviderRegistry:
    """Get the global provider registry."""
    return provider_registry


# Example usage and built-in factories
def create_github_provider(account_id: str, org_name: str, **kwargs):
    """Factory for GitHub provider."""
    from cerebro.providers.github import GitHubProvider

    return GitHubProvider(account_id=account_id, org_name=org_name, **kwargs)


def create_aws_provider(
    account_id: str, aws_account_id: str, region: Optional[str] = None, **kwargs: Any
) -> Any:
    """Factory for AWS provider."""
    from cerebro.providers.aws import AWSProvider

    return AWSProvider(
        account_id=account_id, aws_account_id=aws_account_id, region=region, **kwargs
    )


# Enhanced provider factories
def create_enhanced_gcp_provider(account_id: str, project_id: str, **kwargs):
    """Factory for enhanced GCP provider."""
    from cerebro.providers.gcp.enhanced_provider import EnhancedGCPProvider

    return EnhancedGCPProvider(account_id=account_id, project_id=project_id, **kwargs)


def create_google_workspace_provider(
    account_id: str,
    domain: str,
    service_account_file: str,
    delegate_user: str,
    **kwargs,
):
    """Factory for Google Workspace provider."""
    from cerebro.providers.workspace.provider import GoogleWorkspaceProvider

    return GoogleWorkspaceProvider(
        account_id=account_id,  # type: ignore[arg-type]
        domain=domain,
        service_account_file=service_account_file,
        delegate_user=delegate_user,
        **kwargs,
    )


# Register built-in providers with factories
provider_registry.register("github", None, create_github_provider)  # type: ignore[arg-type]
provider_registry.register("aws", None, create_aws_provider)  # type: ignore[arg-type]
provider_registry.register("gcp_enhanced", None, create_enhanced_gcp_provider)  # type: ignore[arg-type]
provider_registry.register("google_workspace", None, create_google_workspace_provider)  # type: ignore[arg-type]


def init_providers():
    """Initialize provider registry with auto-discovery."""
    # Auto-discover providers
    provider_registry.auto_discover_providers()

    logger.info(
        f"Provider registry initialized with: {provider_registry.list_providers()}"
    )


# CLI helper
def list_available_providers() -> List[Dict[str, Any]]:
    """List all available providers with details."""
    providers = []

    for name in provider_registry.list_providers():
        try:
            info = provider_registry.get_provider_info(name)
            providers.append(info)
        except Exception as e:
            logger.warning(f"Could not get info for provider {name}: {e}")

    return providers
