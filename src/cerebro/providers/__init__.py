"""Provider integrations for Cerebro."""

from __future__ import annotations

from .base import BaseProvider, ProviderError

# Optional provider imports - handle missing dependencies gracefully
GitHubProvider: type[BaseProvider] | None = None
AWSProvider: type[BaseProvider] | None = None
GCPProvider: type[BaseProvider] | None = None
AzureProvider: type[BaseProvider] | None = None
GoogleWorkspaceProvider: type[BaseProvider] | None = None
OktaProvider: type[BaseProvider] | None = None
M365Provider: type[BaseProvider] | None = None
KubernetesProvider: type[BaseProvider] | None = None

try:
    from .github import GitHubProvider as _GitHubProvider

    GitHubProvider = _GitHubProvider
except ImportError:
    pass

try:
    from .aws import AWSProvider as _AWSProvider

    AWSProvider = _AWSProvider
except ImportError:
    pass

try:
    from .gcp import GCPProvider as _GCPProvider

    GCPProvider = _GCPProvider
except ImportError:
    pass

try:
    from .azure import AzureProvider as _AzureProvider

    AzureProvider = _AzureProvider
except ImportError:
    pass

try:
    from .workspace import GoogleWorkspaceProvider as _GoogleWorkspaceProvider

    GoogleWorkspaceProvider = _GoogleWorkspaceProvider
except ImportError:
    pass

try:
    from .okta import OktaProvider as _OktaProvider

    OktaProvider = _OktaProvider
except ImportError:
    pass

try:
    from .m365 import M365Provider as _M365Provider

    M365Provider = _M365Provider
except ImportError:
    pass

try:
    from .kubernetes import KubernetesProvider as _KubernetesProvider

    KubernetesProvider = _KubernetesProvider
except ImportError:
    pass

__all__ = [
    "AWSProvider",
    "AzureProvider",
    "BaseProvider",
    "GCPProvider",
    "GitHubProvider",
    "GoogleWorkspaceProvider",
    "KubernetesProvider",
    "M365Provider",
    "OktaProvider",
    "ProviderError",
]
