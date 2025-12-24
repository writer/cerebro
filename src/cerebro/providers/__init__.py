"""Provider integrations for Cerebro."""

from __future__ import annotations

from .base import BaseProvider, ProviderError

try:  # pragma: no cover - optional dependency
    from .github import GitHubProvider
except Exception:  # pragma: no cover
    GitHubProvider = None  # type: ignore[misc, assignment]

try:  # pragma: no cover - optional dependency
    from .aws import AWSProvider
except Exception:  # pragma: no cover
    AWSProvider = None  # type: ignore[misc, assignment]

try:  # pragma: no cover - optional dependency
    from .gcp import GCPProvider
except Exception:  # pragma: no cover
    GCPProvider = None  # type: ignore[misc, assignment]

try:  # pragma: no cover - optional dependency
    from .azure import AzureProvider
except Exception:  # pragma: no cover
    AzureProvider = None  # type: ignore[misc, assignment]

try:  # pragma: no cover - optional dependency
    from .workspace import GoogleWorkspaceProvider
except Exception:  # pragma: no cover
    GoogleWorkspaceProvider = None  # type: ignore[misc, assignment]

try:  # pragma: no cover - optional dependency
    from .okta import OktaProvider
except Exception:  # pragma: no cover
    OktaProvider = None  # type: ignore[misc, assignment]

try:  # pragma: no cover - optional dependency
    from .m365 import M365Provider
except Exception:  # pragma: no cover
    M365Provider = None  # type: ignore[misc, assignment]

try:  # pragma: no cover - optional dependency
    from .kubernetes import KubernetesProvider
except Exception:  # pragma: no cover
    KubernetesProvider = None  # type: ignore[misc, assignment]

__all__ = [
    "BaseProvider",
    "ProviderError",
    "GitHubProvider",
    "AWSProvider",
    "GCPProvider",
    "AzureProvider",
    "GoogleWorkspaceProvider",
    "OktaProvider",
    "M365Provider",
    "KubernetesProvider",
]
