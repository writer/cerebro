"""Key Management Service integrations."""

from __future__ import annotations

from .base import BaseKMS
from .factory import get_kms

try:  # pragma: no cover - optional providers
    from .aws_kms import AWSKMS
except Exception:  # pragma: no cover
    AWSKMS = None  # type: ignore[assignment,misc]

try:  # pragma: no cover - optional providers
    from .gcp_kms import GCPKMS
except Exception:  # pragma: no cover
    GCPKMS = None  # type: ignore[assignment,misc]

try:  # pragma: no cover - optional providers
    from .azure_kms import AzureKeyVaultKMS
except Exception:  # pragma: no cover
    AzureKeyVaultKMS = None  # type: ignore[assignment,misc]

try:  # pragma: no cover - optional providers
    from .vault_kms import VaultTransitKMS
except Exception:  # pragma: no cover
    VaultTransitKMS = None  # type: ignore[assignment,misc]

from .local_kms import LocalPlaintextKMS, LocalKMS

__all__ = [
    "BaseKMS",
    "get_kms",
    "AWSKMS",
    "GCPKMS",
    "AzureKeyVaultKMS",
    "VaultTransitKMS",
    "LocalPlaintextKMS",
    "LocalKMS",
]
