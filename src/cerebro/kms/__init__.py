"""Key Management Service integrations."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import BaseKMS
from .factory import get_kms

# Optional KMS providers - import errors are handled gracefully
AWSKMS: type[BaseKMS] | None = None
GCPKMS: type[BaseKMS] | None = None
AzureKeyVaultKMS: type[BaseKMS] | None = None
VaultTransitKMS: type[BaseKMS] | None = None

try:
    from .aws_kms import AWSKMS as _AWSKMS

    AWSKMS = _AWSKMS
except ImportError:
    pass

try:
    from .gcp_kms import GCPKMS as _GCPKMS

    GCPKMS = _GCPKMS
except ImportError:
    pass

try:
    from .azure_kms import AzureKeyVaultKMS as _AzureKeyVaultKMS

    AzureKeyVaultKMS = _AzureKeyVaultKMS
except ImportError:
    pass

try:
    from .vault_kms import VaultTransitKMS as _VaultTransitKMS

    VaultTransitKMS = _VaultTransitKMS
except ImportError:
    pass

from .local_kms import LocalKMS, LocalPlaintextKMS

__all__ = [
    "AWSKMS",
    "GCPKMS",
    "AzureKeyVaultKMS",
    "BaseKMS",
    "LocalKMS",
    "LocalPlaintextKMS",
    "VaultTransitKMS",
    "get_kms",
]
