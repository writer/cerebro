"""Minimal change attestation stubs for testing."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class AttestationType(Enum):
    CHANGE = "change"
    ACCESS_REVIEW = "access_review"
    INCIDENT = "incident"


@dataclass
class SignedAttestation:
    change_id: str
    signed_at: datetime
    signer: str
    metadata: Dict[str, Any]


class ChangeAttestationService:
    """Service that issues simple signed attestations."""

    async def create_attestation(
        self, change_id: str, signer: str, **metadata: Any
    ) -> SignedAttestation:  # pragma: no cover
        return SignedAttestation(
            change_id=change_id,
            signed_at=datetime.utcnow(),
            signer=signer,
            metadata=metadata,
        )


_DEFAULT_ATTESTATION_SERVICE: Optional[ChangeAttestationService] = None


def get_attestation_service() -> ChangeAttestationService:
    """Return a shared attestation service instance."""

    global _DEFAULT_ATTESTATION_SERVICE
    if _DEFAULT_ATTESTATION_SERVICE is None:
        _DEFAULT_ATTESTATION_SERVICE = ChangeAttestationService()
    return _DEFAULT_ATTESTATION_SERVICE
