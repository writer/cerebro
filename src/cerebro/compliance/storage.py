"""
Evidence storage backend implementations with dependency injection.

Provides pluggable storage backends that fix the architectural violations
in the original evidence storage implementations.
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import aiofiles
import structlog

from .models import (
    BaseEvidenceMetadata,
    EvidenceBundle,
    EvidenceRepository,
    EvidenceStatus,
)

logger = structlog.get_logger(__name__)


class FileBasedEvidenceRepository(EvidenceRepository):
    """
    File-based evidence repository implementation.

    Consolidates the file storage logic from the old evidence_store.py
    with proper dependency injection and clean architecture.
    """

    def __init__(self, storage_path: str, crypto_service: Any = None) -> None:
        """
        Initialize file-based repository.

        Args:
            storage_path: Base path for evidence storage
            crypto_service: Optional crypto service (injected by caller)
        """
        self.storage_path = Path(storage_path)
        self.metadata_path = self.storage_path / "metadata"
        self.content_path = self.storage_path / "content"
        self.bundles_path = self.storage_path / "bundles"
        self.crypto_service = crypto_service

        # Create directory structure
        self._ensure_directories()

        # In-memory cache for performance
        self._metadata_cache: dict[str, BaseEvidenceMetadata] = {}
        self._bundle_cache: dict[str, EvidenceBundle] = {}

    def _ensure_directories(self) -> None:
        """Ensure storage directory structure exists."""
        for path in [
            self.storage_path,
            self.metadata_path,
            self.content_path,
            self.bundles_path,
        ]:
            path.mkdir(parents=True, exist_ok=True)

    async def store_evidence(
        self, content: bytes, metadata: BaseEvidenceMetadata
    ) -> str:
        """Store evidence content and metadata."""
        try:
            # Generate ID if not set
            if not metadata.id:
                metadata.id = str(uuid4())

            # Calculate content hash if not set
            if not metadata.content_hash:
                metadata.calculate_content_hash(content)

            # Store content using hash-based path for deduplication
            assert metadata.content_hash is not None  # Set by calculate_content_hash
            content_file = self._get_content_path(metadata.content_hash)
            if not content_file.exists():  # Only write if not exists (deduplication)
                content_file.parent.mkdir(parents=True, exist_ok=True)
                async with aiofiles.open(content_file, "wb") as f:
                    await f.write(content)

            # Seal with crypto if available
            if self.crypto_service and metadata.status != EvidenceStatus.SEALED:
                signature = await self.crypto_service.sign_content(content, metadata.id)
                if signature and metadata.crypto_proof:
                    metadata.crypto_proof.signature = signature
                    metadata.crypto_proof.signature_algorithm = "RSA-PSS-SHA256"

            # Store metadata
            metadata_file = self.metadata_path / f"{metadata.id}.json"
            metadata_dict = self._metadata_to_dict(metadata)

            async with aiofiles.open(metadata_file, "w") as f:
                await f.write(json.dumps(metadata_dict, indent=2, default=str))

            # Cache metadata
            self._metadata_cache[metadata.id] = metadata

            logger.debug(
                f"Stored evidence {metadata.id} with hash {metadata.content_hash}"
            )
            return metadata.id

        except Exception as e:
            logger.error(f"Failed to store evidence: {e}")
            raise

    async def get_evidence(
        self, evidence_id: str
    ) -> tuple[bytes, BaseEvidenceMetadata] | None:
        """Retrieve evidence content and metadata."""
        try:
            # Get metadata first
            metadata = await self.get_metadata(evidence_id)
            if not metadata:
                return None

            # Get content
            if not metadata.content_hash:
                logger.warning(f"No content hash for evidence {evidence_id}")
                return None
            content_file = self._get_content_path(metadata.content_hash)
            if not content_file.exists():
                logger.warning(f"Content file not found for evidence {evidence_id}")
                return None

            async with aiofiles.open(content_file, "rb") as f:
                content = await f.read()

            # Verify content integrity
            actual_hash = hashlib.sha256(content).hexdigest()
            if actual_hash != metadata.content_hash:
                logger.error(f"Content hash mismatch for evidence {evidence_id}")
                return None

            return content, metadata

        except Exception as e:
            logger.error(f"Failed to retrieve evidence {evidence_id}: {e}")
            return None

    async def get_metadata(self, evidence_id: str) -> BaseEvidenceMetadata | None:
        """Get evidence metadata."""
        try:
            # Check cache first
            if evidence_id in self._metadata_cache:
                return self._metadata_cache[evidence_id]

            # Load from file
            metadata_file = self.metadata_path / f"{evidence_id}.json"
            if not metadata_file.exists():
                return None

            async with aiofiles.open(metadata_file) as f:
                metadata_dict = json.loads(await f.read())

            metadata = self._dict_to_metadata(metadata_dict)
            self._metadata_cache[evidence_id] = metadata
            return metadata

        except Exception as e:
            logger.error(f"Failed to get metadata for {evidence_id}: {e}")
            return None

    async def search_evidence(self, **filters) -> list[BaseEvidenceMetadata]:
        """Search evidence by filters."""
        try:
            results = []

            # Load all metadata files (in production, would use database index)
            for metadata_file in self.metadata_path.glob("*.json"):
                try:
                    async with aiofiles.open(metadata_file) as f:
                        metadata_dict = json.loads(await f.read())

                    metadata = self._dict_to_metadata(metadata_dict)

                    # Apply filters
                    if self._matches_filters(metadata, filters):
                        results.append(metadata)

                except Exception as e:
                    logger.debug(f"Error processing metadata file {metadata_file}: {e}")
                    continue

            # Sort by creation date (newest first)
            results.sort(key=lambda x: x.created_at, reverse=True)
            return results

        except Exception as e:
            logger.error(f"Evidence search failed: {e}")
            return []

    async def create_bundle(self, bundle: EvidenceBundle) -> str:
        """Create evidence bundle."""
        try:
            if not bundle.id:
                bundle.id = str(uuid4())

            bundle_file = self.bundles_path / f"{bundle.id}.json"
            bundle_dict = self._bundle_to_dict(bundle)

            async with aiofiles.open(bundle_file, "w") as f:
                await f.write(json.dumps(bundle_dict, indent=2, default=str))

            self._bundle_cache[bundle.id] = bundle
            logger.info(f"Created evidence bundle {bundle.id}")
            return bundle.id

        except Exception as e:
            logger.error(f"Failed to create bundle: {e}")
            raise

    async def get_bundle(self, bundle_id: str) -> EvidenceBundle | None:
        """Get evidence bundle."""
        try:
            # Check cache first
            if bundle_id in self._bundle_cache:
                return self._bundle_cache[bundle_id]

            # Load from file
            bundle_file = self.bundles_path / f"{bundle_id}.json"
            if not bundle_file.exists():
                return None

            async with aiofiles.open(bundle_file) as f:
                bundle_dict = json.loads(await f.read())

            bundle = self._dict_to_bundle(bundle_dict)
            self._bundle_cache[bundle_id] = bundle
            return bundle

        except Exception as e:
            logger.error(f"Failed to get bundle {bundle_id}: {e}")
            return None

    def _get_content_path(self, content_hash: str) -> Path:
        """Get content file path using hash-based directory structure."""
        return self.content_path / content_hash[:2] / f"{content_hash}.bin"

    def _matches_filters(
        self, metadata: BaseEvidenceMetadata, filters: dict[str, Any]
    ) -> bool:
        """Check if metadata matches search filters."""
        for key, value in filters.items():
            if key == "framework_name":
                if (
                    hasattr(metadata, "framework_name")
                    and metadata.framework_name != value
                ):
                    return False
            elif key == "control_id":
                if hasattr(metadata, "control_id") and metadata.control_id != value:
                    return False
            elif key == "category":
                if metadata.category != value:
                    return False
            elif key == "status":
                if metadata.status != value:
                    return False
            elif key == "date_range":
                start, end = value
                if not (start <= metadata.created_at <= end):
                    return False
            elif key.startswith("tags."):
                tag_key = key[5:]  # Remove "tags." prefix
                if metadata.tags.get(tag_key) != value:
                    return False

        return True

    def _metadata_to_dict(self, metadata: BaseEvidenceMetadata) -> dict[str, Any]:
        """Convert metadata to dictionary for storage."""
        result = {
            "id": metadata.id,
            "category": metadata.category.value,
            "content_type": metadata.content_type,
            "collector_id": metadata.collector_id,
            "collector_type": metadata.collector_type,
            "collection_method": metadata.collection_method.value,
            "source_system": metadata.source_system,
            "content_size": metadata.content_size,
            "content_hash": metadata.content_hash,
            "created_at": metadata.created_at.isoformat(),
            "collected_at": (
                metadata.collected_at.isoformat() if metadata.collected_at else None
            ),
            "verified_at": (
                metadata.verified_at.isoformat() if metadata.verified_at else None
            ),
            "sealed_at": metadata.sealed_at.isoformat() if metadata.sealed_at else None,
            "status": metadata.status.value,
            "retention_class": metadata.retention_class.value,
            "expires_at": (
                metadata.expires_at.isoformat() if metadata.expires_at else None
            ),
            "pii_detected": metadata.pii_detected,
            "sensitivity_level": metadata.sensitivity_level,
            "encryption_required": metadata.encryption_required,
            "tags": metadata.tags,
            "related_evidence_ids": metadata.related_evidence_ids,
            "parent_bundle_id": metadata.parent_bundle_id,
            "chain_of_custody": [
                {
                    "action": entry.action,
                    "actor_id": entry.actor_id,
                    "actor_type": entry.actor_type,
                    "timestamp": entry.timestamp.isoformat(),
                    "details": entry.details,
                    "ip_address": entry.ip_address,
                    "location": entry.location,
                }
                for entry in metadata.chain_of_custody
            ],
        }

        # Add crypto proof if present
        if metadata.crypto_proof:
            result["crypto_proof"] = {
                "content_hash": metadata.crypto_proof.content_hash or "",
                "signature": metadata.crypto_proof.signature or "",
                "signature_algorithm": metadata.crypto_proof.signature_algorithm or "",
                "timestamp_token": metadata.crypto_proof.timestamp_token or "",
                "merkle_root": metadata.crypto_proof.merkle_root or "",
                "chain_hash": metadata.crypto_proof.chain_hash or "",
            }

        # Add type-specific fields
        if hasattr(metadata, "control_id"):
            result["control_id"] = metadata.control_id
        if hasattr(metadata, "framework_name"):
            result["framework_name"] = metadata.framework_name
        if hasattr(metadata, "query_used"):
            result["query_used"] = metadata.query_used

        return result

    def _dict_to_metadata(self, data: dict[str, Any]) -> BaseEvidenceMetadata:
        """Convert dictionary to metadata object."""
        # Import here to avoid circular imports
        from .models import (
            BaseEvidenceMetadata,
            ChainOfCustodyEntry,
            ComplianceEvidenceMetadata,
            CryptographicProof,
            EvidenceCategory,
            EvidenceCollectionMethod,
            EvidenceStatus,
            RetentionClass,
        )

        # Determine metadata type and create appropriate instance
        if "control_id" in data or "framework_name" in data:
            metadata_class: type[BaseEvidenceMetadata] = ComplianceEvidenceMetadata
        else:
            metadata_class = BaseEvidenceMetadata

        # Parse enums
        category = EvidenceCategory(data["category"])
        collection_method = EvidenceCollectionMethod(data["collection_method"])
        status = EvidenceStatus(data["status"])
        retention_class = RetentionClass(data["retention_class"])

        # Parse timestamps
        created_at = datetime.fromisoformat(data["created_at"])
        collected_at = (
            datetime.fromisoformat(data["collected_at"])
            if data.get("collected_at")
            else None
        )
        verified_at = (
            datetime.fromisoformat(data["verified_at"])
            if data.get("verified_at")
            else None
        )
        sealed_at = (
            datetime.fromisoformat(data["sealed_at"]) if data.get("sealed_at") else None
        )
        expires_at = (
            datetime.fromisoformat(data["expires_at"])
            if data.get("expires_at")
            else None
        )

        # Parse chain of custody
        chain_of_custody = []
        for entry_data in data.get("chain_of_custody", []):
            chain_of_custody.append(
                ChainOfCustodyEntry(
                    action=entry_data["action"],
                    actor_id=entry_data["actor_id"],
                    actor_type=entry_data["actor_type"],
                    timestamp=datetime.fromisoformat(entry_data["timestamp"]),
                    details=entry_data.get("details", {}),
                    ip_address=entry_data.get("ip_address"),
                    location=entry_data.get("location"),
                )
            )

        # Parse crypto proof
        crypto_proof = None
        if "crypto_proof" in data:
            crypto_data = data["crypto_proof"]
            crypto_proof = CryptographicProof(
                content_hash=crypto_data["content_hash"],
                signature=crypto_data.get("signature"),
                signature_algorithm=crypto_data.get("signature_algorithm"),
                timestamp_token=crypto_data.get("timestamp_token"),
                merkle_root=crypto_data.get("merkle_root"),
                chain_hash=crypto_data.get("chain_hash"),
            )

        # Create metadata instance
        metadata = metadata_class(
            id=data["id"],
            category=category,
            content_type=data["content_type"],
            collector_id=data["collector_id"],
            collector_type=data["collector_type"],
            collection_method=collection_method,
            source_system=data.get("source_system"),
            content_size=data["content_size"],
            content_hash=data.get("content_hash"),
            created_at=created_at,
            collected_at=collected_at,
            verified_at=verified_at,
            sealed_at=sealed_at,
            status=status,
            retention_class=retention_class,
            expires_at=expires_at,
            crypto_proof=crypto_proof,
            chain_of_custody=chain_of_custody,
            pii_detected=data.get("pii_detected", False),
            sensitivity_level=data.get("sensitivity_level", "internal"),
            encryption_required=data.get("encryption_required", False),
            tags=data.get("tags", {}),
            related_evidence_ids=data.get("related_evidence_ids", []),
            parent_bundle_id=data.get("parent_bundle_id"),
        )

        # Set type-specific fields
        if hasattr(metadata, "control_id") and "control_id" in data:
            metadata.control_id = data["control_id"]
        if hasattr(metadata, "framework_name") and "framework_name" in data:
            metadata.framework_name = data["framework_name"]
        if hasattr(metadata, "query_used") and "query_used" in data:
            metadata.query_used = data["query_used"]

        return metadata

    def _bundle_to_dict(self, bundle: EvidenceBundle) -> dict[str, Any]:
        """Convert bundle to dictionary for storage."""
        return {
            "id": bundle.id,
            "name": bundle.name,
            "description": bundle.description,
            "bundle_type": bundle.bundle_type,
            "framework_name": bundle.framework_name,
            "control_ids": bundle.control_ids,
            "evidence_ids": bundle.evidence_ids,
            "period_start": (
                bundle.period_start.isoformat() if bundle.period_start else None
            ),
            "period_end": bundle.period_end.isoformat() if bundle.period_end else None,
            "created_at": bundle.created_at.isoformat(),
            "created_by": bundle.created_by,
            "organization_id": bundle.organization_id,
            "bundle_hash": bundle.bundle_hash,
            "manifest": bundle.manifest,
            "sealed": bundle.sealed,
            "exported_at": (
                bundle.exported_at.isoformat() if bundle.exported_at else None
            ),
            "export_format": bundle.export_format,
            "access_granted_to": bundle.access_granted_to,
            "delivery_confirmation": bundle.delivery_confirmation,
            "retention_years": bundle.retention_years,
            "legal_hold": bundle.legal_hold,
            "destruction_date": (
                bundle.destruction_date.isoformat() if bundle.destruction_date else None
            ),
        }

    def _dict_to_bundle(self, data: dict[str, Any]) -> EvidenceBundle:
        """Convert dictionary to bundle object."""
        created_at = datetime.fromisoformat(data["created_at"])
        period_start = (
            datetime.fromisoformat(data["period_start"])
            if data.get("period_start")
            else None
        )
        period_end = (
            datetime.fromisoformat(data["period_end"])
            if data.get("period_end")
            else None
        )
        exported_at = (
            datetime.fromisoformat(data["exported_at"])
            if data.get("exported_at")
            else None
        )
        destruction_date = (
            datetime.fromisoformat(data["destruction_date"])
            if data.get("destruction_date")
            else None
        )

        return EvidenceBundle(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            bundle_type=data["bundle_type"],
            framework_name=data.get("framework_name"),
            control_ids=data.get("control_ids", []),
            evidence_ids=data.get("evidence_ids", []),
            period_start=period_start,
            period_end=period_end,
            created_at=created_at,
            created_by=data["created_by"],
            organization_id=data.get("organization_id"),
            bundle_hash=data.get("bundle_hash"),
            manifest=data.get("manifest", {}),
            sealed=data.get("sealed", False),
            exported_at=exported_at,
            export_format=data.get("export_format", "zip"),
            access_granted_to=data.get("access_granted_to", []),
            delivery_confirmation=data.get("delivery_confirmation"),
            retention_years=data.get("retention_years", 7),
            legal_hold=data.get("legal_hold", False),
            destruction_date=destruction_date,
        )


class InMemoryEvidenceRepository(EvidenceRepository):
    """In-memory evidence repository for testing."""

    def __init__(self):
        self._evidence: dict[str, tuple[bytes, BaseEvidenceMetadata]] = {}
        self._bundles: dict[str, EvidenceBundle] = {}

    async def store_evidence(
        self, content: bytes, metadata: BaseEvidenceMetadata
    ) -> str:
        if not metadata.id:
            metadata.id = str(uuid4())

        metadata.calculate_content_hash(content)
        self._evidence[metadata.id] = (content, metadata)
        return metadata.id

    async def get_evidence(
        self, evidence_id: str
    ) -> tuple[bytes, BaseEvidenceMetadata] | None:
        return self._evidence.get(evidence_id)

    async def get_metadata(self, evidence_id: str) -> BaseEvidenceMetadata | None:
        evidence = self._evidence.get(evidence_id)
        return evidence[1] if evidence else None

    async def search_evidence(self, **filters) -> list[BaseEvidenceMetadata]:
        results = []
        for _content, metadata in self._evidence.values():
            # Simple filter matching - would be more sophisticated in production
            matches = True
            for key, value in filters.items():
                if key == "category" and metadata.category != value:
                    matches = False
                    break
                elif key == "status" and metadata.status != value:
                    matches = False
                    break
            if matches:
                results.append(metadata)
        return results

    async def create_bundle(self, bundle: EvidenceBundle) -> str:
        if not bundle.id:
            bundle.id = str(uuid4())
        self._bundles[bundle.id] = bundle
        return bundle.id

    async def get_bundle(self, bundle_id: str) -> EvidenceBundle | None:
        return self._bundles.get(bundle_id)
