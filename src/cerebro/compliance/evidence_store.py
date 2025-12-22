"""
Immutable evidence store for compliance audit trails.

DEPRECATED: This module is being replaced by the unified evidence system.
Use EvidenceService from evidence_service.py and storage.py for new implementations.

Provides WORM (Write-Once-Read-Many) storage for compliance evidence with
cryptographic hashing, digital signatures, and complete audit trails.
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field, asdict
from pathlib import Path
import aiofiles
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Import unified enums instead of redefining them
from .models import EvidenceStatus, EvidenceCategory


@dataclass
class EvidenceMetadata:
    """Metadata for a stored evidence item."""

    id: str
    category: EvidenceCategory
    content_type: str
    content_hash: str  # SHA-256 of content
    content_size: int

    # Provenance and chain of custody
    collector_id: str  # System/user that collected evidence
    collector_type: str  # "system", "user", "integration"
    source_system: str  # Okta, AWS, GitHub, etc.
    collection_method: str  # "api", "sql_query", "manual_upload", "screenshot"

    # Compliance context
    control_id: Optional[str] = None
    framework_name: Optional[str] = None
    test_run_id: Optional[str] = None
    audit_period_start: Optional[datetime] = None
    audit_period_end: Optional[datetime] = None

    # Timestamps and lifecycle
    created_at: datetime = field(default_factory=datetime.now)
    collected_at: Optional[datetime] = None  # When original data was collected
    sealed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

    # Security and integrity
    status: EvidenceStatus = EvidenceStatus.PENDING
    signature: Optional[str] = None  # Digital signature
    signature_algorithm: Optional[str] = None
    chain_hash: Optional[str] = None  # Hash linking to previous evidence

    # Classification and handling
    pii_tags: List[str] = field(default_factory=list)
    retention_class: str = "standard"  # "standard", "long_term", "permanent"
    encryption_key_id: Optional[str] = None

    # Additional metadata
    tags: Dict[str, str] = field(default_factory=dict)
    related_evidence: List[str] = field(default_factory=list)  # Related evidence IDs


@dataclass
class EvidenceBundle:
    """A collection of related evidence items for audit export."""

    id: str
    name: str
    description: str
    framework_name: str
    control_ids: List[str]
    evidence_ids: List[str]

    # Audit period
    period_start: datetime
    period_end: datetime

    # Bundle metadata
    created_at: datetime = field(default_factory=datetime.now)
    created_by: str = ""
    bundle_hash: Optional[str] = None  # Hash of all evidence in bundle
    manifest: Dict[str, Any] = field(default_factory=dict)

    # Export and delivery
    exported_at: Optional[datetime] = None
    export_format: str = "zip"
    access_granted_to: List[str] = field(default_factory=list)  # Auditor emails


class EvidenceStore:
    """Immutable evidence storage with cryptographic integrity."""

    def __init__(self, storage_path: str, signing_key_path: Optional[str] = None):
        self.storage_path = Path(storage_path)
        self.metadata_path = self.storage_path / "metadata"
        self.blobs_path = self.storage_path / "blobs"
        self.bundles_path = self.storage_path / "bundles"

        # Create directories
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.metadata_path.mkdir(exist_ok=True)
        self.blobs_path.mkdir(exist_ok=True)
        self.bundles_path.mkdir(exist_ok=True)

        # Initialize signing key
        self.signing_key = None
        if signing_key_path:
            self.signing_key = self._load_signing_key(signing_key_path)

        # In-memory metadata cache
        self._metadata_cache: Dict[str, EvidenceMetadata] = {}
        self._chain_tip: Optional[str] = None

    async def store_evidence(
        self,
        content: Union[bytes, str, Dict[str, Any]],
        metadata: EvidenceMetadata,
        seal_immediately: bool = False,
    ) -> str:
        """Store evidence with metadata and return evidence ID."""

        # Convert content to bytes
        if isinstance(content, str):
            content_bytes = content.encode("utf-8")
            metadata.content_type = metadata.content_type or "text/plain"
        elif isinstance(content, dict):
            content_bytes = json.dumps(content, sort_keys=True, indent=2).encode(
                "utf-8"
            )
            metadata.content_type = metadata.content_type or "application/json"
        else:
            content_bytes = content

        # Calculate content hash
        content_hash = hashlib.sha256(content_bytes).hexdigest()
        metadata.content_hash = content_hash
        metadata.content_size = len(content_bytes)

        # Check for duplicates
        existing_evidence = await self._find_by_content_hash(content_hash)
        if existing_evidence:
            # Link to existing evidence instead of duplicating
            metadata.related_evidence.append(existing_evidence.id)

        # Calculate chain hash
        if self._chain_tip:
            chain_input = f"{self._chain_tip}:{metadata.id}:{content_hash}"
            metadata.chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()
        else:
            metadata.chain_hash = hashlib.sha256(
                f"{metadata.id}:{content_hash}".encode()
            ).hexdigest()

        # Store blob content
        blob_path = self.blobs_path / f"{content_hash[:2]}" / f"{content_hash}.blob"
        blob_path.parent.mkdir(exist_ok=True)

        if not blob_path.exists():  # Don't overwrite existing blobs
            async with aiofiles.open(blob_path, "wb") as f:
                await f.write(content_bytes)

        # Update metadata status
        metadata.status = EvidenceStatus.STORED

        # Sign if requested and key available
        if seal_immediately and self.signing_key:
            await self._seal_evidence(metadata)

        # Store metadata
        await self._store_metadata(metadata)

        # Update chain tip
        self._chain_tip = metadata.id

        # Add to cache
        self._metadata_cache[metadata.id] = metadata

        return metadata.id

    async def get_evidence(
        self, evidence_id: str
    ) -> Optional[tuple[bytes, EvidenceMetadata]]:
        """Retrieve evidence content and metadata."""
        metadata = await self.get_metadata(evidence_id)
        if not metadata:
            return None

        # Load content from blob storage
        blob_path = (
            self.blobs_path
            / f"{metadata.content_hash[:2]}"
            / f"{metadata.content_hash}.blob"
        )

        if not blob_path.exists():
            return None

        async with aiofiles.open(blob_path, "rb") as f:
            content = await f.read()

        # Verify integrity
        actual_hash = hashlib.sha256(content).hexdigest()
        if actual_hash != metadata.content_hash:
            raise ValueError(f"Evidence integrity check failed for {evidence_id}")

        return content, metadata

    async def get_metadata(self, evidence_id: str) -> Optional[EvidenceMetadata]:
        """Get evidence metadata."""
        if evidence_id in self._metadata_cache:
            return self._metadata_cache[evidence_id]

        metadata_file = self.metadata_path / f"{evidence_id}.json"
        if not metadata_file.exists():
            return None

        async with aiofiles.open(metadata_file, "r") as f:
            data = json.loads(await f.read())

        metadata = EvidenceMetadata(**data)
        self._metadata_cache[evidence_id] = metadata
        return metadata

    async def seal_evidence(self, evidence_id: str) -> bool:
        """Cryptographically seal evidence for audit."""
        metadata = await self.get_metadata(evidence_id)
        if not metadata or not self.signing_key:
            return False

        return await self._seal_evidence(metadata)

    async def verify_evidence(self, evidence_id: str) -> bool:
        """Verify evidence integrity and signature."""
        content, metadata = await self.get_evidence(evidence_id)
        if not content or not metadata:
            return False

        # Verify content hash
        actual_hash = hashlib.sha256(content).hexdigest()
        if actual_hash != metadata.content_hash:
            return False

        # Verify signature if present
        if metadata.signature and self.signing_key:
            return self._verify_signature(metadata)

        return True

    async def create_evidence_bundle(
        self, bundle: EvidenceBundle, include_content: bool = True
    ) -> str:
        """Create an audit evidence bundle."""

        # Collect all evidence metadata
        evidence_items = []
        for evidence_id in bundle.evidence_ids:
            metadata = await self.get_metadata(evidence_id)
            if metadata:
                evidence_items.append(metadata)

        # Calculate bundle hash
        evidence_hashes = [item.content_hash for item in evidence_items]
        bundle_content = json.dumps(evidence_hashes, sort_keys=True)
        bundle.bundle_hash = hashlib.sha256(bundle_content.encode()).hexdigest()

        # Create manifest
        bundle.manifest = {
            "version": "1.0",
            "created_at": bundle.created_at.isoformat(),
            "framework": bundle.framework_name,
            "controls": bundle.control_ids,
            "period": {
                "start": bundle.period_start.isoformat(),
                "end": bundle.period_end.isoformat(),
            },
            "evidence_count": len(evidence_items),
            "evidence_items": [
                {
                    "id": item.id,
                    "category": item.category.value,
                    "hash": item.content_hash,
                    "control_id": item.control_id,
                    "collected_at": (
                        item.collected_at.isoformat() if item.collected_at else None
                    ),
                    "sealed": item.status == EvidenceStatus.SEALED,
                }
                for item in evidence_items
            ],
        }

        # Store bundle metadata
        bundle_path = self.bundles_path / f"{bundle.id}.json"
        async with aiofiles.open(bundle_path, "w") as f:
            await f.write(json.dumps(asdict(bundle), indent=2, default=str))

        return bundle.id

    async def export_bundle(
        self, bundle_id: str, export_path: str, format: str = "zip"
    ) -> str:
        """Export evidence bundle for audit delivery."""
        # Load bundle
        bundle_path = self.bundles_path / f"{bundle_id}.json"
        if not bundle_path.exists():
            raise ValueError(f"Bundle {bundle_id} not found")

        async with aiofiles.open(bundle_path, "r") as f:
            bundle_data = json.loads(await f.read())

        bundle = EvidenceBundle(**bundle_data)

        # Create export directory
        export_dir = Path(export_path) / f"evidence_bundle_{bundle_id}"
        export_dir.mkdir(parents=True, exist_ok=True)

        # Export manifest
        manifest_path = export_dir / "manifest.json"
        async with aiofiles.open(manifest_path, "w") as f:
            await f.write(json.dumps(bundle.manifest, indent=2))

        # Export evidence files
        evidence_dir = export_dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)

        for evidence_id in bundle.evidence_ids:
            content, metadata = await self.get_evidence(evidence_id)
            if content and metadata:
                # Determine file extension
                ext = self._get_file_extension(metadata.content_type)
                evidence_file = evidence_dir / f"{evidence_id}{ext}"

                async with aiofiles.open(evidence_file, "wb") as f:
                    await f.write(content)

                # Export metadata
                metadata_file = evidence_dir / f"{evidence_id}_metadata.json"
                async with aiofiles.open(metadata_file, "w") as f:
                    await f.write(json.dumps(asdict(metadata), indent=2, default=str))

        # Create ZIP if requested
        if format == "zip":
            import zipfile

            zip_path = f"{export_path}/evidence_bundle_{bundle_id}.zip"
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                for file_path in export_dir.rglob("*"):
                    if file_path.is_file():
                        arcname = file_path.relative_to(export_dir)
                        zipf.write(file_path, arcname)

            # Update bundle export info
            bundle.exported_at = datetime.now()
            bundle.export_format = format

            async with aiofiles.open(bundle_path, "w") as f:
                await f.write(json.dumps(asdict(bundle), indent=2, default=str))

            return zip_path

        return str(export_dir)

    async def search_evidence(
        self,
        control_id: Optional[str] = None,
        framework_name: Optional[str] = None,
        category: Optional[EvidenceCategory] = None,
        date_range: Optional[tuple[datetime, datetime]] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> List[EvidenceMetadata]:
        """Search for evidence matching criteria."""
        results = []

        # Load all metadata (in production, would use database index)
        for metadata_file in self.metadata_path.glob("*.json"):
            try:
                async with aiofiles.open(metadata_file, "r") as f:
                    data = json.loads(await f.read())
                metadata = EvidenceMetadata(**data)

                # Apply filters
                if control_id and metadata.control_id != control_id:
                    continue
                if framework_name and metadata.framework_name != framework_name:
                    continue
                if category and metadata.category != category:
                    continue
                if date_range:
                    start, end = date_range
                    if not (start <= metadata.created_at <= end):
                        continue
                if tags:
                    if not all(metadata.tags.get(k) == v for k, v in tags.items()):
                        continue

                results.append(metadata)

            except Exception:
                continue  # Skip corrupted metadata

        return sorted(results, key=lambda x: x.created_at, reverse=True)

    async def _find_by_content_hash(
        self, content_hash: str
    ) -> Optional[EvidenceMetadata]:
        """Find existing evidence by content hash."""
        for metadata in self._metadata_cache.values():
            if metadata.content_hash == content_hash:
                return metadata
        return None

    async def _store_metadata(self, metadata: EvidenceMetadata):
        """Store evidence metadata to disk."""
        metadata_file = self.metadata_path / f"{metadata.id}.json"
        async with aiofiles.open(metadata_file, "w") as f:
            await f.write(json.dumps(asdict(metadata), indent=2, default=str))

    async def _seal_evidence(self, metadata: EvidenceMetadata) -> bool:
        """Cryptographically seal evidence."""
        if not self.signing_key:
            return False

        # Create signature payload
        payload = (
            f"{metadata.id}:{metadata.content_hash}:{metadata.created_at.isoformat()}"
        )
        signature = self.signing_key.sign(
            payload.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        metadata.signature = signature.hex()
        metadata.signature_algorithm = "RSA-PSS-SHA256"
        metadata.sealed_at = datetime.now()
        metadata.status = EvidenceStatus.SEALED

        await self._store_metadata(metadata)
        return True

    def _verify_signature(self, metadata: EvidenceMetadata) -> bool:
        """Verify evidence signature."""
        if not self.signing_key or not metadata.signature:
            return False

        try:
            payload = f"{metadata.id}:{metadata.content_hash}:{metadata.created_at.isoformat()}"
            signature = bytes.fromhex(metadata.signature)

            public_key = self.signing_key.public_key()
            public_key.verify(
                signature,
                payload.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    def _load_signing_key(self, key_path: str):
        """Load RSA signing key."""
        key_file = Path(key_path)
        if not key_file.exists():
            # Generate new key
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            key_file.write_bytes(pem)
            return key
        else:
            pem_data = key_file.read_bytes()
            return serialization.load_pem_private_key(pem_data, password=None)

    def _get_file_extension(self, content_type: str) -> str:
        """Get file extension for content type."""
        extensions = {
            "application/json": ".json",
            "text/plain": ".txt",
            "text/csv": ".csv",
            "image/png": ".png",
            "image/jpeg": ".jpg",
            "application/pdf": ".pdf",
            "text/html": ".html",
        }
        return extensions.get(content_type, ".dat")


# Factory function for easy initialization
def create_evidence_store(
    storage_path: str, signing_key_path: Optional[str] = None
) -> EvidenceStore:
    """Create and initialize an evidence store."""
    return EvidenceStore(storage_path, signing_key_path)
