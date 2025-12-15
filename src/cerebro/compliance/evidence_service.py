"""
Unified evidence collection and management service.

Consolidates the 3 different evidence collection patterns into a single,
clean service with proper dependency injection and storage abstraction.
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional, Union
from datetime import datetime

from .models import (
    BaseEvidenceMetadata, ComplianceEvidenceMetadata, EvidenceStatus, EvidenceCategory, EvidenceCollectionMethod,
    EvidenceRepository, EvidenceBundle,
    create_compliance_evidence
)

logger = logging.getLogger(__name__)


class EvidenceCollectionError(Exception):
    """Raised when evidence collection fails."""
    pass


class EvidenceStorageError(Exception):
    """Raised when evidence storage fails."""
    pass


class EvidenceService:
    """
    Unified evidence collection and management service.

    Consolidates evidence collection, storage, and retrieval with proper
    dependency injection and pluggable storage backends.
    """

    def __init__(self, repository: EvidenceRepository, query_engine=None, crypto_service=None):
        """
        Initialize evidence service.

        Args:
            repository: Evidence storage backend
            query_engine: Optional query engine (injected by caller)
            crypto_service: Optional crypto service (injected by caller)
        """
        self.repository = repository
        self.query_engine = query_engine
        self.crypto_service = crypto_service

        # Performance tracking
        self._collection_stats = {
            "total_collected": 0,
            "successful": 0,
            "failed": 0,
            "avg_collection_time_ms": 0
        }

    async def collect_compliance_evidence(
        self,
        control_id: str,
        framework_name: str,
        queries: List[str],
        collector_id: str = "system",
        test_run_id: Optional[str] = None
    ) -> List[str]:
        """
        Collect evidence for compliance controls.

        Args:
            control_id: Compliance control identifier
            framework_name: Compliance framework name
            queries: SQL queries to execute for evidence
            collector_id: ID of the system/user collecting evidence
            test_run_id: Optional test run identifier

        Returns:
            List of evidence IDs created
        """
        if not self.query_engine:
            raise EvidenceCollectionError("Query engine not configured")

        evidence_ids = []
        collection_start = datetime.utcnow()

        logger.info(f"Collecting compliance evidence for control {control_id} in framework {framework_name}")

        for i, query in enumerate(queries):
            try:
                # Create evidence metadata
                metadata = create_compliance_evidence(
                    control_id=control_id,
                    framework_name=framework_name,
                    collector_id=collector_id,
                    collection_method=EvidenceCollectionMethod.SQL_QUERY,
                    test_run_id=test_run_id,
                    query_used=query,
                    status=EvidenceStatus.COLLECTING
                )
                metadata.add_custody_entry("collection_started", collector_id, "system", query=query)

                # Execute query
                query_start = datetime.utcnow()
                try:
                    result = await self.query_engine.execute_query(query)
                    query_duration = (datetime.utcnow() - query_start).total_seconds() * 1000
                    metadata.query_execution_time_ms = int(query_duration)

                    # Prepare evidence content
                    evidence_content = {
                        "control_id": control_id,
                        "framework": framework_name,
                        "query": query,
                        "execution_time_ms": metadata.query_execution_time_ms,
                        "collected_at": datetime.utcnow().isoformat(),
                        "result": {
                            "columns": result.columns,
                            "rows": result.rows,
                            "total_rows": result.total_rows,
                            "tables_queried": result.tables_queried
                        }
                    }

                    # Update metadata based on results
                    metadata.status = EvidenceStatus.COLLECTED
                    metadata.collected_at = datetime.utcnow()
                    metadata.findings_count = result.total_rows
                    metadata.data_source_tables = result.tables_queried or []

                    # Determine control status based on findings
                    if result.total_rows == 0:
                        metadata.control_status = "compliant"
                    else:
                        metadata.control_status = "non_compliant"
                        metadata.remediation_required = True

                except Exception as query_error:
                    logger.error(f"Query execution failed for control {control_id}: {query_error}")

                    # Store error as evidence
                    evidence_content = {
                        "control_id": control_id,
                        "framework": framework_name,
                        "query": query,
                        "collected_at": datetime.utcnow().isoformat(),
                        "error": str(query_error),
                        "error_type": type(query_error).__name__
                    }

                    metadata.status = EvidenceStatus.COLLECTED
                    metadata.collected_at = datetime.utcnow()
                    metadata.control_status = "testing"
                    metadata.tags["collection_error"] = "true"

                # Calculate content hash
                metadata.calculate_content_hash(evidence_content)
                metadata.add_custody_entry("collection_completed", collector_id, "system")

                # Store evidence
                evidence_id = await self._store_evidence_safely(
                    json.dumps(evidence_content, indent=2),
                    metadata
                )
                evidence_ids.append(evidence_id)

                self._collection_stats["successful"] += 1

            except Exception as e:
                logger.error(f"Failed to collect evidence for query {i+1} in control {control_id}: {e}")
                self._collection_stats["failed"] += 1

        collection_duration = (datetime.utcnow() - collection_start).total_seconds() * 1000
        self._collection_stats["total_collected"] += len(evidence_ids)

        if self._collection_stats["total_collected"] > 0:
            self._collection_stats["avg_collection_time_ms"] = int(
                (self._collection_stats["avg_collection_time_ms"] * (self._collection_stats["total_collected"] - len(evidence_ids)) +
                 collection_duration) / self._collection_stats["total_collected"]
            )

        logger.info(f"Collected {len(evidence_ids)} evidence items for control {control_id}")
        return evidence_ids

    async def collect_configuration_evidence(
        self,
        resource_id: str,
        provider: str,
        configuration_data: Dict[str, Any],
        collector_id: str = "system",
        **metadata_kwargs
    ) -> str:
        """
        Collect configuration evidence for resources.

        Args:
            resource_id: Resource identifier
            provider: Provider name (aws, okta, github, etc.)
            configuration_data: Resource configuration
            collector_id: Collector identifier
            **metadata_kwargs: Additional metadata fields

        Returns:
            Evidence ID
        """
        metadata = ComplianceEvidenceMetadata(
            category=EvidenceCategory.CONFIGURATION,
            collector_id=collector_id,
            collection_method=EvidenceCollectionMethod.API_QUERY,
            source_system=provider,
            status=EvidenceStatus.COLLECTING,
            **metadata_kwargs
        )

        # Add resource context to tags
        metadata.tags.update({
            "resource_id": resource_id,
            "provider": provider,
            "resource_type": configuration_data.get("resource_type", "unknown")
        })

        metadata.add_custody_entry("collection_started", collector_id, "system",
                                 resource_id=resource_id, provider=provider)

        # Prepare evidence content
        evidence_content = {
            "resource_id": resource_id,
            "provider": provider,
            "collected_at": datetime.utcnow().isoformat(),
            "configuration": configuration_data
        }

        # Update metadata
        metadata.status = EvidenceStatus.COLLECTED
        metadata.collected_at = datetime.utcnow()
        metadata.calculate_content_hash(evidence_content)
        metadata.add_custody_entry("collection_completed", collector_id, "system")

        # Store evidence
        evidence_id = await self._store_evidence_safely(
            json.dumps(evidence_content, indent=2),
            metadata
        )

        return evidence_id

    async def collect_log_evidence(
        self,
        log_entries: List[Dict[str, Any]],
        log_type: str,
        source_system: str,
        collector_id: str = "system",
        **metadata_kwargs
    ) -> str:
        """
        Collect log evidence (access logs, audit logs, etc.).

        Args:
            log_entries: Log entries to store
            log_type: Type of logs (access, audit, security, etc.)
            source_system: System that generated logs
            collector_id: Collector identifier
            **metadata_kwargs: Additional metadata fields

        Returns:
            Evidence ID
        """
        # Determine evidence category
        category_mapping = {
            "access": EvidenceCategory.ACCESS_LOG,
            "audit": EvidenceCategory.AUDIT_LOG,
            "security": EvidenceCategory.AUDIT_LOG,
            "system": EvidenceCategory.SYSTEM_REPORT
        }
        category = category_mapping.get(log_type.lower(), EvidenceCategory.AUDIT_LOG)

        metadata = ComplianceEvidenceMetadata(
            category=category,
            collector_id=collector_id,
            collection_method=EvidenceCollectionMethod.API_QUERY,
            source_system=source_system,
            status=EvidenceStatus.COLLECTING,
            **metadata_kwargs
        )

        metadata.tags.update({
            "log_type": log_type,
            "entry_count": str(len(log_entries)),
            "source_system": source_system
        })

        metadata.add_custody_entry("collection_started", collector_id, "system",
                                 log_type=log_type, entry_count=len(log_entries))

        # Check for PII in logs
        pii_patterns = ["email", "phone", "ssn", "credit_card", "password"]
        log_text = json.dumps(log_entries).lower()
        metadata.pii_detected = any(pattern in log_text for pattern in pii_patterns)

        # Prepare evidence content
        evidence_content = {
            "log_type": log_type,
            "source_system": source_system,
            "collected_at": datetime.utcnow().isoformat(),
            "entry_count": len(log_entries),
            "entries": log_entries
        }

        # Update metadata
        metadata.status = EvidenceStatus.COLLECTED
        metadata.collected_at = datetime.utcnow()
        metadata.calculate_content_hash(evidence_content)
        metadata.add_custody_entry("collection_completed", collector_id, "system")

        # Store evidence
        evidence_id = await self._store_evidence_safely(
            json.dumps(evidence_content, indent=2),
            metadata
        )

        return evidence_id

    async def collect_document_evidence(
        self,
        document_content: Union[str, bytes],
        document_name: str,
        document_type: str,
        collector_id: str,
        **metadata_kwargs
    ) -> str:
        """
        Collect document evidence (policies, procedures, etc.).

        Args:
            document_content: Document content
            document_name: Name of document
            document_type: Type of document (policy, procedure, etc.)
            collector_id: Collector identifier
            **metadata_kwargs: Additional metadata fields

        Returns:
            Evidence ID
        """
        metadata = ComplianceEvidenceMetadata(
            category=EvidenceCategory.POLICY_DOCUMENT,
            collector_id=collector_id,
            collection_method=EvidenceCollectionMethod.FILE_UPLOAD,
            status=EvidenceStatus.COLLECTING,
            **metadata_kwargs
        )

        metadata.tags.update({
            "document_name": document_name,
            "document_type": document_type
        })

        # Determine content type
        if isinstance(document_content, str):
            metadata.content_type = "text/plain"
            content_bytes = document_content.encode('utf-8')
        else:
            metadata.content_type = "application/octet-stream"
            content_bytes = document_content

        metadata.add_custody_entry("collection_started", collector_id, "user",
                                 document_name=document_name, document_type=document_type)

        # Update metadata
        metadata.status = EvidenceStatus.COLLECTED
        metadata.collected_at = datetime.utcnow()
        metadata.calculate_content_hash(content_bytes)
        metadata.add_custody_entry("collection_completed", collector_id, "user")

        # Store evidence
        evidence_id = await self._store_evidence_safely(content_bytes, metadata)
        return evidence_id

    async def seal_evidence(self, evidence_id: str, sealer_id: str) -> bool:
        """
        Cryptographically seal evidence for audit.

        Args:
            evidence_id: Evidence to seal
            sealer_id: ID of user/system performing sealing

        Returns:
            True if sealing succeeded
        """
        try:
            # Get evidence metadata
            metadata = await self.repository.get_metadata(evidence_id)
            if not metadata or metadata.status == EvidenceStatus.SEALED:
                return False

            # Add custody entry
            metadata.add_custody_entry("sealing_started", sealer_id, "system")

            # Perform cryptographic sealing if crypto service available
            if self.crypto_service:
                # Get evidence content for signing
                content, _ = await self.repository.get_evidence(evidence_id)
                if content:
                    signature = await self.crypto_service.sign_data(content, evidence_id)
                    if signature:
                        if not metadata.crypto_proof:
                            from .models import CryptographicProof
                            metadata.crypto_proof = CryptographicProof(
                                content_hash=metadata.content_hash
                            )
                        metadata.crypto_proof.signature = signature
                        metadata.crypto_proof.signature_algorithm = "RSA-PSS-SHA256"

            # Update status
            metadata.status = EvidenceStatus.SEALED
            metadata.sealed_at = datetime.utcnow()
            metadata.add_custody_entry("sealed", sealer_id, "system")

            # Update in repository
            await self.repository.store_evidence(b"", metadata)  # Update metadata only

            logger.info(f"Successfully sealed evidence {evidence_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to seal evidence {evidence_id}: {e}")
            return False

    async def create_evidence_bundle(
        self,
        bundle_name: str,
        framework_name: str,
        control_ids: List[str],
        evidence_ids: List[str],
        created_by: str,
        **bundle_kwargs
    ) -> str:
        """
        Create evidence bundle for audit delivery.

        Args:
            bundle_name: Name of the bundle
            framework_name: Compliance framework
            control_ids: Controls covered by bundle
            evidence_ids: Evidence items to include
            created_by: Bundle creator
            **bundle_kwargs: Additional bundle properties

        Returns:
            Bundle ID
        """
        bundle = EvidenceBundle(
            name=bundle_name,
            framework_name=framework_name,
            control_ids=control_ids,
            evidence_ids=evidence_ids,
            created_by=created_by,
            **bundle_kwargs
        )

        # Calculate bundle hash
        evidence_hashes = []
        for evidence_id in evidence_ids:
            metadata = await self.repository.get_metadata(evidence_id)
            if metadata and metadata.content_hash:
                evidence_hashes.append(metadata.content_hash)

        bundle.calculate_bundle_hash(evidence_hashes)

        # Create manifest
        bundle.manifest = {
            "version": "1.0",
            "created_at": bundle.created_at.isoformat(),
            "framework": framework_name,
            "controls": control_ids,
            "evidence_count": len(evidence_ids),
            "bundle_hash": bundle.bundle_hash
        }

        # Store bundle
        bundle_id = await self.repository.create_bundle(bundle)

        logger.info(f"Created evidence bundle {bundle_id} with {len(evidence_ids)} items")
        return bundle_id

    async def get_collection_stats(self) -> Dict[str, Any]:
        """Get evidence collection statistics."""
        return {
            **self._collection_stats,
            "timestamp": datetime.utcnow().isoformat()
        }

    async def _store_evidence_safely(
        self,
        content: Union[str, bytes],
        metadata: BaseEvidenceMetadata
    ) -> str:
        """
        Safely store evidence with error handling and retry logic.

        Args:
            content: Evidence content
            metadata: Evidence metadata

        Returns:
            Evidence ID

        Raises:
            EvidenceStorageError: If storage fails after retries
        """
        if isinstance(content, str):
            content_bytes = content.encode('utf-8')
        else:
            content_bytes = content

        # Retry storage with exponential backoff
        max_retries = 3
        for attempt in range(max_retries):
            try:
                evidence_id = await self.repository.store_evidence(content_bytes, metadata)

                # Verify storage
                stored_metadata = await self.repository.get_metadata(evidence_id)
                if not stored_metadata:
                    raise EvidenceStorageError("Evidence metadata not found after storage")

                return evidence_id

            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error(f"Failed to store evidence after {max_retries} attempts: {e}")
                    raise EvidenceStorageError(f"Storage failed: {e}")

                # Wait before retry (exponential backoff)
                await asyncio.sleep(2 ** attempt)
                logger.warning(f"Evidence storage attempt {attempt + 1} failed, retrying: {e}")

        raise EvidenceStorageError("Storage failed after all retries")


class EvidenceQueryService:
    """Service for querying and searching evidence."""

    def __init__(self, repository: EvidenceRepository):
        self.repository = repository

    async def get_evidence_by_control(
        self,
        control_id: str,
        framework_name: Optional[str] = None
    ) -> List[BaseEvidenceMetadata]:
        """Get all evidence for a specific control."""
        filters = {"tags.control_id": control_id}
        if framework_name:
            filters["framework_name"] = framework_name

        return await self.repository.search_evidence(**filters)

    async def get_evidence_by_bundle(self, bundle_id: str) -> List[BaseEvidenceMetadata]:
        """Get all evidence in a bundle."""
        bundle = await self.repository.get_bundle(bundle_id)
        if not bundle:
            return []

        evidence_items = []
        for evidence_id in bundle.evidence_ids:
            metadata = await self.repository.get_metadata(evidence_id)
            if metadata:
                evidence_items.append(metadata)

        return evidence_items

    async def search_evidence(
        self,
        framework_name: Optional[str] = None,
        control_id: Optional[str] = None,
        date_range: Optional[tuple[datetime, datetime]] = None,
        status: Optional[EvidenceStatus] = None,
        category: Optional[EvidenceCategory] = None
    ) -> List[BaseEvidenceMetadata]:
        """Search evidence with multiple filters."""
        filters = {}

        if framework_name:
            filters["framework_name"] = framework_name
        if control_id:
            filters["control_id"] = control_id
        if status:
            filters["status"] = status
        if category:
            filters["category"] = category
        if date_range:
            filters["date_range"] = date_range

        return await self.repository.search_evidence(**filters)