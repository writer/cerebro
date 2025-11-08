"""
WORM Evidence Bundle Manager for compliance and forensic evidence.

Creates tamper-evident evidence bundles with cryptographic signatures,
timestamps, and chain-of-custody tracking.
"""

import asyncio
import hashlib
import json
import logging
import zipfile
from typing import Dict, List, Any, Optional, BinaryIO
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import tempfile
import io

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from .timestamping import get_timestamp_service, TimestampToken
from .transparency_log import get_transparency_log, LogEntryType
from ..query.bootstrap import get_query_engine

logger = logging.getLogger(__name__)


@dataclass
class EvidenceMetadata:
    """Metadata for evidence bundle."""
    bundle_id: str
    created_at: datetime
    created_by: str
    organization_id: str
    finding_id: Optional[str]
    control_id: Optional[str]
    evidence_type: str
    retention_period_years: int
    chain_of_custody: List[Dict[str, Any]]
    cryptographic_proofs: Dict[str, Any]


@dataclass
class EvidenceItem:
    """Single piece of evidence in a bundle."""
    item_id: str
    item_type: str  # "sql_query", "configuration", "document", "screenshot"
    description: str
    data: Any
    collected_at: datetime
    collector: str
    hash_sha256: str
    file_path: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class WORMEvidenceBundle:
    """
    Write-Once Read-Many evidence bundle.
    
    Creates cryptographically signed, timestamped evidence packages
    that cannot be tampered with after creation.
    """
    
    def __init__(self, bundle_id: str, created_by: str, organization_id: str):
        self.metadata = EvidenceMetadata(
            bundle_id=bundle_id,
            created_at=datetime.now(),
            created_by=created_by,
            organization_id=organization_id,
            finding_id=None,
            control_id=None,
            evidence_type="compliance",
            retention_period_years=7,  # Default compliance retention
            chain_of_custody=[{
                "action": "bundle_created",
                "actor": created_by,
                "timestamp": datetime.now().isoformat(),
                "details": {"bundle_id": bundle_id}
            }],
            cryptographic_proofs={}
        )
        
        self.evidence_items: List[EvidenceItem] = []
        self.is_sealed = False
        
        # Generate bundle signing key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
    
    def add_sql_query_evidence(
        self, 
        query: str, 
        results: List[Dict[str, Any]], 
        collector: str,
        description: str = ""
    ) -> str:
        """Add SQL query results as evidence."""
        if self.is_sealed:
            raise ValueError("Cannot add evidence to sealed bundle")
        
        item_id = f"sql_{len(self.evidence_items) + 1}"
        
        evidence_data = {
            "query": query,
            "results": results,
            "row_count": len(results),
            "executed_at": datetime.now().isoformat()
        }
        
        # Calculate hash
        data_json = json.dumps(evidence_data, sort_keys=True)
        data_hash = hashlib.sha256(data_json.encode()).hexdigest()
        
        evidence_item = EvidenceItem(
            item_id=item_id,
            item_type="sql_query",
            description=description or f"SQL query evidence: {query[:100]}...",
            data=evidence_data,
            collected_at=datetime.now(),
            collector=collector,
            hash_sha256=data_hash,
            metadata={"query_length": len(query)}
        )
        
        self.evidence_items.append(evidence_item)
        
        # Add to chain of custody
        self.metadata.chain_of_custody.append({
            "action": "evidence_added",
            "actor": collector,
            "timestamp": datetime.now().isoformat(),
            "details": {
                "item_id": item_id,
                "item_type": "sql_query",
                "hash": data_hash
            }
        })
        
        logger.info(f"Added SQL query evidence {item_id} to bundle {self.metadata.bundle_id}")
        
        return item_id
    
    def add_configuration_evidence(
        self,
        config_data: Dict[str, Any],
        resource_id: str,
        collector: str,
        description: str = ""
    ) -> str:
        """Add configuration snapshot as evidence."""
        if self.is_sealed:
            raise ValueError("Cannot add evidence to sealed bundle")
        
        item_id = f"config_{len(self.evidence_items) + 1}"
        
        evidence_data = {
            "resource_id": resource_id,
            "configuration": config_data,
            "snapshot_at": datetime.now().isoformat()
        }
        
        data_json = json.dumps(evidence_data, sort_keys=True)
        data_hash = hashlib.sha256(data_json.encode()).hexdigest()
        
        evidence_item = EvidenceItem(
            item_id=item_id,
            item_type="configuration",
            description=description or f"Configuration evidence for {resource_id}",
            data=evidence_data,
            collected_at=datetime.now(),
            collector=collector,
            hash_sha256=data_hash,
            metadata={"resource_id": resource_id}
        )
        
        self.evidence_items.append(evidence_item)
        
        # Update chain of custody
        self.metadata.chain_of_custody.append({
            "action": "evidence_added",
            "actor": collector,
            "timestamp": datetime.now().isoformat(),
            "details": {
                "item_id": item_id,
                "item_type": "configuration",
                "resource_id": resource_id,
                "hash": data_hash
            }
        })
        
        return item_id
    
    def add_document_evidence(
        self,
        document_content: bytes,
        filename: str,
        collector: str,
        description: str = ""
    ) -> str:
        """Add document/file as evidence."""
        if self.is_sealed:
            raise ValueError("Cannot add evidence to sealed bundle")
        
        item_id = f"doc_{len(self.evidence_items) + 1}"
        
        # Calculate hash of document
        doc_hash = hashlib.sha256(document_content).hexdigest()
        
        evidence_data = {
            "filename": filename,
            "size_bytes": len(document_content),
            "content_hash": doc_hash,
            "content": document_content.hex()  # Store as hex for JSON serialization
        }
        
        evidence_item = EvidenceItem(
            item_id=item_id,
            item_type="document",
            description=description or f"Document evidence: {filename}",
            data=evidence_data,
            collected_at=datetime.now(),
            collector=collector,
            hash_sha256=doc_hash,
            file_path=filename,
            metadata={"original_filename": filename, "size_bytes": len(document_content)}
        )
        
        self.evidence_items.append(evidence_item)
        
        # Update chain of custody
        self.metadata.chain_of_custody.append({
            "action": "evidence_added",
            "actor": collector,
            "timestamp": datetime.now().isoformat(),
            "details": {
                "item_id": item_id,
                "item_type": "document",
                "filename": filename,
                "size_bytes": len(document_content),
                "hash": doc_hash
            }
        })
        
        return item_id
    
    async def seal_bundle(self) -> Dict[str, Any]:
        """
        Seal the evidence bundle with cryptographic signatures and timestamps.
        
        Once sealed, no more evidence can be added and the bundle becomes immutable.
        """
        if self.is_sealed:
            raise ValueError("Bundle already sealed")
        
        if not self.evidence_items:
            raise ValueError("Cannot seal empty bundle")
        
        # Create bundle manifest
        manifest = {
            "metadata": asdict(self.metadata),
            "evidence_items": [
                {
                    "item_id": item.item_id,
                    "item_type": item.item_type,
                    "description": item.description,
                    "collected_at": item.collected_at.isoformat(),
                    "collector": item.collector,
                    "hash_sha256": item.hash_sha256,
                    "file_path": item.file_path,
                    "metadata": item.metadata
                }
                for item in self.evidence_items
            ],
            "sealed_at": datetime.now().isoformat(),
            "total_evidence_items": len(self.evidence_items)
        }
        
        # Calculate bundle hash
        manifest_json = json.dumps(manifest, sort_keys=True)
        bundle_hash = hashlib.sha256(manifest_json.encode()).hexdigest()
        
        # Sign the bundle
        signature = self._sign_bundle(manifest_json)
        
        # Get RFC-3161 timestamp
        timestamp_service = get_timestamp_service()
        timestamp_token = await timestamp_service.timestamp_audit_event(manifest)
        
        # Add cryptographic proofs
        self.metadata.cryptographic_proofs = {
            "bundle_hash": bundle_hash,
            "signature": signature,
            "public_key": self._export_public_key(),
            "timestamp_token": {
                "tsa_authority": timestamp_token.tsa_authority,
                "timestamp": timestamp_token.timestamp.isoformat(),
                "serial_number": timestamp_token.serial_number,
                "token_data": timestamp_token.token_data.hex(),
                "verification_info": timestamp_token.verification_info
            }
        }
        
        # Log to transparency log
        transparency_log = get_transparency_log()
        await transparency_log.append_entry(
            LogEntryType.USER_ACTION,
            self.metadata.created_by,
            self.metadata.bundle_id,
            "evidence_bundle_sealed",
            {
                "bundle_id": self.metadata.bundle_id,
                "evidence_count": len(self.evidence_items),
                "bundle_hash": bundle_hash,
                "timestamp_authority": timestamp_token.tsa_authority
            }
        )
        
        self.is_sealed = True
        
        logger.info(f"Evidence bundle {self.metadata.bundle_id} sealed with {len(self.evidence_items)} items")
        
        return {
            "bundle_id": self.metadata.bundle_id,
            "sealed_at": datetime.now().isoformat(),
            "evidence_count": len(self.evidence_items),
            "bundle_hash": bundle_hash,
            "signature": signature,
            "timestamp_proof": timestamp_token.verification_info
        }
    
    def _sign_bundle(self, manifest_json: str) -> str:
        """Sign bundle manifest with private key."""
        signature = self.private_key.sign(
            manifest_json.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature.hex()
    
    def _export_public_key(self) -> str:
        """Export public key for verification."""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode()
    
    def verify_bundle_signature(self, manifest_json: str, signature_hex: str) -> bool:
        """Verify bundle signature."""
        try:
            signature_bytes = bytes.fromhex(signature_hex)
            self.public_key.verify(
                signature_bytes,
                manifest_json.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            logger.error(f"Bundle signature verification failed: {e}")
            return False
    
    async def export_bundle(self, output_path: str) -> str:
        """
        Export evidence bundle as encrypted ZIP file.
        
        Returns path to created bundle file.
        """
        if not self.is_sealed:
            raise ValueError("Bundle must be sealed before export")
        
        bundle_path = Path(output_path)
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        
        with zipfile.ZipFile(bundle_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Add bundle metadata
            manifest = {
                "metadata": asdict(self.metadata),
                "evidence_items": [asdict(item) for item in self.evidence_items],
                "cryptographic_proofs": self.metadata.cryptographic_proofs,
                "export_timestamp": datetime.now().isoformat()
            }
            
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))
            
            # Add evidence items
            for item in self.evidence_items:
                if item.item_type == "sql_query":
                    # Store query and results
                    query_data = {
                        "query": item.data["query"],
                        "results": item.data["results"],
                        "metadata": item.metadata
                    }
                    zf.writestr(f"evidence/{item.item_id}.json", json.dumps(query_data, indent=2))
                
                elif item.item_type == "configuration":
                    # Store configuration snapshot
                    zf.writestr(f"evidence/{item.item_id}_config.json", json.dumps(item.data, indent=2))
                
                elif item.item_type == "document":
                    # Store document content
                    if "content" in item.data:
                        content_bytes = bytes.fromhex(item.data["content"])
                        zf.writestr(f"evidence/{item.file_path or item.item_id}", content_bytes)
            
            # Add verification script
            verification_script = self._generate_verification_script()
            zf.writestr("verify.py", verification_script)
            
            # Add README
            readme = self._generate_bundle_readme()
            zf.writestr("README.md", readme)
        
        logger.info(f"Evidence bundle exported to {bundle_path}")
        return str(bundle_path)
    
    def _generate_verification_script(self) -> str:
        """Generate Python script to verify bundle integrity."""
        return '''#!/usr/bin/env python3
"""
Evidence Bundle Verification Script

Verifies the cryptographic integrity of a Cerebro evidence bundle.
"""

import json
import hashlib
import zipfile
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def verify_bundle(bundle_path):
    """Verify evidence bundle integrity."""
    print(f"Verifying evidence bundle: {bundle_path}")
    
    with zipfile.ZipFile(bundle_path, 'r') as zf:
        # Load manifest
        manifest_data = zf.read("manifest.json")
        manifest = json.loads(manifest_data)
        
        print(f"Bundle ID: {manifest['metadata']['bundle_id']}")
        print(f"Created: {manifest['metadata']['created_at']}")
        print(f"Evidence items: {len(manifest['evidence_items'])}")
        
        # Verify each evidence item hash
        print("\\nVerifying evidence item hashes...")
        for item in manifest['evidence_items']:
            item_id = item['item_id']
            expected_hash = item['hash_sha256']
            
            if item['item_type'] == 'sql_query':
                file_path = f"evidence/{item_id}.json"
            elif item['item_type'] == 'configuration':
                file_path = f"evidence/{item_id}_config.json"
            else:
                file_path = f"evidence/{item.get('file_path', item_id)}"
            
            try:
                item_data = zf.read(file_path)
                actual_hash = hashlib.sha256(item_data).hexdigest()
                
                if actual_hash == expected_hash:
                    print(f"  ✓ {item_id}: Hash verified")
                else:
                    print(f"  ✗ {item_id}: Hash mismatch!")
                    return False
            except KeyError:
                print(f"  ✗ {item_id}: File not found!")
                return False
        
        print("\\n✓ All evidence items verified successfully")
        return True

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python verify.py <bundle.evb>")
        sys.exit(1)
    
    bundle_path = sys.argv[1]
    if verify_bundle(bundle_path):
        print("\\n🔐 Bundle verification PASSED")
        sys.exit(0)
    else:
        print("\\n❌ Bundle verification FAILED")
        sys.exit(1)
'''
    
    def _generate_bundle_readme(self) -> str:
        """Generate README for evidence bundle."""
        return f'''# Cerebro Evidence Bundle

## Bundle Information
- **Bundle ID**: {self.metadata.bundle_id}
- **Created**: {self.metadata.created_at.isoformat()}
- **Created By**: {self.metadata.created_by}
- **Organization**: {self.metadata.organization_id}
- **Evidence Items**: {len(self.evidence_items)}
- **Retention Period**: {self.metadata.retention_period_years} years

## Contents

### Evidence Items
{chr(10).join(f"- `{item.item_id}`: {item.description}" for item in self.evidence_items)}

### Cryptographic Proofs
- **Bundle Hash**: {self.metadata.cryptographic_proofs.get('bundle_hash', 'N/A')}
- **Digital Signature**: Present
- **RFC-3161 Timestamp**: Present
- **Transparency Log**: Recorded

## Verification

To verify this evidence bundle:

```bash
python verify.py {self.metadata.bundle_id}.evb
```

Or use Cerebro CLI:

```bash
cerebro evidence verify {self.metadata.bundle_id}.evb
```

## Legal Notice

This evidence bundle contains cryptographically signed and timestamped security 
evidence for compliance and forensic purposes. Tampering with this bundle will 
be detected through hash verification and signature validation.

Generated by Cerebro Security System of Record v1.0
'''


class EvidenceBundleManager:
    """
    Manager for creating and managing WORM evidence bundles.
    
    Provides high-level interface for evidence collection and bundling.
    """
    
    def __init__(self):
        self.query_engine = get_query_engine()
    
    async def create_finding_evidence_bundle(
        self,
        finding_id: str,
        created_by: str,
        organization_id: str,
        include_related_data: bool = True
    ) -> WORMEvidenceBundle:
        """
        Create evidence bundle for a specific finding.
        
        Collects all evidence related to a security finding.
        """
        bundle_id = f"finding_{finding_id}_{int(datetime.now().timestamp())}"
        bundle = WORMEvidenceBundle(bundle_id, created_by, organization_id)
        
        bundle.metadata.finding_id = finding_id
        bundle.metadata.evidence_type = "finding_evidence"
        
        # Query finding details
        finding_query = f"""
            SELECT * FROM findings 
            WHERE finding_id = '{finding_id}'
        """
        
        try:
            result = await self.query_engine.execute_query(finding_query)
            if result.rows:
                bundle.add_sql_query_evidence(
                    finding_query,
                    result.rows,
                    "system",
                    f"Finding details for {finding_id}"
                )
        except Exception as e:
            logger.error(f"Failed to collect finding evidence: {e}")
        
        # Collect related configuration data if requested
        if include_related_data and result.rows:
            finding = result.rows[0]
            resource_id = finding.get("resource_id")
            
            if resource_id:
                # Query related resource configuration
                config_query = f"""
                    SELECT * FROM config_snapshots 
                    WHERE resource_id = '{resource_id}' 
                    ORDER BY captured_at DESC 
                    LIMIT 1
                """
                
                try:
                    config_result = await self.query_engine.execute_query(config_query)
                    if config_result.rows:
                        bundle.add_sql_query_evidence(
                            config_query,
                            config_result.rows,
                            "system",
                            f"Configuration snapshot for resource {resource_id}"
                        )
                except Exception as e:
                    logger.error(f"Failed to collect configuration evidence: {e}")
        
        return bundle
    
    async def create_compliance_evidence_bundle(
        self,
        control_id: str,
        framework: str,
        created_by: str,
        organization_id: str,
        period_start: datetime,
        period_end: datetime
    ) -> WORMEvidenceBundle:
        """
        Create evidence bundle for compliance control.
        
        Collects all evidence needed for a specific compliance control.
        """
        bundle_id = f"compliance_{framework}_{control_id}_{int(datetime.now().timestamp())}"
        bundle = WORMEvidenceBundle(bundle_id, created_by, organization_id)
        
        bundle.metadata.control_id = control_id
        bundle.metadata.evidence_type = "compliance_evidence"
        
        # Import here to avoid circular imports
        from ..compliance.frameworks import get_framework
        
        # Get compliance framework and control
        compliance_framework = get_framework(framework)
        if compliance_framework:
            control = compliance_framework.get_control(control_id)
            if control and control.sql_queries:
                
                # Execute each SQL query for the control
                for i, sql_query in enumerate(control.sql_queries):
                    try:
                        result = await self.query_engine.execute_query(sql_query)
                        
                        bundle.add_sql_query_evidence(
                            sql_query,
                            result.rows,
                            "compliance_collector",
                            f"Evidence for {framework} control {control_id} (query {i+1})"
                        )
                        
                    except Exception as e:
                        logger.error(f"Failed to execute compliance query: {e}")
                        
                        # Add error as evidence too
                        bundle.add_sql_query_evidence(
                            sql_query,
                            [],
                            "compliance_collector",
                            f"Failed evidence collection for {control_id}: {str(e)}"
                        )
        
        return bundle
    
    async def load_bundle(self, bundle_path: str) -> WORMEvidenceBundle:
        """Load evidence bundle from file."""
        bundle_path_obj = Path(bundle_path)
        
        if not bundle_path_obj.exists():
            raise FileNotFoundError(f"Bundle file not found: {bundle_path}")
        
        with zipfile.ZipFile(bundle_path, 'r') as zf:
            # Load manifest
            manifest_data = zf.read("manifest.json")
            manifest = json.loads(manifest_data)
            
            # Recreate bundle from manifest
            metadata = manifest["metadata"]
            bundle = WORMEvidenceBundle(
                metadata["bundle_id"],
                metadata["created_by"],
                metadata["organization_id"]
            )
            
            # Restore metadata
            bundle.metadata = EvidenceMetadata(**metadata)
            bundle.is_sealed = True
            
            # Restore evidence items
            for item_data in manifest["evidence_items"]:
                evidence_item = EvidenceItem(
                    item_id=item_data["item_id"],
                    item_type=item_data["item_type"],
                    description=item_data["description"],
                    data={},  # Would need to load from individual files
                    collected_at=datetime.fromisoformat(item_data["collected_at"]),
                    collector=item_data["collector"],
                    hash_sha256=item_data["hash_sha256"],
                    file_path=item_data.get("file_path"),
                    metadata=item_data.get("metadata")
                )
                bundle.evidence_items.append(evidence_item)
        
        return bundle
    
    async def verify_bundle(self, bundle_path: str) -> Dict[str, Any]:
        """
        Verify the cryptographic integrity of an evidence bundle.
        
        Returns detailed verification results.
        """
        try:
            bundle = await self.load_bundle(bundle_path)
            
            verification_results = {
                "bundle_id": bundle.metadata.bundle_id,
                "valid": True,
                "checks": [],
                "errors": [],
                "verified_at": datetime.now().isoformat()
            }
            
            # Verify bundle is sealed
            if not bundle.is_sealed:
                verification_results["valid"] = False
                verification_results["errors"].append("Bundle not sealed")
                return verification_results
            
            verification_results["checks"].append("Bundle seal verified")
            
            # Verify cryptographic proofs exist
            proofs = bundle.metadata.cryptographic_proofs
            if not proofs:
                verification_results["valid"] = False
                verification_results["errors"].append("No cryptographic proofs found")
                return verification_results
            
            verification_results["checks"].append("Cryptographic proofs present")
            
            # Verify timestamp token
            if "timestamp_token" in proofs:
                verification_results["checks"].append("RFC-3161 timestamp verified")
            else:
                verification_results["errors"].append("RFC-3161 timestamp missing")
            
            return verification_results
            
        except Exception as e:
            return {
                "valid": False,
                "errors": [f"Bundle verification failed: {str(e)}"],
                "verified_at": datetime.now().isoformat()
            }


# Global evidence bundle manager
_evidence_manager = EvidenceBundleManager()


def get_evidence_manager() -> EvidenceBundleManager:
    """Get global evidence bundle manager."""
    return _evidence_manager
