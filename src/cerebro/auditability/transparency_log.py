"""
Transparency log implementation with Merkle tree for cryptographic auditability.

Provides an immutable, verifiable log of all security events with cryptographic proofs.
"""

import hashlib
import json
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from sqlalchemy import select

from ..core.database import async_session_factory
from ..core.models import AuditEvent

logger = logging.getLogger(__name__)


class LogEntryType(Enum):
    """Types of entries that can be logged."""

    CONFIG_SNAPSHOT = "config_snapshot"
    RULE_CHANGE = "rule_change"
    FINDING_CREATED = "finding_created"
    FINDING_UPDATED = "finding_updated"
    USER_ACTION = "user_action"
    POLICY_CHANGE = "policy_change"
    ACCESS_GRANTED = "access_granted"
    ACCESS_REVOKED = "access_revoked"
    INTEGRATION_SYNC = "integration_sync"


@dataclass
class LogEntry:
    """Single entry in the transparency log."""

    sequence_number: int
    timestamp: datetime
    entry_type: LogEntryType
    actor: str  # User/system that performed the action
    resource_id: str
    action: str
    details: Dict[str, Any]
    previous_hash: str
    entry_hash: str
    signature: Optional[str] = None


@dataclass
class MerkleNode:
    """Node in the Merkle tree."""

    hash: str
    left_child: Optional["MerkleNode"] = None
    right_child: Optional["MerkleNode"] = None
    is_leaf: bool = False
    data: Optional[str] = None


class MerkleTree:
    """
    Merkle tree implementation for cryptographic verification of log integrity.

    Provides efficient proof generation and verification for log entries.
    """

    def __init__(self, entries: List[str]):
        """Initialize Merkle tree from list of entry hashes."""
        if not entries:
            raise ValueError("Cannot create empty Merkle tree")

        self.leaves = [
            MerkleNode(hash=entry, is_leaf=True, data=entry) for entry in entries
        ]
        self.root = self._build_tree(self.leaves)

    def _build_tree(self, nodes: List[MerkleNode]) -> MerkleNode:
        """Build Merkle tree from leaf nodes."""
        if len(nodes) == 1:
            return nodes[0]

        next_level = []

        # Process nodes in pairs
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = (
                nodes[i + 1] if i + 1 < len(nodes) else left
            )  # Duplicate last node if odd

            # Create parent node
            combined_hash = self._hash_pair(left.hash, right.hash)
            parent = MerkleNode(
                hash=combined_hash,
                left_child=left,
                right_child=right if right != left else None,
            )
            next_level.append(parent)

        return self._build_tree(next_level)

    def _hash_pair(self, left_hash: str, right_hash: str) -> str:
        """Hash two child hashes together."""
        combined = left_hash + right_hash
        return hashlib.sha256(combined.encode()).hexdigest()

    def get_root_hash(self) -> str:
        """Get the root hash of the tree."""
        return self.root.hash

    def generate_proof(self, entry_hash: str) -> List[Dict[str, Any]]:
        """
        Generate inclusion proof for an entry.

        Returns list of sibling hashes needed to verify inclusion.
        """
        proof = []

        # Find the leaf node
        leaf_index = None
        for i, leaf in enumerate(self.leaves):
            if leaf.hash == entry_hash:
                leaf_index = i
                break

        if leaf_index is None:
            raise ValueError(f"Entry hash {entry_hash} not found in tree")

        # Traverse tree to collect proof
        current_index = leaf_index
        current_level = self.leaves

        while len(current_level) > 1:
            # Get sibling
            if current_index % 2 == 0:  # Left child
                sibling_index = current_index + 1
                position = "right"
            else:  # Right child
                sibling_index = current_index - 1
                position = "left"

            if sibling_index < len(current_level):
                sibling_hash = current_level[sibling_index].hash
                proof.append({"hash": sibling_hash, "position": position})

            # Move to parent level
            current_index = current_index // 2
            next_level = []

            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined_hash = self._hash_pair(left.hash, right.hash)
                next_level.append(MerkleNode(hash=combined_hash))

            current_level = next_level

        return proof

    def verify_proof(
        self, entry_hash: str, proof: List[Dict[str, Any]], root_hash: str
    ) -> bool:
        """
        Verify inclusion proof for an entry.

        Returns True if the entry is included in the tree with the given root hash.
        """
        current_hash = entry_hash

        for proof_element in proof:
            sibling_hash = proof_element["hash"]
            position = proof_element["position"]

            if position == "left":
                current_hash = self._hash_pair(sibling_hash, current_hash)
            else:
                current_hash = self._hash_pair(current_hash, sibling_hash)

        return current_hash == root_hash


class TransparencyLog:
    """
    Cryptographic transparency log for audit events.

    Maintains an immutable, verifiable log of all security-related actions
    with Merkle tree proofs and cryptographic signatures.
    """

    def __init__(self):
        self.current_sequence = 0
        self.previous_hash = "0" * 64  # Genesis hash

        # Generate or load signing key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.public_key = self.private_key.public_key()

    async def append_entry(
        self,
        entry_type: LogEntryType,
        actor: str,
        resource_id: str,
        action: str,
        details: Dict[str, Any],
    ) -> LogEntry:
        """
        Append a new entry to the transparency log.

        Returns the created log entry with cryptographic proof.
        """
        # Get next sequence number
        self.current_sequence += 1

        # Create log entry
        entry = LogEntry(
            sequence_number=self.current_sequence,
            timestamp=datetime.now(),
            entry_type=entry_type,
            actor=actor,
            resource_id=resource_id,
            action=action,
            details=details,
            previous_hash=self.previous_hash,
            entry_hash="",  # Will be calculated
        )

        # Calculate entry hash
        entry_data = {
            "sequence_number": entry.sequence_number,
            "timestamp": entry.timestamp.isoformat(),
            "entry_type": entry.entry_type.value,
            "actor": entry.actor,
            "resource_id": entry.resource_id,
            "action": entry.action,
            "details": entry.details,
            "previous_hash": entry.previous_hash,
        }

        entry_json = json.dumps(entry_data, sort_keys=True)
        entry.entry_hash = hashlib.sha256(entry_json.encode()).hexdigest()

        # Sign the entry
        entry.signature = self._sign_entry(entry_json)

        # Update previous hash for next entry
        self.previous_hash = entry.entry_hash

        # Store in database
        await self._store_entry(entry)

        logger.info(
            f"Transparency log entry {entry.sequence_number} created: {entry.entry_hash}"
        )

        return entry

    def _sign_entry(self, entry_json: str) -> str:
        """Sign log entry with private key."""
        signature = self.private_key.sign(
            entry_json.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        return signature.hex()

    def verify_entry_signature(self, entry: LogEntry) -> bool:
        """Verify the signature of a log entry."""
        if not entry.signature:
            return False

        # Reconstruct entry data for verification
        entry_data = {
            "sequence_number": entry.sequence_number,
            "timestamp": entry.timestamp.isoformat(),
            "entry_type": entry.entry_type.value,
            "actor": entry.actor,
            "resource_id": entry.resource_id,
            "action": entry.action,
            "details": entry.details,
            "previous_hash": entry.previous_hash,
        }

        entry_json = json.dumps(entry_data, sort_keys=True)

        try:
            signature_bytes = bytes.fromhex(entry.signature)
            self.public_key.verify(
                signature_bytes,
                entry_json.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

    async def _store_entry(self, entry: LogEntry):
        """Store log entry in database."""
        async with async_session_factory() as db:
            audit_event = AuditEvent(
                timestamp=entry.timestamp,
                principal_id=entry.actor,
                action=entry.action,
                resource_type="transparency_log",
                resource_id=entry.resource_id,
                metadata={
                    "sequence_number": entry.sequence_number,
                    "entry_type": entry.entry_type.value,
                    "entry_hash": entry.entry_hash,
                    "previous_hash": entry.previous_hash,
                    "signature": entry.signature,
                    "details": entry.details,
                },
            )

            db.add(audit_event)
            await db.commit()

    async def get_entries(
        self,
        start_sequence: Optional[int] = None,
        end_sequence: Optional[int] = None,
        entry_type: Optional[LogEntryType] = None,
    ) -> List[LogEntry]:
        """Retrieve log entries with optional filtering."""
        async with async_session_factory() as db:
            stmt = select(AuditEvent).where(
                AuditEvent.action == "transparency_log"
            )

            if start_sequence is not None:
                stmt = stmt.where(
                    AuditEvent.raw["sequence_number"].as_integer()
                    >= start_sequence
                )

            if end_sequence is not None:
                stmt = stmt.where(
                    AuditEvent.raw["sequence_number"].as_integer() <= end_sequence
                )

            if entry_type is not None:
                stmt = stmt.where(
                    AuditEvent.raw["entry_type"].as_string() == entry_type.value
                )

            stmt = stmt.order_by(AuditEvent.raw["sequence_number"])

            events = await db.scalars(stmt)

            # Convert to LogEntry objects
            entries: List[LogEntry] = []
            for event in events:
                raw = event.raw
                entry = LogEntry(
                    sequence_number=raw["sequence_number"],
                    timestamp=event.occurred_at,
                    entry_type=LogEntryType(raw["entry_type"]),
                    actor=event.actor_external_id or "",
                    resource_id=event.resource_external_id or "",
                    action=event.action,
                    details=raw.get("details", {}),
                    previous_hash=raw["previous_hash"],
                    entry_hash=raw["entry_hash"],
                    signature=raw.get("signature"),
                )
                entries.append(entry)

            return entries

    async def verify_log_integrity(
        self, start_sequence: int = 1, end_sequence: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Verify the integrity of the transparency log.

        Checks hash chain consistency and signature validity.
        """
        entries = await self.get_entries(start_sequence, end_sequence)

        if not entries:
            return {"valid": True, "message": "No entries to verify"}

        failed_entries: List[Dict[str, Any]] = []
        verification_results: Dict[str, Any] = {
            "valid": True,
            "total_entries": len(entries),
            "verified_entries": 0,
            "failed_entries": failed_entries,
            "hash_chain_valid": True,
            "signature_check_passed": 0,
            "signature_check_failed": 0,
        }

        previous_hash = "0" * 64 if start_sequence == 1 else None

        for entry in entries:
            # Verify hash chain continuity
            if previous_hash is not None and entry.previous_hash != previous_hash:
                verification_results["valid"] = False
                verification_results["hash_chain_valid"] = False
                failed_entries.append(
                    {
                        "sequence": entry.sequence_number,
                        "error": "Hash chain broken",
                        "expected_previous": previous_hash,
                        "actual_previous": entry.previous_hash,
                    }
                )
                continue

            # Verify entry hash
            entry_data = {
                "sequence_number": entry.sequence_number,
                "timestamp": entry.timestamp.isoformat(),
                "entry_type": entry.entry_type.value,
                "actor": entry.actor,
                "resource_id": entry.resource_id,
                "action": entry.action,
                "details": entry.details,
                "previous_hash": entry.previous_hash,
            }

            expected_hash = hashlib.sha256(
                json.dumps(entry_data, sort_keys=True).encode()
            ).hexdigest()

            if expected_hash != entry.entry_hash:
                verification_results["valid"] = False
                failed_entries.append(
                    {
                        "sequence": entry.sequence_number,
                        "error": "Entry hash mismatch",
                        "expected_hash": expected_hash,
                        "actual_hash": entry.entry_hash,
                    }
                )
                continue

            # Verify signature
            sig_passed = int(verification_results["signature_check_passed"])
            sig_failed = int(verification_results["signature_check_failed"])
            verified = int(verification_results["verified_entries"])
            if entry.signature and self.verify_entry_signature(entry):
                verification_results["signature_check_passed"] = sig_passed + 1
            elif entry.signature:
                verification_results["signature_check_failed"] = sig_failed + 1
                failed_entries.append(
                    {"sequence": entry.sequence_number, "error": "Invalid signature"}
                )

            verification_results["verified_entries"] = verified + 1
            previous_hash = entry.entry_hash

        return verification_results

    async def get_merkle_proof(self, sequence_number: int) -> Dict[str, Any]:
        """
        Generate Merkle proof for a specific log entry.

        Returns proof that can be independently verified.
        """
        # Get a range of entries around the target
        batch_size = 1000
        start_seq = max(1, (sequence_number // batch_size) * batch_size)
        end_seq = start_seq + batch_size - 1

        entries = await self.get_entries(start_seq, end_seq)

        if not entries:
            raise ValueError(f"No entries found for sequence {sequence_number}")

        # Find target entry
        target_entry = None
        for entry in entries:
            if entry.sequence_number == sequence_number:
                target_entry = entry
                break

        if not target_entry:
            raise ValueError(f"Entry {sequence_number} not found")

        # Build Merkle tree for this batch
        entry_hashes = [entry.entry_hash for entry in entries]
        merkle_tree = MerkleTree(entry_hashes)

        # Generate inclusion proof
        proof = merkle_tree.generate_proof(target_entry.entry_hash)

        return {
            "sequence_number": sequence_number,
            "entry_hash": target_entry.entry_hash,
            "root_hash": merkle_tree.get_root_hash(),
            "proof": proof,
            "batch_range": {"start": start_seq, "end": end_seq},
            "generated_at": datetime.now().isoformat(),
        }

    async def verify_merkle_proof(self, proof_data: Dict[str, Any]) -> bool:
        """Verify a Merkle inclusion proof."""
        try:
            # Extract proof components
            entry_hash = proof_data["entry_hash"]
            root_hash = proof_data["root_hash"]
            proof = proof_data["proof"]

            # Create temporary Merkle tree for verification
            # In production, we'd rebuild the tree from the specific batch
            current_hash = entry_hash

            for proof_element in proof:
                sibling_hash = proof_element["hash"]
                position = proof_element["position"]

                if position == "left":
                    current_hash = hashlib.sha256(
                        (sibling_hash + current_hash).encode()
                    ).hexdigest()
                else:
                    current_hash = hashlib.sha256(
                        (current_hash + sibling_hash).encode()
                    ).hexdigest()

            return current_hash == root_hash

        except Exception as e:
            logger.error(f"Merkle proof verification failed: {e}")
            return False

    def export_public_key(self) -> str:
        """Export public key for signature verification."""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode()

    async def get_log_summary(self) -> Dict[str, Any]:
        """Get summary statistics of the transparency log."""
        async with async_session_factory() as db:
            # Count entries by type
            stmt = select(AuditEvent).where(
                AuditEvent.action == "transparency_log"
            )

            all_entries = await db.scalars(stmt)
            entries_list = list(all_entries)

            if not entries_list:
                return {
                    "total_entries": 0,
                    "latest_sequence": 0,
                    "log_start": None,
                    "log_end": None,
                }

            # Group by entry type
            entry_types: Dict[str, int] = {}
            latest_sequence = 0
            earliest_time: Optional[datetime] = None
            latest_time: Optional[datetime] = None

            for event in entries_list:
                raw = event.raw
                entry_type = raw.get("entry_type", "unknown")
                sequence_num = raw.get("sequence_number", 0)

                entry_types[entry_type] = entry_types.get(entry_type, 0) + 1
                latest_sequence = max(latest_sequence, sequence_num)

                if earliest_time is None or event.occurred_at < earliest_time:
                    earliest_time = event.occurred_at
                if latest_time is None or event.occurred_at > latest_time:
                    latest_time = event.occurred_at

            return {
                "total_entries": len(entries_list),
                "latest_sequence": latest_sequence,
                "log_start": earliest_time.isoformat() if earliest_time else None,
                "log_end": latest_time.isoformat() if latest_time else None,
                "entries_by_type": entry_types,
                "public_key_fingerprint": self._get_public_key_fingerprint(),
            }

    def _get_public_key_fingerprint(self) -> str:
        """Get fingerprint of public key for verification."""
        public_key_pem = self.export_public_key()
        return hashlib.sha256(public_key_pem.encode()).hexdigest()[:16]


# Global transparency log instance
_transparency_log = TransparencyLog()


def get_transparency_log() -> TransparencyLog:
    """Get the global transparency log instance."""
    return _transparency_log


async def log_security_event(
    entry_type: LogEntryType,
    actor: str,
    resource_id: str,
    action: str,
    details: Dict[str, Any],
) -> LogEntry:
    """Convenience function to log security events."""
    return await _transparency_log.append_entry(
        entry_type, actor, resource_id, action, details
    )
