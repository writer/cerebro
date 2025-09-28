"""
Change attestation service for rule edits and suppressions.

Implements Sigstore/Rekor-style attestation for all policy changes
with cryptographic signatures and transparency log integration.
"""

import asyncio
import hashlib
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from .transparency_log import get_transparency_log, LogEntryType
from .timestamping import get_timestamp_service

logger = logging.getLogger(__name__)


class AttestationType(Enum):
    """Types of attestations that can be created."""
    RULE_CREATION = "rule_creation"
    RULE_MODIFICATION = "rule_modification"
    RULE_DELETION = "rule_deletion"
    FINDING_SUPPRESSION = "finding_suppression"
    POLICY_CHANGE = "policy_change"
    ACCESS_GRANT = "access_grant"
    ACCESS_REVOKE = "access_revoke"
    CONFIGURATION_CHANGE = "configuration_change"


@dataclass
class AttestationSubject:
    """Subject of an attestation (what is being attested)."""
    subject_type: str  # "rule", "finding", "policy", "access"
    subject_id: str
    previous_state: Optional[Dict[str, Any]]
    new_state: Dict[str, Any]
    change_summary: str


@dataclass
class AttestationPredicate:
    """Predicate of an attestation (what is being claimed)."""
    predicate_type: str  # "https://cerebro.security/attestation/v1/rule-change"
    timestamp: datetime
    actor: str
    justification: str
    approval_chain: List[Dict[str, Any]]
    evidence_references: List[str]


@dataclass
class SignedAttestation:
    """
    Signed attestation following in-toto/Sigstore patterns.
    
    Provides cryptographic proof of authorized changes.
    """
    attestation_id: str
    subject: AttestationSubject
    predicate: AttestationPredicate
    signature: str
    public_key: str
    timestamp_token: Optional[Dict[str, Any]]
    transparency_log_entry: str
    created_at: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert attestation to dictionary."""
        return {
            "attestation_id": self.attestation_id,
            "subject": asdict(self.subject),
            "predicate": asdict(self.predicate),
            "signature": self.signature,
            "public_key": self.public_key,
            "timestamp_token": self.timestamp_token,
            "transparency_log_entry": self.transparency_log_entry,
            "created_at": self.created_at.isoformat()
        }


class ChangeAttestationService:
    """
    Service for creating and verifying change attestations.
    
    Implements cryptographic attestation for all security policy changes
    with transparency log integration and timestamping.
    """
    
    def __init__(self):
        # Generate or load attestation signing key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        
        self.transparency_log = get_transparency_log()
        self.timestamp_service = get_timestamp_service()
    
    async def attest_rule_change(
        self,
        rule_id: str,
        actor: str,
        change_type: AttestationType,
        previous_rule: Optional[Dict[str, Any]],
        new_rule: Dict[str, Any],
        justification: str,
        approvers: List[str] = None
    ) -> SignedAttestation:
        """
        Create attestation for rule change.
        
        Args:
            rule_id: ID of the rule being changed
            actor: User making the change
            change_type: Type of change (creation, modification, deletion)
            previous_rule: Previous rule state (None for creation)
            new_rule: New rule state
            justification: Reason for the change
            approvers: List of users who approved the change
            
        Returns:
            Signed attestation with cryptographic proof
        """
        # Create attestation ID
        attestation_id = f"attest_{change_type.value}_{rule_id}_{int(datetime.now().timestamp())}"
        
        # Create subject
        subject = AttestationSubject(
            subject_type="rule",
            subject_id=rule_id,
            previous_state=previous_rule,
            new_state=new_rule,
            change_summary=self._generate_change_summary(previous_rule, new_rule)
        )
        
        # Create predicate
        predicate = AttestationPredicate(
            predicate_type=f"https://cerebro.security/attestation/v1/{change_type.value}",
            timestamp=datetime.now(),
            actor=actor,
            justification=justification,
            approval_chain=self._build_approval_chain(actor, approvers or []),
            evidence_references=[]  # Could reference evidence bundles
        )
        
        # Create attestation
        attestation = await self._create_signed_attestation(
            attestation_id, subject, predicate
        )
        
        logger.info(f"Created change attestation {attestation_id} for rule {rule_id}")
        
        return attestation
    
    async def attest_finding_suppression(
        self,
        finding_id: str,
        actor: str,
        suppression_reason: str,
        expiry_date: Optional[datetime] = None,
        approver: Optional[str] = None
    ) -> SignedAttestation:
        """
        Create attestation for finding suppression.
        
        Provides cryptographic proof of authorized finding suppression.
        """
        attestation_id = f"attest_suppression_{finding_id}_{int(datetime.now().timestamp())}"
        
        # Get current finding state
        finding_query = f"SELECT * FROM findings WHERE finding_id = '{finding_id}'"
        result = await self.query_engine.execute_query(finding_query)
        
        current_state = result.rows[0] if result.rows else {}
        
        subject = AttestationSubject(
            subject_type="finding",
            subject_id=finding_id,
            previous_state=current_state,
            new_state={**current_state, "status": "suppressed", "suppressed_at": datetime.now().isoformat()},
            change_summary=f"Finding suppressed: {suppression_reason}"
        )
        
        predicate = AttestationPredicate(
            predicate_type="https://cerebro.security/attestation/v1/finding_suppression",
            timestamp=datetime.now(),
            actor=actor,
            justification=suppression_reason,
            approval_chain=self._build_approval_chain(actor, [approver] if approver else []),
            evidence_references=[]
        )
        
        # Add expiry info to predicate
        if expiry_date:
            predicate.evidence_references.append(f"expiry_date:{expiry_date.isoformat()}")
        
        attestation = await self._create_signed_attestation(
            attestation_id, subject, predicate
        )
        
        return attestation
    
    async def _create_signed_attestation(
        self,
        attestation_id: str,
        subject: AttestationSubject,
        predicate: AttestationPredicate
    ) -> SignedAttestation:
        """Create cryptographically signed attestation."""
        
        # Create attestation payload
        payload = {
            "attestation_id": attestation_id,
            "subject": asdict(subject),
            "predicate": asdict(predicate)
        }
        
        # Convert dates to ISO format for signing
        payload_json = json.dumps(payload, sort_keys=True, default=str)
        
        # Sign the payload
        signature = self._sign_payload(payload_json)
        
        # Export public key
        public_key_pem = self._export_public_key()
        
        # Create timestamp token
        timestamp_token_data = await self.timestamp_service.timestamp_audit_event(payload)
        
        # Log to transparency log
        log_entry = await self.transparency_log.append_entry(
            LogEntryType.POLICY_CHANGE,
            predicate.actor,
            subject.subject_id,
            f"attestation_created_{subject.subject_type}",
            {
                "attestation_id": attestation_id,
                "change_type": subject.change_summary,
                "justification": predicate.justification,
                "approval_chain": predicate.approval_chain
            }
        )
        
        # Create final attestation
        attestation = SignedAttestation(
            attestation_id=attestation_id,
            subject=subject,
            predicate=predicate,
            signature=signature,
            public_key=public_key_pem,
            timestamp_token={
                "authority": timestamp_token_data.tsa_authority,
                "timestamp": timestamp_token_data.timestamp.isoformat(),
                "token": timestamp_token_data.token_data.hex(),
                "verification": timestamp_token_data.verification_info
            },
            transparency_log_entry=log_entry.entry_hash,
            created_at=datetime.now()
        )
        
        return attestation
    
    def _sign_payload(self, payload_json: str) -> str:
        """Sign attestation payload."""
        signature = self.private_key.sign(
            payload_json.encode(),
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
    
    def _generate_change_summary(
        self, 
        previous_state: Optional[Dict[str, Any]], 
        new_state: Dict[str, Any]
    ) -> str:
        """Generate human-readable change summary."""
        if previous_state is None:
            return f"Created new resource"
        
        # Compare states and generate summary
        changes = []
        
        for key, new_value in new_state.items():
            if key not in previous_state:
                changes.append(f"Added {key}: {new_value}")
            elif previous_state[key] != new_value:
                changes.append(f"Changed {key}: {previous_state[key]} -> {new_value}")
        
        for key in previous_state:
            if key not in new_state:
                changes.append(f"Removed {key}")
        
        if not changes:
            return "No changes detected"
        
        return "; ".join(changes[:5])  # Limit to first 5 changes
    
    def _build_approval_chain(self, actor: str, approvers: List[str]) -> List[Dict[str, Any]]:
        """Build approval chain for attestation."""
        chain = [{
            "role": "actor",
            "principal": actor,
            "timestamp": datetime.now().isoformat(),
            "action": "initiated_change"
        }]
        
        for approver in approvers:
            chain.append({
                "role": "approver",
                "principal": approver,
                "timestamp": datetime.now().isoformat(),
                "action": "approved_change"
            })
        
        return chain
    
    def verify_attestation(self, attestation: SignedAttestation) -> bool:
        """
        Verify the cryptographic signature of an attestation.
        
        Returns True if attestation is valid.
        """
        try:
            # Reconstruct payload for verification
            payload = {
                "attestation_id": attestation.attestation_id,
                "subject": asdict(attestation.subject),
                "predicate": asdict(attestation.predicate)
            }
            
            payload_json = json.dumps(payload, sort_keys=True, default=str)
            
            # Load public key
            public_key = serialization.load_pem_public_key(
                attestation.public_key.encode()
            )
            
            # Verify signature
            signature_bytes = bytes.fromhex(attestation.signature)
            public_key.verify(
                signature_bytes,
                payload_json.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Attestation verification failed: {e}")
            return False
    
    async def get_attestations_for_resource(
        self, 
        resource_id: str, 
        attestation_type: Optional[AttestationType] = None
    ) -> List[SignedAttestation]:
        """Get all attestations for a specific resource."""
        # Query transparency log for attestations
        entries = await self.transparency_log.get_entries(
            entry_type=LogEntryType.POLICY_CHANGE
        )
        
        # Filter for specific resource and type
        matching_attestations = []
        for entry in entries:
            if entry.resource_id == resource_id:
                details = entry.details
                if "attestation_id" in details:
                    # This would load the full attestation from storage
                    # For now, create a simplified version
                    attestation_id = details["attestation_id"]
                    matching_attestations.append(attestation_id)
        
        # In production, would load full attestations from storage
        return []


# Global attestation service
_attestation_service = ChangeAttestationService()


def get_attestation_service() -> ChangeAttestationService:
    """Get global change attestation service."""
    return _attestation_service
