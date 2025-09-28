"""Identity stitching across providers."""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from uuid import UUID
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_

from .models import Principal, Account

logger = logging.getLogger(__name__)


@dataclass
class IdentityCluster:
    """A cluster of related identities across providers."""
    cluster_id: str
    principals: List[Principal]
    confidence_score: float
    stitching_evidence: Dict[str, str]


class IdentityStitcher:
    """Stitches identities across different providers."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize identity stitcher."""
        self.db = db_session
    
    async def find_identity_clusters(self, org_id: UUID) -> List[IdentityCluster]:
        """Find identity clusters for an organization."""
        # Get all principals for the organization
        stmt = select(Principal).join(Principal.account).where(
            Principal.account.has(org_id=org_id)
        )
        principals = list(await self.db.scalars(stmt))
        
        if not principals:
            return []
        
        logger.info(f"Analyzing {len(principals)} principals for identity stitching")
        
        # Group by email first (strongest signal)
        email_groups = self._group_by_email(principals)
        
        # Group by display name patterns
        name_groups = self._group_by_name(principals)
        
        # Merge groups and calculate confidence
        clusters = []
        processed_ids = set()
        
        for email, email_principals in email_groups.items():
            if not email or len(email_principals) < 2:
                continue
                
            principal_ids = {p.principal_id for p in email_principals}
            if principal_ids.intersection(processed_ids):
                continue
                
            cluster = IdentityCluster(
                cluster_id=f"email-{hash(email)}",
                principals=email_principals,
                confidence_score=0.9,  # High confidence for email matches
                stitching_evidence={"method": "email_match", "email": email}
            )
            clusters.append(cluster)
            processed_ids.update(principal_ids)
        
        # Add name-based clusters for remaining principals
        for name, name_principals in name_groups.items():
            if not name or len(name_principals) < 2:
                continue
                
            principal_ids = {p.principal_id for p in name_principals}
            if principal_ids.intersection(processed_ids):
                continue
                
            cluster = IdentityCluster(
                cluster_id=f"name-{hash(name)}",
                principals=name_principals,
                confidence_score=0.6,  # Lower confidence for name matches
                stitching_evidence={"method": "name_match", "name": name}
            )
            clusters.append(cluster)
            processed_ids.update(principal_ids)
        
        logger.info(f"Found {len(clusters)} identity clusters")
        return clusters
    
    def _group_by_email(self, principals: List[Principal]) -> Dict[str, List[Principal]]:
        """Group principals by email address."""
        groups = {}
        for principal in principals:
            if principal.email and principal.is_human:
                email = principal.email.lower().strip()
                if email not in groups:
                    groups[email] = []
                groups[email].append(principal)
        return groups
    
    def _group_by_name(self, principals: List[Principal]) -> Dict[str, List[Principal]]:
        """Group principals by display name."""
        groups = {}
        for principal in principals:
            if principal.display_name and principal.is_human:
                # Normalize name (remove common variations)
                name = self._normalize_name(principal.display_name)
                if name not in groups:
                    groups[name] = []
                groups[name].append(principal)
        return groups
    
    def _normalize_name(self, display_name: str) -> str:
        """Normalize display name for matching."""
        name = display_name.lower().strip()
        
        # Remove common suffixes
        suffixes = [" (contractor)", " - contractor", " (external)"]
        for suffix in suffixes:
            if name.endswith(suffix):
                name = name[:-len(suffix)]
        
        return name
    
    async def get_unified_identity(self, principal_id: UUID) -> Optional[Dict]:
        """Get unified identity information for a principal."""
        principal = await self.db.get(Principal, principal_id)
        if not principal:
            return None
        
        # Find cluster containing this principal
        clusters = await self.find_identity_clusters(principal.account.org_id)
        
        for cluster in clusters:
            if any(p.principal_id == principal_id for p in cluster.principals):
                return {
                    "cluster_id": cluster.cluster_id,
                    "confidence_score": cluster.confidence_score,
                    "stitching_evidence": cluster.stitching_evidence,
                    "related_principals": [
                        {
                            "principal_id": p.principal_id,
                            "provider": p.provider,
                            "external_id": p.external_id,
                            "email": p.email,
                            "display_name": p.display_name
                        }
                        for p in cluster.principals
                    ]
                }
        
        return None
