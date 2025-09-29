"""
Discovered vendor tracking from OAuth apps and integrations.

Automatically discovers vendors through OAuth applications, API integrations,
and network traffic analysis.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from ..oauth_risk.registry import get_oauth_registry, OAuthApp
from ..query.engine import QueryEngine
from ..providers.tables import register_all_provider_tables

logger = logging.getLogger(__name__)


class DiscoveryMethod(Enum):
    """Methods for discovering vendors."""
    OAUTH_APPLICATION = "oauth_application"
    API_INTEGRATION = "api_integration"
    NETWORK_TRAFFIC = "network_traffic"
    DNS_ANALYSIS = "dns_analysis"
    CERTIFICATE_ANALYSIS = "certificate_analysis"
    MANUAL_ENTRY = "manual_entry"


@dataclass
class DiscoveredVendor:
    """Automatically discovered vendor relationship."""
    discovered_vendor_id: str
    vendor_name: str
    domain: str
    discovery_method: DiscoveryMethod
    discovered_at: datetime
    last_seen: datetime
    
    # Discovery context
    discovered_via: str  # Specific app/integration that led to discovery
    confidence_score: float  # How confident we are this is actually a vendor
    
    # Risk indicators
    data_access_detected: bool
    authentication_observed: bool
    external_network_access: bool
    
    # Vendor classification
    estimated_category: str
    risk_indicators: List[str]
    
    # Associated resources
    oauth_apps: List[str]
    integrations: List[str]
    network_connections: List[str]
    
    # Status
    reviewed: bool
    promoted_to_vendor: bool
    suppressed: bool
    suppression_reason: Optional[str]
    
    # Metadata
    metadata: Dict[str, Any]


class DiscoveredVendorTracker:
    """
    Tracks automatically discovered vendor relationships.
    
    Analyzes OAuth apps, integrations, and network traffic to
    automatically discover vendor relationships.
    """
    
    def __init__(self):
        self.oauth_registry = get_oauth_registry()
        self.query_engine = QueryEngine()
        register_all_provider_tables()
        self.discovered_vendors: Dict[str, DiscoveredVendor] = {}
    
    async def discover_vendors_from_oauth(self, org_id: str) -> List[DiscoveredVendor]:
        """Discover vendors through OAuth application analysis."""
        discovered = []
        
        # Get all OAuth apps
        oauth_apps = await self.oauth_registry.discover_oauth_apps(org_id)
        
        for app in oauth_apps:
            # Skip internal apps
            if app.is_internal:
                continue
            
            # Extract vendor info from app
            vendor_domain = app.publisher_domain
            if not vendor_domain:
                continue
            
            # Check if we've already discovered this vendor
            existing = next(
                (v for v in self.discovered_vendors.values() if v.domain == vendor_domain),
                None
            )
            
            if existing:
                # Update existing discovery
                existing.last_seen = datetime.now()
                existing.oauth_apps.append(app.app_id)
                continue
            
            # Create new discovered vendor
            discovered_vendor = DiscoveredVendor(
                discovered_vendor_id=f"discovered_{vendor_domain}_{int(datetime.now().timestamp())}",
                vendor_name=self._extract_vendor_name(vendor_domain, app.app_name),
                domain=vendor_domain,
                discovery_method=DiscoveryMethod.OAUTH_APPLICATION,
                discovered_at=datetime.now(),
                last_seen=datetime.now(),
                discovered_via=app.app_name,
                confidence_score=self._calculate_discovery_confidence(app),
                data_access_detected=any(scope.sensitive_data_access for scope in app.scopes),
                authentication_observed=True,  # OAuth inherently involves authentication
                external_network_access=True,  # OAuth apps typically external
                estimated_category=self._estimate_vendor_category(app),
                risk_indicators=self._identify_vendor_risk_indicators(app),
                oauth_apps=[app.app_id],
                integrations=[],
                network_connections=[],
                reviewed=False,
                promoted_to_vendor=False,
                suppressed=False,
                suppression_reason=None,
                metadata={
                    "discovery_app": app.app_name,
                    "app_category": app.category.value,
                    "scope_count": len(app.scopes),
                    "risk_level": app.risk_level.value
                }
            )
            
            self.discovered_vendors[discovered_vendor.discovered_vendor_id] = discovered_vendor
            discovered.append(discovered_vendor)
        
        logger.info(f"Discovered {len(discovered)} new vendors from OAuth apps")
        
        return discovered
    
    async def discover_vendors_from_integrations(self, org_id: str) -> List[DiscoveredVendor]:
        """Discover vendors through API integrations and connections."""
        discovered = []
        
        try:
            # Query GitHub repositories for external integrations
            github_result = await self.query_engine.execute_query("""
                SELECT repository, topics, language, created_at
                FROM github_repository
                WHERE topics LIKE '%integration%' OR topics LIKE '%api%'
            """)
            
            for repo in github_result.rows:
                # Analyze repository for vendor integrations
                vendor_indicators = self._analyze_repo_for_vendors(repo)
                
                for indicator in vendor_indicators:
                    discovered_vendor = DiscoveredVendor(
                        discovered_vendor_id=f"discovered_integration_{indicator['domain']}_{int(datetime.now().timestamp())}",
                        vendor_name=indicator["vendor_name"],
                        domain=indicator["domain"],
                        discovery_method=DiscoveryMethod.API_INTEGRATION,
                        discovered_at=datetime.now(),
                        last_seen=datetime.now(),
                        discovered_via=repo["repository"],
                        confidence_score=indicator["confidence"],
                        data_access_detected=indicator.get("data_access", False),
                        authentication_observed=indicator.get("auth_detected", False),
                        external_network_access=True,
                        estimated_category=indicator.get("category", "unknown"),
                        risk_indicators=indicator.get("risk_indicators", []),
                        oauth_apps=[],
                        integrations=[repo["repository"]],
                        network_connections=[],
                        reviewed=False,
                        promoted_to_vendor=False,
                        suppressed=False,
                        suppression_reason=None,
                        metadata={
                            "discovery_repository": repo["repository"],
                            "repository_language": repo.get("language"),
                            "repository_topics": repo.get("topics", [])
                        }
                    )
                    
                    discovered.append(discovered_vendor)
                    
        except Exception as e:
            logger.error(f"Failed to discover vendors from integrations: {e}")
        
        return discovered
    
    def _extract_vendor_name(self, domain: str, app_name: str) -> str:
        """Extract vendor name from domain and app name."""
        # Remove common TLD and subdomain patterns
        clean_domain = domain.replace("www.", "").split(".")[0]
        
        # Use app name if it's more descriptive
        if len(app_name) > len(clean_domain) and clean_domain.lower() in app_name.lower():
            return app_name
        
        # Capitalize domain name
        return clean_domain.capitalize()
    
    def _calculate_discovery_confidence(self, app: OAuthApp) -> float:
        """Calculate confidence score for vendor discovery."""
        confidence = 0.7  # Base confidence for OAuth apps
        
        # Higher confidence for verified publishers
        if app.is_verified:
            confidence += 0.2
        
        # Higher confidence for well-known domains
        well_known_domains = ["microsoft.com", "google.com", "slack.com", "github.com"]
        if any(domain in app.publisher_domain for domain in well_known_domains):
            confidence += 0.1
        
        # Lower confidence for generic domains
        if app.publisher_domain.endswith(".io") or app.publisher_domain.endswith(".app"):
            confidence -= 0.1
        
        return min(max(confidence, 0.0), 1.0)
    
    def _estimate_vendor_category(self, app: OAuthApp) -> str:
        """Estimate vendor category from OAuth app."""
        app_name_lower = app.app_name.lower()
        
        # Map app patterns to vendor categories
        if any(term in app_name_lower for term in ["slack", "teams", "zoom", "meet"]):
            return "communication_platform"
        elif any(term in app_name_lower for term in ["github", "gitlab", "jenkins", "ci"]):
            return "development_platform"
        elif any(term in app_name_lower for term in ["salesforce", "hubspot", "crm"]):
            return "business_application"
        elif any(term in app_name_lower for term in ["analytics", "tableau", "looker"]):
            return "analytics_platform"
        elif any(term in app_name_lower for term in ["security", "auth", "identity"]):
            return "security_vendor"
        else:
            return "saas_application"
    
    def _identify_vendor_risk_indicators(self, app: OAuthApp) -> List[str]:
        """Identify risk indicators for discovered vendor."""
        indicators = []
        
        # OAuth-specific risks
        if any(scope.sensitive_data_access for scope in app.scopes):
            indicators.append("sensitive_data_access")
        
        if any(scope.write_permissions for scope in app.scopes):
            indicators.append("write_permissions")
        
        if not app.is_verified:
            indicators.append("unverified_publisher")
        
        if app.risk_level.value in ["high", "critical"]:
            indicators.append("high_risk_oauth_app")
        
        if not app.owner:
            indicators.append("no_internal_owner")
        
        return indicators
    
    def _analyze_repo_for_vendors(self, repo: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze repository for vendor integration indicators."""
        indicators = []
        
        repo_name = repo.get("repository", "")
        topics = repo.get("topics", [])
        language = repo.get("language", "")
        
        # Look for integration patterns in topics
        integration_topics = [topic for topic in topics if any(
            term in topic.lower() for term in ["api", "integration", "connector", "webhook"]
        )]
        
        for topic in integration_topics:
            # Extract potential vendor name from topic
            if "_" in topic:
                potential_vendor = topic.split("_")[0]
            elif "-" in topic:
                potential_vendor = topic.split("-")[0]
            else:
                potential_vendor = topic
            
            if len(potential_vendor) > 2:  # Filter out very short names
                indicators.append({
                    "vendor_name": potential_vendor.capitalize(),
                    "domain": f"{potential_vendor.lower()}.com",  # Estimated
                    "confidence": 0.6,
                    "category": "api_integration",
                    "data_access": "api" in topic.lower(),
                    "auth_detected": "auth" in topic.lower() or "oauth" in topic.lower(),
                    "risk_indicators": ["external_api_integration"]
                })
        
        return indicators
    
    async def review_discovered_vendor(
        self,
        discovered_vendor_id: str,
        reviewer: str,
        promote_to_vendor: bool,
        suppression_reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """Review a discovered vendor and decide on action."""
        discovered = self.discovered_vendors.get(discovered_vendor_id)
        if not discovered:
            raise ValueError(f"Discovered vendor {discovered_vendor_id} not found")
        
        # Update review status
        discovered.reviewed = True
        discovered.promoted_to_vendor = promote_to_vendor
        
        if not promote_to_vendor and suppression_reason:
            discovered.suppressed = True
            discovered.suppression_reason = suppression_reason
        
        review_result = {
            "discovered_vendor_id": discovered_vendor_id,
            "reviewer": reviewer,
            "reviewed_at": datetime.now().isoformat(),
            "decision": "promoted" if promote_to_vendor else "suppressed",
            "suppression_reason": suppression_reason
        }
        
        logger.info(f"Reviewed discovered vendor {discovered_vendor_id}: {review_result['decision']}")
        
        return review_result


# Global discovered vendor tracker
_discovered_vendor_tracker = DiscoveredVendorTracker()


def get_discovered_vendor_tracker() -> DiscoveredVendorTracker:
    """Get global discovered vendor tracker."""
    return _discovered_vendor_tracker
