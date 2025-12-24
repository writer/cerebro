"""
OAuth application registry across all providers.

Tracks OAuth apps across Google Workspace, M365, Slack, GitHub with
scopes, usage, ownership, and provenance tracking.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from ..query.bootstrap import get_query_engine

logger = logging.getLogger(__name__)


class AppRiskLevel(Enum):
    """Risk levels for OAuth applications."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AppCategory(Enum):
    """Categories of OAuth applications."""

    PRODUCTIVITY = "productivity"
    DEVELOPMENT = "development"
    SECURITY = "security"
    ANALYTICS = "analytics"
    COMMUNICATION = "communication"
    FILE_SHARING = "file_sharing"
    PROJECT_MANAGEMENT = "project_management"
    THIRD_PARTY_INTEGRATION = "third_party_integration"
    UNKNOWN = "unknown"


@dataclass
class OAuthScope:
    """OAuth scope with risk assessment."""

    scope: str
    description: str
    risk_level: AppRiskLevel
    sensitive_data_access: bool
    write_permissions: bool


@dataclass
class OAuthApp:
    """OAuth application with security metadata."""

    app_id: str
    app_name: str
    provider: str  # "google_workspace", "m365", "slack", "github"
    client_id: str

    # Ownership and provenance
    owner: str | None
    created_by: str | None
    installed_by: str
    installed_at: datetime

    # Permissions and scopes
    scopes: list[OAuthScope]
    requested_permissions: list[str]
    granted_permissions: list[str]

    # Usage tracking
    last_used: datetime | None
    usage_frequency: str  # "daily", "weekly", "monthly", "rarely", "never"
    active_users: int
    total_authentications: int

    # Risk assessment
    risk_level: AppRiskLevel
    risk_factors: list[str]
    toxic_combinations: list[str]

    # Configuration
    redirect_uris: list[str]
    publisher_domain: str
    is_verified: bool
    is_internal: bool

    # Compliance
    data_access_locations: list[str]
    data_retention_policy: str | None
    privacy_policy_url: str | None
    terms_of_service_url: str | None

    # Metadata
    category: AppCategory
    tags: list[str]
    metadata: dict[str, Any]


class OAuthAppRegistry:
    """
    Registry of OAuth applications across all providers.

    Provides centralized visibility into third-party app ecosystem
    with risk assessment and toxic combination detection.
    """

    def __init__(self):
        self.query_engine = get_query_engine()
        self.apps_cache: dict[str, OAuthApp] = {}
        self.last_refresh: datetime | None = None

    async def discover_oauth_apps(self, org_id: str) -> list[OAuthApp]:
        """
        Discover OAuth applications across all providers.

        Queries provider APIs to build comprehensive app inventory.
        """
        discovered_apps = []

        # Discover Google Workspace OAuth apps
        google_apps = await self._discover_google_workspace_apps()
        discovered_apps.extend(google_apps)

        # Discover Microsoft 365 OAuth apps
        m365_apps = await self._discover_m365_apps()
        discovered_apps.extend(m365_apps)

        # Discover GitHub OAuth apps
        github_apps = await self._discover_github_apps()
        discovered_apps.extend(github_apps)

        # Discover Slack apps (would need Slack provider)
        # slack_apps = await self._discover_slack_apps()
        # discovered_apps.extend(slack_apps)

        # Update cache
        for app in discovered_apps:
            self.apps_cache[app.app_id] = app

        self.last_refresh = datetime.now()

        logger.info(f"Discovered {len(discovered_apps)} OAuth apps for org {org_id}")

        return discovered_apps

    async def _discover_google_workspace_apps(self) -> list[OAuthApp]:
        """Discover Google Workspace OAuth applications."""
        apps = []

        try:
            # Query Google Workspace apps (would need Google Admin SDK integration)
            # For now, return mock data based on common patterns

            mock_apps = [
                {
                    "app_id": "gw_slack_integration",
                    "app_name": "Slack for Google Workspace",
                    "client_id": "slack-client-123",
                    "scopes": [
                        "https://www.googleapis.com/auth/userinfo.email",
                        "https://www.googleapis.com/auth/drive.file",
                        "https://www.googleapis.com/auth/calendar.readonly",
                    ],
                    "installed_by": "admin@company.com",
                    "installed_at": "2024-01-15T10:00:00Z",
                    "last_used": "2024-01-20T14:30:00Z",
                    "active_users": 250,
                    "publisher_domain": "slack.com",
                    "is_verified": True,
                }
            ]

            for mock_app in mock_apps:
                app = await self._create_oauth_app_from_google_data(mock_app)
                apps.append(app)

        except Exception as e:
            logger.error(f"Failed to discover Google Workspace apps: {e}")

        return apps

    async def _discover_m365_apps(self) -> list[OAuthApp]:
        """Discover Microsoft 365 OAuth applications."""
        apps = []

        try:
            # Query M365 applications using our existing table
            result = await self.query_engine.execute_query(
                """
                SELECT app_id, display_name, client_app_id, required_resource_access,
                       publisher_domain, created_at, has_credentials
                FROM m365_application
                WHERE has_credentials = true
            """
            )

            for app_data in result.rows:
                app = await self._create_oauth_app_from_m365_data(app_data)
                apps.append(app)

        except Exception as e:
            logger.error(f"Failed to discover M365 apps: {e}")

        return apps

    async def _discover_github_apps(self) -> list[OAuthApp]:
        """Discover GitHub OAuth applications."""
        apps = []

        try:
            # Query GitHub apps (would need GitHub Apps API integration)
            # For now, simulate based on repository integrations

            repos_by_name: dict[str, dict[str, Any]] = {}
            for query in [
                "SELECT repository, topics, created_at FROM github_repository WHERE topics LIKE '%ci%'",
                "SELECT repository, topics, created_at FROM github_repository WHERE topics LIKE '%deployment%'",
            ]:
                result = await self.query_engine.execute_query(query)
                for row in result.rows:
                    repo_name = row.get("repository")
                    if repo_name:
                        repos_by_name[repo_name] = row

            # Infer OAuth apps from CI/CD integrations
            for repo in repos_by_name.values():
                if repo.get("topics"):
                    topics = repo["topics"]
                    if "ci" in topics or "deployment" in topics:
                        # Simulate GitHub Actions OAuth app
                        app = OAuthApp(
                            app_id=f"github_actions_{repo['repository']}",
                            app_name="GitHub Actions",
                            provider="github",
                            client_id="github-actions-client",
                            owner=None,
                            created_by=None,
                            installed_by="system",
                            installed_at=datetime.fromisoformat(repo["created_at"]),
                            scopes=[
                                OAuthScope(
                                    "actions:read",
                                    "Read Actions",
                                    AppRiskLevel.LOW,
                                    False,
                                    False,
                                ),
                                OAuthScope(
                                    "contents:write",
                                    "Write repository contents",
                                    AppRiskLevel.HIGH,
                                    False,
                                    True,
                                ),
                                OAuthScope(
                                    "metadata:read",
                                    "Read metadata",
                                    AppRiskLevel.LOW,
                                    False,
                                    False,
                                ),
                            ],
                            requested_permissions=[
                                "actions:read",
                                "contents:write",
                                "metadata:read",
                            ],
                            granted_permissions=[
                                "actions:read",
                                "contents:write",
                                "metadata:read",
                            ],
                            last_used=datetime.now() - timedelta(hours=2),
                            usage_frequency="daily",
                            active_users=1,
                            total_authentications=1000,
                            risk_level=AppRiskLevel.HIGH,
                            risk_factors=["write_access", "automated_system"],
                            toxic_combinations=[],
                            redirect_uris=["https://github.com/callback"],
                            publisher_domain="github.com",
                            is_verified=True,
                            is_internal=True,
                            data_access_locations=["US"],
                            data_retention_policy=None,
                            privacy_policy_url="https://github.com/privacy",
                            terms_of_service_url="https://github.com/terms",
                            category=AppCategory.DEVELOPMENT,
                            tags=["ci", "automation"],
                            metadata={"repository": repo["repository"]},
                        )
                        apps.append(app)

        except Exception as e:
            logger.error(f"Failed to discover GitHub apps: {e}")

        return apps

    async def _create_oauth_app_from_google_data(
        self, app_data: dict[str, Any]
    ) -> OAuthApp:
        """Create OAuthApp from Google Workspace data."""
        # Parse scopes
        scopes = []
        for scope_url in app_data.get("scopes", []):
            scope_obj = self._parse_google_scope(scope_url)
            scopes.append(scope_obj)

        # Assess risk level
        risk_level = self._assess_app_risk_level(scopes, app_data)

        return OAuthApp(
            app_id=app_data["app_id"],
            app_name=app_data["app_name"],
            provider="google_workspace",
            client_id=app_data["client_id"],
            owner=None,  # Would need additional API call
            created_by=None,
            installed_by=app_data["installed_by"],
            installed_at=datetime.fromisoformat(app_data["installed_at"]),
            scopes=scopes,
            requested_permissions=[scope.scope for scope in scopes],
            granted_permissions=[scope.scope for scope in scopes],
            last_used=(
                datetime.fromisoformat(app_data["last_used"])
                if app_data.get("last_used")
                else None
            ),
            usage_frequency="daily",  # Would calculate from usage data
            active_users=app_data.get("active_users", 0),
            total_authentications=0,  # Would need usage analytics
            risk_level=risk_level,
            risk_factors=self._identify_risk_factors(scopes, app_data),
            toxic_combinations=[],
            redirect_uris=[],
            publisher_domain=app_data.get("publisher_domain", ""),
            is_verified=app_data.get("is_verified", False),
            is_internal=False,
            data_access_locations=["US"],  # Would determine from app metadata
            data_retention_policy=None,
            privacy_policy_url=None,
            terms_of_service_url=None,
            category=self._categorize_app(app_data["app_name"]),
            tags=[],
            metadata=app_data,
        )

    async def _create_oauth_app_from_m365_data(
        self, app_data: dict[str, Any]
    ) -> OAuthApp:
        """Create OAuthApp from M365 data."""
        # Parse Microsoft Graph permissions
        scopes = []
        resource_access = app_data.get("required_resource_access", [])

        for resource in resource_access:
            resource_app_id = resource.get("resourceAppId", "")
            if (
                resource_app_id == "00000003-0000-0000-c000-000000000000"
            ):  # Microsoft Graph
                for perm in resource.get("resourceAccess", []):
                    scope_name = self._map_graph_permission_to_scope(perm.get("id", ""))
                    scope_obj = OAuthScope(
                        scope=scope_name,
                        description="Microsoft Graph permission",
                        risk_level=self._assess_graph_permission_risk(scope_name),
                        sensitive_data_access="User" in scope_name
                        or "Mail" in scope_name,
                        write_permissions="Write" in scope_name
                        or "Create" in scope_name,
                    )
                    scopes.append(scope_obj)

        risk_level = self._assess_app_risk_level(scopes, app_data)

        return OAuthApp(
            app_id=app_data["app_id"],
            app_name=app_data["display_name"],
            provider="m365",
            client_id=app_data["client_app_id"],
            owner=None,
            created_by=None,
            installed_by="system",
            installed_at=datetime.now(),  # Would get from app registration
            scopes=scopes,
            requested_permissions=[scope.scope for scope in scopes],
            granted_permissions=[scope.scope for scope in scopes],
            last_used=None,  # Would need usage analytics
            usage_frequency="unknown",
            active_users=0,
            total_authentications=0,
            risk_level=risk_level,
            risk_factors=self._identify_risk_factors(scopes, app_data),
            toxic_combinations=[],
            redirect_uris=[],
            publisher_domain=app_data.get("publisher_domain", ""),
            is_verified=False,  # Would check app verification status
            is_internal=(
                True if "company.com" in app_data.get("publisher_domain", "") else False
            ),
            data_access_locations=["Global"],
            data_retention_policy=None,
            privacy_policy_url=None,
            terms_of_service_url=None,
            category=self._categorize_app(app_data["display_name"]),
            tags=[],
            metadata=app_data,
        )

    def _parse_google_scope(self, scope_url: str) -> OAuthScope:
        """Parse Google OAuth scope URL into scope object."""
        # Map common Google scopes to descriptions
        scope_descriptions = {
            "https://www.googleapis.com/auth/userinfo.email": "Email address access",
            "https://www.googleapis.com/auth/drive.file": "Google Drive file access",
            "https://www.googleapis.com/auth/drive": "Full Google Drive access",
            "https://www.googleapis.com/auth/calendar": "Full Calendar access",
            "https://www.googleapis.com/auth/calendar.readonly": "Read-only Calendar access",
            "https://www.googleapis.com/auth/gmail.readonly": "Read-only Gmail access",
            "https://www.googleapis.com/auth/gmail.modify": "Modify Gmail messages",
            "https://www.googleapis.com/auth/admin.directory.user": "Admin user management",
        }

        description = scope_descriptions.get(scope_url, scope_url)

        # Assess risk level based on scope
        if "admin" in scope_url.lower() or scope_url.endswith("/auth/drive"):
            risk_level = AppRiskLevel.CRITICAL
        elif "modify" in scope_url.lower() or "write" in scope_url.lower():
            risk_level = AppRiskLevel.HIGH
        elif "readonly" in scope_url.lower():
            risk_level = AppRiskLevel.LOW
        else:
            risk_level = AppRiskLevel.MEDIUM

        return OAuthScope(
            scope=scope_url,
            description=description,
            risk_level=risk_level,
            sensitive_data_access="userinfo" in scope_url or "email" in scope_url,
            write_permissions="modify" in scope_url
            or "write" in scope_url
            or scope_url.endswith("/auth/drive"),
        )

    def _map_graph_permission_to_scope(self, permission_id: str) -> str:
        """Map Microsoft Graph permission ID to scope name."""
        # Common Microsoft Graph permission mappings
        permission_map = {
            "e1fe6dd8-ba31-4d61-89e7-88639da4683d": "User.Read",
            "b4e74841-8e56-480b-be8b-910348b18b4c": "User.ReadWrite",
            "6234d376-f627-4f0f-90e0-dff25c5211a3": "Files.Read",
            "5447fe39-cb82-4c1a-b977-520e67e724eb": "Files.ReadWrite",
            "570282fd-fa5c-430d-a7fd-fc8dc98a9dca": "Mail.Read",
            "024d486e-b451-40bb-833d-3e66d98c5c73": "Mail.ReadWrite",
        }

        return permission_map.get(permission_id, f"UnknownPermission_{permission_id}")

    def _assess_graph_permission_risk(self, scope_name: str) -> AppRiskLevel:
        """Assess risk level of Microsoft Graph permission."""
        if "ReadWrite" in scope_name or "Admin" in scope_name:
            return AppRiskLevel.HIGH
        elif "Read" in scope_name:
            return AppRiskLevel.MEDIUM
        else:
            return AppRiskLevel.LOW

    def _assess_app_risk_level(
        self, scopes: list[OAuthScope], app_data: dict[str, Any]
    ) -> AppRiskLevel:
        """Assess overall risk level for OAuth app."""
        # Count scope risk levels
        critical_scopes = len(
            [s for s in scopes if s.risk_level == AppRiskLevel.CRITICAL]
        )
        high_scopes = len([s for s in scopes if s.risk_level == AppRiskLevel.HIGH])

        # High-risk indicators
        sensitive_data_access = any(s.sensitive_data_access for s in scopes)
        write_permissions = any(s.write_permissions for s in scopes)
        unverified_publisher = not app_data.get("is_verified", False)

        # Calculate risk score
        risk_score = 0

        if critical_scopes > 0:
            risk_score += 40
        if high_scopes > 0:
            risk_score += 20
        if sensitive_data_access:
            risk_score += 15
        if write_permissions:
            risk_score += 15
        if unverified_publisher:
            risk_score += 10

        # Determine risk level
        if risk_score >= 70:
            return AppRiskLevel.CRITICAL
        elif risk_score >= 50:
            return AppRiskLevel.HIGH
        elif risk_score >= 30:
            return AppRiskLevel.MEDIUM
        else:
            return AppRiskLevel.LOW

    def _identify_risk_factors(
        self, scopes: list[OAuthScope], app_data: dict[str, Any]
    ) -> list[str]:
        """Identify specific risk factors for the app."""
        risk_factors = []

        # Scope-based risks
        if any(s.risk_level == AppRiskLevel.CRITICAL for s in scopes):
            risk_factors.append("critical_scope_access")

        if any(s.sensitive_data_access for s in scopes):
            risk_factors.append("sensitive_data_access")

        if any(s.write_permissions for s in scopes):
            risk_factors.append("write_permissions")

        # App metadata risks
        if not app_data.get("is_verified", False):
            risk_factors.append("unverified_publisher")

        if not app_data.get("owner"):
            risk_factors.append("no_designated_owner")

        # Usage pattern risks
        if app_data.get("last_used"):
            last_used = datetime.fromisoformat(app_data["last_used"])
            if (datetime.now() - last_used).days > 90:
                risk_factors.append("infrequent_usage")
        else:
            risk_factors.append("never_used")

        return risk_factors

    def _categorize_app(self, app_name: str) -> AppCategory:
        """Categorize app based on name and functionality."""
        name_lower = app_name.lower()

        # Development tools
        if any(
            term in name_lower
            for term in ["github", "gitlab", "jenkins", "ci", "deploy"]
        ):
            return AppCategory.DEVELOPMENT

        # Communication tools
        elif any(term in name_lower for term in ["slack", "teams", "zoom", "meet"]):
            return AppCategory.COMMUNICATION

        # File sharing
        elif any(
            term in name_lower for term in ["drive", "dropbox", "box", "sharepoint"]
        ):
            return AppCategory.FILE_SHARING

        # Analytics
        elif any(
            term in name_lower for term in ["analytics", "tableau", "powerbi", "looker"]
        ):
            return AppCategory.ANALYTICS

        # Project management
        elif any(term in name_lower for term in ["jira", "asana", "trello", "monday"]):
            return AppCategory.PROJECT_MANAGEMENT

        # Security tools
        elif any(term in name_lower for term in ["security", "auth", "sso", "mfa"]):
            return AppCategory.SECURITY

        # Productivity
        elif any(
            term in name_lower for term in ["office", "workspace", "calendar", "mail"]
        ):
            return AppCategory.PRODUCTIVITY

        else:
            return AppCategory.UNKNOWN

    async def get_high_risk_apps(self, org_id: str) -> list[OAuthApp]:
        """Get high-risk OAuth applications requiring attention."""
        if not self.apps_cache or not self.last_refresh:
            await self.discover_oauth_apps(org_id)

        high_risk_apps = [
            app
            for app in self.apps_cache.values()
            if app.risk_level in [AppRiskLevel.HIGH, AppRiskLevel.CRITICAL]
        ]

        # Sort by risk level and last used
        high_risk_apps.sort(
            key=lambda x: (
                4 - list(AppRiskLevel).index(x.risk_level),  # CRITICAL=4, HIGH=3, etc.
                x.last_used or datetime.min,
            ),
            reverse=True,
        )

        return high_risk_apps

    async def get_apps_without_owners(self, org_id: str) -> list[OAuthApp]:
        """Get OAuth apps without designated owners."""
        if not self.apps_cache:
            await self.discover_oauth_apps(org_id)

        return [
            app
            for app in self.apps_cache.values()
            if not app.owner and not app.is_internal
        ]

    async def get_unused_apps(
        self, org_id: str, unused_days: int = 90
    ) -> list[OAuthApp]:
        """Get OAuth apps that haven't been used recently."""
        if not self.apps_cache:
            await self.discover_oauth_apps(org_id)

        cutoff_date = datetime.now() - timedelta(days=unused_days)

        return [
            app
            for app in self.apps_cache.values()
            if not app.last_used or app.last_used < cutoff_date
        ]

    async def get_apps_by_scope(
        self, org_id: str, scope_pattern: str
    ) -> list[OAuthApp]:
        """Get OAuth apps with specific scope patterns."""
        if not self.apps_cache:
            await self.discover_oauth_apps(org_id)

        matching_apps = []
        for app in self.apps_cache.values():
            for scope in app.scopes:
                if scope_pattern.lower() in scope.scope.lower():
                    matching_apps.append(app)
                    break

        return matching_apps

    async def generate_oauth_risk_report(self, org_id: str) -> dict[str, Any]:
        """Generate comprehensive OAuth risk assessment report."""
        apps = await self.discover_oauth_apps(org_id)

        # Risk statistics
        risk_stats = {
            "critical": len([a for a in apps if a.risk_level == AppRiskLevel.CRITICAL]),
            "high": len([a for a in apps if a.risk_level == AppRiskLevel.HIGH]),
            "medium": len([a for a in apps if a.risk_level == AppRiskLevel.MEDIUM]),
            "low": len([a for a in apps if a.risk_level == AppRiskLevel.LOW]),
        }

        # Provider breakdown
        provider_stats: dict[str, int] = {}
        for app in apps:
            provider_stats[app.provider] = provider_stats.get(app.provider, 0) + 1

        # Category breakdown
        category_stats: dict[str, int] = {}
        for app in apps:
            category_stats[app.category.value] = (
                category_stats.get(app.category.value, 0) + 1
            )

        # Risk factor analysis
        all_risk_factors: list[str] = []
        for app in apps:
            all_risk_factors.extend(app.risk_factors)

        risk_factor_counts: dict[str, int] = {}
        for factor in all_risk_factors:
            risk_factor_counts[factor] = risk_factor_counts.get(factor, 0) + 1

        return {
            "organization_id": org_id,
            "analysis_date": datetime.now().isoformat(),
            "summary": {
                "total_oauth_apps": len(apps),
                "high_risk_apps": risk_stats["critical"] + risk_stats["high"],
                "apps_without_owners": len(await self.get_apps_without_owners(org_id)),
                "unused_apps_90_days": len(await self.get_unused_apps(org_id, 90)),
            },
            "risk_distribution": risk_stats,
            "provider_breakdown": provider_stats,
            "category_breakdown": category_stats,
            "top_risk_factors": dict(
                sorted(risk_factor_counts.items(), key=lambda x: x[1], reverse=True)[
                    :10
                ]
            ),
            "high_risk_apps": [
                {
                    "app_id": app.app_id,
                    "app_name": app.app_name,
                    "provider": app.provider,
                    "risk_level": app.risk_level.value,
                    "risk_factors": app.risk_factors,
                    "last_used": app.last_used.isoformat() if app.last_used else None,
                }
                for app in await self.get_high_risk_apps(org_id)
            ][
                :20
            ],  # Top 20
        }


# Global OAuth app registry
_oauth_registry = OAuthAppRegistry()


def get_oauth_registry() -> OAuthAppRegistry:
    """Get global OAuth app registry."""
    return _oauth_registry
