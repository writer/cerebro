"""Microsoft 365 provider implementation."""

from typing import Any, Dict, List, Optional, AsyncGenerator
from datetime import datetime
from uuid import UUID
import logging

import httpx

from cerebro.core.config import settings
from ..base import (
    BaseProvider,
    ResourceInfo,
    PrincipalInfo,
    ConfigurationSnapshot,
    IamPermission,
    ProviderError,
)

logger = logging.getLogger(__name__)


class M365Provider(BaseProvider):
    """Microsoft 365 provider for collecting users, files, and security configurations."""

    def __init__(
        self,
        account_id: UUID,
        tenant_id: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize M365 provider."""
        super().__init__(account_id, **kwargs)
        self.tenant_id = tenant_id
        self.client_id = client_id or getattr(settings, "m365_client_id", None)
        self.client_secret = client_secret or getattr(
            settings, "m365_client_secret", None
        )
        self._access_token: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def name(self) -> str:
        """Get provider name."""
        return "m365"

    async def authenticate(self) -> bool:
        """Authenticate with Microsoft 365."""
        try:
            if not self.client_id or not self.client_secret:
                raise ProviderError("M365 client credentials not configured")

            # Get OAuth token
            token_url = (
                f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            )
            token_data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://graph.microsoft.com/.default",
            }

            async with httpx.AsyncClient() as temp_client:
                response = await temp_client.post(token_url, data=token_data)
                response.raise_for_status()
                token_response = response.json()
                self._access_token = token_response["access_token"]

            # Create Graph API client
            self._client = httpx.AsyncClient(
                base_url="https://graph.microsoft.com/v1.0",
                headers={
                    "Authorization": f"Bearer {self._access_token}",
                    "Content-Type": "application/json",
                    "ConsistencyLevel": "eventual",
                },
                timeout=30.0,
            )

            # Test authentication
            response = await self._client.get("/organization")
            response.raise_for_status()

            logger.info(f"Authenticated with M365 tenant: {self.tenant_id}")
            return True

        except httpx.HTTPError as e:
            logger.error(f"M365 authentication failed: {e}")
            raise ProviderError(f"M365 authentication failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during M365 auth: {e}")
            return False

    async def discover_resources(
        self, resource_types: Optional[List[str]] = None
    ) -> AsyncGenerator[ResourceInfo, None]:
        """Discover M365 resources."""
        if not self._client:
            await self.authenticate()

        # Discover users for identity hygiene
        if not resource_types or "m365.user" in resource_types:
            async for user in self._discover_users():
                yield user

        # Discover SharePoint sites
        if not resource_types or "m365.sharepoint.site" in resource_types:
            async for site in self._discover_sharepoint_sites():
                yield site

        # Discover Teams
        if not resource_types or "m365.teams.team" in resource_types:
            async for team in self._discover_teams():
                yield team

        # Discover Exchange mailboxes
        if not resource_types or "m365.exchange.mailbox" in resource_types:
            async for mailbox in self._discover_mailboxes():
                yield mailbox

    async def _discover_sharepoint_sites(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover SharePoint sites."""
        try:
            response = await self._client.get("/sites")
            response.raise_for_status()
            sites = response.json()

            for site in sites.get("value", []):
                yield ResourceInfo(
                    external_id=site["id"],
                    name=site.get("displayName"),
                    resource_type="m365.sharepoint.site",
                    metadata={
                        "web_url": site.get("webUrl"),
                        "created_datetime": site.get("createdDateTime"),
                        "last_modified": site.get("lastModifiedDateTime"),
                        "site_collection": site.get("siteCollection", {}),
                    },
                )
        except Exception as e:
            logger.error(f"Failed to discover SharePoint sites: {e}")

    async def _discover_teams(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Microsoft Teams."""
        try:
            response = await self._client.get("/teams")
            response.raise_for_status()
            teams = response.json()

            for team in teams.get("value", []):
                yield ResourceInfo(
                    external_id=team["id"],
                    name=team.get("displayName"),
                    resource_type="m365.teams.team",
                    metadata={
                        "description": team.get("description"),
                        "visibility": team.get("visibility"),
                        "web_url": team.get("webUrl"),
                        "created_datetime": team.get("createdDateTime"),
                        "archived": team.get("isArchived", False),
                    },
                )
        except Exception as e:
            logger.error(f"Failed to discover Teams: {e}")

    async def _discover_mailboxes(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Exchange mailboxes."""
        try:
            response = await self._client.get("/users")
            response.raise_for_status()
            users = response.json()

            for user in users.get("value", []):
                if user.get("mail"):  # Only users with mailboxes
                    yield ResourceInfo(
                        external_id=user["id"],
                        name=user.get("mail"),
                        resource_type="m365.exchange.mailbox",
                        metadata={
                            "display_name": user.get("displayName"),
                            "user_principal_name": user.get("userPrincipalName"),
                            "account_enabled": user.get("accountEnabled"),
                            "created_datetime": user.get("createdDateTime"),
                            "last_sign_in": user.get("signInActivity", {}).get(
                                "lastSignInDateTime"
                            ),
                        },
                    )
        except Exception as e:
            logger.error(f"Failed to discover Exchange mailboxes: {e}")

    async def discover_principals(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover M365 users and groups."""
        if not self._client:
            await self.authenticate()

        # Discover users
        try:
            response = await self._client.get("/users")
            response.raise_for_status()
            users = response.json()

            for user in users.get("value", []):
                yield PrincipalInfo(
                    external_id=user["id"],
                    principal_type="user",
                    email=user.get("mail") or user.get("userPrincipalName"),
                    display_name=user.get("displayName"),
                    is_human=True,
                    metadata={
                        "account_enabled": user.get("accountEnabled"),
                        "user_type": user.get("userType"),
                        "created_datetime": user.get("createdDateTime"),
                        "last_sign_in": user.get("signInActivity", {}).get(
                            "lastSignInDateTime"
                        ),
                        "job_title": user.get("jobTitle"),
                        "department": user.get("department"),
                        "company_name": user.get("companyName"),
                    },
                )
        except Exception as e:
            logger.error(f"Failed to discover M365 users: {e}")

        # Discover groups
        try:
            response = await self._client.get("/groups")
            response.raise_for_status()
            groups = response.json()

            for group in groups.get("value", []):
                yield PrincipalInfo(
                    external_id=group["id"],
                    principal_type="group",
                    email=group.get("mail"),
                    display_name=group.get("displayName"),
                    is_human=False,
                    metadata={
                        "group_types": group.get("groupTypes", []),
                        "security_enabled": group.get("securityEnabled"),
                        "mail_enabled": group.get("mailEnabled"),
                        "created_datetime": group.get("createdDateTime"),
                        "description": group.get("description"),
                        "visibility": group.get("visibility"),
                    },
                )
        except Exception as e:
            logger.error(f"Failed to discover M365 groups: {e}")

    async def get_resource_configuration(
        self, resource: ResourceInfo
    ) -> ConfigurationSnapshot:
        """Get M365 resource configuration."""
        if not self._client:
            await self.authenticate()

        config = {}

        if resource.resource_type == "m365.user":
            config = await self._get_user_config(resource.external_id)
        elif resource.resource_type == "m365.sharepoint.site":
            config = await self._get_sharepoint_config(resource.external_id)
        elif resource.resource_type == "m365.teams.team":
            config = await self._get_teams_config(resource.external_id)
        elif resource.resource_type == "m365.exchange.mailbox":
            config = await self._get_mailbox_config(resource.external_id)

        return ConfigurationSnapshot(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config=config,
        )

    async def _get_sharepoint_config(self, site_id: str) -> Dict[str, Any]:
        """Get SharePoint site configuration."""
        try:
            # Get site details
            response = await self._client.get(f"/sites/{site_id}")
            response.raise_for_status()
            site = response.json()

            # Get site permissions
            perms_response = await self._client.get(f"/sites/{site_id}/permissions")
            perms_response.raise_for_status()
            permissions = perms_response.json()

            return {
                "id": site["id"],
                "display_name": site.get("displayName"),
                "web_url": site.get("webUrl"),
                "created_datetime": site.get("createdDateTime"),
                "last_modified": site.get("lastModifiedDateTime"),
                "permissions": permissions.get("value", []),
                "site_collection": site.get("siteCollection", {}),
                "sharing_capability": site.get("sharingCapability"),
                "external_sharing": site.get("externalSharingEnabled", False),
            }
        except Exception as e:
            logger.error(f"Failed to get SharePoint config for {site_id}: {e}")
            return {}

    async def _discover_users(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Microsoft 365 users as resources."""
        try:
            url = "/users"
            params = {
                "$top": 100,
                "$select": "id,displayName,userPrincipalName,mail,userType,accountEnabled,signInActivity",
            }

            while url:
                response = await self._client.get(
                    url,
                    params=params if not url.startswith("http") else None,
                )
                response.raise_for_status()
                data = response.json()

                for user in data.get("value", []):
                    yield ResourceInfo(
                        external_id=user.get("id"),
                        name=user.get("displayName") or user.get("userPrincipalName"),
                        resource_type="m365.user",
                        metadata={
                            "user_principal_name": user.get("userPrincipalName"),
                            "mail": user.get("mail"),
                            "user_type": user.get("userType"),
                            "account_enabled": user.get("accountEnabled"),
                        },
                    )

                next_link = data.get("@odata.nextLink")
                if next_link and next_link.startswith("https://"):
                    url = next_link.replace("https://graph.microsoft.com/v1.0", "")
                else:
                    break
                params = None

        except Exception as e:
            logger.error(f"Failed to discover M365 users: {e}")

    async def _get_user_config(self, user_id: str) -> Dict[str, Any]:
        """Get Microsoft 365 user configuration."""
        try:
            select_fields = (
                "id,displayName,userPrincipalName,mail,userType,accountEnabled,"
                "createdDateTime,lastPasswordChangeDateTime,signInActivity,usageLocation,department,jobTitle"
            )

            user_response = await self._client.get(
                f"/users/{user_id}",
                params={"$select": select_fields},
            )
            user_response.raise_for_status()
            user = user_response.json()

            directory_roles = (
                await self._safe_graph_get(
                    f"/users/{user_id}/memberOf",
                    params={"$select": "id,displayName,roleTemplateId,@odata.type"},
                )
                or {}
            )

            authentication_methods = (
                await self._safe_graph_get(
                    f"/users/{user_id}/authentication/methods",
                    params={"$select": "id,displayName,@odata.type"},
                )
                or {}
            )

            roles = []
            for entry in directory_roles.get("value", []):
                if entry.get("@odata.type", "").endswith("directoryRole"):
                    roles.append(
                        {
                            "id": entry.get("id"),
                            "display_name": entry.get("displayName"),
                            "role_template_id": entry.get("roleTemplateId"),
                        }
                    )

            mfa_methods = []
            for method in authentication_methods.get("value", []):
                method_type = method.get("@odata.type", "")
                display_name = method.get("displayName") or method_type.split(".")[-1]
                mfa_methods.append(
                    {
                        "id": method.get("id"),
                        "display_name": display_name,
                        "odata_type": method_type,
                    }
                )

            # Determine if MFA is enrolled by looking for non-password methods
            mfa_enrolled = any(
                not method.get("odata_type", "").endswith(
                    "passwordAuthenticationMethod"
                )
                for method in mfa_methods
            )

            sign_in_activity = user.get("signInActivity", {}) or {}
            last_login = sign_in_activity.get("lastSignInDateTime")

            return {
                "id": user.get("id"),
                "display_name": user.get("displayName"),
                "user_principal_name": user.get("userPrincipalName"),
                "email": user.get("mail") or user.get("userPrincipalName"),
                "user_type": user.get("userType"),
                "account_enabled": user.get("accountEnabled"),
                "created": user.get("createdDateTime"),
                "last_password_change": user.get("lastPasswordChangeDateTime"),
                "last_login": last_login,
                "sign_in_activity": sign_in_activity,
                "department": user.get("department"),
                "job_title": user.get("jobTitle"),
                "usage_location": user.get("usageLocation"),
                "directory_roles": roles,
                "role_names": [
                    role.get("display_name")
                    for role in roles
                    if role.get("display_name")
                ],
                "is_admin": bool(roles),
                "is_guest": (user.get("userType") or "").lower() == "guest",
                "mfa_methods": mfa_methods,
                "mfa_enrolled": mfa_enrolled,
            }

        except Exception as e:
            logger.error(f"Failed to get M365 user config for {user_id}: {e}")
            return {}

    async def _safe_graph_get(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """Perform Graph API GET with graceful handling."""
        try:
            response = await self._client.get(path, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                logger.debug(f"Graph endpoint not found for {path}: {exc}")
                return None
            logger.warning(f"Graph API error {exc.response.status_code} for {path}")
            return None
        except Exception as exc:
            logger.warning(f"Graph API request failed for {path}: {exc}")
            return None

    async def _get_teams_config(self, team_id: str) -> Dict[str, Any]:
        """Get Teams configuration."""
        try:
            response = await self._client.get(f"/teams/{team_id}")
            response.raise_for_status()
            team = response.json()

            # Get team members
            members_response = await self._client.get(f"/teams/{team_id}/members")
            members_response.raise_for_status()
            members = members_response.json()

            return {
                "id": team["id"],
                "display_name": team.get("displayName"),
                "description": team.get("description"),
                "visibility": team.get("visibility"),
                "web_url": team.get("webUrl"),
                "created_datetime": team.get("createdDateTime"),
                "archived": team.get("isArchived", False),
                "members_count": len(members.get("value", [])),
                "guest_settings": team.get("guestSettings", {}),
                "member_settings": team.get("memberSettings", {}),
                "messaging_settings": team.get("messagingSettings", {}),
                "fun_settings": team.get("funSettings", {}),
            }
        except Exception as e:
            logger.error(f"Failed to get Teams config for {team_id}: {e}")
            return {}

    async def _get_mailbox_config(self, user_id: str) -> Dict[str, Any]:
        """Get Exchange mailbox configuration."""
        try:
            # Get user details
            response = await self._client.get(f"/users/{user_id}")
            response.raise_for_status()
            user = response.json()

            # Get mailbox settings (simplified)
            return {
                "user_id": user["id"],
                "mail": user.get("mail"),
                "display_name": user.get("displayName"),
                "account_enabled": user.get("accountEnabled"),
                "mfa_enabled": user.get("strongAuthenticationMethods", []) != [],
                "last_sign_in": user.get("signInActivity", {}).get(
                    "lastSignInDateTime"
                ),
                "assigned_licenses": user.get("assignedLicenses", []),
                "user_type": user.get("userType"),
                "on_premises_synced": user.get("onPremisesSyncEnabled", False),
            }
        except Exception as e:
            logger.error(f"Failed to get mailbox config for {user_id}: {e}")
            return {}

    async def discover_iam_edges(
        self, resource: Optional[ResourceInfo] = None
    ) -> AsyncGenerator[IamPermission, None]:
        """Discover M365 permissions and role assignments."""
        if not self._client:
            await self.authenticate()

        try:
            # Get directory role assignments
            response = await self._client.get("/directoryRoles")
            response.raise_for_status()
            roles = response.json()

            for role in roles.get("value", []):
                # Get role members
                members_response = await self._client.get(
                    f"/directoryRoles/{role['id']}/members"
                )
                members_response.raise_for_status()
                members = members_response.json()

                for member in members.get("value", []):
                    is_admin = "admin" in role.get("displayName", "").lower()

                    yield IamPermission(
                        principal_external_id=member["id"],
                        resource_external_id=None,  # Tenant-level role
                        permission=f"m365.directory.role.{role.get('roleTemplateId', 'unknown')}",
                        via=f"directory_role:{role.get('displayName')}",
                        effective_at=datetime.utcnow(),
                        is_admin=is_admin,
                    )

        except Exception as e:
            logger.error(f"Failed to discover M365 permissions: {e}")

    async def cleanup(self):
        """Cleanup HTTP client."""
        if self._client:
            await self._client.aclose()
