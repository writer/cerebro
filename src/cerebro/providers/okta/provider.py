"""Okta provider implementation."""

import logging
from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Any
from uuid import UUID

import httpx

from cerebro.core.config import settings

from ..base import (
    BaseProvider,
    ConfigurationSnapshot,
    IamPermission,
    PrincipalInfo,
    ProviderError,
    ResourceInfo,
)

logger = logging.getLogger(__name__)


class OktaProvider(BaseProvider):
    """Okta provider for collecting users, groups, and applications."""

    def __init__(self, account_id: UUID, domain: str, api_token: str | None = None, **kwargs: Any) -> None:
        """Initialize Okta provider."""
        super().__init__(account_id, **kwargs)
        self.domain = domain
        self.api_token = api_token or getattr(settings, "okta_api_token", None)
        self.base_url = f"https://{domain}"
        self._client: httpx.AsyncClient | None = None  # type: ignore[assignment]

    @property
    def name(self) -> str:
        """Get provider name."""
        return "okta"

    @property
    def client(self) -> httpx.AsyncClient:
        """Get the authenticated HTTP client, raising if not authenticated."""
        if self._client is None:
            raise ProviderError("Okta provider not authenticated")
        return self._client

    async def authenticate(self) -> bool:
        """Authenticate with Okta."""
        try:
            if not self.api_token:
                raise ProviderError("Okta API token not configured")

            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={
                    "Authorization": f"SSWS {self.api_token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )

            # Test authentication by getting org info
            response = await self.client.get("/api/v1/org")
            response.raise_for_status()

            org_info = response.json()
            logger.info(
                f"Authenticated with Okta org: {org_info.get('companyName', 'Unknown')}"
            )
            return True

        except httpx.HTTPError as e:
            logger.error(f"Okta authentication failed: {e}")
            raise ProviderError(f"Okta authentication failed: {e}") from e

        except Exception as e:
            logger.error(f"Unexpected error during Okta auth: {e}")
            return False

    async def discover_resources(
        self, resource_types: list[str] | None = None
    ) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Okta resources (applications, policies, network zones)."""
        if not self._client:
            await self.authenticate()

        # Discover users as manageable resources for identity hygiene
        if not resource_types or "okta.user" in resource_types:
            async for user in self._discover_users():
                yield user

        # Discover applications
        if not resource_types or "okta.app" in resource_types:
            async for app in self._discover_applications():
                yield app

        # Discover policies
        if not resource_types or "okta.policy" in resource_types:
            async for policy in self._discover_policies():
                yield policy

        # Discover network zones
        if not resource_types or "okta.network_zone" in resource_types:
            async for zone in self._discover_network_zones():
                yield zone

    async def _discover_applications(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Okta applications."""
        try:
            response = await self.client.get("/api/v1/apps")
            response.raise_for_status()
            apps = response.json()

            for app in apps:
                yield ResourceInfo(
                    external_id=app["id"],
                    name=app["label"],
                    resource_type="okta.app",
                    metadata={
                        "status": app["status"],
                        "sign_on_mode": app.get("signOnMode"),
                        "app_type": app.get("name"),
                        "created": app.get("created"),
                        "last_updated": app.get("lastUpdated"),
                        "visibility": app.get("visibility", {}),
                    },
                )
        except Exception as e:
            logger.error(f"Failed to discover Okta applications: {e}")

    async def _discover_policies(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Okta policies."""
        try:
            # Get different policy types
            policy_types = ["OKTA_SIGN_ON", "PASSWORD", "MFA_ENROLL", "ACCESS_POLICY"]

            for policy_type in policy_types:
                response = await self.client.get(
                    f"/api/v1/policies?type={policy_type}"
                )
                response.raise_for_status()
                policies = response.json()

                for policy in policies:
                    yield ResourceInfo(
                        external_id=policy["id"],
                        name=policy["name"],
                        resource_type="okta.policy",
                        metadata={
                            "type": policy["type"],
                            "status": policy["status"],
                            "priority": policy.get("priority"),
                            "description": policy.get("description"),
                            "created": policy.get("created"),
                            "last_updated": policy.get("lastUpdated"),
                        },
                    )
        except Exception as e:
            logger.error(f"Failed to discover Okta policies: {e}")

    async def _discover_network_zones(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Okta network zones."""
        try:
            response = await self.client.get("/api/v1/zones")
            response.raise_for_status()
            zones = response.json()

            for zone in zones:
                yield ResourceInfo(
                    external_id=zone["id"],
                    name=zone["name"],
                    resource_type="okta.network_zone",
                    metadata={
                        "type": zone["type"],
                        "status": zone["status"],
                        "gateways": zone.get("gateways", []),
                        "proxies": zone.get("proxies", []),
                        "created": zone.get("created"),
                        "last_updated": zone.get("lastUpdated"),
                    },
                )
        except Exception as e:
            logger.error(f"Failed to discover Okta network zones: {e}")

    async def _discover_users(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Okta users as resources."""
        try:
            url = "/api/v1/users"
            params: dict[str, int] | None = {"limit": 200}

            while url:
                response = await self.client.get(
                    url,
                    params=params if not url.startswith("http") else None,
                )
                response.raise_for_status()

                users = response.json()
                if isinstance(users, dict):
                    users = [users]

                for user in users:
                    profile = user.get("profile", {})
                    display_name = f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip() or profile.get(
                        "login"
                    )
                    yield ResourceInfo(
                        external_id=user["id"],
                        name=display_name,
                        resource_type="okta.user",
                        metadata={
                            "status": user.get("status"),
                            "email": profile.get("email"),
                            "login": profile.get("login"),
                        },
                    )

                # Pagination handling via Link header
                next_url = None
                links = response.headers.get("Link", "")
                for link in links.split(","):
                    if 'rel="next"' in link:
                        next_url = link.split("<")[1].split(">")[0]
                        break

                if next_url and next_url.startswith("http"):
                    url = next_url.replace(self.base_url, "")
                else:
                    break
                params = None

        except Exception as e:
            logger.error(f"Failed to discover Okta users: {e}")

    async def discover_principals(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover Okta users and groups."""
        if not self._client:
            await self.authenticate()

        # Discover users
        try:
            response = await self.client.get("/api/v1/users")
            response.raise_for_status()
            users = response.json()

            for user in users:
                profile = user.get("profile", {})

                yield PrincipalInfo(
                    external_id=user["id"],
                    principal_type="user",
                    email=profile.get("email"),
                    display_name=f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip(),
                    is_human=True,
                    metadata={
                        "status": user["status"],
                        "created": user.get("created"),
                        "activated": user.get("activated"),
                        "last_login": user.get("lastLogin"),
                        "login": profile.get("login"),
                        "mobile_phone": profile.get("mobilePhone"),
                        "employee_number": profile.get("employeeNumber"),
                    },
                )
        except Exception as e:
            logger.error(f"Failed to discover Okta users: {e}")

        # Discover groups
        try:
            response = await self.client.get("/api/v1/groups")
            response.raise_for_status()
            groups = response.json()

            for group in groups:
                profile = group.get("profile", {})

                yield PrincipalInfo(
                    external_id=group["id"],
                    principal_type="group",
                    display_name=profile.get("name"),
                    is_human=False,
                    metadata={
                        "type": group["type"],
                        "description": profile.get("description"),
                        "created": group.get("created"),
                        "last_updated": group.get("lastUpdated"),
                        "last_membership_updated": group.get("lastMembershipUpdated"),
                    },
                )
        except Exception as e:
            logger.error(f"Failed to discover Okta groups: {e}")

    async def get_resource_configuration(
        self, resource: ResourceInfo
    ) -> ConfigurationSnapshot:
        """Get Okta resource configuration."""
        if not self._client:
            await self.authenticate()

        config = {}

        if resource.resource_type == "okta.user":
            config = await self._get_user_config(resource.external_id)
        elif resource.resource_type == "okta.app":
            config = await self._get_app_config(resource.external_id)
        elif resource.resource_type == "okta.policy":
            config = await self._get_policy_config(resource.external_id)
        elif resource.resource_type == "okta.network_zone":
            config = await self._get_zone_config(resource.external_id)

        return ConfigurationSnapshot(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config=config,
        )

    async def _get_app_config(self, app_id: str) -> dict[str, Any]:
        """Get application configuration."""
        try:
            response = await self.client.get(f"/api/v1/apps/{app_id}")
            response.raise_for_status()
            app = response.json()

            # Get app users
            users_response = await self.client.get(f"/api/v1/apps/{app_id}/users")
            users_response.raise_for_status()
            app_users = users_response.json()

            return {
                "id": app["id"],
                "label": app["label"],
                "status": app["status"],
                "sign_on_mode": app.get("signOnMode"),
                "accessibility": app.get("accessibility", {}),
                "visibility": app.get("visibility", {}),
                "features": app.get("features", []),
                "settings": app.get("settings", {}),
                "credentials": app.get("credentials", {}),
                "assigned_users_count": len(app_users),
                "created": app.get("created"),
                "last_updated": app.get("lastUpdated"),
            }
        except Exception as e:
            logger.error(f"Failed to get Okta app config for {app_id}: {e}")
            return {}

    async def _get_user_config(self, user_id: str) -> dict[str, Any]:
        """Get detailed user configuration for identity hygiene checks."""
        try:
            user_response = await self.client.get(f"/api/v1/users/{user_id}")
            user_response.raise_for_status()
            user = user_response.json()

            # Fetch related data with graceful degradation
            factors = await self._safe_get(f"/api/v1/users/{user_id}/factors") or []
            groups = await self._safe_get(f"/api/v1/users/{user_id}/groups") or []
            roles = await self._safe_get(f"/api/v1/users/{user_id}/roles") or []
            app_links = await self._safe_get(f"/api/v1/users/{user_id}/appLinks") or []

            profile = user.get("profile", {})

            mfa_factors = []
            mfa_enrolled = False
            for factor in factors if isinstance(factors, list) else []:
                factor_type = factor.get("factorType") or factor.get("provider")
                status = factor.get("status", "UNKNOWN")
                mfa_factors.append(
                    {
                        "id": factor.get("id"),
                        "factor_type": factor_type,
                        "provider": factor.get("provider"),
                        "status": status,
                    }
                )
                if status in {"ACTIVE", "ENABLED", "ENROLLED"}:
                    mfa_enrolled = True

            admin_roles = []
            formatted_roles = []
            for role in roles if isinstance(roles, list) else []:
                label = role.get("label") or role.get("type") or role.get("name")
                formatted_roles.append(
                    {
                        "id": role.get("id"),
                        "label": label,
                        "type": role.get("type"),
                        "assignment_type": role.get("assignmentType"),
                    }
                )
                if label:
                    admin_roles.append(label)

            group_memberships = []
            for group in groups if isinstance(groups, list) else []:
                profile_data = group.get("profile", {})
                group_memberships.append(
                    {
                        "id": group.get("id"),
                        "name": profile_data.get("name"),
                        "type": group.get("type"),
                    }
                )

            applications = []
            for app in app_links if isinstance(app_links, list) else []:
                applications.append(
                    {
                        "id": app.get("appInstanceId"),
                        "label": app.get("label"),
                        "link": app.get("linkUrl"),
                        "app_name": app.get("appName"),
                    }
                )

            service_account = bool(
                (profile.get("userType") or "").lower() in {"service", "serviceaccount"}
                or profile.get("login", "").lower().startswith("svc")
            )

            return {
                "id": user.get("id"),
                "status": user.get("status"),
                "status_changed": user.get("statusChanged"),
                "email": profile.get("email"),
                "login": profile.get("login"),
                "display_name": (
                    f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip()
                    or profile.get("login")
                ),
                "profile": profile,
                "created": user.get("created"),
                "activated": user.get("activated"),
                "last_login": user.get("lastLogin"),
                "password_changed": user.get("passwordChanged"),
                "credentials": user.get("credentials", {}),
                "mfa_enrolled": mfa_enrolled,
                "mfa_factors": mfa_factors,
                "roles": formatted_roles,
                "admin_roles": admin_roles,
                "groups": group_memberships,
                "applications": applications,
                "is_admin": bool(admin_roles),
                "is_service_account": service_account,
            }

        except Exception as e:
            logger.error(f"Failed to get Okta user config for {user_id}: {e}")
            return {}

    async def _safe_get(self, path: str) -> Any | None:
        """Fetch auxiliary Okta data with graceful fallback."""
        try:
            response = await self.client.get(path)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                logger.debug(f"Okta endpoint not found for {path}: {exc}")
                return None
            logger.warning(
                f"Okta API returned error {exc.response.status_code} for {path}"
            )
            return None
        except Exception as exc:
            logger.warning(f"Okta API request failed for {path}: {exc}")
            return None

    async def _get_policy_config(self, policy_id: str) -> dict[str, Any]:
        """Get policy configuration."""
        try:
            response = await self.client.get(f"/api/v1/policies/{policy_id}")
            response.raise_for_status()
            policy = response.json()

            # Get policy rules
            rules_response = await self.client.get(
                f"/api/v1/policies/{policy_id}/rules"
            )
            rules_response.raise_for_status()
            rules = rules_response.json()

            return {
                "id": policy["id"],
                "name": policy["name"],
                "type": policy["type"],
                "status": policy["status"],
                "priority": policy.get("priority"),
                "description": policy.get("description"),
                "conditions": policy.get("conditions", {}),
                "rules": rules,
                "rules_count": len(rules),
                "created": policy.get("created"),
                "last_updated": policy.get("lastUpdated"),
            }
        except Exception as e:
            logger.error(f"Failed to get Okta policy config for {policy_id}: {e}")
            return {}

    async def _get_zone_config(self, zone_id: str) -> dict[str, Any]:
        """Get network zone configuration."""
        try:
            response = await self.client.get(f"/api/v1/zones/{zone_id}")
            response.raise_for_status()
            zone = response.json()

            return {
                "id": zone["id"],
                "name": zone["name"],
                "type": zone["type"],
                "status": zone["status"],
                "gateways": zone.get("gateways", []),
                "proxies": zone.get("proxies", []),
                "locations": zone.get("locations", []),
                "system": zone.get("system", False),
                "created": zone.get("created"),
                "last_updated": zone.get("lastUpdated"),
            }
        except Exception as e:
            logger.error(f"Failed to get Okta zone config for {zone_id}: {e}")
            return {}

    async def discover_iam_edges(
        self, resource: ResourceInfo | None = None
    ) -> AsyncGenerator[IamPermission, None]:
        """Discover Okta permissions and assignments."""
        if not self._client:
            await self.authenticate()

        try:
            # Get user-group memberships
            users_response = await self.client.get("/api/v1/users")
            users_response.raise_for_status()
            users = users_response.json()

            for user in users:
                user_id = user["id"]

                # Get user's group memberships
                groups_response = await self.client.get(
                    f"/api/v1/users/{user_id}/groups"
                )
                groups_response.raise_for_status()
                user_groups = groups_response.json()

                for group in user_groups:
                    yield IamPermission(
                        principal_external_id=user["id"],
                        resource_external_id=group["id"],
                        permission="okta.group.member",
                        via="direct_assignment",
                        effective_at=datetime.utcnow(),
                        is_admin="admin"
                        in group.get("profile", {}).get("name", "").lower(),
                    )

                # Get user's app assignments
                apps_response = await self.client.get(
                    f"/api/v1/users/{user_id}/appLinks"
                )
                apps_response.raise_for_status()
                user_apps = apps_response.json()

                for app in user_apps:
                    yield IamPermission(
                        principal_external_id=user["id"],
                        resource_external_id=app["appInstanceId"],
                        permission="okta.app.access",
                        via="user_assignment",
                        effective_at=datetime.utcnow(),
                        is_admin=False,
                    )

        except Exception as e:
            logger.error(f"Failed to discover Okta permissions: {e}")

    async def cleanup(self):
        """Cleanup HTTP client."""
        if self._client:
            await self._client.aclose()
