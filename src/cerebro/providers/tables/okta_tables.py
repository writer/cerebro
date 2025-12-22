"""
Okta provider table implementations.

Exposes Okta identity resources as SQL tables.
"""

from typing import AsyncGenerator, Dict, Any, Optional
from datetime import datetime
import logging

from ...query.table import ProviderSecurityTable, QueryContext
from ...query.registry import register_table
from ...query.schema import SecurityColumn, ColumnType, SecuritySchema


# Real Okta API client implementation
class OktaClient:
    def __init__(self, domain: str = None, api_token: str = None):
        self.domain = domain
        self.api_token = api_token
        self.base_url = f"https://{domain}" if domain else None
        self._client = None

    async def authenticate(self):
        """Authenticate with Okta API."""
        try:
            import httpx
            from cerebro.core.config import settings

            # Use provided credentials or fall back to settings
            domain = self.domain or getattr(settings, "okta_domain", "demo")
            api_token = self.api_token or getattr(settings, "okta_api_token", None)

            if not api_token:
                logger.error("Okta API token not configured")
                return False

            self.base_url = f"https://{domain}"
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={
                    "Authorization": f"SSWS {api_token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )

            return True

        except ImportError:
            logger.error("httpx not installed. Run: pip install httpx")
            return False
        except Exception as e:
            logger.error(f"Okta authentication failed: {e}")
            return False

    async def list_users(self, **params):
        """List all users from Okta API."""
        try:
            if not self._client:
                if not await self.authenticate():
                    return

            url = "/api/v1/users"

            while url:
                response = await self._client.get(
                    url, params=params if not url.startswith("http") else None
                )
                response.raise_for_status()

                users = response.json()

                # Handle both list and single object responses
                if isinstance(users, list):
                    for user in users:
                        yield user
                else:
                    yield users

                # Handle pagination
                links = response.headers.get("Link", "")
                next_url = None
                for link in links.split(","):
                    if 'rel="next"' in link:
                        next_url = link.split("<")[1].split(">")[0]
                        break

                if next_url and next_url.startswith("http"):
                    url = next_url.replace(self.base_url, "")
                else:
                    break
                params = None  # Parameters are included in next URL

        except Exception as e:
            logger.error(f"Error listing Okta users: {e}")
            return

    async def list_applications(self):
        """List all applications from Okta API."""
        try:
            if not self._client:
                if not await self.authenticate():
                    return

            url = "/api/v1/apps"

            while url:
                response = await self._client.get(url)
                response.raise_for_status()

                apps = response.json()

                # Handle both list and single object responses
                if isinstance(apps, list):
                    for app in apps:
                        yield app
                else:
                    yield apps

                # Handle pagination
                links = response.headers.get("Link", "")
                next_url = None
                for link in links.split(","):
                    if 'rel="next"' in link:
                        next_url = link.split("<")[1].split(">")[0]
                        break

                if next_url and next_url.startswith("http"):
                    url = next_url.replace(self.base_url, "")
                else:
                    break

        except Exception as e:
            logger.error(f"Error listing Okta applications: {e}")
            return

    async def list_groups(self):
        """List all groups from Okta API."""
        try:
            if not self._client:
                if not await self.authenticate():
                    return

            url = "/api/v1/groups"

            while url:
                response = await self._client.get(url)
                response.raise_for_status()

                groups = response.json()

                # Handle both list and single object responses
                if isinstance(groups, list):
                    for group in groups:
                        yield group
                else:
                    yield groups

                # Handle pagination
                links = response.headers.get("Link", "")
                next_url = None
                for link in links.split(","):
                    if 'rel="next"' in link:
                        next_url = link.split("<")[1].split(">")[0]
                        break

                if next_url and next_url.startswith("http"):
                    url = next_url.replace(self.base_url, "")
                else:
                    break

        except Exception as e:
            logger.error(f"Error listing Okta groups: {e}")
            return


logger = logging.getLogger(__name__)


class OktaUserTable(ProviderSecurityTable):
    """Okta users as a security table."""

    def __init__(self):
        super().__init__(
            name="okta_user",
            description="Okta user accounts with profile and authentication data",
            provider_name="okta",
            columns=SecuritySchema.IDENTITY_COLUMNS,
        )

        # Add Okta-specific columns
        okta_columns = [
            SecurityColumn(
                "login",
                ColumnType.TEXT,
                "Okta login username",
                source_field="profile.login",
            ),
            SecurityColumn(
                "first_name",
                ColumnType.TEXT,
                "First name",
                source_field="profile.firstName",
            ),
            SecurityColumn(
                "last_name",
                ColumnType.TEXT,
                "Last name",
                source_field="profile.lastName",
            ),
            SecurityColumn(
                "mobile_phone",
                ColumnType.TEXT,
                "Mobile phone",
                source_field="profile.mobilePhone",
            ),
            SecurityColumn(
                "activated",
                ColumnType.TIMESTAMP,
                "Account activation date",
                source_field="activated",
            ),
            SecurityColumn(
                "status_changed",
                ColumnType.TIMESTAMP,
                "Status change date",
                source_field="statusChanged",
            ),
            SecurityColumn(
                "password_changed",
                ColumnType.TIMESTAMP,
                "Password change date",
                source_field="passwordChanged",
            ),
            SecurityColumn(
                "credentials",
                ColumnType.JSON,
                "Credential information",
                source_field="credentials",
            ),
            SecurityColumn(
                "profile", ColumnType.JSON, "Full user profile", source_field="profile"
            ),
        ]

        self.columns.extend(okta_columns)
        self.column_map.update({col.name: col for col in okta_columns})

    async def fetch_from_api(
        self, ctx: QueryContext
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch users from Okta API."""
        client = OktaClient(
            domain=ctx.config.get("okta_domain"),
            api_token=ctx.config.get("okta_api_token"),
        )

        try:
            # Authenticate if needed
            await client.authenticate()

            # Build query parameters from context filters
            params = self._build_okta_query_params(ctx)

            # Fetch users with pagination
            async for user in client.list_users(**params):
                # Transform Okta user to our schema
                transformed_user = self._transform_okta_user(user)
                yield transformed_user

        except Exception as e:
            logger.error(f"Error fetching Okta users: {e}")
            return

    def _build_okta_query_params(self, ctx: QueryContext) -> Dict[str, Any]:
        """Build Okta API query parameters from QueryContext."""
        params = {}

        # Map common filters to Okta query parameters
        for filter_condition in ctx.filters:
            if filter_condition.column == "status":
                params["filter"] = f'status eq "{filter_condition.value}"'
            elif filter_condition.column == "email":
                params["search"] = f'profile.email eq "{filter_condition.value}"'
            elif filter_condition.column == "username":
                params["search"] = f'profile.login eq "{filter_condition.value}"'

        # Set pagination
        if ctx.limit:
            params["limit"] = min(ctx.limit, 200)  # Okta max is 200

        return params

    def _transform_okta_user(self, okta_user: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Okta user data to our standard schema."""
        profile = okta_user.get("profile", {})

        return {
            "id": okta_user["id"],
            "provider": "okta",
            "account_id": self._get_okta_domain(),
            "region": "global",
            "created_at": self._parse_okta_timestamp(okta_user.get("created")),
            "updated_at": self._parse_okta_timestamp(okta_user.get("lastUpdated")),
            "user_id": okta_user["id"],
            "username": profile.get("login"),
            "email": profile.get("email"),
            "display_name": f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip(),
            "status": okta_user.get("status", "").lower(),
            "last_login": self._parse_okta_timestamp(okta_user.get("lastLogin")),
            "mfa_enabled": self._check_mfa_enabled(okta_user),
            "locked": okta_user.get("status") == "LOCKED_OUT",
            "password_changed": self._parse_okta_timestamp(
                okta_user.get("passwordChanged")
            ),
            "groups": [],  # Would require additional API call
            "roles": [],  # Would require additional API call
            "attributes": profile,
            "tags": {},
            "metadata": {
                "activated": okta_user.get("activated"),
                "status_changed": okta_user.get("statusChanged"),
                "credentials": okta_user.get("credentials"),
                "okta_profile": profile,
            },
        }

    def _get_okta_domain(self) -> str:
        """Get Okta domain/tenant identifier."""
        # This would come from configuration
        return "example.okta.com"

    def _parse_okta_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse Okta timestamp string."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            return None

    def _check_mfa_enabled(self, user: Dict[str, Any]) -> bool:
        """Check if MFA is enabled (simplified)."""
        # This would require additional API calls to get factors
        return False


class OktaApplicationTable(ProviderSecurityTable):
    """Okta applications as a security table."""

    def __init__(self):
        app_columns = [
            SecurityColumn(
                "app_id",
                ColumnType.TEXT,
                "Application ID",
                required=True,
                source_field="id",
            ),
            SecurityColumn(
                "app_name", ColumnType.TEXT, "Application name", source_field="name"
            ),
            SecurityColumn(
                "label", ColumnType.TEXT, "Application label", source_field="label"
            ),
            SecurityColumn(
                "app_status",
                ColumnType.STATUS,
                "Application status",
                source_field="status",
            ),
            SecurityColumn(
                "sign_on_mode",
                ColumnType.TEXT,
                "Sign-on mode",
                source_field="signOnMode",
            ),
            SecurityColumn(
                "features", ColumnType.JSON, "Enabled features", source_field="features"
            ),
            SecurityColumn(
                "settings",
                ColumnType.JSON,
                "Application settings",
                source_field="settings",
            ),
            SecurityColumn(
                "visibility",
                ColumnType.JSON,
                "Visibility settings",
                source_field="visibility",
            ),
            SecurityColumn(
                "accessibility",
                ColumnType.JSON,
                "Accessibility settings",
                source_field="accessibility",
            ),
            SecurityColumn(
                "licensing", ColumnType.JSON, "Licensing info", source_field="licensing"
            ),
            SecurityColumn(
                "assigned_users",
                ColumnType.INTEGER,
                "Number of assigned users",
                transform="count_assigned_users",
            ),
            SecurityColumn(
                "assigned_groups",
                ColumnType.INTEGER,
                "Number of assigned groups",
                transform="count_assigned_groups",
            ),
        ]

        super().__init__(
            name="okta_application",
            description="Okta applications and their configurations",
            provider_name="okta",
            columns=app_columns,
        )

    async def fetch_from_api(
        self, ctx: QueryContext
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch applications from Okta API."""
        client = OktaClient(
            domain=ctx.config.get("okta_domain"),
            api_token=ctx.config.get("okta_api_token"),
        )

        try:
            # Authenticate if needed
            await client.authenticate()

            async for app in client.list_applications():
                # Add provider metadata
                app["provider"] = "okta"
                app["account_id"] = ctx.config.get("okta_domain", "unknown-okta")
                app["region"] = "global"
                app["created_at"] = self._parse_okta_timestamp(app.get("created"))
                app["updated_at"] = self._parse_okta_timestamp(app.get("lastUpdated"))
                app["tags"] = {}
                app["metadata"] = {"okta_app_data": app}

                yield app

        except Exception as e:
            logger.error(f"Error fetching Okta applications: {e}")
            return

    def _get_okta_domain(self) -> str:
        """Get Okta domain."""
        return "example.okta.com"

    def _parse_okta_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse Okta timestamp."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            return None

    def count_assigned_users(self, app_data: Dict[str, Any]) -> int:
        """Count assigned users (would require additional API call)."""
        return 0

    def count_assigned_groups(self, app_data: Dict[str, Any]) -> int:
        """Count assigned groups (would require additional API call)."""
        return 0


class OktaGroupTable(ProviderSecurityTable):
    """Okta groups as a security table."""

    def __init__(self):
        group_columns = [
            SecurityColumn(
                "group_id",
                ColumnType.TEXT,
                "Group ID",
                required=True,
                source_field="id",
            ),
            SecurityColumn(
                "group_name", ColumnType.TEXT, "Group name", source_field="profile.name"
            ),
            SecurityColumn(
                "description",
                ColumnType.TEXT,
                "Group description",
                source_field="profile.description",
            ),
            SecurityColumn(
                "group_type", ColumnType.TEXT, "Group type", source_field="type"
            ),
            SecurityColumn(
                "profile", ColumnType.JSON, "Group profile", source_field="profile"
            ),
            SecurityColumn(
                "member_count",
                ColumnType.INTEGER,
                "Number of members",
                transform="count_members",
            ),
        ]

        super().__init__(
            name="okta_group",
            description="Okta groups and their memberships",
            provider_name="okta",
            columns=group_columns,
        )

    async def fetch_from_api(
        self, ctx: QueryContext
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch groups from Okta API."""
        client = OktaClient(
            domain=ctx.config.get("okta_domain"),
            api_token=ctx.config.get("okta_api_token"),
        )

        try:
            # Authenticate if needed
            await client.authenticate()

            async for group in client.list_groups():
                # Add provider metadata
                group["provider"] = "okta"
                group["account_id"] = ctx.config.get("okta_domain", "unknown-okta")
                group["region"] = "global"
                group["created_at"] = self._parse_okta_timestamp(group.get("created"))
                group["updated_at"] = self._parse_okta_timestamp(
                    group.get("lastUpdated")
                )
                group["tags"] = {}
                group["metadata"] = {"okta_group_data": group}

                yield group

        except Exception as e:
            logger.error(f"Error fetching Okta groups: {e}")
            return

    def _get_okta_domain(self) -> str:
        """Get Okta domain."""
        return "example.okta.com"

    def _parse_okta_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse Okta timestamp."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            return None

    def count_members(self, group_data: Dict[str, Any]) -> int:
        """Count group members (would require additional API call)."""
        return 0


def register_okta_tables():
    """Register all Okta tables with the query engine."""
    register_table(OktaUserTable(), aliases=["okta_users", "users"])
    register_table(OktaApplicationTable(), aliases=["okta_apps", "applications"])
    register_table(OktaGroupTable(), aliases=["okta_groups", "groups"])
