"""
Microsoft 365 provider table implementations.

Exposes Microsoft 365 security resources as SQL tables following Steampipe patterns.
"""

from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Any

import structlog

from ...query.registry import register_table
from ...query.schema import ColumnType, SecurityColumn, SecuritySchema
from ...query.table import ProviderSecurityTable, QueryContext

logger = structlog.get_logger(__name__)


# Real Microsoft Graph client implementation
class M365Client:
    def __init__(
        self,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._access_token: str | None = None
        self._client: Any = None

    async def authenticate(self):
        """Authenticate with Microsoft Graph API."""
        try:
            import httpx

            from cerebro.core.config import settings

            # Use provided credentials or fall back to settings
            tenant_id = self.tenant_id or getattr(
                settings, "m365_tenant_id", "default-tenant"
            )
            client_id = self.client_id or getattr(settings, "m365_client_id", None)
            client_secret = self.client_secret or getattr(
                settings, "m365_client_secret", None
            )

            if not client_id or not client_secret:
                logger.error("M365 client credentials not configured")
                return False

            # Get OAuth token
            token_url = (
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            )
            token_data = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
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
                },
                timeout=30.0,
            )

            self.tenant_id = tenant_id
            return True

        except ImportError:
            logger.error("httpx not installed. Run: pip install httpx")
            return False
        except Exception as e:
            logger.error(f"M365 authentication failed: {e}")
            return False

    async def get_tenant_id(self) -> str:
        """Get tenant ID."""
        return self.tenant_id or "unknown-tenant"

    async def list_users(self):
        """List all users from Microsoft Graph API."""
        try:
            if not self._client:
                if not await self.authenticate():
                    return

            url = "/users"
            params: dict[str, str] | None = {
                "$select": "id,userPrincipalName,displayName,givenName,surname,mail,mobilePhone,officeLocation,jobTitle,department,companyName,country,usageLocation,accountEnabled,createdDateTime,lastSignInDateTime,assignedLicenses,signInActivity"
            }

            while url:
                response = await self._client.get(
                    url, params=params if not url.startswith("http") else None
                )
                response.raise_for_status()
                data = response.json()

                for user in data.get("value", []):
                    yield user

                # Handle pagination
                url = data.get("@odata.nextLink")
                if url and url.startswith("http"):
                    # Remove base URL for next request
                    url = url.replace("https://graph.microsoft.com/v1.0", "")
                params = None  # Parameters are included in nextLink URL

        except Exception as e:
            logger.error(f"Error listing M365 users: {e}")
            return

    async def list_applications(self):
        """List all applications from Microsoft Graph API."""
        try:
            if not self._client:
                if not await self.authenticate():
                    return

            url = "/applications"
            params: dict[str, str] | None = {
                "$select": "id,appId,displayName,signInAudience,createdDateTime,publisherDomain,requiredResourceAccess,keyCredentials,passwordCredentials"
            }

            while url:
                response = await self._client.get(
                    url, params=params if not url.startswith("http") else None
                )
                response.raise_for_status()
                data = response.json()

                for app in data.get("value", []):
                    yield app

                # Handle pagination
                url = data.get("@odata.nextLink")
                if url and url.startswith("http"):
                    url = url.replace("https://graph.microsoft.com/v1.0", "")
                params = None

        except Exception as e:
            logger.error(f"Error listing M365 applications: {e}")
            return

    async def list_conditional_access_policies(self):
        """List Conditional Access policies from Microsoft Graph API."""
        try:
            if not self._client:
                if not await self.authenticate():
                    return

            url = "/identity/conditionalAccess/policies"

            while url:
                response = await self._client.get(url)
                response.raise_for_status()
                data = response.json()

                for policy in data.get("value", []):
                    yield policy

                # Handle pagination
                url = data.get("@odata.nextLink")
                if url and url.startswith("http"):
                    url = url.replace("https://graph.microsoft.com/v1.0", "")

        except Exception as e:
            logger.error(f"Error listing Conditional Access policies: {e}")
            return


class M365UserTable(ProviderSecurityTable):
    """Microsoft 365 users as a security table."""

    def __init__(self):
        super().__init__(
            name="m365_user",
            description="Microsoft 365 user accounts with profile and security data",
            provider_name="m365",
            columns=SecuritySchema.IDENTITY_COLUMNS,
        )

        # Add M365-specific columns
        m365_columns = [
            SecurityColumn(
                "user_principal_name",
                ColumnType.TEXT,
                "User principal name",
                source_field="userPrincipalName",
            ),
            SecurityColumn(
                "given_name", ColumnType.TEXT, "First name", source_field="givenName"
            ),
            SecurityColumn(
                "surname", ColumnType.TEXT, "Last name", source_field="surname"
            ),
            SecurityColumn(
                "mail", ColumnType.TEXT, "Primary email", source_field="mail"
            ),
            SecurityColumn(
                "mobile_phone",
                ColumnType.TEXT,
                "Mobile phone",
                source_field="mobilePhone",
            ),
            SecurityColumn(
                "office_location",
                ColumnType.TEXT,
                "Office location",
                source_field="officeLocation",
            ),
            SecurityColumn(
                "job_title", ColumnType.TEXT, "Job title", source_field="jobTitle"
            ),
            SecurityColumn(
                "department", ColumnType.TEXT, "Department", source_field="department"
            ),
            SecurityColumn(
                "company_name",
                ColumnType.TEXT,
                "Company name",
                source_field="companyName",
            ),
            SecurityColumn(
                "country", ColumnType.TEXT, "Country", source_field="country"
            ),
            SecurityColumn(
                "usage_location",
                ColumnType.TEXT,
                "Usage location",
                source_field="usageLocation",
            ),
            SecurityColumn(
                "account_enabled",
                ColumnType.BOOLEAN,
                "Account enabled",
                source_field="accountEnabled",
            ),
            SecurityColumn(
                "last_sign_in",
                ColumnType.TIMESTAMP,
                "Last sign-in time",
                source_field="lastSignInDateTime",
            ),
            SecurityColumn(
                "assigned_licenses",
                ColumnType.JSON,
                "Assigned licenses",
                source_field="assignedLicenses",
            ),
            SecurityColumn(
                "sign_in_activity",
                ColumnType.JSON,
                "Sign-in activity",
                source_field="signInActivity",
            ),
        ]

        self.columns.extend(m365_columns)
        self.column_map.update({col.name: col for col in m365_columns})

    async def fetch_from_api(
        self, ctx: QueryContext
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Fetch users from Microsoft Graph API."""
        config = ctx.config or {}
        client = M365Client(
            tenant_id=config.get("m365_tenant_id"),
            client_id=config.get("m365_client_id"),
            client_secret=config.get("m365_client_secret"),
        )

        try:
            # Authenticate if needed
            await client.authenticate()

            async for user in client.list_users():
                # Transform M365 user to our schema
                transformed_user = self._transform_m365_user(
                    user, await client.get_tenant_id()
                )
                yield transformed_user

        except Exception as e:
            logger.error(f"Error fetching M365 users: {e}")
            return

    def _transform_m365_user(
        self, m365_user: dict[str, Any], tenant_id: str
    ) -> dict[str, Any]:
        """Transform M365 user data to our standard schema."""
        return {
            "id": m365_user["id"],
            "provider": "m365",
            "account_id": tenant_id,
            "region": "global",
            "created_at": self._parse_m365_timestamp(m365_user.get("createdDateTime")),
            "updated_at": datetime.now(),
            "user_id": m365_user["id"],
            "username": m365_user.get("userPrincipalName"),
            "email": m365_user.get("mail") or m365_user.get("userPrincipalName"),
            "display_name": m365_user.get("displayName"),
            "status": "active" if m365_user.get("accountEnabled") else "disabled",
            "last_login": self._parse_m365_timestamp(
                m365_user.get("lastSignInDateTime")
            ),
            "mfa_enabled": False,  # Would require additional Graph API call
            "locked": not m365_user.get("accountEnabled", True),
            "password_changed": None,  # Would require additional Graph API call
            "groups": [],  # Would require additional Graph API call
            "roles": [],  # Would require additional Graph API call
            "attributes": {
                "givenName": m365_user.get("givenName"),
                "surname": m365_user.get("surname"),
                "jobTitle": m365_user.get("jobTitle"),
                "department": m365_user.get("department"),
                "officeLocation": m365_user.get("officeLocation"),
            },
            "tags": {},
            "metadata": {"m365_user_data": m365_user},
            # M365-specific fields
            "user_principal_name": m365_user.get("userPrincipalName"),
            "given_name": m365_user.get("givenName"),
            "surname": m365_user.get("surname"),
            "mail": m365_user.get("mail"),
            "mobile_phone": m365_user.get("mobilePhone"),
            "office_location": m365_user.get("officeLocation"),
            "job_title": m365_user.get("jobTitle"),
            "department": m365_user.get("department"),
            "company_name": m365_user.get("companyName"),
            "country": m365_user.get("country"),
            "usage_location": m365_user.get("usageLocation"),
            "account_enabled": m365_user.get("accountEnabled"),
            "last_sign_in": self._parse_m365_timestamp(
                m365_user.get("lastSignInDateTime")
            ),
            "assigned_licenses": m365_user.get("assignedLicenses", []),
            "sign_in_activity": m365_user.get("signInActivity", {}),
        }

    def _parse_m365_timestamp(self, timestamp_str: str | None) -> datetime | None:
        """Parse M365 timestamp string."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            return None


class M365ApplicationTable(ProviderSecurityTable):
    """Microsoft 365 applications as a security table."""

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
                "client_app_id",
                ColumnType.TEXT,
                "Client application ID",
                source_field="appId",
            ),
            SecurityColumn(
                "display_name",
                ColumnType.TEXT,
                "Application name",
                source_field="displayName",
            ),
            SecurityColumn(
                "sign_in_audience",
                ColumnType.TEXT,
                "Sign-in audience",
                source_field="signInAudience",
            ),
            SecurityColumn(
                "publisher_domain",
                ColumnType.TEXT,
                "Publisher domain",
                source_field="publisherDomain",
            ),
            SecurityColumn(
                "required_resource_access",
                ColumnType.JSON,
                "Required resource access",
                source_field="requiredResourceAccess",
            ),
            SecurityColumn(
                "key_credentials",
                ColumnType.JSON,
                "Key credentials",
                source_field="keyCredentials",
            ),
            SecurityColumn(
                "password_credentials",
                ColumnType.JSON,
                "Password credentials",
                source_field="passwordCredentials",
            ),
            SecurityColumn(
                "has_credentials",
                ColumnType.BOOLEAN,
                "Has authentication credentials",
                transform="check_credentials",
            ),
            SecurityColumn(
                "permission_count",
                ColumnType.INTEGER,
                "Number of permissions",
                transform="count_permissions",
            ),
        ]

        super().__init__(
            name="m365_application",
            description="Microsoft 365 applications and their configurations",
            provider_name="m365",
            columns=app_columns,
        )

    async def fetch_from_api(
        self, ctx: QueryContext
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Fetch applications from Microsoft Graph API."""
        config = ctx.config or {}
        client = M365Client(
            tenant_id=config.get("m365_tenant_id"),
            client_id=config.get("m365_client_id"),
            client_secret=config.get("m365_client_secret"),
        )

        try:
            # Authenticate if needed
            await client.authenticate()

            async for app in client.list_applications():
                # Add provider metadata
                app["provider"] = "m365"
                app["account_id"] = await client.get_tenant_id()
                app["region"] = "global"
                app["created_at"] = self._parse_m365_timestamp(
                    app.get("createdDateTime")
                )
                app["updated_at"] = datetime.now()
                app["tags"] = {}
                app["metadata"] = {"m365_app_data": app}

                yield app

        except Exception as e:
            logger.error(f"Error fetching M365 applications: {e}")
            return

    def check_credentials(self, app_data: dict[str, Any]) -> bool:
        """Check if application has authentication credentials."""
        key_creds = app_data.get("keyCredentials", [])
        password_creds = app_data.get("passwordCredentials", [])
        return len(key_creds) > 0 or len(password_creds) > 0

    def count_permissions(self, app_data: dict[str, Any]) -> int:
        """Count total permissions requested by application."""
        resource_access = app_data.get("requiredResourceAccess", [])
        total_permissions = 0

        for resource in resource_access:
            total_permissions += len(resource.get("resourceAccess", []))

        return total_permissions

    def _parse_m365_timestamp(self, timestamp_str: str | None) -> datetime | None:
        """Parse M365 timestamp string."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            return None


class M365ConditionalAccessTable(ProviderSecurityTable):
    """Microsoft 365 Conditional Access policies as a security table."""

    def __init__(self):
        ca_columns = [
            SecurityColumn(
                "policy_id",
                ColumnType.TEXT,
                "Policy ID",
                required=True,
                source_field="id",
            ),
            SecurityColumn(
                "display_name",
                ColumnType.TEXT,
                "Policy name",
                source_field="displayName",
            ),
            SecurityColumn(
                "state", ColumnType.TEXT, "Policy state", source_field="state"
            ),
            SecurityColumn(
                "conditions",
                ColumnType.JSON,
                "Policy conditions",
                source_field="conditions",
            ),
            SecurityColumn(
                "grant_controls",
                ColumnType.JSON,
                "Grant controls",
                source_field="grantControls",
            ),
            SecurityColumn(
                "session_controls",
                ColumnType.JSON,
                "Session controls",
                source_field="sessionControls",
            ),
            SecurityColumn(
                "modified_date",
                ColumnType.TIMESTAMP,
                "Last modified",
                source_field="modifiedDateTime",
            ),
            SecurityColumn(
                "includes_all_users",
                ColumnType.BOOLEAN,
                "Includes all users",
                transform="check_all_users",
            ),
            SecurityColumn(
                "requires_mfa",
                ColumnType.BOOLEAN,
                "Requires MFA",
                transform="check_mfa_requirement",
            ),
            SecurityColumn(
                "applies_to_all_apps",
                ColumnType.BOOLEAN,
                "Applies to all applications",
                transform="check_all_apps",
            ),
        ]

        super().__init__(
            name="m365_conditional_access_policy",
            description="Microsoft 365 Conditional Access policies",
            provider_name="m365",
            columns=ca_columns,
        )

    async def fetch_from_api(
        self, ctx: QueryContext
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Fetch Conditional Access policies from Microsoft Graph API."""
        config = ctx.config or {}
        client = M365Client(
            tenant_id=config.get("m365_tenant_id"),
            client_id=config.get("m365_client_id"),
            client_secret=config.get("m365_client_secret"),
        )

        try:
            # Authenticate if needed
            await client.authenticate()

            async for policy in client.list_conditional_access_policies():
                # Add provider metadata
                policy["provider"] = "m365"
                policy["account_id"] = await client.get_tenant_id()
                policy["region"] = "global"
                policy["created_at"] = self._parse_m365_timestamp(
                    policy.get("createdDateTime")
                )
                policy["updated_at"] = self._parse_m365_timestamp(
                    policy.get("modifiedDateTime")
                )
                policy["tags"] = {}
                policy["metadata"] = {"m365_ca_policy_data": policy}

                yield policy

        except Exception as e:
            logger.error(f"Error fetching M365 Conditional Access policies: {e}")
            return

    def check_all_users(self, policy_data: dict[str, Any]) -> bool:
        """Check if policy applies to all users."""
        conditions = policy_data.get("conditions", {})
        users = conditions.get("users", {})
        include_users = users.get("includeUsers", [])
        return "All" in include_users

    def check_mfa_requirement(self, policy_data: dict[str, Any]) -> bool:
        """Check if policy requires MFA."""
        grant_controls = policy_data.get("grantControls", {})
        built_in_controls = grant_controls.get("builtInControls", [])
        return "mfa" in built_in_controls

    def check_all_apps(self, policy_data: dict[str, Any]) -> bool:
        """Check if policy applies to all applications."""
        conditions = policy_data.get("conditions", {})
        applications = conditions.get("applications", {})
        include_apps = applications.get("includeApplications", [])
        return "All" in include_apps

    def _parse_m365_timestamp(self, timestamp_str: str | None) -> datetime | None:
        """Parse M365 timestamp string."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            return None


def register_m365_tables():
    """Register all Microsoft 365 tables with the query engine."""
    register_table(M365UserTable(), aliases=["m365_users", "office365_users"])
    register_table(M365ApplicationTable(), aliases=["m365_apps", "azure_ad_apps"])
    register_table(
        M365ConditionalAccessTable(), aliases=["m365_ca", "conditional_access"]
    )
