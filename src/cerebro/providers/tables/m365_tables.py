"""
Microsoft 365 provider table implementations.

Exposes Microsoft 365 security resources as SQL tables following Steampipe patterns.
"""

import asyncio
import logging
from typing import AsyncGenerator, Dict, Any, List, Optional
from datetime import datetime

from ...query.table import ProviderSecurityTable, QueryContext
from ...query.registry import register_table
from ...query.schema import SecurityColumn, ColumnType, SecuritySchema

logger = logging.getLogger(__name__)

# Mock M365 client for demonstration
class M365Client:
    async def get_client(self, service: str):
        return MockM365Service()
    
    async def get_tenant_id(self) -> str:
        return "12345678-1234-1234-1234-123456789012"

class MockM365Service:
    async def list_users(self):
        users = [{
            "id": "12345678-abcd-efgh-ijkl-123456789012",
            "userPrincipalName": "john.doe@contoso.com",
            "displayName": "John Doe",
            "givenName": "John",
            "surname": "Doe",
            "mail": "john.doe@contoso.com",
            "mobilePhone": "+1-555-555-5555",
            "officeLocation": "Seattle",
            "preferredLanguage": "en-US",
            "jobTitle": "Software Engineer",
            "department": "Engineering",
            "companyName": "Contoso Ltd",
            "country": "United States",
            "usageLocation": "US",
            "accountEnabled": True,
            "lastSignInDateTime": "2024-01-15T10:30:00Z",
            "createdDateTime": "2024-01-01T00:00:00Z",
            "assignedLicenses": [
                {"skuId": "c7df2760-2c81-4ef7-b578-5b5392b571df"}  # Office 365 E5
            ],
            "signInActivity": {
                "lastSignInDateTime": "2024-01-15T10:30:00Z",
                "lastNonInteractiveSignInDateTime": "2024-01-15T09:15:00Z"
            }
        }]
        for user in users:
            yield user
    
    async def list_applications(self):
        apps = [{
            "id": "87654321-dcba-hgfe-lkji-210987654321",
            "appId": "12345678-1234-1234-1234-123456789012",
            "displayName": "Custom Business App",
            "signInAudience": "AzureADMyOrg",
            "createdDateTime": "2024-01-01T00:00:00Z",
            "publisherDomain": "contoso.com",
            "requiredResourceAccess": [
                {
                    "resourceAppId": "00000003-0000-0000-c000-000000000000",  # Microsoft Graph
                    "resourceAccess": [
                        {"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope"}  # User.Read
                    ]
                }
            ],
            "keyCredentials": [],
            "passwordCredentials": []
        }]
        for app in apps:
            yield app
    
    async def list_conditional_access_policies(self):
        policies = [{
            "id": "11111111-2222-3333-4444-555555555555",
            "displayName": "Require MFA for All Users",
            "state": "enabled",
            "conditions": {
                "users": {
                    "includeUsers": ["All"],
                    "excludeUsers": []
                },
                "applications": {
                    "includeApplications": ["All"]
                },
                "locations": {
                    "includeLocations": ["All"],
                    "excludeLocations": ["AllTrusted"]
                }
            },
            "grantControls": {
                "operator": "OR",
                "builtInControls": ["mfa"]
            },
            "createdDateTime": "2024-01-01T00:00:00Z",
            "modifiedDateTime": "2024-01-15T10:00:00Z"
        }]
        for policy in policies:
            yield policy


class M365UserTable(ProviderSecurityTable):
    """Microsoft 365 users as a security table."""
    
    def __init__(self):
        super().__init__(
            name="m365_user", 
            description="Microsoft 365 user accounts with profile and security data",
            provider_name="m365",
            columns=SecuritySchema.IDENTITY_COLUMNS
        )
        
        # Add M365-specific columns
        m365_columns = [
            SecurityColumn("user_principal_name", ColumnType.TEXT, "User principal name", source_field="userPrincipalName"),
            SecurityColumn("given_name", ColumnType.TEXT, "First name", source_field="givenName"),
            SecurityColumn("surname", ColumnType.TEXT, "Last name", source_field="surname"),
            SecurityColumn("mail", ColumnType.TEXT, "Primary email", source_field="mail"),
            SecurityColumn("mobile_phone", ColumnType.TEXT, "Mobile phone", source_field="mobilePhone"),
            SecurityColumn("office_location", ColumnType.TEXT, "Office location", source_field="officeLocation"),
            SecurityColumn("job_title", ColumnType.TEXT, "Job title", source_field="jobTitle"),
            SecurityColumn("department", ColumnType.TEXT, "Department", source_field="department"),
            SecurityColumn("company_name", ColumnType.TEXT, "Company name", source_field="companyName"),
            SecurityColumn("country", ColumnType.TEXT, "Country", source_field="country"),
            SecurityColumn("usage_location", ColumnType.TEXT, "Usage location", source_field="usageLocation"),
            SecurityColumn("account_enabled", ColumnType.BOOLEAN, "Account enabled", source_field="accountEnabled"),
            SecurityColumn("last_sign_in", ColumnType.TIMESTAMP, "Last sign-in time", source_field="lastSignInDateTime"),
            SecurityColumn("assigned_licenses", ColumnType.JSON, "Assigned licenses", source_field="assignedLicenses"),
            SecurityColumn("sign_in_activity", ColumnType.JSON, "Sign-in activity", source_field="signInActivity"),
        ]
        
        self.columns.extend(m365_columns)
        self.column_map.update({col.name: col for col in m365_columns})
    
    async def fetch_from_api(self, ctx: QueryContext) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch users from Microsoft Graph API."""
        client = M365Client()
        
        try:
            graph_service = await client.get_client("graph")
            
            async for user in graph_service.list_users():
                # Transform M365 user to our schema
                transformed_user = self._transform_m365_user(user, await client.get_tenant_id())
                yield transformed_user
                
        except Exception as e:
            logger.error(f"Error fetching M365 users: {e}")
            raise
    
    def _transform_m365_user(self, m365_user: Dict[str, Any], tenant_id: str) -> Dict[str, Any]:
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
            "last_login": self._parse_m365_timestamp(m365_user.get("lastSignInDateTime")),
            "mfa_enabled": False,  # Would require additional Graph API call
            "locked": not m365_user.get("accountEnabled", True),
            "password_changed": None,  # Would require additional Graph API call
            "groups": [],  # Would require additional Graph API call
            "roles": [],   # Would require additional Graph API call
            "attributes": {
                "givenName": m365_user.get("givenName"),
                "surname": m365_user.get("surname"),
                "jobTitle": m365_user.get("jobTitle"),
                "department": m365_user.get("department"),
                "officeLocation": m365_user.get("officeLocation")
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
            "last_sign_in": self._parse_m365_timestamp(m365_user.get("lastSignInDateTime")),
            "assigned_licenses": m365_user.get("assignedLicenses", []),
            "sign_in_activity": m365_user.get("signInActivity", {})
        }
    
    def _parse_m365_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse M365 timestamp string."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except Exception:
            return None


class M365ApplicationTable(ProviderSecurityTable):
    """Microsoft 365 applications as a security table."""
    
    def __init__(self):
        app_columns = [
            SecurityColumn("app_id", ColumnType.TEXT, "Application ID", required=True, source_field="id"),
            SecurityColumn("client_app_id", ColumnType.TEXT, "Client application ID", source_field="appId"),
            SecurityColumn("display_name", ColumnType.TEXT, "Application name", source_field="displayName"),
            SecurityColumn("sign_in_audience", ColumnType.TEXT, "Sign-in audience", source_field="signInAudience"),
            SecurityColumn("publisher_domain", ColumnType.TEXT, "Publisher domain", source_field="publisherDomain"),
            SecurityColumn("required_resource_access", ColumnType.JSON, "Required resource access", source_field="requiredResourceAccess"),
            SecurityColumn("key_credentials", ColumnType.JSON, "Key credentials", source_field="keyCredentials"),
            SecurityColumn("password_credentials", ColumnType.JSON, "Password credentials", source_field="passwordCredentials"),
            SecurityColumn("has_credentials", ColumnType.BOOLEAN, "Has authentication credentials", transform="check_credentials"),
            SecurityColumn("permission_count", ColumnType.INTEGER, "Number of permissions", transform="count_permissions"),
        ]
        
        super().__init__(
            name="m365_application",
            description="Microsoft 365 applications and their configurations",
            provider_name="m365",
            columns=app_columns
        )
    
    async def fetch_from_api(self, ctx: QueryContext) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch applications from Microsoft Graph API."""
        client = M365Client()
        
        try:
            graph_service = await client.get_client("graph")
            
            async for app in graph_service.list_applications():
                # Add provider metadata
                app["provider"] = "m365"
                app["account_id"] = await client.get_tenant_id()
                app["region"] = "global"
                app["created_at"] = self._parse_m365_timestamp(app.get("createdDateTime"))
                app["updated_at"] = datetime.now()
                app["tags"] = {}
                app["metadata"] = {"m365_app_data": app}
                
                yield app
                
        except Exception as e:
            logger.error(f"Error fetching M365 applications: {e}")
            raise
    
    def check_credentials(self, app_data: Dict[str, Any]) -> bool:
        """Check if application has authentication credentials."""
        key_creds = app_data.get("keyCredentials", [])
        password_creds = app_data.get("passwordCredentials", [])
        return len(key_creds) > 0 or len(password_creds) > 0
    
    def count_permissions(self, app_data: Dict[str, Any]) -> int:
        """Count total permissions requested by application."""
        resource_access = app_data.get("requiredResourceAccess", [])
        total_permissions = 0
        
        for resource in resource_access:
            total_permissions += len(resource.get("resourceAccess", []))
        
        return total_permissions
    
    def _parse_m365_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse M365 timestamp string."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except Exception:
            return None


class M365ConditionalAccessTable(ProviderSecurityTable):
    """Microsoft 365 Conditional Access policies as a security table."""
    
    def __init__(self):
        ca_columns = [
            SecurityColumn("policy_id", ColumnType.TEXT, "Policy ID", required=True, source_field="id"),
            SecurityColumn("display_name", ColumnType.TEXT, "Policy name", source_field="displayName"),
            SecurityColumn("state", ColumnType.TEXT, "Policy state", source_field="state"),
            SecurityColumn("conditions", ColumnType.JSON, "Policy conditions", source_field="conditions"),
            SecurityColumn("grant_controls", ColumnType.JSON, "Grant controls", source_field="grantControls"),
            SecurityColumn("session_controls", ColumnType.JSON, "Session controls", source_field="sessionControls"),
            SecurityColumn("modified_date", ColumnType.TIMESTAMP, "Last modified", source_field="modifiedDateTime"),
            SecurityColumn("includes_all_users", ColumnType.BOOLEAN, "Includes all users", transform="check_all_users"),
            SecurityColumn("requires_mfa", ColumnType.BOOLEAN, "Requires MFA", transform="check_mfa_requirement"),
            SecurityColumn("applies_to_all_apps", ColumnType.BOOLEAN, "Applies to all applications", transform="check_all_apps"),
        ]
        
        super().__init__(
            name="m365_conditional_access_policy",
            description="Microsoft 365 Conditional Access policies",
            provider_name="m365",
            columns=ca_columns
        )
    
    async def fetch_from_api(self, ctx: QueryContext) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch Conditional Access policies from Microsoft Graph API."""
        client = M365Client()
        
        try:
            graph_service = await client.get_client("graph")
            
            async for policy in graph_service.list_conditional_access_policies():
                # Add provider metadata
                policy["provider"] = "m365"
                policy["account_id"] = await client.get_tenant_id()
                policy["region"] = "global"
                policy["created_at"] = self._parse_m365_timestamp(policy.get("createdDateTime"))
                policy["updated_at"] = self._parse_m365_timestamp(policy.get("modifiedDateTime"))
                policy["tags"] = {}
                policy["metadata"] = {"m365_ca_policy_data": policy}
                
                yield policy
                
        except Exception as e:
            logger.error(f"Error fetching M365 Conditional Access policies: {e}")
            raise
    
    def check_all_users(self, policy_data: Dict[str, Any]) -> bool:
        """Check if policy applies to all users."""
        conditions = policy_data.get("conditions", {})
        users = conditions.get("users", {})
        include_users = users.get("includeUsers", [])
        return "All" in include_users
    
    def check_mfa_requirement(self, policy_data: Dict[str, Any]) -> bool:
        """Check if policy requires MFA."""
        grant_controls = policy_data.get("grantControls", {})
        built_in_controls = grant_controls.get("builtInControls", [])
        return "mfa" in built_in_controls
    
    def check_all_apps(self, policy_data: Dict[str, Any]) -> bool:
        """Check if policy applies to all applications."""
        conditions = policy_data.get("conditions", {})
        applications = conditions.get("applications", {})
        include_apps = applications.get("includeApplications", [])
        return "All" in include_apps
    
    def _parse_m365_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse M365 timestamp string."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except Exception:
            return None


def register_m365_tables():
    """Register all Microsoft 365 tables with the query engine."""
    register_table(M365UserTable(), aliases=['m365_users', 'office365_users'])
    register_table(M365ApplicationTable(), aliases=['m365_apps', 'azure_ad_apps'])
    register_table(M365ConditionalAccessTable(), aliases=['m365_ca', 'conditional_access'])
