"""
Okta provider table implementations.

Exposes Okta identity resources as SQL tables.
"""

import asyncio
from typing import AsyncGenerator, Dict, Any, List, Optional
from datetime import datetime
import logging

from ...query.table import ProviderSecurityTable, QueryContext  
from ...query.registry import register_table
from ...query.schema import SecurityColumn, ColumnType, SecuritySchema

# Mock Okta client for demonstration
class OktaClient:
    async def list_users(self, **params):
        # Mock user data
        users = [{
            "id": "00u1234567890abcdef",
            "status": "ACTIVE",
            "created": "2024-01-01T00:00:00.000Z",
            "lastUpdated": "2024-01-01T00:00:00.000Z",
            "lastLogin": "2024-01-01T12:00:00.000Z",
            "passwordChanged": "2024-01-01T00:00:00.000Z",
            "profile": {
                "login": "john.doe@example.com",
                "firstName": "John",
                "lastName": "Doe",
                "email": "john.doe@example.com",
                "mobilePhone": "+1-555-555-5555"
            }
        }]
        for user in users:
            yield user
    
    async def list_applications(self):
        apps = [{
            "id": "0oa1234567890abcdef",
            "name": "example_saml_app",
            "label": "Example SAML App",
            "status": "ACTIVE",
            "created": "2024-01-01T00:00:00.000Z",
            "lastUpdated": "2024-01-01T00:00:00.000Z",
            "signOnMode": "SAML_2_0"
        }]
        for app in apps:
            yield app
    
    async def list_groups(self):
        groups = [{
            "id": "00g1234567890abcdef",
            "created": "2024-01-01T00:00:00.000Z",
            "lastUpdated": "2024-01-01T00:00:00.000Z",
            "profile": {
                "name": "Everyone",
                "description": "All users in the organization"
            },
            "type": "BUILT_IN"
        }]
        for group in groups:
            yield group

logger = logging.getLogger(__name__)


class OktaUserTable(ProviderSecurityTable):
    """Okta users as a security table."""
    
    def __init__(self):
        super().__init__(
            name="okta_user",
            description="Okta user accounts with profile and authentication data",
            provider_name="okta",
            columns=SecuritySchema.IDENTITY_COLUMNS
        )
        
        # Add Okta-specific columns
        okta_columns = [
            SecurityColumn("login", ColumnType.TEXT, "Okta login username", source_field="profile.login"),
            SecurityColumn("first_name", ColumnType.TEXT, "First name", source_field="profile.firstName"),
            SecurityColumn("last_name", ColumnType.TEXT, "Last name", source_field="profile.lastName"),
            SecurityColumn("mobile_phone", ColumnType.TEXT, "Mobile phone", source_field="profile.mobilePhone"),
            SecurityColumn("activated", ColumnType.TIMESTAMP, "Account activation date", source_field="activated"),
            SecurityColumn("status_changed", ColumnType.TIMESTAMP, "Status change date", source_field="statusChanged"),
            SecurityColumn("password_changed", ColumnType.TIMESTAMP, "Password change date", source_field="passwordChanged"),
            SecurityColumn("credentials", ColumnType.JSON, "Credential information", source_field="credentials"),
            SecurityColumn("profile", ColumnType.JSON, "Full user profile", source_field="profile"),
        ]
        
        self.columns.extend(okta_columns)
        self.column_map.update({col.name: col for col in okta_columns})
    
    async def fetch_from_api(self, ctx: QueryContext) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch users from Okta API."""
        client = OktaClient()
        
        try:
            # Build query parameters from context filters
            params = self._build_okta_query_params(ctx)
            
            # Fetch users with pagination
            async for user in client.list_users(**params):
                # Transform Okta user to our schema
                transformed_user = self._transform_okta_user(user)
                yield transformed_user
                
        except Exception as e:
            logger.error(f"Error fetching Okta users: {e}")
            raise
    
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
            "password_changed": self._parse_okta_timestamp(okta_user.get("passwordChanged")),
            "groups": [],  # Would require additional API call
            "roles": [],   # Would require additional API call
            "attributes": profile,
            "tags": {},
            "metadata": {
                "activated": okta_user.get("activated"),
                "status_changed": okta_user.get("statusChanged"),
                "credentials": okta_user.get("credentials"),
                "okta_profile": profile,
            }
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
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
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
            SecurityColumn("app_id", ColumnType.TEXT, "Application ID", required=True, source_field="id"),
            SecurityColumn("app_name", ColumnType.TEXT, "Application name", source_field="name"),
            SecurityColumn("label", ColumnType.TEXT, "Application label", source_field="label"),
            SecurityColumn("app_status", ColumnType.STATUS, "Application status", source_field="status"),
            SecurityColumn("sign_on_mode", ColumnType.TEXT, "Sign-on mode", source_field="signOnMode"),
            SecurityColumn("features", ColumnType.JSON, "Enabled features", source_field="features"),
            SecurityColumn("settings", ColumnType.JSON, "Application settings", source_field="settings"),
            SecurityColumn("visibility", ColumnType.JSON, "Visibility settings", source_field="visibility"),
            SecurityColumn("accessibility", ColumnType.JSON, "Accessibility settings", source_field="accessibility"),
            SecurityColumn("licensing", ColumnType.JSON, "Licensing info", source_field="licensing"),
            SecurityColumn("assigned_users", ColumnType.INTEGER, "Number of assigned users", transform="count_assigned_users"),
            SecurityColumn("assigned_groups", ColumnType.INTEGER, "Number of assigned groups", transform="count_assigned_groups"),
        ]
        
        super().__init__(
            name="okta_application", 
            description="Okta applications and their configurations",
            provider_name="okta",
            columns=app_columns
        )
    
    async def fetch_from_api(self, ctx: QueryContext) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch applications from Okta API."""
        client = OktaClient()
        
        try:
            async for app in client.list_applications():
                # Add provider metadata
                app["provider"] = "okta"
                app["account_id"] = self._get_okta_domain()
                app["region"] = "global"
                app["created_at"] = self._parse_okta_timestamp(app.get("created"))
                app["updated_at"] = self._parse_okta_timestamp(app.get("lastUpdated"))
                app["tags"] = {}
                app["metadata"] = {"okta_app_data": app}
                
                yield app
                
        except Exception as e:
            logger.error(f"Error fetching Okta applications: {e}")
            raise
    
    def _get_okta_domain(self) -> str:
        """Get Okta domain."""
        return "example.okta.com"
    
    def _parse_okta_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse Okta timestamp."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
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
            SecurityColumn("group_id", ColumnType.TEXT, "Group ID", required=True, source_field="id"),
            SecurityColumn("group_name", ColumnType.TEXT, "Group name", source_field="profile.name"),
            SecurityColumn("description", ColumnType.TEXT, "Group description", source_field="profile.description"),
            SecurityColumn("group_type", ColumnType.TEXT, "Group type", source_field="type"),
            SecurityColumn("profile", ColumnType.JSON, "Group profile", source_field="profile"),
            SecurityColumn("member_count", ColumnType.INTEGER, "Number of members", transform="count_members"),
        ]
        
        super().__init__(
            name="okta_group",
            description="Okta groups and their memberships", 
            provider_name="okta",
            columns=group_columns
        )
    
    async def fetch_from_api(self, ctx: QueryContext) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch groups from Okta API."""
        client = OktaClient()
        
        try:
            async for group in client.list_groups():
                # Add provider metadata
                group["provider"] = "okta"
                group["account_id"] = self._get_okta_domain()
                group["region"] = "global"
                group["created_at"] = self._parse_okta_timestamp(group.get("created"))
                group["updated_at"] = self._parse_okta_timestamp(group.get("lastUpdated"))
                group["tags"] = {}
                group["metadata"] = {"okta_group_data": group}
                
                yield group
                
        except Exception as e:
            logger.error(f"Error fetching Okta groups: {e}")
            raise
    
    def _get_okta_domain(self) -> str:
        """Get Okta domain.""" 
        return "example.okta.com"
    
    def _parse_okta_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse Okta timestamp."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except Exception:
            return None
    
    def count_members(self, group_data: Dict[str, Any]) -> int:
        """Count group members (would require additional API call)."""
        return 0


def register_okta_tables():
    """Register all Okta tables with the query engine."""
    register_table(OktaUserTable(), aliases=['okta_users', 'users'])
    register_table(OktaApplicationTable(), aliases=['okta_apps', 'applications'])
    register_table(OktaGroupTable(), aliases=['okta_groups', 'groups'])
