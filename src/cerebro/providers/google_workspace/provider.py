"""Google Workspace provider implementation."""

from typing import Any, Dict, List, Optional, AsyncGenerator
from datetime import datetime
import logging

from ..base import (
    BaseProvider, ResourceInfo, PrincipalInfo, 
    ConfigurationSnapshot, IamPermission, ProviderError
)

logger = logging.getLogger(__name__)


class GoogleWorkspaceProvider(BaseProvider):
    """Google Workspace provider for collecting users and groups."""
    
    def __init__(self, account_id, domain: str, credentials_path: str = None, **kwargs):
        """Initialize Google Workspace provider."""
        super().__init__(account_id, **kwargs)
        self.domain = domain
        self.credentials_path = credentials_path
        self.service = None
    
    @property
    def name(self) -> str:
        """Get provider name."""
        return "google_workspace"
    
    async def authenticate(self) -> bool:
        """Authenticate with Google Workspace."""
        try:
            # Import Google API client libraries
            from google.auth.transport.requests import Request
            from google.oauth2 import service_account
            from googleapiclient.discovery import build
            
            # Load service account credentials
            if not hasattr(self, 'credentials_path') or not self.credentials_path:
                logger.error("Google Workspace credentials not configured")
                return False
                
            credentials = service_account.Credentials.from_service_account_file(
                self.credentials_path,
                scopes=[
                    'https://www.googleapis.com/auth/admin.directory.user.readonly',
                    'https://www.googleapis.com/auth/admin.directory.group.readonly',
                    'https://www.googleapis.com/auth/admin.directory.orgunit.readonly'
                ]
            )
            
            # Test authentication by listing users (with limit)
            service = build('admin', 'directory_v1', credentials=credentials)
            users_result = service.users().list(domain=self.domain, maxResults=1).execute()
            
            self.service = service
            logger.info(f"Successfully authenticated with Google Workspace domain: {self.domain}")
            return True
            
        except Exception as e:
            logger.error(f"Google Workspace authentication failed: {e}")
            return False
    
    async def discover_resources(
        self,
        resource_types: Optional[List[str]] = None
    ) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Google Workspace resources (org units, groups as resources)."""
        if not self.service:
            logger.error("Not authenticated with Google Workspace")
            return

        try:
            # Discover organizational units as resources
            orgunits_result = self.service.orgunits().list(customerId='my_customer').execute()

            for orgunit in orgunits_result.get('organizationUnits', []):
                yield ResourceInfo(
                    resource_id=orgunit['orgUnitId'],
                    resource_type="google_workspace.orgunit",
                    name=orgunit.get('name', ''),
                    region=self.domain,  # Use domain as region identifier
                    tags={},
                    created_at=datetime.utcnow(),  # API doesn't provide creation time
                    account_id=self.account_id,
                    external_id=orgunit['orgUnitPath'],
                    provider=self.name,
                    metadata={
                        'path': orgunit['orgUnitPath'],
                        'parent_path': orgunit.get('parentOrgUnitPath', ''),
                        'description': orgunit.get('description', ''),
                        'block_inheritance': orgunit.get('blockInheritance', False)
                    }
                )

            # Discover groups as resources too (they can have resources/permissions assigned)
            page_token = None
            while True:
                if page_token:
                    groups_result = self.service.groups().list(
                        domain=self.domain,
                        maxResults=100,
                        pageToken=page_token
                    ).execute()
                else:
                    groups_result = self.service.groups().list(
                        domain=self.domain,
                        maxResults=100
                    ).execute()

                groups = groups_result.get('groups', [])
                for group in groups:
                    yield ResourceInfo(
                        resource_id=group['id'],
                        resource_type="google_workspace.group",
                        name=group.get('name', ''),
                        region=self.domain,
                        tags={},
                        created_at=datetime.utcnow(),
                        account_id=self.account_id,
                        external_id=group['email'],
                        provider=self.name,
                        metadata={
                            'email': group['email'],
                            'description': group.get('description', ''),
                            'members_count': group.get('directMembersCount', 0)
                        }
                    )

                page_token = groups_result.get('nextPageToken')
                if not page_token:
                    break

        except Exception as e:
            logger.error(f"Error discovering Google Workspace resources: {e}")
            return
    
    async def discover_principals(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover Google Workspace principals."""
        if not self.service:
            logger.error("Not authenticated with Google Workspace")
            return
            
        try:
            # Discover users
            async for user in self._discover_users():
                yield user
                
            # Discover groups
            async for group in self._discover_groups():
                yield group
                
        except Exception as e:
            logger.error(f"Error discovering Google Workspace principals: {e}")
            
    async def _discover_users(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover Google Workspace users."""
        try:
            page_token = None
            while True:
                if page_token:
                    users_result = self.service.users().list(
                        domain=self.domain,
                        maxResults=100,
                        pageToken=page_token
                    ).execute()
                else:
                    users_result = self.service.users().list(
                        domain=self.domain,
                        maxResults=100
                    ).execute()
                
                users = users_result.get('users', [])
                for user in users:
                    yield PrincipalInfo(
                        external_id=user['id'],
                        principal_type='user',
                        name=user.get('name', {}).get('fullName', ''),
                        email=user.get('primaryEmail', ''),
                        provider=self.name,
                        metadata={
                            'suspended': user.get('suspended', False),
                            'created_time': user.get('creationTime'),
                            'last_login': user.get('lastLoginTime'),
                            'org_unit_path': user.get('orgUnitPath', ''),
                            'is_admin': user.get('isAdmin', False)
                        }
                    )
                
                page_token = users_result.get('nextPageToken')
                if not page_token:
                    break
                    
        except Exception as e:
            logger.error(f"Error discovering Google Workspace users: {e}")
    
    async def _discover_groups(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover Google Workspace groups."""
        try:
            page_token = None
            while True:
                if page_token:
                    groups_result = self.service.groups().list(
                        domain=self.domain,
                        maxResults=100,
                        pageToken=page_token
                    ).execute()
                else:
                    groups_result = self.service.groups().list(
                        domain=self.domain,
                        maxResults=100
                    ).execute()
                
                groups = groups_result.get('groups', [])
                for group in groups:
                    yield PrincipalInfo(
                        external_id=group['id'],
                        principal_type='group',
                        name=group.get('name', ''),
                        email=group.get('email', ''),
                        provider=self.name,
                        metadata={
                            'description': group.get('description', ''),
                            'members_count': group.get('directMembersCount', 0)
                        }
                    )
                
                page_token = groups_result.get('nextPageToken')
                if not page_token:
                    break
                    
        except Exception as e:
            logger.error(f"Error discovering Google Workspace groups: {e}")
    
    async def get_resource_configuration(
        self,
        resource: ResourceInfo
    ) -> ConfigurationSnapshot:
        """Get Google Workspace resource configuration."""
        if not self.service:
            return ConfigurationSnapshot(
                resource_external_id=resource.external_id,
                captured_at=datetime.utcnow(),
                normalized_config={}
            )

        try:
            config = {}

            if resource.resource_type == "google_workspace.orgunit":
                # Get detailed org unit information
                orgunit_result = self.service.orgunits().get(
                    customerId='my_customer',
                    orgUnitPath=resource.external_id
                ).execute()

                config = {
                    "orgUnitId": orgunit_result.get('orgUnitId'),
                    "name": orgunit_result.get('name'),
                    "orgUnitPath": orgunit_result.get('orgUnitPath'),
                    "parentOrgUnitPath": orgunit_result.get('parentOrgUnitPath'),
                    "description": orgunit_result.get('description', ''),
                    "blockInheritance": orgunit_result.get('blockInheritance', False),
                    "etag": orgunit_result.get('etag')
                }

            elif resource.resource_type == "google_workspace.group":
                # Get detailed group information
                group_result = self.service.groups().get(groupKey=resource.external_id).execute()

                # Get group members
                members_result = self.service.members().list(groupKey=resource.external_id).execute()

                config = {
                    "id": group_result.get('id'),
                    "email": group_result.get('email'),
                    "name": group_result.get('name'),
                    "description": group_result.get('description', ''),
                    "directMembersCount": group_result.get('directMembersCount', 0),
                    "members": [
                        {
                            "email": member.get('email'),
                            "role": member.get('role'),
                            "type": member.get('type'),
                            "status": member.get('status')
                        }
                        for member in members_result.get('members', [])
                    ],
                    "adminCreated": group_result.get('adminCreated', False),
                    "etag": group_result.get('etag')
                }

            return ConfigurationSnapshot(
                resource_external_id=resource.external_id,
                captured_at=datetime.utcnow(),
                normalized_config=config
            )

        except Exception as e:
            logger.error(f"Failed to get Google Workspace resource configuration: {e}")
            return ConfigurationSnapshot(
                resource_external_id=resource.external_id,
                captured_at=datetime.utcnow(),
                normalized_config={}
            )
    
    async def discover_iam_edges(
        self,
        resource: Optional[ResourceInfo] = None
    ) -> AsyncGenerator[IamPermission, None]:
        """Discover Google Workspace permissions (group memberships and admin roles)."""
        if not self.service:
            logger.error("Not authenticated with Google Workspace")
            return

        try:
            # Get group memberships as permissions
            page_token = None
            while True:
                if page_token:
                    groups_result = self.service.groups().list(
                        domain=self.domain,
                        maxResults=100,
                        pageToken=page_token
                    ).execute()
                else:
                    groups_result = self.service.groups().list(
                        domain=self.domain,
                        maxResults=100
                    ).execute()

                groups = groups_result.get('groups', [])
                for group in groups:
                    # Get group members
                    try:
                        members_result = self.service.members().list(
                            groupKey=group['email']
                        ).execute()

                        for member in members_result.get('members', []):
                            # Map member type and role to permissions
                            permission_type = self._map_group_role_to_permission(
                                member.get('role', 'MEMBER'),
                                group.get('name', '')
                            )

                            yield IamPermission(
                                principal_external_id=member.get('email', ''),
                                resource_external_id=group['email'],
                                permission=permission_type,
                                via=f"group_membership:{group['email']}"
                            )

                    except Exception as e:
                        logger.warning(f"Failed to get members for group {group['email']}: {e}")
                        continue

                page_token = groups_result.get('nextPageToken')
                if not page_token:
                    break

            # Get admin role assignments
            try:
                admin_users = self.service.users().list(
                    domain=self.domain,
                    query="isAdmin=true",
                    maxResults=500
                ).execute()

                for admin_user in admin_users.get('users', []):
                    yield IamPermission(
                        principal_external_id=admin_user.get('primaryEmail', ''),
                        resource_external_id=f"domain:{self.domain}",
                        permission="admin",
                        via="super_admin_role"
                    )

            except Exception as e:
                logger.warning(f"Failed to get admin users: {e}")

        except Exception as e:
            logger.error(f"Failed to discover Google Workspace IAM edges: {e}")
            return

    def _map_group_role_to_permission(self, role: str, group_name: str) -> str:
        """Map Google Workspace group role to permission type."""
        role_mapping = {
            "OWNER": "group.owner",
            "MANAGER": "group.manager",
            "MEMBER": "group.member"
        }

        base_permission = role_mapping.get(role, "group.member")

        # Add context based on group name patterns
        if "admin" in group_name.lower():
            return f"{base_permission}.admin_group"
        elif "security" in group_name.lower():
            return f"{base_permission}.security_group"
        else:
            return base_permission
