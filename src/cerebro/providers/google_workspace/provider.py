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
        """Discover Google Workspace resources."""
        # TODO: Implement Google Workspace resource discovery
        return
        yield  # Make this an async generator
    
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
        # TODO: Implement Google Workspace configuration collection
        return ConfigurationSnapshot(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={}
        )
    
    async def discover_iam_edges(
        self,
        resource: Optional[ResourceInfo] = None
    ) -> AsyncGenerator[IamPermission, None]:
        """Discover Google Workspace permissions."""
        # TODO: Implement Google Workspace permission discovery
        return
        yield  # Make this an async generator
