"""
Enhanced GCP provider implementation with comprehensive Google Cloud and Google Workspace support.

Based on GAM patterns and Google Cloud best practices.
"""

import json
import asyncio
from typing import Any, Dict, List, Optional, AsyncGenerator, Union
from datetime import datetime
from pathlib import Path
import logging

from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.cloud import compute_v1, storage, resourcemanager_v3, iam_v1
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from cerebro.core.config import settings
from ..base import (
    BaseProvider, ResourceInfo, PrincipalInfo, 
    ConfigurationSnapshot, IamPermission, ProviderError
)

logger = logging.getLogger(__name__)


class EnhancedGCPProvider(BaseProvider):
    """
    Enhanced GCP provider with comprehensive Google Cloud and Google Workspace support.
    
    Features:
    - Service account authentication with domain-wide delegation
    - Google Cloud resource discovery (compute, storage, IAM, etc.)
    - Google Workspace resource discovery (users, groups, org units, etc.)
    - Comprehensive IAM permission mapping
    - Configuration collection for security analysis
    
    Based on GAM (Google Apps Manager) patterns for authentication and API usage.
    """
    
    def __init__(
        self, 
        account_id: str, 
        project_id: str,
        service_account_file: Optional[str] = None,
        workspace_domain: Optional[str] = None,
        delegate_user: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize enhanced GCP provider.
        
        Args:
            account_id: Account identifier
            project_id: GCP project ID
            service_account_file: Path to service account JSON file
            workspace_domain: Google Workspace domain (if applicable)
            delegate_user: User to impersonate for workspace operations
        """
        super().__init__(account_id, **kwargs)
        self.project_id = project_id
        self.workspace_domain = workspace_domain
        self.delegate_user = delegate_user
        
        # Service account configuration
        self.service_account_file = service_account_file or getattr(settings, 'gcp_service_account_file', None)
        
        # API clients (initialized during authentication)
        self._credentials = None
        self._workspace_credentials = None
        self._compute_client = None
        self._storage_client = None
        self._iam_client = None
        self._resource_manager_client = None
        
        # Google Workspace API services
        self._admin_service = None
        self._reports_service = None
        self._directory_service = None
        
        # Required scopes for comprehensive access
        self.cloud_scopes = [
            'https://www.googleapis.com/auth/cloud-platform',
            'https://www.googleapis.com/auth/compute.readonly',
            'https://www.googleapis.com/auth/devstorage.readonly',
            'https://www.googleapis.com/auth/iam.readonly'
        ]
        
        self.workspace_scopes = [
            'https://www.googleapis.com/auth/admin.directory.user.readonly',
            'https://www.googleapis.com/auth/admin.directory.group.readonly',
            'https://www.googleapis.com/auth/admin.directory.orgunit.readonly',
            'https://www.googleapis.com/auth/admin.directory.domain.readonly',
            'https://www.googleapis.com/auth/admin.reports.audit.readonly',
            'https://www.googleapis.com/auth/admin.reports.usage.readonly',
            'https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly',
            'https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly'
        ]
    
    @property
    def name(self) -> str:
        """Get provider name."""
        return "gcp"
    
    async def authenticate(self) -> bool:
        """
        Authenticate with Google Cloud and Google Workspace APIs.
        
        Uses service account with domain-wide delegation pattern from GAM.
        """
        try:
            if not self.service_account_file or not Path(self.service_account_file).exists():
                raise ProviderError(f"Service account file not found: {self.service_account_file}")
            
            # Load service account credentials
            with open(self.service_account_file, 'r') as f:
                service_account_info = json.load(f)
            
            # Create credentials for Google Cloud APIs
            self._credentials = service_account.Credentials.from_service_account_file(
                self.service_account_file,
                scopes=self.cloud_scopes
            )
            
            # Test Google Cloud authentication
            await self._test_cloud_auth()
            logger.info(f"Successfully authenticated with GCP project: {self.project_id}")
            
            # If workspace domain is configured, set up domain-wide delegation
            if self.workspace_domain and self.delegate_user:
                await self._setup_workspace_auth()
                logger.info(f"Successfully set up Google Workspace authentication for domain: {self.workspace_domain}")
            
            return True
            
        except FileNotFoundError:
            logger.error(f"Service account file not found: {self.service_account_file}")
            return False
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in service account file: {self.service_account_file}")
            return False
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return False
    
    async def _test_cloud_auth(self):
        """Test Google Cloud authentication."""
        try:
            # Test with a simple compute API call
            self._compute_client = compute_v1.InstancesClient(credentials=self._credentials)
            
            # Test with resource manager to verify project access
            self._resource_manager_client = resourcemanager_v3.ProjectsClient(credentials=self._credentials)
            request = resourcemanager_v3.GetProjectRequest(name=f"projects/{self.project_id}")
            await asyncio.get_event_loop().run_in_executor(
                None, self._resource_manager_client.get_project, request
            )
        except Exception as e:
            raise ProviderError(f"Google Cloud authentication test failed: {e}")
    
    async def _setup_workspace_auth(self):
        """Set up Google Workspace authentication with domain-wide delegation."""
        try:
            # Create delegated credentials for workspace APIs
            self._workspace_credentials = self._credentials.with_subject(self.delegate_user)
            
            # Initialize workspace API services
            loop = asyncio.get_event_loop()
            
            # Admin SDK Directory API
            self._admin_service = await loop.run_in_executor(
                None,
                lambda: build('admin', 'directory_v1', credentials=self._workspace_credentials)
            )
            
            # Admin SDK Reports API
            self._reports_service = await loop.run_in_executor(
                None,
                lambda: build('admin', 'reports_v1', credentials=self._workspace_credentials)
            )
            
            # Test workspace authentication
            await loop.run_in_executor(
                None,
                lambda: self._admin_service.users().list(domain=self.workspace_domain, maxResults=1).execute()
            )
            
        except Exception as e:
            raise ProviderError(f"Google Workspace authentication setup failed: {e}")
    
    async def discover_resources(
        self, 
        resource_types: Optional[List[str]] = None
    ) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Google Cloud and Google Workspace resources."""
        if not self._credentials:
            await self.authenticate()
        
        # Google Cloud resources
        if not resource_types or any(rt.startswith('gcp.') for rt in resource_types):
            async for resource in self._discover_cloud_resources(resource_types):
                yield resource
        
        # Google Workspace resources  
        if self._admin_service and (not resource_types or any(rt.startswith('workspace.') for rt in resource_types)):
            async for resource in self._discover_workspace_resources(resource_types):
                yield resource
    
    async def _discover_cloud_resources(
        self, 
        resource_types: Optional[List[str]] = None
    ) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Google Cloud resources."""
        
        # Compute instances
        if not resource_types or 'gcp.compute.instance' in resource_types:
            async for instance in self._discover_compute_instances():
                yield instance
        
        # Storage buckets
        if not resource_types or 'gcp.storage.bucket' in resource_types:
            async for bucket in self._discover_storage_buckets():
                yield bucket
        
        # IAM service accounts
        if not resource_types or 'gcp.iam.service_account' in resource_types:
            async for sa in self._discover_service_accounts():
                yield sa
        
        # Additional resources can be added here
        # - GKE clusters
        # - Cloud SQL instances
        # - App Engine services
        # - Cloud Functions
        # - Pub/Sub topics
        # etc.
    
    async def _discover_compute_instances(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover GCP Compute Engine instances."""
        try:
            if not self._compute_client:
                self._compute_client = compute_v1.InstancesClient(credentials=self._credentials)
            
            loop = asyncio.get_event_loop()
            request = compute_v1.AggregatedListInstancesRequest(project=self.project_id)
            
            page_result = await loop.run_in_executor(
                None, self._compute_client.aggregated_list, request
            )
            
            for zone, response in page_result:
                if hasattr(response, 'instances') and response.instances:
                    for instance in response.instances:
                        # Extract network information
                        network_interfaces = []
                        for ni in instance.network_interfaces:
                            interface_info = {
                                "network": ni.network,
                                "subnetwork": ni.subnetwork,
                                "internal_ip": ni.network_i_p,
                                "external_ips": [ac.nat_i_p for ac in ni.access_configs if ac.nat_i_p]
                            }
                            network_interfaces.append(interface_info)
                        
                        # Extract service accounts
                        service_accounts = []
                        for sa in instance.service_accounts:
                            sa_info = {
                                "email": sa.email,
                                "scopes": list(sa.scopes)
                            }
                            service_accounts.append(sa_info)
                        
                        yield ResourceInfo(
                            external_id=f"projects/{self.project_id}/zones/{zone.split('/')[-1]}/instances/{instance.name}",
                            name=instance.name,
                            resource_type="gcp.compute.instance",
                            region=zone.split('/')[-1] if zone else "unknown",
                            tags=dict(instance.labels) if instance.labels else {},
                            created_at=self._parse_gcp_timestamp(instance.creation_timestamp),
                            account_id=self.account_id,
                            metadata={
                                "machine_type": instance.machine_type,
                                "status": instance.status,
                                "zone": zone,
                                "network_interfaces": network_interfaces,
                                "service_accounts": service_accounts,
                                "disk_count": len(instance.disks),
                                "tags": list(instance.tags.items) if instance.tags and instance.tags.items else [],
                                "can_ip_forward": instance.can_ip_forward,
                                "scheduling": {
                                    "preemptible": instance.scheduling.preemptible if instance.scheduling else False
                                }
                            }
                        )
        except Exception as e:
            logger.error(f"Failed to discover compute instances: {e}")
    
    async def _discover_storage_buckets(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover GCP Cloud Storage buckets."""
        try:
            if not self._storage_client:
                from google.cloud import storage
                self._storage_client = storage.Client(
                    credentials=self._credentials,
                    project=self.project_id
                )
            
            loop = asyncio.get_event_loop()
            buckets = await loop.run_in_executor(None, list, self._storage_client.list_buckets())
            
            for bucket in buckets:
                # Get bucket IAM policy
                iam_policy = await loop.run_in_executor(None, bucket.get_iam_policy)
                
                # Process IAM bindings
                iam_bindings = []
                for binding in iam_policy.bindings:
                    binding_info = {
                        "role": binding["role"],
                        "members": list(binding["members"]),
                        "condition": binding.get("condition")
                    }
                    iam_bindings.append(binding_info)
                
                # Check for public access
                is_public = any(
                    "allUsers" in binding["members"] or "allAuthenticatedUsers" in binding["members"]
                    for binding in iam_policy.bindings
                )
                
                yield ResourceInfo(
                    external_id=f"projects/{self.project_id}/buckets/{bucket.name}",
                    name=bucket.name,
                    resource_type="gcp.storage.bucket",
                    region=bucket.location,
                    tags={},
                    created_at=bucket.time_created,
                    account_id=self.account_id,
                    metadata={
                        "location": bucket.location,
                        "storage_class": bucket.storage_class,
                        "versioning_enabled": bucket.versioning_enabled,
                        "lifecycle_rules": list(bucket.lifecycle_rules),
                        "cors": list(bucket.cors),
                        "public_access_prevention": getattr(bucket, 'public_access_prevention', None),
                        "uniform_bucket_level_access": {
                            "enabled": bucket.iam_configuration.uniform_bucket_level_access_enabled
                        } if bucket.iam_configuration else {"enabled": False},
                        "iam_bindings": iam_bindings,
                        "is_public": is_public,
                        "size_bytes": bucket.size,
                        "object_count": bucket.object_count if hasattr(bucket, 'object_count') else None
                    }
                )
        except Exception as e:
            logger.error(f"Failed to discover storage buckets: {e}")
    
    async def _discover_service_accounts(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover GCP IAM service accounts."""
        try:
            if not self._iam_client:
                self._iam_client = iam_v1.IAMClient(credentials=self._credentials)
            
            loop = asyncio.get_event_loop()
            
            # List service accounts
            request = iam_v1.ListServiceAccountsRequest(
                name=f"projects/{self.project_id}"
            )
            
            response = await loop.run_in_executor(
                None, self._iam_client.list_service_accounts, request
            )
            
            for service_account in response.accounts:
                # Get service account keys
                keys_request = iam_v1.ListServiceAccountKeysRequest(
                    name=service_account.name
                )
                keys_response = await loop.run_in_executor(
                    None, self._iam_client.list_service_account_keys, keys_request
                )
                
                keys_info = []
                for key in keys_response.keys:
                    key_info = {
                        "name": key.name,
                        "key_type": key.key_type,
                        "key_algorithm": key.key_algorithm,
                        "valid_after_time": key.valid_after_time,
                        "valid_before_time": key.valid_before_time
                    }
                    keys_info.append(key_info)
                
                yield ResourceInfo(
                    external_id=service_account.name,
                    name=service_account.display_name or service_account.email,
                    resource_type="gcp.iam.service_account",
                    region="global",
                    tags={},
                    created_at=datetime.utcnow(),  # Service accounts don't have creation time in API
                    account_id=self.account_id,
                    metadata={
                        "email": service_account.email,
                        "unique_id": service_account.unique_id,
                        "project_id": service_account.project_id,
                        "description": service_account.description,
                        "disabled": service_account.disabled,
                        "oauth2_client_id": service_account.oauth2_client_id,
                        "keys": keys_info,
                        "key_count": len(keys_info)
                    }
                )
        except Exception as e:
            logger.error(f"Failed to discover service accounts: {e}")
    
    async def _discover_workspace_resources(
        self, 
        resource_types: Optional[List[str]] = None
    ) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Google Workspace resources using Admin SDK APIs."""
        
        # Organizational units
        if not resource_types or 'workspace.orgunit' in resource_types:
            async for ou in self._discover_org_units():
                yield ou
        
        # Chrome OS devices
        if not resource_types or 'workspace.device.chromeos' in resource_types:
            async for device in self._discover_chromeos_devices():
                yield device
        
        # Domain information
        if not resource_types or 'workspace.domain' in resource_types:
            async for domain in self._discover_domains():
                yield domain
    
    async def _discover_org_units(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Google Workspace organizational units."""
        try:
            if not self._admin_service:
                return
            
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._admin_service.orgunits().list(
                    customerId='my_customer',
                    type='all'
                ).execute()
            )
            
            for orgunit in result.get('organizationUnits', []):
                yield ResourceInfo(
                    external_id=orgunit['orgUnitId'],
                    name=orgunit['name'],
                    resource_type="workspace.orgunit",
                    region="global",
                    tags={},
                    created_at=datetime.utcnow(),
                    account_id=self.account_id,
                    metadata={
                        "org_unit_path": orgunit['orgUnitPath'],
                        "parent_org_unit_id": orgunit.get('parentOrgUnitId'),
                        "parent_org_unit_path": orgunit.get('parentOrgUnitPath'),
                        "description": orgunit.get('description'),
                        "block_inheritance": orgunit.get('blockInheritance', False)
                    }
                )
        except Exception as e:
            logger.error(f"Failed to discover organizational units: {e}")
    
    async def _discover_chromeos_devices(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Google Workspace Chrome OS devices."""
        try:
            if not self._admin_service:
                return
            
            loop = asyncio.get_event_loop()
            
            # Use pagination for large device lists
            page_token = None
            while True:
                request_params = {
                    'customerId': 'my_customer',
                    'maxResults': 100,
                    'projection': 'FULL'
                }
                if page_token:
                    request_params['pageToken'] = page_token
                
                result = await loop.run_in_executor(
                    None,
                    lambda: self._admin_service.chromeosdevices().list(**request_params).execute()
                )
                
                for device in result.get('chromeosdevices', []):
                    # Extract network information
                    recent_users = device.get('recentUsers', [])
                    active_time_ranges = device.get('activeTimeRanges', [])
                    
                    yield ResourceInfo(
                        external_id=device['deviceId'],
                        name=device.get('annotatedUser', device.get('deviceId')),
                        resource_type="workspace.device.chromeos",
                        region="global",
                        tags={
                            'model': device.get('model', ''),
                            'platform_version': device.get('platformVersion', ''),
                            'status': device.get('status', '')
                        },
                        created_at=self._parse_gcp_timestamp(device.get('firstEnrollmentTime')),
                        account_id=self.account_id,
                        metadata={
                            "serial_number": device.get('serialNumber'),
                            "annotated_location": device.get('annotatedLocation'),
                            "annotated_user": device.get('annotatedUser'),
                            "auto_update_expiration": device.get('autoUpdateExpiration'),
                            "boot_mode": device.get('bootMode'),
                            "ethernet_mac_address": device.get('ethernetMacAddress'),
                            "firmware_version": device.get('firmwareVersion'),
                            "last_enrollment_time": device.get('lastEnrollmentTime'),
                            "last_sync": device.get('lastSync'),
                            "mac_address": device.get('macAddress'),
                            "meid": device.get('meid'),
                            "model": device.get('model'),
                            "notes": device.get('notes'),
                            "org_unit_path": device.get('orgUnitPath'),
                            "os_version": device.get('osVersion'),
                            "platform_version": device.get('platformVersion'),
                            "status": device.get('status'),
                            "support_end_date": device.get('supportEndDate'),
                            "will_auto_renew": device.get('willAutoRenew'),
                            "recent_users": recent_users,
                            "active_time_ranges": active_time_ranges
                        }
                    )
                
                # Check for next page
                page_token = result.get('nextPageToken')
                if not page_token:
                    break
                    
        except Exception as e:
            logger.error(f"Failed to discover Chrome OS devices: {e}")
    
    async def _discover_domains(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Google Workspace domains."""
        try:
            if not self._admin_service:
                return
            
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._admin_service.domains().list(customer='my_customer').execute()
            )
            
            for domain in result.get('domains', []):
                yield ResourceInfo(
                    external_id=domain['domainName'],
                    name=domain['domainName'],
                    resource_type="workspace.domain",
                    region="global",
                    tags={
                        'primary': str(domain.get('isPrimary', False)),
                        'verified': str(domain.get('verified', False))
                    },
                    created_at=self._parse_gcp_timestamp(domain.get('creationTime')),
                    account_id=self.account_id,
                    metadata={
                        "domain_name": domain['domainName'],
                        "is_primary": domain.get('isPrimary', False),
                        "verified": domain.get('verified', False),
                        "creation_time": domain.get('creationTime'),
                        "domain_aliases": domain.get('domainAliases', [])
                    }
                )
        except Exception as e:
            logger.error(f"Failed to discover domains: {e}")
    
    def _parse_gcp_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse GCP timestamp string to datetime."""
        if not timestamp_str:
            return None
        try:
            # Handle various GCP timestamp formats
            if timestamp_str.endswith('Z'):
                return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            elif '+' in timestamp_str or '-' in timestamp_str[-6:]:
                return datetime.fromisoformat(timestamp_str)
            else:
                return datetime.fromisoformat(timestamp_str + '+00:00')
        except Exception:
            logger.warning(f"Failed to parse timestamp: {timestamp_str}")
            return None
    
    # TODO: Implement remaining methods
    async def discover_principals(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover GCP and Google Workspace principals."""
        # Implementation for discovering users, groups, service accounts
        pass
    
    async def get_resource_configuration(
        self, 
        resource: ResourceInfo
    ) -> ConfigurationSnapshot:
        """Get comprehensive resource configuration."""
        # Implementation for collecting detailed resource configurations
        pass
    
    async def discover_iam_edges(
        self,
        resource: Optional[ResourceInfo] = None
    ) -> AsyncGenerator[IamPermission, None]:
        """Discover comprehensive IAM permissions."""
        # Implementation for discovering IAM permissions across GCP and Workspace
        pass
