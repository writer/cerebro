"""GCP provider implementation."""

from typing import Any, Dict, List, Optional, AsyncGenerator
from datetime import datetime
import logging

from ..base import (
    BaseProvider, ResourceInfo, PrincipalInfo, 
    ConfigurationSnapshot, IamPermission, ProviderError
)

logger = logging.getLogger(__name__)


class GCPProvider(BaseProvider):
    """GCP provider for collecting resources, users, and permissions."""
    
    def __init__(self, account_id, project_id: str, **kwargs):
        """Initialize GCP provider."""
        super().__init__(account_id, **kwargs)
        self.project_id = project_id
    
    @property
    def name(self) -> str:
        """Get provider name."""
        return "gcp"
    
    async def authenticate(self) -> bool:
        """Authenticate with GCP."""
        try:
            from google.cloud import compute_v1
            from google.auth import default
            
            # Attempt to get default credentials
            credentials, project = default()
            
            # Test authentication with a simple API call
            client = compute_v1.InstancesClient(credentials=credentials)
            
            # If we get here, authentication is working
            logger.info(f"Successfully authenticated with GCP project: {project or self.project_id}")
            return True
            
        except ImportError:
            logger.error("GCP client libraries not installed. Run: pip install google-cloud-compute")
            return False
        except Exception as e:
            logger.warning(f"GCP authentication failed: {e}")
            return False
    
    async def discover_resources(
        self, 
        resource_types: Optional[List[str]] = None
    ) -> AsyncGenerator[ResourceInfo, None]:
        """Discover GCP resources."""
        try:
            from google.cloud import compute_v1
            from google.auth import default
            
            credentials, _ = default()
            client = compute_v1.InstancesClient(credentials=credentials)
            
            # List compute instances
            request = compute_v1.AggregatedListInstancesRequest(project=self.project_id)
            page_result = client.aggregated_list(request=request)
            
            for zone, response in page_result:
                if hasattr(response, 'instances') and response.instances:
                    for instance in response.instances:
                        yield ResourceInfo(
                            resource_id=str(instance.id),
                            resource_type="gcp.compute.instance",
                            name=instance.name,
                            region=zone.split('/')[-1] if zone else "unknown",
                            tags=dict(instance.labels) if instance.labels else {},
                            created_at=datetime.utcnow(),
                            account_id=self.account_id
                        )
                        
        except ImportError:
            logger.error("GCP client libraries not installed")
            return
        except Exception as e:
            logger.error(f"Failed to discover GCP resources: {e}")
            return
    
    async def discover_principals(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover GCP principals.""" 
        # TODO: Implement GCP principal discovery
        return
        yield  # Make this an async generator
    
    async def get_resource_configuration(
        self, 
        resource: ResourceInfo
    ) -> ConfigurationSnapshot:
        """Get GCP resource configuration."""
        # TODO: Implement GCP configuration collection
        return ConfigurationSnapshot(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={}
        )
    
    async def discover_iam_edges(
        self,
        resource: Optional[ResourceInfo] = None
    ) -> AsyncGenerator[IamPermission, None]:
        """Discover GCP IAM permissions."""
        # TODO: Implement GCP IAM discovery
        return
        yield  # Make this an async generator
