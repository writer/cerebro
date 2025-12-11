"""Base classes for IAM edge harvesting across providers."""

from abc import ABC, abstractmethod
from typing import AsyncGenerator
from uuid import UUID
import logging

from .base import IamPermission

logger = logging.getLogger(__name__)


class BaseEdgeHarvester(ABC):
    """
    Base class for harvesting IAM edges from providers.
    
    Inspired by findings-producer pattern - each harvester is responsible
    for a single provider and publishes edges independently.
    """
    
    provider: str
    
    def __init__(self, account_id: UUID):
        self.account_id = account_id
    
    @abstractmethod
    async def harvest(self) -> AsyncGenerator[IamPermission, None]:
        """
        Harvest IAM permissions/edges from the provider.
        
        Yields IamPermission entities that represent privilege relationships.
        """
        pass
    
    async def validate_connection(self) -> bool:
        """
        Validate that the harvester can connect to the provider.
        
        Returns True if connection is successful, False otherwise.
        """
        try:
            # Try to harvest one edge to test connectivity
            async for _ in self.harvest():
                return True
            return True  # Empty harvest is still a successful connection
        except Exception as e:
            logger.error(f"Connection validation failed for {self.provider}: {e}")
            return False


class AWSEdgeHarvester(BaseEdgeHarvester):
    """Harvests IAM edges from AWS using boto3."""
    
    provider = "aws"
    
    async def harvest(self) -> AsyncGenerator[IamPermission, None]:
        """Harvest AWS IAM permissions using real boto3 calls."""
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            
            # Initialize AWS clients
            iam = boto3.client('iam')
            sts = boto3.client('sts')
            
            # Get account ID
            try:
                account_info = sts.get_caller_identity()
                account_id = account_info['Account']
            except Exception as e:
                logger.error(f"Failed to get AWS account ID: {e}")
                return
            
            # Harvest user permissions
            try:
                paginator = iam.get_paginator('list_users')
                for page in paginator.paginate():
                    for user in page['Users']:
                        # Get user policies
                        user_name = user['UserName']
                        
                        # Inline policies
                        policy_paginator = iam.get_paginator('list_user_policies')
                        for policy_page in policy_paginator.paginate(UserName=user_name):
                            for policy_name in policy_page['PolicyNames']:
                                policy_doc = iam.get_user_policy(
                                    UserName=user_name,
                                    PolicyName=policy_name
                                )
                                
                                yield IamPermission(
                                    principal_id=user['Arn'],
                                    principal_type='user',
                                    resource_arn='*',  # TODO: Parse policy document
                                    permission_type='policy',
                                    permission_name=policy_name,
                                    granted_at=user['CreateDate'],
                                    account_id=account_id,
                                    provider=self.provider
                                )
                        
                        # Attached managed policies
                        attached_paginator = iam.get_paginator('list_attached_user_policies')
                        for attached_page in attached_paginator.paginate(UserName=user_name):
                            for policy in attached_page['AttachedPolicies']:
                                yield IamPermission(
                                    principal_id=user['Arn'],
                                    principal_type='user',
                                    resource_arn=policy['PolicyArn'],
                                    permission_type='managed_policy',
                                    permission_name=policy['PolicyName'],
                                    granted_at=user['CreateDate'],
                                    account_id=account_id,
                                    provider=self.provider
                                )
                                
            except ClientError as e:
                logger.error(f"AWS IAM API error: {e}")
                
        except ImportError:
            logger.error("boto3 not installed - cannot harvest AWS edges")
        except NoCredentialsError:
            logger.error("AWS credentials not configured")
        except Exception as e:
            logger.error(f"Unexpected error harvesting AWS edges: {e}")


class GitHubEdgeHarvester(BaseEdgeHarvester):
    """Harvests IAM edges from GitHub using GitHub API."""
    
    provider = "github"
    
    async def harvest(self) -> AsyncGenerator[IamPermission, None]:
        """Harvest GitHub permissions using real GitHub API calls."""
        try:
            import aiohttp
            import os
            
            github_token = os.getenv('GITHUB_TOKEN')
            if not github_token:
                logger.error("GITHUB_TOKEN not configured")
                return
            
            headers = {
                'Authorization': f'token {github_token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            async with aiohttp.ClientSession(headers=headers) as session:
                # Get organization members and their permissions
                org_url = f"https://api.github.com/orgs/{self.account_id}/members"
                
                async with session.get(org_url) as response:
                    if response.status == 200:
                        members = await response.json()
                        
                        for member in members:
                            yield IamPermission(
                                principal_id=member['login'],
                                principal_type='user',
                                resource_arn=f"github.com/{self.account_id}",
                                permission_type='member',
                                permission_name='organization_member',
                                granted_at=None,  # GitHub doesn't provide this
                                account_id=str(self.account_id),
                                provider=self.provider
                            )
                    else:
                        logger.warning(f"GitHub API returned {response.status}")
                        
        except ImportError:
            logger.error("aiohttp not installed - cannot harvest GitHub edges")
        except Exception as e:
            logger.error(f"Error harvesting GitHub edges: {e}")


class OktaEdgeHarvester(BaseEdgeHarvester):
    """Harvests IAM edges from Okta using Okta API."""
    
    provider = "okta"
    
    async def harvest(self) -> AsyncGenerator[IamPermission, None]:
        """Harvest Okta permissions using real Okta API calls."""
        try:
            import aiohttp
            import os
            
            okta_token = os.getenv('OKTA_API_TOKEN')
            okta_domain = os.getenv('OKTA_DOMAIN')
            
            if not okta_token or not okta_domain:
                logger.error("OKTA_API_TOKEN and OKTA_DOMAIN not configured")
                return
            
            headers = {
                'Authorization': f'SSWS {okta_token}',
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            base_url = f"https://{okta_domain}"
            
            async with aiohttp.ClientSession(headers=headers) as session:
                # Get users and their group memberships
                users_url = f"{base_url}/api/v1/users"
                
                async with session.get(users_url) as response:
                    if response.status == 200:
                        users = await response.json()
                        
                        for user in users:
                            # Get user's groups
                            groups_url = f"{base_url}/api/v1/users/{user['id']}/groups"
                            
                            async with session.get(groups_url) as group_response:
                                if group_response.status == 200:
                                    groups = await group_response.json()
                                    
                                    for group in groups:
                                        yield IamPermission(
                                            principal_id=user['profile']['email'],
                                            principal_type='user',
                                            resource_arn=group['id'],
                                            permission_type='group_membership',
                                            permission_name=group['profile']['name'],
                                            granted_at=user['created'],
                                            account_id=str(self.account_id),
                                            provider=self.provider
                                        )
                                        
        except ImportError:
            logger.error("aiohttp not installed - cannot harvest Okta edges")
        except Exception as e:
            logger.error(f"Error harvesting Okta edges: {e}")


# Auto-discovery pattern inspired by findings-producer
def discover_edge_harvesters() -> dict:
    """Discover all available edge harvesters by provider."""
    harvesters = {
        'aws': AWSEdgeHarvester,
        'github': GitHubEdgeHarvester,
        'okta': OktaEdgeHarvester,
    }
    
    logger.info(f"Discovered {len(harvesters)} edge harvesters: {list(harvesters.keys())}")
    return harvesters


async def harvest_all_edges(account_id: UUID) -> AsyncGenerator[IamPermission, None]:
    """
    Harvest edges from all available providers.
    
    This replaces the mock edge generation in attack path analysis.
    """
    harvesters = discover_edge_harvesters()
    
    for provider_name, harvester_class in harvesters.items():
        try:
            harvester = harvester_class(account_id)
            
            # Validate connection before harvesting
            if await harvester.validate_connection():
                logger.info(f"Harvesting edges from {provider_name}")
                async for edge in harvester.harvest():
                    yield edge
            else:
                logger.warning(f"Skipping {provider_name} - connection validation failed")
                
        except Exception as e:
            logger.error(f"Failed to harvest edges from {provider_name}: {e}")
