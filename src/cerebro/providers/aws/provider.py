"""AWS provider implementation."""

from typing import Any, Dict, List, Optional, AsyncGenerator
from datetime import datetime
import json
import logging
import asyncio
import boto3
from botocore.exceptions import ClientError, BotoCoreError

from cerebro.core.config import settings
from ..base import (
    BaseProvider, ResourceInfo, PrincipalInfo, 
    ConfigurationSnapshot, IamPermission, ProviderError
)

logger = logging.getLogger(__name__)


class AWSProvider(BaseProvider):
    """AWS provider for collecting resources, users, and permissions."""
    
    def __init__(self, account_id, aws_account_id: str, region: Optional[str] = None, **kwargs):
        """Initialize AWS provider."""
        super().__init__(account_id, **kwargs)
        self.aws_account_id = aws_account_id
        self.region = region or settings.aws_default_region
        self._session: Optional[boto3.Session] = None
    
    @property
    def name(self) -> str:
        """Get provider name."""
        return "aws"
    
    async def authenticate(self) -> bool:
        """Authenticate with AWS."""
        try:
            loop = asyncio.get_event_loop()
            
            def _create_session():
                session = boto3.Session(
                    aws_access_key_id=settings.aws_access_key_id,
                    aws_secret_access_key=settings.aws_secret_access_key,
                    region_name=self.region
                )
                
                # Test authentication
                sts = session.client('sts')
                identity = sts.get_caller_identity()
                
                # Verify we're in the right account
                if identity['Account'] != self.aws_account_id:
                    raise ProviderError(f"Expected account {self.aws_account_id}, got {identity['Account']}")
                
                return session
            
            self._session = await loop.run_in_executor(None, _create_session)
            return True
            
        except ClientError as e:
            logger.error(f"AWS authentication failed: {e}")
            raise ProviderError(f"AWS authentication failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during AWS auth: {e}")
            return False
    
    async def discover_resources(
        self, 
        resource_types: Optional[List[str]] = None
    ) -> AsyncGenerator[ResourceInfo, None]:
        """Discover AWS resources."""
        if not self._session:
            await self.authenticate()
        
        loop = asyncio.get_event_loop()
        
        # S3 Buckets
        if not resource_types or "aws.s3.bucket" in resource_types:
            def _get_s3_buckets():
                s3 = self._session.client('s3')
                response = s3.list_buckets()
                return response.get('Buckets', [])
            
            buckets = await loop.run_in_executor(None, _get_s3_buckets)
            
            for bucket in buckets:
                yield ResourceInfo(
                    external_id=bucket['Name'],
                    name=bucket['Name'],
                    resource_type="aws.s3.bucket",
                    metadata={
                        "creation_date": bucket['CreationDate'].isoformat()
                    }
                )
        
        # EC2 Instances
        if not resource_types or "aws.ec2.instance" in resource_types:
            def _get_ec2_instances():
                ec2 = self._session.client('ec2')
                paginator = ec2.get_paginator('describe_instances')
                instances = []
                
                for page in paginator.paginate():
                    for reservation in page['Reservations']:
                        instances.extend(reservation['Instances'])
                
                return instances
            
            instances = await loop.run_in_executor(None, _get_ec2_instances)
            
            for instance in instances:
                name = None
                for tag in instance.get('Tags', []):
                    if tag['Key'] == 'Name':
                        name = tag['Value']
                        break
                
                yield ResourceInfo(
                    external_id=instance['InstanceId'],
                    name=name,
                    resource_type="aws.ec2.instance",
                    metadata={
                        "state": instance['State']['Name'],
                        "instance_type": instance['InstanceType'],
                        "vpc_id": instance.get('VpcId'),
                        "subnet_id": instance.get('SubnetId'),
                    }
                )
        
        # VPCs
        if not resource_types or "aws.ec2.vpc" in resource_types:
            def _get_vpcs():
                ec2 = self._session.client('ec2')
                response = ec2.describe_vpcs()
                return response.get('Vpcs', [])
            
            vpcs = await loop.run_in_executor(None, _get_vpcs)
            
            for vpc in vpcs:
                name = None
                for tag in vpc.get('Tags', []):
                    if tag['Key'] == 'Name':
                        name = tag['Value']
                        break
                
                yield ResourceInfo(
                    external_id=vpc['VpcId'],
                    name=name,
                    resource_type="aws.ec2.vpc",
                    metadata={
                        "state": vpc['State'],
                        "cidr_block": vpc['CidrBlock'],
                        "is_default": vpc['IsDefault'],
                    }
                )
    
    async def discover_principals(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover AWS IAM users, groups, and roles."""
        if not self._session:
            await self.authenticate()
        
        loop = asyncio.get_event_loop()
        
        # IAM Users
        def _get_iam_users():
            iam = self._session.client('iam')
            paginator = iam.get_paginator('list_users')
            users = []
            
            for page in paginator.paginate():
                users.extend(page['Users'])
            
            return users
        
        users = await loop.run_in_executor(None, _get_iam_users)
        
        for user in users:
            yield PrincipalInfo(
                external_id=user['Arn'],
                principal_type="user",
                display_name=user['UserName'],
                is_human=True,  # Assume IAM users are human unless proven otherwise
                metadata={
                    "path": user['Path'],
                    "create_date": user['CreateDate'].isoformat(),
                    "password_last_used": user.get('PasswordLastUsed', '').isoformat() if user.get('PasswordLastUsed') else None,
                }
            )
        
        # IAM Roles
        def _get_iam_roles():
            iam = self._session.client('iam')
            paginator = iam.get_paginator('list_roles')
            roles = []
            
            for page in paginator.paginate():
                roles.extend(page['Roles'])
            
            return roles
        
        roles = await loop.run_in_executor(None, _get_iam_roles)
        
        for role in roles:
            yield PrincipalInfo(
                external_id=role['Arn'],
                principal_type="role",
                display_name=role['RoleName'],
                is_human=False,
                metadata={
                    "path": role['Path'],
                    "create_date": role['CreateDate'].isoformat(),
                    "assume_role_policy": role['AssumeRolePolicyDocument'],
                }
            )
        
        # IAM Groups
        def _get_iam_groups():
            iam = self._session.client('iam')
            paginator = iam.get_paginator('list_groups')
            groups = []
            
            for page in paginator.paginate():
                groups.extend(page['Groups'])
            
            return groups
        
        groups = await loop.run_in_executor(None, _get_iam_groups)
        
        for group in groups:
            yield PrincipalInfo(
                external_id=group['Arn'],
                principal_type="group",
                display_name=group['GroupName'],
                is_human=False,
                metadata={
                    "path": group['Path'],
                    "create_date": group['CreateDate'].isoformat(),
                }
            )
    
    async def get_resource_configuration(
        self, 
        resource: ResourceInfo
    ) -> ConfigurationSnapshot:
        """Get AWS resource configuration."""
        if not self._session:
            await self.authenticate()
        
        loop = asyncio.get_event_loop()
        
        if resource.resource_type == "aws.s3.bucket":
            config = await self._get_s3_bucket_config(resource.external_id, loop)
        elif resource.resource_type == "aws.ec2.instance":
            config = await self._get_ec2_instance_config(resource.external_id, loop)
        elif resource.resource_type == "aws.ec2.vpc":
            config = await self._get_vpc_config(resource.external_id, loop)
        else:
            config = {}
        
        return ConfigurationSnapshot(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config=config
        )
    
    async def _get_s3_bucket_config(self, bucket_name: str, loop) -> Dict[str, Any]:
        """Get S3 bucket configuration."""
        def _get_config():
            s3 = self._session.client('s3')
            
            config = {"name": bucket_name}
            
            try:
                # Bucket policy
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                config["policy"] = json.loads(policy['Policy'])
                config["policyAllowsPublic"] = self._check_s3_policy_public(config["policy"])
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    logger.warning(f"Could not get policy for bucket {bucket_name}: {e}")
                config["policy"] = None
                config["policyAllowsPublic"] = False
            
            try:
                # Bucket ACL
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                config["acl"] = acl
                config["aclAllowsPublic"] = self._check_s3_acl_public(acl)
            except ClientError as e:
                logger.warning(f"Could not get ACL for bucket {bucket_name}: {e}")
                config["acl"] = None
                config["aclAllowsPublic"] = False
            
            try:
                # Public access block
                pab = s3.get_public_access_block(Bucket=bucket_name)
                config["blockPublicAccess"] = pab['PublicAccessBlockConfiguration']
                config["blockPublicAccess"]["effective"] = all([
                    pab['PublicAccessBlockConfiguration'].get('BlockPublicAcls', False),
                    pab['PublicAccessBlockConfiguration'].get('IgnorePublicAcls', False),
                    pab['PublicAccessBlockConfiguration'].get('BlockPublicPolicy', False),
                    pab['PublicAccessBlockConfiguration'].get('RestrictPublicBuckets', False),
                ])
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
                    logger.warning(f"Could not get public access block for bucket {bucket_name}: {e}")
                config["blockPublicAccess"] = {"effective": False}
            
            return config
        
        return await loop.run_in_executor(None, _get_config)
    
    def _check_s3_policy_public(self, policy: Dict[str, Any]) -> bool:
        """Check if S3 bucket policy allows public access."""
        if not policy or 'Statement' not in policy:
            return False
        
        for statement in policy['Statement']:
            if statement.get('Effect') == 'Allow':
                principals = statement.get('Principal', [])
                if principals == '*' or (isinstance(principals, dict) and principals.get('AWS') == '*'):
                    return True
        
        return False
    
    def _check_s3_acl_public(self, acl: Dict[str, Any]) -> bool:
        """Check if S3 bucket ACL allows public access."""
        if not acl or 'Grants' not in acl:
            return False
        
        public_uris = [
            'http://acs.amazonaws.com/groups/global/AllUsers',
            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
        ]
        
        for grant in acl['Grants']:
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') in public_uris:
                return True
        
        return False
    
    async def _get_ec2_instance_config(self, instance_id: str, loop) -> Dict[str, Any]:
        """Get EC2 instance configuration."""
        def _get_config():
            ec2 = self._session.client('ec2')
            response = ec2.describe_instances(InstanceIds=[instance_id])
            
            instance = response['Reservations'][0]['Instances'][0]
            
            return {
                "instanceId": instance['InstanceId'],
                "state": instance['State']['Name'],
                "instanceType": instance['InstanceType'],
                "imageId": instance['ImageId'],
                "vpcId": instance.get('VpcId'),
                "subnetId": instance.get('SubnetId'),
                "securityGroups": [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
                "publicIp": instance.get('PublicIpAddress'),
                "privateIp": instance.get('PrivateIpAddress'),
                "tags": {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])},
            }
        
        return await loop.run_in_executor(None, _get_config)
    
    async def _get_vpc_config(self, vpc_id: str, loop) -> Dict[str, Any]:
        """Get VPC configuration.""" 
        def _get_config():
            ec2 = self._session.client('ec2')
            response = ec2.describe_vpcs(VpcIds=[vpc_id])
            
            vpc = response['Vpcs'][0]
            
            return {
                "vpcId": vpc['VpcId'],
                "state": vpc['State'],
                "cidrBlock": vpc['CidrBlock'],
                "isDefault": vpc['IsDefault'],
                "tags": {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])},
            }
        
        return await loop.run_in_executor(None, _get_config)
    
    async def discover_iam_edges(
        self,
        resource: Optional[ResourceInfo] = None
    ) -> AsyncGenerator[IamPermission, None]:
        """Discover AWS IAM permissions with comprehensive policy evaluation."""
        if not self._session:
            await self.authenticate()
        
        loop = asyncio.get_event_loop()
        
        # Comprehensive IAM analysis
        def _get_comprehensive_iam_permissions():
            iam = self._session.client('iam')
            permissions = []
            
            # 1. User permissions
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    user_permissions = self._analyze_user_permissions(iam, user)
                    permissions.extend(user_permissions)
            
            # 2. Role permissions
            paginator = iam.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    role_permissions = self._analyze_role_permissions(iam, role)
                    permissions.extend(role_permissions)
            
            # 3. Group permissions
            paginator = iam.get_paginator('list_groups')
            for page in paginator.paginate():
                for group in page['Groups']:
                    group_permissions = self._analyze_group_permissions(iam, group)
                    permissions.extend(group_permissions)
            
            return permissions
        
        perms = await loop.run_in_executor(None, _get_comprehensive_iam_permissions)
        
        for perm in perms:
            yield IamPermission(
                principal_external_id=perm['principal_arn'],
                resource_external_id=perm.get('resource_arn'),
                permission=perm['permission'],
                via=perm['via'],
                effective_at=datetime.utcnow(),
                is_admin=perm['is_admin']
            )
    
    def _analyze_user_permissions(self, iam, user: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze all permissions for an IAM user."""
        permissions = []
        user_arn = user['Arn']
        user_name = user['UserName']
        
        # 1. Directly attached managed policies
        user_policies = iam.list_attached_user_policies(UserName=user_name)
        for policy in user_policies['AttachedPolicies']:
            is_admin = self._is_admin_policy(policy['PolicyArn'])
            permissions.append({
                'principal_arn': user_arn,
                'permission': f"aws.iam.policy.{policy['PolicyName']}",
                'via': f"direct_attachment:{policy['PolicyArn']}",
                'is_admin': is_admin,
                'resource_arn': None
            })
        
        # 2. Inline user policies
        inline_policies = iam.list_user_policies(UserName=user_name)
        for policy_name in inline_policies['PolicyNames']:
            policy_doc = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
            statements = policy_doc['PolicyDocument'].get('Statement', [])
            
            for statement in statements:
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    for action in actions:
                        is_admin = action == '*' or 'Admin' in action
                        permissions.append({
                            'principal_arn': user_arn,
                            'permission': f"aws.action.{action}",
                            'via': f"inline_policy:{policy_name}",
                            'is_admin': is_admin,
                            'resource_arn': None
                        })
        
        # 3. Group memberships
        user_groups = iam.get_groups_for_user(UserName=user_name)
        for group in user_groups['Groups']:
            group_permissions = self._analyze_group_permissions_for_user(iam, group, user_arn)
            permissions.extend(group_permissions)
        
        return permissions
    
    def _analyze_role_permissions(self, iam, role: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze permissions for an IAM role."""
        permissions = []
        role_arn = role['Arn']
        role_name = role['RoleName']
        
        # Attached managed policies
        role_policies = iam.list_attached_role_policies(RoleName=role_name)
        for policy in role_policies['AttachedPolicies']:
            is_admin = self._is_admin_policy(policy['PolicyArn'])
            permissions.append({
                'principal_arn': role_arn,
                'permission': f"aws.iam.policy.{policy['PolicyName']}",
                'via': f"role_attachment:{policy['PolicyArn']}",
                'is_admin': is_admin,
                'resource_arn': None
            })
        
        # Inline role policies
        inline_policies = iam.list_role_policies(RoleName=role_name)
        for policy_name in inline_policies['PolicyNames']:
            policy_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            statements = policy_doc['PolicyDocument'].get('Statement', [])
            
            for statement in statements:
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    for action in actions:
                        is_admin = action == '*' or 'Admin' in action
                        permissions.append({
                            'principal_arn': role_arn,
                            'permission': f"aws.action.{action}",
                            'via': f"role_inline_policy:{policy_name}",
                            'is_admin': is_admin,
                            'resource_arn': None
                        })
        
        return permissions
    
    def _analyze_group_permissions(self, iam, group: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze permissions for an IAM group."""
        permissions = []
        group_arn = group['Arn']
        group_name = group['GroupName']
        
        # Get group members
        group_members = iam.get_group(GroupName=group_name)
        member_arns = [user['Arn'] for user in group_members['Users']]
        
        # Attached managed policies
        group_policies = iam.list_attached_group_policies(GroupName=group_name)
        for policy in group_policies['AttachedPolicies']:
            is_admin = self._is_admin_policy(policy['PolicyArn'])
            
            # Create permission for each group member
            for member_arn in member_arns:
                permissions.append({
                    'principal_arn': member_arn,
                    'permission': f"aws.iam.policy.{policy['PolicyName']}",
                    'via': f"group_membership:{group_name}:{policy['PolicyArn']}",
                    'is_admin': is_admin,
                    'resource_arn': None
                })
        
        return permissions
    
    def _analyze_group_permissions_for_user(
        self, 
        iam, 
        group: Dict[str, Any], 
        user_arn: str
    ) -> List[Dict[str, Any]]:
        """Analyze group permissions for a specific user."""
        permissions = []
        group_name = group['GroupName']
        
        # Attached managed policies
        group_policies = iam.list_attached_group_policies(GroupName=group_name)
        for policy in group_policies['AttachedPolicies']:
            is_admin = self._is_admin_policy(policy['PolicyArn'])
            permissions.append({
                'principal_arn': user_arn,
                'permission': f"aws.iam.policy.{policy['PolicyName']}",
                'via': f"group_membership:{group_name}:{policy['PolicyArn']}",
                'is_admin': is_admin,
                'resource_arn': None
            })
        
        return permissions
    
    def _is_admin_policy(self, policy_arn: str) -> bool:
        """Check if a policy provides administrative access."""
        admin_policies = [
            'arn:aws:iam::aws:policy/AdministratorAccess',
            'arn:aws:iam::aws:policy/IAMFullAccess',
            'arn:aws:iam::aws:policy/PowerUserAccess'
        ]
        
        return (policy_arn in admin_policies or 
                'Administrator' in policy_arn or
                'FullAccess' in policy_arn)
