"""AWS provider implementation.

The :class:`AWSProvider` wraps ``boto3`` clients to expose AWS resource and IAM
state in the collector contract.  It currently focuses on S3, EC2, and IAM data
required for risk analyses.
"""

from typing import Any, Dict, List, Optional, AsyncGenerator, Set
from datetime import datetime
import json
import logging
import boto3
from botocore.exceptions import ClientError, BotoCoreError

from cerebro.core.config import settings
from ..base import (
    BaseProvider, ResourceInfo, PrincipalInfo, 
    ConfigurationSnapshot, IamPermission, ProviderError
)
from ..utils.connector import call_sync_with_retries, iterate_sync_iterator

logger = logging.getLogger(__name__)


class AWSProvider(BaseProvider):
    """Collect AWS resources, principals, and IAM edges via ``boto3``."""
    
    def __init__(self, account_id, aws_account_id: str, region: Optional[str] = None, **kwargs):
        """Create an AWS provider bound to a specific account and region."""
        super().__init__(account_id, **kwargs)
        self.aws_account_id = aws_account_id
        self.region = region or settings.aws_default_region
        self._session: Optional[boto3.Session] = None
    
    @property
    def name(self) -> str:
        """Get provider name."""
        return "aws"
    
    async def authenticate(self) -> bool:
        """Authenticate with AWS and verify the expected account id."""
        try:
            def _create_session():
                session = boto3.Session(
                    aws_access_key_id=settings.aws_access_key_id,
                    aws_secret_access_key=settings.aws_secret_access_key,
                    region_name=self.region
                )

                sts = session.client('sts')
                identity = sts.get_caller_identity()

                if identity['Account'] != self.aws_account_id:
                    raise ProviderError(f"Expected account {self.aws_account_id}, got {identity['Account']}")

                return session

            self._session = await call_sync_with_retries(
                _create_session,
                exceptions=(ClientError, BotoCoreError),
                logger=logger,
            )
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
        
        # S3 Buckets
        if not resource_types or "aws.s3.bucket" in resource_types:
            s3_client = self._session.client('s3')

            buckets = await call_sync_with_retries(
                lambda: s3_client.list_buckets().get('Buckets', []),
                exceptions=(ClientError, BotoCoreError),
                logger=logger,
            )

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
            ec2_client = self._session.client('ec2')
            paginator = ec2_client.get_paginator('describe_instances')

            instances = []
            async for page in iterate_sync_iterator(
                lambda: paginator.paginate(),
                exceptions=(ClientError, BotoCoreError),
                logger=logger,
            ):
                for reservation in page.get('Reservations', []):
                    instances.extend(reservation.get('Instances', []))

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
            ec2_client = self._session.client('ec2')
            vpcs = await call_sync_with_retries(
                lambda: ec2_client.describe_vpcs().get('Vpcs', []),
                exceptions=(ClientError, BotoCoreError),
                logger=logger,
            )

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

        # Security Groups
        if not resource_types or "aws.ec2.security_group" in resource_types:
            ec2_client = self._session.client('ec2')
            paginator = ec2_client.get_paginator('describe_security_groups')

            async for page in iterate_sync_iterator(
                lambda: paginator.paginate(),
                exceptions=(ClientError, BotoCoreError),
                logger=logger,
            ):
                for group in page.get('SecurityGroups', []):
                    yield ResourceInfo(
                        external_id=group['GroupId'],
                        name=group.get('GroupName'),
                        resource_type="aws.ec2.security_group",
                        metadata={
                            "group_name": group.get('GroupName'),
                            "description": group.get('Description'),
                            "vpc_id": group.get('VpcId'),
                            "owner_id": group.get('OwnerId'),
                        }
                    )

        # Load Balancers (Application/Network)
        if not resource_types or "aws.elbv2.load_balancer" in resource_types:
            elb_client = self._session.client('elbv2')
            paginator = elb_client.get_paginator('describe_load_balancers')

            async for page in iterate_sync_iterator(
                lambda: paginator.paginate(),
                exceptions=(ClientError, BotoCoreError),
                logger=logger,
            ):
                for lb in page.get('LoadBalancers', []):
                    yield ResourceInfo(
                        external_id=lb.get('LoadBalancerArn'),
                        name=lb.get('LoadBalancerName'),
                        resource_type="aws.elbv2.load_balancer",
                        metadata={
                            "type": lb.get('Type'),
                            "scheme": lb.get('Scheme'),
                            "state": (lb.get('State') or {}).get('Code'),
                            "dns_name": lb.get('DNSName'),
                        }
                    )

        # CodeBuild projects
        if not resource_types or "aws.codebuild.project" in resource_types:
            codebuild_client = self._session.client('codebuild')
            paginator = codebuild_client.get_paginator('list_projects')

            project_names: List[str] = []
            async for page in iterate_sync_iterator(
                lambda: paginator.paginate(),
                exceptions=(ClientError, BotoCoreError),
                logger=logger,
            ):
                project_names.extend(page.get('projects', []))

            # Batch-get project metadata in chunks of 100 to avoid API limits
            for index in range(0, len(project_names), 100):
                batch = project_names[index : index + 100]
                if not batch:
                    continue

                response = await call_sync_with_retries(
                    lambda names=batch: codebuild_client.batch_get_projects(names=names),
                    exceptions=(ClientError, BotoCoreError),
                    logger=logger,
                )

                for project in response.get('projects', []):
                    arn = project.get('arn')
                    name = project.get('name')
                    source = project.get('source', {})
                    webhook = project.get('webhook', {})

                    metadata = {
                        "arn": arn,
                        "service_role": project.get('serviceRole'),
                        "created": project.get('created')
                        .isoformat()
                        if isinstance(project.get('created'), datetime)
                        else None,
                        "last_modified": project.get('lastModified')
                        .isoformat()
                        if isinstance(project.get('lastModified'), datetime)
                        else None,
                        "source_type": source.get('type'),
                        "source_location": source.get('location'),
                        "source_auth_type": (source.get('auth') or {}).get('type'),
                        "webhook_enabled": bool(webhook),
                        "webhook_filter_groups": webhook.get('filterGroups'),
                        "environment_type": (project.get('environment') or {}).get('type'),
                        "privileged_mode": (project.get('environment') or {}).get('privilegedMode'),
                        "badge_enabled": project.get('badge', {}).get('badgeEnabled')
                        if isinstance(project.get('badge'), dict)
                        else None,
                    }

                    yield ResourceInfo(
                        external_id=name or arn,
                        name=name,
                        resource_type="aws.codebuild.project",
                        metadata=metadata,
                    )

        # IAM Roles (service accounts)
        if not resource_types or "aws.iam.role" in resource_types:
            iam_client = self._session.client('iam')
            role_paginator = iam_client.get_paginator('list_roles')

            roles: List[Dict[str, Any]] = []
            async for page in iterate_sync_iterator(
                lambda: role_paginator.paginate(),
                exceptions=(ClientError, BotoCoreError),
                logger=logger,
            ):
                roles.extend(page.get('Roles', []))

            for role in roles:
                yield ResourceInfo(
                    external_id=role['Arn'],
                    name=role['RoleName'],
                    resource_type="aws.iam.role",
                    metadata={
                        "path": role.get('Path'),
                        "max_session_duration": role.get('MaxSessionDuration'),
                        "description": role.get('Description'),
                    },
                )
    
    async def discover_principals(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover AWS IAM users, groups, and roles."""
        if not self._session:
            await self.authenticate()
        
        iam_client = self._session.client('iam')
        user_paginator = iam_client.get_paginator('list_users')
        users = []
        async for page in iterate_sync_iterator(
            lambda: user_paginator.paginate(),
            exceptions=(ClientError, BotoCoreError),
            logger=logger,
        ):
            users.extend(page.get('Users', []))

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
        role_paginator = iam_client.get_paginator('list_roles')
        roles = []
        async for page in iterate_sync_iterator(
            lambda: role_paginator.paginate(),
            exceptions=(ClientError, BotoCoreError),
            logger=logger,
        ):
            roles.extend(page.get('Roles', []))

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
        group_paginator = iam_client.get_paginator('list_groups')
        groups = []
        async for page in iterate_sync_iterator(
            lambda: group_paginator.paginate(),
            exceptions=(ClientError, BotoCoreError),
            logger=logger,
        ):
            groups.extend(page.get('Groups', []))

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
        
        if resource.resource_type == "aws.s3.bucket":
            config = await self._get_s3_bucket_config(resource.external_id)
        elif resource.resource_type == "aws.ec2.instance":
            config = await self._get_ec2_instance_config(resource.external_id)
        elif resource.resource_type == "aws.ec2.vpc":
            config = await self._get_vpc_config(resource.external_id)
        elif resource.resource_type == "aws.ec2.security_group":
            config = await self._get_security_group_config(resource.external_id)
        elif resource.resource_type == "aws.elbv2.load_balancer":
            config = await self._get_load_balancer_config(resource.external_id)
        elif resource.resource_type == "aws.codebuild.project":
            config = await self._get_codebuild_project_config(resource.external_id)
        elif resource.resource_type == "aws.iam.role":
            config = await self._get_iam_role_config(resource.external_id)
        else:
            config = {}
        
        return ConfigurationSnapshot(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config=config
        )

    async def _get_security_group_config(self, group_id: str) -> Dict[str, Any]:
        """Get Security Group configuration."""

        def _describe_security_group():
            ec2 = self._session.client('ec2')
            response = ec2.describe_security_groups(GroupIds=[group_id])
            groups = response.get('SecurityGroups', [])
            if not groups:
                return {}
            group = groups[0]

            return {
                "groupId": group.get('GroupId'),
                "groupName": group.get('GroupName'),
                "description": group.get('Description'),
                "vpcId": group.get('VpcId'),
                "ownerId": group.get('OwnerId'),
                "ingressRules": [
                    self._normalize_security_group_permission(permission)
                    for permission in group.get('IpPermissions', [])
                ],
                "egressRules": [
                    self._normalize_security_group_permission(permission)
                    for permission in group.get('IpPermissionsEgress', [])
                ],
            }

        return await call_sync_with_retries(
            _describe_security_group,
            exceptions=(ClientError, BotoCoreError),
            logger=logger,
        )

    async def _get_load_balancer_config(self, lb_arn: str) -> Dict[str, Any]:
        """Get load balancer configuration."""

        def _describe_load_balancer():
            elb = self._session.client('elbv2')
            try:
                acm_client = self._session.client('acm')
            except (ClientError, BotoCoreError):
                acm_client = None
            try:
                ec2_client = self._session.client('ec2')
            except (ClientError, BotoCoreError):
                ec2_client = None
            response = elb.describe_load_balancers(LoadBalancerArns=[lb_arn])
            load_balancers = response.get('LoadBalancers', [])
            if not load_balancers:
                return {}

            lb = load_balancers[0]

            listeners: List[Dict[str, Any]] = []
            target_groups: List[Dict[str, Any]] = []
            marker = None
            while True:
                params = {"LoadBalancerArn": lb_arn}
                if marker:
                    params["Marker"] = marker
                listener_response = elb.describe_listeners(**params)
                for listener in listener_response.get('Listeners', []):
                    certificates = []
                    for certificate in listener.get('Certificates', []) or []:
                        cert_info: Dict[str, Any] = {
                            "certificateArn": certificate.get('CertificateArn'),
                            "isDefault": certificate.get('IsDefault'),
                        }
                        cert_arn = certificate.get('CertificateArn')
                        if (
                            acm_client
                            and cert_arn
                            and isinstance(cert_arn, str)
                            and ":acm:" in cert_arn
                        ):
                            try:
                                cert_details = acm_client.describe_certificate(
                                    CertificateArn=cert_arn
                                )
                                certificate_meta = cert_details.get('Certificate', {})
                                not_before = certificate_meta.get('NotBefore')
                                not_after = certificate_meta.get('NotAfter')
                                cert_info.update(
                                    {
                                        "status": certificate_meta.get('Status'),
                                        "type": certificate_meta.get('Type'),
                                        "inUseBy": certificate_meta.get('InUseBy'),
                                        "notBefore": not_before.isoformat()
                                        if hasattr(not_before, "isoformat")
                                        else None,
                                        "notAfter": not_after.isoformat()
                                        if hasattr(not_after, "isoformat")
                                        else None,
                                    }
                                )
                            except ClientError as exc:
                                logger.warning(
                                    "Failed to describe ACM certificate %s: %s",
                                    cert_arn,
                                    exc,
                                )
                        certificates.append(cert_info)

                    listeners.append(
                        {
                            "listenerArn": listener.get('ListenerArn'),
                            "port": listener.get('Port'),
                            "protocol": listener.get('Protocol'),
                            "sslPolicy": listener.get('SslPolicy'),
                            "defaultActions": [
                                {
                                    "type": action.get('Type'),
                                    "order": action.get('Order'),
                                    "targetGroupArn": action.get('TargetGroupArn'),
                                    "redirectConfig": action.get('RedirectConfig'),
                                    "fixedResponseConfig": action.get('FixedResponseConfig'),
                                }
                                for action in listener.get('DefaultActions', [])
                            ],
                            "certificates": certificates,
                        }
                    )
                marker = listener_response.get('NextMarker')
                if not marker:
                    break

            tg_response = elb.describe_target_groups(LoadBalancerArn=lb_arn)
            for target_group in tg_response.get('TargetGroups', []):
                target_group_arn = target_group.get('TargetGroupArn')
                tg_targets: List[Dict[str, Any]] = []
                try:
                    health_response = elb.describe_target_health(
                        TargetGroupArn=target_group_arn
                    )
                    for description in health_response.get(
                        'TargetHealthDescriptions', []
                    ):
                        target = description.get('Target', {})
                        target_health = description.get('TargetHealth', {})
                        tg_targets.append(
                            {
                                "id": target.get('Id'),
                                "port": target.get('Port'),
                                "availabilityZone": target.get('AvailabilityZone'),
                                "healthState": target_health.get('State'),
                                "reason": target_health.get('ReasonCode'),
                                "description": target_health.get('Description'),
                            }
                        )
                except ClientError as exc:
                    logger.warning(
                        "Failed to describe target health for %s: %s",
                        target_group_arn,
                        exc,
                    )

                target_groups.append(
                    {
                        "targetGroupArn": target_group_arn,
                        "targetGroupName": target_group.get('TargetGroupName'),
                        "targetType": target_group.get('TargetType'),
                        "vpcId": target_group.get('VpcId'),
                        "protocol": target_group.get('Protocol'),
                        "port": target_group.get('Port'),
                        "healthCheckProtocol": target_group.get('HealthCheckProtocol'),
                        "healthCheckPort": target_group.get('HealthCheckPort'),
                        "healthCheckPath": target_group.get('HealthCheckPath'),
                        "matcher": target_group.get('Matcher'),
                        "targets": tg_targets,
                    }
                )

            instance_target_ids: Set[str] = set()
            security_group_ids: Set[str] = set()
            for target_group in target_groups:
                if target_group.get("targetType") != "instance":
                    continue
                for target in target_group.get("targets") or []:
                    target_id = target.get("id")
                    if target_id:
                        instance_target_ids.add(target_id)

            instance_details: Dict[str, Dict[str, Any]] = {}
            if instance_target_ids and ec2_client:
                instance_id_list = list(instance_target_ids)
                for index in range(0, len(instance_id_list), 100):
                    batch_ids = instance_id_list[index : index + 100]
                    try:
                        instances_response = ec2_client.describe_instances(
                            InstanceIds=batch_ids
                        )
                    except ClientError as exc:
                        logger.warning(
                            "Failed to describe instances %s: %s",
                            batch_ids,
                            exc,
                        )
                        continue

                    for reservation in instances_response.get('Reservations', []):
                        for instance in reservation.get('Instances', []):
                            instance_id = instance.get('InstanceId')
                            if not instance_id:
                                continue

                            public_ip = instance.get('PublicIpAddress')
                            public_dns = instance.get('PublicDnsName')
                            network_interfaces = instance.get('NetworkInterfaces') or []
                            interface_public_ips: List[str] = []
                            for interface in network_interfaces:
                                association = interface.get('Association') or {}
                                interface_ip = association.get('PublicIp')
                                if interface_ip:
                                    interface_public_ips.append(interface_ip)

                            security_groups = instance.get('SecurityGroups') or []
                            group_ids = [
                                group.get('GroupId')
                                for group in security_groups
                                if group.get('GroupId')
                            ]
                            security_group_ids.update(group_ids)

                            instance_details[instance_id] = {
                                "publicIpAddress": public_ip,
                                "publicDnsName": public_dns,
                                "networkInterfacePublicIps": interface_public_ips,
                                "hasPublicInterface": bool(public_ip or interface_public_ips),
                                "state": (instance.get('State') or {}).get('Name'),
                                "privateIpAddress": instance.get('PrivateIpAddress'),
                                "subnetId": instance.get('SubnetId'),
                                "vpcId": instance.get('VpcId'),
                                "securityGroupIds": group_ids,
                            }

            security_group_details: Dict[str, Dict[str, Any]] = {}
            if security_group_ids and ec2_client:
                sg_id_list = list(security_group_ids)
                for index in range(0, len(sg_id_list), 100):
                    batch_ids = sg_id_list[index : index + 100]
                    try:
                        sg_response = ec2_client.describe_security_groups(
                            GroupIds=batch_ids
                        )
                    except ClientError as exc:
                        logger.warning(
                            "Failed to describe security groups %s: %s",
                            batch_ids,
                            exc,
                        )
                        continue

                    for group in sg_response.get('SecurityGroups', []):
                        group_id = group.get('GroupId')
                        if not group_id:
                            continue
                        security_group_details[group_id] = {
                            "groupId": group_id,
                            "groupName": group.get('GroupName'),
                            "description": group.get('Description'),
                            "ingressRules": [
                                self._normalize_security_group_permission(permission)
                                for permission in group.get('IpPermissions', [])
                            ],
                        }

            if instance_details:
                for target_group in target_groups:
                    if target_group.get("targetType") != "instance":
                        continue
                    for target in target_group.get("targets") or []:
                        target_id = target.get("id")
                        if target_id and target_id in instance_details:
                            instance_info = instance_details[target_id]
                            security_groups = []
                            for group_id in instance_info.get("securityGroupIds", []):
                                if group_id in security_group_details:
                                    security_groups.append(security_group_details[group_id])
                            instance_info["securityGroups"] = security_groups
                            instance_info.pop("securityGroupIds", None)
                            target["instance"] = instance_info

            availability_zones = []
            for az in lb.get('AvailabilityZones', []) or []:
                availability_zones.append(
                    {
                        "zoneName": az.get('ZoneName'),
                        "subnetId": az.get('SubnetId'),
                        "outpostArn": az.get('OutpostArn'),
                    }
                )

            state = lb.get('State') or {}

            return {
                "loadBalancerArn": lb.get('LoadBalancerArn'),
                "name": lb.get('LoadBalancerName'),
                "scheme": lb.get('Scheme'),
                "type": lb.get('Type'),
                "dnsName": lb.get('DNSName'),
                "ipAddressType": lb.get('IpAddressType'),
                "createdTime": lb.get('CreatedTime').isoformat() if lb.get('CreatedTime') else None,
                "state": 
                    {
                        "code": state.get('Code'),
                        "reason": state.get('Reason'),
                    },
                "securityGroups": lb.get('SecurityGroups'),
                "availabilityZones": availability_zones,
                "listeners": listeners,
                "targetGroups": target_groups,
            }

        return await call_sync_with_retries(
            _describe_load_balancer,
            exceptions=(ClientError, BotoCoreError),
            logger=logger,
        )
    
    async def _get_s3_bucket_config(self, bucket_name: str) -> Dict[str, Any]:
        """Get S3 bucket configuration."""
        def _get_config():
            s3 = self._session.client('s3')

            config = {"name": bucket_name}

            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                config["policy"] = json.loads(policy['Policy'])
                config["policyAllowsPublic"] = self._check_s3_policy_public(config["policy"])
                config["policyAllowsPublicWrite"] = self._check_s3_policy_public_write(config["policy"])
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    logger.warning(f"Could not get policy for bucket {bucket_name}: {e}")
                config["policy"] = None
                config["policyAllowsPublic"] = False
                config["policyAllowsPublicWrite"] = False

            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                config["acl"] = acl
                config["aclAllowsPublic"] = self._check_s3_acl_public(acl)
                config["aclAllowsPublicWrite"] = self._check_s3_acl_public_write(acl)
            except ClientError as e:
                logger.warning(f"Could not get ACL for bucket {bucket_name}: {e}")
                config["acl"] = None
                config["aclAllowsPublic"] = False
                config["aclAllowsPublicWrite"] = False

            try:
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

            try:
                location = s3.get_bucket_location(Bucket=bucket_name)
                config["region"] = location.get("LocationConstraint") or "us-east-1"
            except ClientError as e:
                logger.debug(f"Could not determine bucket location for {bucket_name}: {e}")
                config["region"] = None

            try:
                encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                config["encryption"] = {
                    "enabled": bool(rules),
                    "rules": rules,
                }
            except ClientError as e:
                if e.response['Error']['Code'] not in {'ServerSideEncryptionConfigurationNotFoundError', 'AccessDenied'}:
                    logger.debug(f"Could not get encryption for bucket {bucket_name}: {e}")
                config["encryption"] = {"enabled": False}

            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                config["versioning"] = {
                    "enabled": versioning.get("Status") == "Enabled",
                    "mfa_delete": versioning.get("MFADelete") == "Enabled",
                }
            except ClientError as e:
                logger.debug(f"Could not get versioning for bucket {bucket_name}: {e}")
                config["versioning"] = {"enabled": False}

            try:
                logging_cfg = s3.get_bucket_logging(Bucket=bucket_name)
                logging_enabled = logging_cfg.get("LoggingEnabled")
                config["logging"] = {
                    "enabled": logging_enabled is not None,
                    "target_bucket": logging_enabled.get("TargetBucket") if logging_enabled else None,
                }
            except ClientError as e:
                logger.debug(f"Could not get logging configuration for bucket {bucket_name}: {e}")
                config["logging"] = {"enabled": False}

            try:
                lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                config["lifecycle"] = lifecycle.get("Rules", [])
            except ClientError:
                config["lifecycle"] = []

            config["objectsSample"] = []
            try:
                object_listing = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=50)
                for obj in object_listing.get("Contents", []):
                    config["objectsSample"].append(
                        {
                            "key": obj.get("Key"),
                            "size": obj.get("Size"),
                            "modified": obj.get("LastModified").isoformat() if obj.get("LastModified") else None,
                        }
                    )
                config["objectCount"] = object_listing.get("KeyCount")
            except ClientError as e:
                logger.debug(f"Could not list objects for bucket {bucket_name}: {e}")
                config["objectCount"] = None

            return config

        return await call_sync_with_retries(
            _get_config,
            exceptions=(ClientError, BotoCoreError),
            logger=logger,
        )

    async def _get_codebuild_project_config(self, project_name: str) -> Dict[str, Any]:
        """Fetch CodeBuild project configuration."""

        def _get_project():
            codebuild = self._session.client('codebuild')
            response = codebuild.batch_get_projects(names=[project_name])
            projects = response.get('projects', [])
            if not projects:
                return {}

            project = projects[0]

            def _serialize_source(src: Dict[str, Any]) -> Dict[str, Any]:
                if not src:
                    return {}
                auth = src.get('auth') or {}
                return {
                    "type": src.get('type'),
                    "location": src.get('location'),
                    "gitCloneDepth": src.get('gitCloneDepth'),
                    "insecureSsl": src.get('insecureSsl'),
                    "reportBuildStatus": src.get('reportBuildStatus'),
                    "buildspec": src.get('buildspec'),
                    "auth": {
                        "type": auth.get('type'),
                        "resource": auth.get('resource'),
                    },
                }

            def _serialize_artifacts(artifacts: Dict[str, Any]) -> Dict[str, Any]:
                if not artifacts:
                    return {}
                return {
                    "type": artifacts.get('type'),
                    "location": artifacts.get('location'),
                    "path": artifacts.get('path'),
                    "namespaceType": artifacts.get('namespaceType'),
                    "packaging": artifacts.get('packaging'),
                    "encryptionDisabled": artifacts.get('encryptionDisabled'),
                }

            def _serialize_environment(env: Dict[str, Any]) -> Dict[str, Any]:
                if not env:
                    return {}
                return {
                    "type": env.get('type'),
                    "image": env.get('image'),
                    "computeType": env.get('computeType'),
                    "privilegedMode": env.get('privilegedMode'),
                    "environmentVariables": env.get('environmentVariables'),
                }

            def _serialize_webhook(wh: Dict[str, Any]) -> Dict[str, Any]:
                if not wh:
                    return {}
                return {
                    "url": wh.get('url'),
                    "payloadUrl": wh.get('payloadUrl'),
                    "buildType": wh.get('buildType'),
                    "filterGroups": wh.get('filterGroups'),
                    "branchFilter": wh.get('branchFilter'),
                }

            return {
                "arn": project.get('arn'),
                "name": project.get('name'),
                "serviceRole": project.get('serviceRole'),
                "source": _serialize_source(project.get('source') or {}),
                "secondarySources": [
                    _serialize_source(src) for src in project.get('secondarySources', [])
                ],
                "artifacts": _serialize_artifacts(project.get('artifacts') or {}),
                "secondaryArtifacts": [
                    _serialize_artifacts(artifact)
                    for artifact in project.get('secondaryArtifacts', [])
                ],
                "environment": _serialize_environment(project.get('environment') or {}),
                "encryptionKey": project.get('encryptionKey'),
                "logsConfig": project.get('logsConfig'),
                "vpcConfig": project.get('vpcConfig'),
                "badge": project.get('badge'),
                "queuedTimeoutInMinutes": project.get('queuedTimeoutInMinutes'),
                "timeoutInMinutes": project.get('timeoutInMinutes'),
                "webhook": _serialize_webhook(project.get('webhook') or {}),
                "tags": project.get('tags'),
            }

        return await call_sync_with_retries(
            _get_project,
            exceptions=(ClientError, BotoCoreError),
            logger=logger,
        )

    async def _get_iam_role_config(self, role_arn: str) -> Dict[str, Any]:
        """Fetch IAM role configuration, including trust and permission policies."""

        def _get_role():
            iam = self._session.client('iam')

            role_name = role_arn.split('/')[-1]
            role_response = iam.get_role(RoleName=role_name)
            role = role_response.get('Role', {})

            attached_policies: List[Dict[str, Any]] = []
            attached_resp = iam.list_attached_role_policies(RoleName=role_name)
            for policy in attached_resp.get('AttachedPolicies', []):
                attached_policies.append(
                    {
                        "policy_name": policy.get('PolicyName'),
                        "policy_arn": policy.get('PolicyArn'),
                    }
                )

            inline_policies: Dict[str, Any] = {}
            inline_names = iam.list_role_policies(RoleName=role_name).get('PolicyNames', [])
            for policy_name in inline_names:
                inline_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                inline_policies[policy_name] = inline_doc.get('PolicyDocument')

            try:
                tag_response = iam.list_role_tags(RoleName=role_name)
                tags = tag_response.get('Tags', [])
            except ClientError as exc:
                if exc.response['Error']['Code'] == 'NoSuchEntity':
                    tags = []
                else:
                    logger.debug(f"Could not list tags for role {role_name}: {exc}")
                    tags = []

            return {
                "role_name": role.get('RoleName'),
                "arn": role.get('Arn'),
                "path": role.get('Path'),
                "created": role.get('CreateDate').isoformat() if role.get('CreateDate') else None,
                "description": role.get('Description'),
                "max_session_duration": role.get('MaxSessionDuration'),
                "assume_role_policy": role.get('AssumeRolePolicyDocument'),
                "attached_policies": attached_policies,
                "inline_policies": inline_policies,
                "tags": tags,
                "account_id": self.aws_account_id,
                "last_used": role.get('RoleLastUsed'),
            }

        return await call_sync_with_retries(
            _get_role,
            exceptions=(ClientError, BotoCoreError),
            logger=logger,
        )
    
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

    def _check_s3_acl_public_write(self, acl: Dict[str, Any]) -> bool:
        """Check if S3 bucket ACL grants public write access."""
        if not acl or 'Grants' not in acl:
            return False

        public_uris = {
            'http://acs.amazonaws.com/groups/global/AllUsers',
            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
        }

        writable_permissions = {"WRITE", "FULL_CONTROL", "WRITE_ACP"}

        for grant in acl['Grants']:
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') in public_uris and grant.get('Permission') in writable_permissions:
                return True

        return False

    def _principal_allows_public(self, principals: Any) -> bool:
        if principals == "*":
            return True
        if isinstance(principals, dict):
            if principals.get("AWS") == "*":
                return True
            uri = principals.get("URI")
            if isinstance(uri, str) and uri.endswith("AllUsers"):
                return True
            if isinstance(principals.get("AWS"), list) and "*" in principals.get("AWS"):
                return True
        if isinstance(principals, list):
            return any(self._principal_allows_public(p) for p in principals)
        return False

    def _check_s3_policy_public_write(self, policy: Dict[str, Any]) -> bool:
        """Check if S3 bucket policy allows public write access."""
        if not policy or 'Statement' not in policy:
            return False

        for statement in policy['Statement']:
            if statement.get('Effect') != 'Allow':
                continue
            principals = statement.get('Principal')
            if not self._principal_allows_public(principals):
                continue

            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            actions = [action.lower() for action in actions]
            if any(action in {"s3:*", "s3:putobject", "s3:putobjectacl", "s3:deleteobject"} for action in actions):
                return True

        return False

    def _normalize_security_group_permission(self, permission: Dict[str, Any]) -> Dict[str, Any]:
        ipv4_ranges = [
            rng.get('CidrIp')
            for rng in permission.get('IpRanges', []) or []
            if rng.get('CidrIp')
        ]
        ipv6_ranges = [
            rng.get('CidrIpv6')
            for rng in permission.get('Ipv6Ranges', []) or []
            if rng.get('CidrIpv6')
        ]
        prefix_list_ids = [
            entry.get('PrefixListId')
            for entry in permission.get('PrefixListIds', []) or []
            if entry.get('PrefixListId')
        ]
        user_group_pairs = []
        for pair in permission.get('UserIdGroupPairs', []) or []:
            user_group_pairs.append(
                {
                    "groupId": pair.get('GroupId'),
                    "userId": pair.get('UserId'),
                    "peeringStatus": pair.get('PeeringStatus'),
                    "vpcId": pair.get('VpcId'),
                    "vpcPeeringConnectionId": pair.get('VpcPeeringConnectionId'),
                }
            )

        return {
            "ipProtocol": permission.get('IpProtocol'),
            "fromPort": permission.get('FromPort'),
            "toPort": permission.get('ToPort'),
            "ipv4Cidr": ipv4_ranges,
            "ipv6Cidr": ipv6_ranges,
            "prefixListIds": prefix_list_ids,
            "userIdGroupPairs": user_group_pairs,
        }
    
    async def _get_ec2_instance_config(self, instance_id: str) -> Dict[str, Any]:
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
        
        return await call_sync_with_retries(
            _get_config,
            exceptions=(ClientError, BotoCoreError),
            logger=logger,
        )
    
    async def _get_vpc_config(self, vpc_id: str) -> Dict[str, Any]:
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
        
        return await call_sync_with_retries(
            _get_config,
            exceptions=(ClientError, BotoCoreError),
            logger=logger,
        )
    
    async def discover_iam_edges(
        self,
        resource: Optional[ResourceInfo] = None
    ) -> AsyncGenerator[IamPermission, None]:
        """Discover AWS IAM permissions with comprehensive policy evaluation."""
        if not self._session:
            await self.authenticate()
        
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
        
        perms = await call_sync_with_retries(
            _get_comprehensive_iam_permissions,
            exceptions=(ClientError, BotoCoreError),
            logger=logger,
        )
        
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
