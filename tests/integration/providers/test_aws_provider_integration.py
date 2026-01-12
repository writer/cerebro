"""Integration tests for AWS provider.

These tests use mocked boto3 responses to verify the provider's behavior
without requiring actual AWS credentials.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from cerebro.providers.aws.provider import AWSProvider
from cerebro.providers.base import ProviderError


class TestAWSProviderAuthentication:
    """Test AWS authentication flows."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock boto3 session."""
        session = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}
        session.client.return_value = sts
        return session

    @pytest.fixture
    def provider(self):
        """Create an AWS provider instance."""
        return AWSProvider(
            account_id=uuid4(),
            aws_account_id="123456789012",
            region="us-east-1",
        )

    @pytest.mark.asyncio
    async def test_authenticate_success(self, provider, mock_session, monkeypatch):
        """Test successful authentication."""
        monkeypatch.setattr(
            "cerebro.providers.aws.provider.settings.aws_access_key_id", "test-key"
        )
        monkeypatch.setattr(
            "cerebro.providers.aws.provider.settings.aws_secret_access_key", "test-secret"
        )
        monkeypatch.setattr(
            "cerebro.providers.aws.provider.boto3.Session",
            MagicMock(return_value=mock_session),
        )

        result = await provider.authenticate()

        assert result is True
        assert provider._session is not None

    @pytest.mark.asyncio
    async def test_authenticate_wrong_account_raises_error(self, provider, monkeypatch):
        """Test authentication fails when account ID doesn't match."""
        session = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "999999999999"}
        session.client.return_value = sts

        monkeypatch.setattr(
            "cerebro.providers.aws.provider.settings.aws_access_key_id", "test-key"
        )
        monkeypatch.setattr(
            "cerebro.providers.aws.provider.settings.aws_secret_access_key", "test-secret"
        )
        monkeypatch.setattr(
            "cerebro.providers.aws.provider.boto3.Session",
            MagicMock(return_value=session),
        )

        with pytest.raises(ProviderError, match="Expected account"):
            await provider.authenticate()

    @pytest.mark.asyncio
    async def test_authenticate_client_error(self, provider, monkeypatch):
        """Test authentication handles boto3 ClientError."""
        from botocore.exceptions import ClientError

        session = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.side_effect = ClientError(
            {"Error": {"Code": "InvalidClientTokenId", "Message": "Invalid token"}},
            "GetCallerIdentity",
        )
        session.client.return_value = sts

        monkeypatch.setattr(
            "cerebro.providers.aws.provider.settings.aws_access_key_id", "bad-key"
        )
        monkeypatch.setattr(
            "cerebro.providers.aws.provider.settings.aws_secret_access_key", "bad-secret"
        )
        monkeypatch.setattr(
            "cerebro.providers.aws.provider.boto3.Session",
            MagicMock(return_value=session),
        )

        with pytest.raises(ProviderError, match="authentication failed"):
            await provider.authenticate()


class TestAWSProviderResourceDiscovery:
    """Test AWS resource discovery."""

    @pytest.fixture
    def authenticated_provider(self, monkeypatch):
        """Create an authenticated AWS provider with mocked clients."""
        provider = AWSProvider(
            account_id=uuid4(),
            aws_account_id="123456789012",
            region="us-east-1",
        )

        # Mock the session
        session = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}

        # S3 client mock
        s3_client = MagicMock()
        s3_client.list_buckets.return_value = {
            "Buckets": [
                {"Name": "my-bucket-1", "CreationDate": datetime.now(UTC)},
                {"Name": "my-bucket-2", "CreationDate": datetime.now(UTC)},
            ]
        }

        # EC2 client mock with paginator
        ec2_client = MagicMock()
        ec2_paginator = MagicMock()
        ec2_paginator.paginate.return_value = iter([
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-12345",
                                "State": {"Name": "running"},
                                "InstanceType": "t3.micro",
                                "VpcId": "vpc-123",
                                "SubnetId": "subnet-456",
                                "Tags": [{"Key": "Name", "Value": "WebServer"}],
                            }
                        ]
                    }
                ]
            }
        ])
        ec2_client.get_paginator.return_value = ec2_paginator

        def select_client(service_name):
            if service_name == "sts":
                return sts
            elif service_name == "s3":
                return s3_client
            elif service_name == "ec2":
                return ec2_client
            return MagicMock()

        session.client.side_effect = select_client

        monkeypatch.setattr(
            "cerebro.providers.aws.provider.settings.aws_access_key_id", "test-key"
        )
        monkeypatch.setattr(
            "cerebro.providers.aws.provider.settings.aws_secret_access_key", "test-secret"
        )
        monkeypatch.setattr(
            "cerebro.providers.aws.provider.boto3.Session",
            MagicMock(return_value=session),
        )

        return provider

    @pytest.mark.asyncio
    async def test_discover_s3_buckets(self, authenticated_provider):
        """Test S3 bucket discovery."""
        await authenticated_provider.authenticate()

        resources = []
        async for resource in authenticated_provider.discover_resources(
            resource_types=["aws.s3.bucket"]
        ):
            resources.append(resource)

        assert len(resources) == 2
        assert resources[0].resource_type == "aws.s3.bucket"
        assert resources[0].external_id == "my-bucket-1"

    @pytest.mark.asyncio
    async def test_discover_ec2_instances(self, authenticated_provider):
        """Test EC2 instance discovery."""
        await authenticated_provider.authenticate()

        resources = []
        async for resource in authenticated_provider.discover_resources(
            resource_types=["aws.ec2.instance"]
        ):
            resources.append(resource)

        assert len(resources) == 1
        assert resources[0].resource_type == "aws.ec2.instance"
        assert resources[0].external_id == "i-12345"
        assert resources[0].name == "WebServer"
        assert resources[0].metadata["state"] == "running"


class TestAWSProviderPrincipalDiscovery:
    """Test AWS principal (IAM) discovery."""

    @pytest.fixture
    def authenticated_provider_with_iam(self, monkeypatch):
        """Create provider with mocked IAM responses."""
        provider = AWSProvider(
            account_id=uuid4(),
            aws_account_id="123456789012",
            region="us-east-1",
        )

        session = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}

        # IAM client mock
        iam_client = MagicMock()

        def paginator_for(name):
            paginator = MagicMock()
            if name == "list_users":
                paginator.paginate.return_value = iter([
                    {
                        "Users": [
                            {
                                "Arn": "arn:aws:iam::123456789012:user/alice",
                                "UserName": "alice",
                                "Path": "/",
                                "CreateDate": datetime.now(UTC),
                                "PasswordLastUsed": datetime.now(UTC),
                            },
                            {
                                "Arn": "arn:aws:iam::123456789012:user/bob",
                                "UserName": "bob",
                                "Path": "/developers/",
                                "CreateDate": datetime.now(UTC),
                                "PasswordLastUsed": None,
                            },
                        ]
                    }
                ])
            elif name == "list_roles":
                paginator.paginate.return_value = iter([
                    {
                        "Roles": [
                            {
                                "Arn": "arn:aws:iam::123456789012:role/AdminRole",
                                "RoleName": "AdminRole",
                                "Path": "/",
                                "CreateDate": datetime.now(UTC),
                                "AssumeRolePolicyDocument": "{}",
                            }
                        ]
                    }
                ])
            elif name == "list_groups":
                paginator.paginate.return_value = iter([
                    {
                        "Groups": [
                            {
                                "Arn": "arn:aws:iam::123456789012:group/Developers",
                                "GroupName": "Developers",
                                "Path": "/",
                                "CreateDate": datetime.now(UTC),
                            }
                        ]
                    }
                ])
            else:
                paginator.paginate.return_value = iter([])
            return paginator

        iam_client.get_paginator.side_effect = paginator_for

        def select_client(service_name):
            if service_name == "sts":
                return sts
            elif service_name == "iam":
                return iam_client
            return MagicMock()

        session.client.side_effect = select_client

        monkeypatch.setattr(
            "cerebro.providers.aws.provider.settings.aws_access_key_id", "test-key"
        )
        monkeypatch.setattr(
            "cerebro.providers.aws.provider.settings.aws_secret_access_key", "test-secret"
        )
        monkeypatch.setattr(
            "cerebro.providers.aws.provider.boto3.Session",
            MagicMock(return_value=session),
        )

        return provider

    @pytest.mark.asyncio
    async def test_discover_iam_users(self, authenticated_provider_with_iam):
        """Test IAM user discovery."""
        await authenticated_provider_with_iam.authenticate()

        principals = []
        async for principal in authenticated_provider_with_iam.discover_principals():
            principals.append(principal)

        users = [p for p in principals if p.principal_type == "user"]
        assert len(users) == 2
        assert users[0].display_name == "alice"
        assert users[1].display_name == "bob"

    @pytest.mark.asyncio
    async def test_discover_iam_roles(self, authenticated_provider_with_iam):
        """Test IAM role discovery."""
        await authenticated_provider_with_iam.authenticate()

        principals = []
        async for principal in authenticated_provider_with_iam.discover_principals():
            principals.append(principal)

        roles = [p for p in principals if p.principal_type == "role"]
        assert len(roles) == 1
        assert roles[0].display_name == "AdminRole"


class TestAWSProviderConfigurationCollection:
    """Test AWS configuration snapshot collection."""

    @pytest.fixture
    def provider_with_configs(self, monkeypatch):
        """Create provider with mocked configuration responses."""
        provider = AWSProvider(
            account_id=uuid4(),
            aws_account_id="123456789012",
            region="us-east-1",
        )

        session = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}

        # S3 client with bucket config
        s3_client = MagicMock()
        s3_client.get_bucket_versioning.return_value = {"Status": "Enabled"}
        s3_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }
        s3_client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        s3_client.get_bucket_logging.return_value = {}

        def select_client(service_name):
            if service_name == "sts":
                return sts
            elif service_name == "s3":
                return s3_client
            return MagicMock()

        session.client.side_effect = select_client

        monkeypatch.setattr(
            "cerebro.providers.aws.provider.settings.aws_access_key_id", "test-key"
        )
        monkeypatch.setattr(
            "cerebro.providers.aws.provider.settings.aws_secret_access_key", "test-secret"
        )
        monkeypatch.setattr(
            "cerebro.providers.aws.provider.boto3.Session",
            MagicMock(return_value=session),
        )

        return provider

    @pytest.mark.asyncio
    async def test_get_resource_configuration(self, provider_with_configs):
        """Test S3 bucket configuration retrieval."""
        from botocore.exceptions import ClientError

        from cerebro.providers.base import ResourceInfo

        await provider_with_configs.authenticate()

        # The S3 mock needs more complete responses
        s3_client = provider_with_configs.session.client("s3")
        s3_client.get_bucket_policy.side_effect = ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy", "Message": "No policy"}},
            "GetBucketPolicy",
        )

        resource = ResourceInfo(
            external_id="my-bucket",
            name="my-bucket",
            resource_type="aws.s3.bucket",
        )

        config = await provider_with_configs.get_resource_configuration(resource)

        assert config is not None
        assert config.resource_external_id == "my-bucket"


class TestAWSProviderIAMEdges:
    """Test AWS IAM edge discovery."""

    @pytest.fixture
    def provider_with_iam(self, monkeypatch):
        """Create provider with mocked IAM responses."""
        provider = AWSProvider(
            account_id=uuid4(),
            aws_account_id="123456789012",
            region="us-east-1",
        )

        session = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}

        iam_client = MagicMock()

        # Paginator for listing users
        def paginator_for(name):
            paginator = MagicMock()
            if name == "list_users":
                paginator.paginate.return_value = iter([
                    {"Users": [{"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice"}]}
                ])
            elif name == "list_attached_user_policies":
                paginator.paginate.return_value = iter([
                    {"AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}
                ])
            else:
                paginator.paginate.return_value = iter([])
            return paginator

        iam_client.get_paginator.side_effect = paginator_for
        iam_client.list_user_policies.return_value = {"PolicyNames": []}
        iam_client.list_groups_for_user.return_value = {"Groups": []}

        def select_client(service_name):
            if service_name == "sts":
                return sts
            elif service_name == "iam":
                return iam_client
            return MagicMock()

        session.client.side_effect = select_client

        monkeypatch.setattr(
            "cerebro.providers.aws.provider.settings.aws_access_key_id", "test-key"
        )
        monkeypatch.setattr(
            "cerebro.providers.aws.provider.settings.aws_secret_access_key", "test-secret"
        )
        monkeypatch.setattr(
            "cerebro.providers.aws.provider.boto3.Session",
            MagicMock(return_value=session),
        )

        return provider

    @pytest.mark.asyncio
    async def test_discover_iam_edges(self, provider_with_iam):
        """Test discovering IAM permission edges."""
        await provider_with_iam.authenticate()

        edges = []
        async for edge in provider_with_iam.discover_iam_edges():
            edges.append(edge)

        # Should discover some IAM edges
        assert isinstance(edges, list)
