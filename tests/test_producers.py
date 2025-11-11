"""Test finding producers."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cerebro.domain.entities import ConfigEntity, ResourceEntity, Severity
from cerebro.findings.producers.aws.bucket_cleartext_key import BucketCleartextKeyProducer
from cerebro.findings.producers.aws.iam_user_without_mfa import (
    IAMUserWithoutMFAProducer,
)
from cerebro.findings.producers.aws.s3_bucket_public import S3BucketPublicProducer
from cerebro.findings.producers.aws.storage_write_access import StorageWriteAccessProducer
from cerebro.findings.producers.gcp.bucket_public_write import GCPBucketPublicWriteProducer
from cerebro.findings.producers.gcp.bucket_secret_artifacts import GCPBucketSecretArtifactProducer
from cerebro.findings.producers.github.public_repo_no_branch_protection import (
    PublicRepoNoBranchProtectionProducer,
)
from cerebro.findings.producers.m365.guest_admin import M365GuestAdminProducer
from cerebro.findings.producers.m365.inactive_admin import (
    M365InactivePrivilegedUserProducer,
)
from cerebro.findings.producers.m365.sharepoint_anonymous_link import (
    M365SharePointAnonymousLinkProducer,
)
from cerebro.findings.producers.okta.dormant_admin import OktaDormantAdminProducer
from cerebro.findings.producers.telemetry.repo_secret_key import RepoSecretKeyProducer
from cerebro.telemetry.schemas import SecretsScanResult


class TestGitHubProducers:
    """Test GitHub finding producers."""

    def test_public_repo_branch_protection_producer(self):
        """Test GitHub public repo without branch protection producer."""
        producer = PublicRepoNoBranchProtectionProducer()

        # Test resource that should trigger finding
        resource = ResourceEntity(
            external_id="test-org/public-repo",
            resource_type="github.repo",
            provider="github",
            name="public-repo"
        )

        config = ConfigEntity(
            resource_external_id="test-org/public-repo",
            captured_at=datetime.utcnow(),
            normalized_config={
                "visibility": "public",
                "branchProtection": {"requirePR": False},
                "archived": False,
                "fullName": "test-org/public-repo",
                "defaultBranch": "main"
            }
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert "public-repo" in finding.title
        assert finding.evidence["visibility"] == "public"
        assert not finding.evidence["branch_protection"]["enabled"]

    def test_public_repo_with_protection_no_finding(self):
        """Test that repos with branch protection don't trigger findings."""
        producer = PublicRepoNoBranchProtectionProducer()

        resource = ResourceEntity(
            external_id="test-org/protected-repo",
            resource_type="github.repo",
            provider="github",
            name="protected-repo"
        )

        config = ConfigEntity(
            resource_external_id="test-org/protected-repo",
            captured_at=datetime.utcnow(),
            normalized_config={
                "visibility": "public",
                "branchProtection": {"requirePR": True, "requiredReviewers": 2},
                "archived": False
            }
        )

        findings = producer.evaluate(resource, config)
        assert len(findings) == 0


class TestAWSProducers:
    """Test AWS finding producers."""

    def test_s3_bucket_public_producer(self):
        """Test S3 public bucket producer."""
        producer = S3BucketPublicProducer()

        resource = ResourceEntity(
            external_id="test-public-bucket",
            resource_type="aws.s3.bucket",
            provider="aws",
            name="test-public-bucket"
        )

        config = ConfigEntity(
            resource_external_id="test-public-bucket",
            captured_at=datetime.utcnow(),
            normalized_config={
                "policyAllowsPublic": True,
                "aclAllowsPublic": False,
                "blockPublicAccess": {"effective": False},
                "region": "us-east-1"
            }
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert "test-public-bucket" in finding.title
        assert "bucket_policy" in finding.evidence["access_vectors"]

    def test_s3_bucket_cleartext_key_producer(self):
        producer = BucketCleartextKeyProducer()

        resource = ResourceEntity(
            external_id="secret-bucket",
            resource_type="aws.s3.bucket",
            provider="aws",
            name="secret-bucket",
        )

        config = ConfigEntity(
            resource_external_id="secret-bucket",
            captured_at=datetime.utcnow(),
            normalized_config={
                "objectsSample": [
                    {"key": "backups/api_keys.env", "size": 120, "modified": datetime.utcnow().isoformat()},
                    {"key": "README.md", "size": 80, "modified": datetime.utcnow().isoformat()},
                ],
                "policyAllowsPublic": True,
                "aclAllowsPublic": False,
                "blockPublicAccess": {"effective": False},
                "region": "us-west-2",
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert "api_keys" in finding.evidence["matched_objects"][0]["key"]

    def test_storage_write_access_producer(self):
        producer = StorageWriteAccessProducer()

        resource = ResourceEntity(
            external_id="writeable-bucket",
            resource_type="aws.s3.bucket",
            provider="aws",
            name="writeable-bucket",
        )

        config = ConfigEntity(
            resource_external_id="writeable-bucket",
            captured_at=datetime.utcnow(),
            normalized_config={
                "policyAllowsPublicWrite": True,
                "aclAllowsPublicWrite": False,
                "blockPublicAccess": {"effective": False},
                "region": "us-east-2",
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert finding.evidence["policy_allows_public_write"] is True

    def test_iam_user_without_mfa_producer(self):
        """Test IAM user without MFA producer."""
        producer = IAMUserWithoutMFAProducer()

        resource = ResourceEntity(
            external_id="arn:aws:iam::123456789012:user/testuser",
            resource_type="aws.iam.user",
            provider="aws",
            name="testuser"
        )

        config = ConfigEntity(
            resource_external_id="arn:aws:iam::123456789012:user/testuser",
            captured_at=datetime.utcnow(),
            normalized_config={
                "console_access": True,
                "mfa": {"enabled": False},
                "password_last_used": "2024-01-01T10:00:00Z",
                "attached_policies": ["ReadOnlyAccess"],
                "groups": []
            }
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert "testuser" in finding.title
        assert finding.evidence["console_access"] is True
        assert finding.evidence["mfa_enabled"] is False

    def test_iam_admin_user_without_mfa_critical_severity(self):
        """Test that admin users without MFA get critical severity."""
        producer = IAMUserWithoutMFAProducer()

        resource = ResourceEntity(
            external_id="arn:aws:iam::123456789012:user/admin",
            resource_type="aws.iam.user",
            provider="aws",
            name="admin"
        )

        config = ConfigEntity(
            resource_external_id="arn:aws:iam::123456789012:user/admin",
            captured_at=datetime.utcnow(),
            normalized_config={
                "console_access": True,
                "mfa": {"enabled": False},
                "password_last_used": "2024-01-01T10:00:00Z",
                "attached_policies": ["AdministratorAccess"],
                "groups": []
            }
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL  # Escalated for admin
        assert "has_admin_privileges" in finding.evidence["risk_factors"]


class TestGCPProducers:
    """Test GCP storage producers."""

    def test_gcp_bucket_public_write(self):
        producer = GCPBucketPublicWriteProducer()

        resource = ResourceEntity(
            external_id="projects/acme/buckets/public-bucket",
            resource_type="gcp.storage.bucket",
            provider="gcp",
            name="public-bucket",
        )

        config = ConfigEntity(
            resource_external_id="projects/acme/buckets/public-bucket",
            captured_at=datetime.utcnow(),
            normalized_config={
                "iam_bindings": [
                    {
                        "role": "roles/storage.objectAdmin",
                        "members": ["allUsers"],
                    }
                ],
                "uniform_bucket_level_access": {"enabled": False},
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert finding.evidence["iam_bindings"][0]["members"] == ["allUsers"]

    def test_gcp_bucket_secret_artifacts(self):
        producer = GCPBucketSecretArtifactProducer()

        resource = ResourceEntity(
            external_id="projects/acme/buckets/exposed-secrets",
            resource_type="gcp.storage.bucket",
            provider="gcp",
            name="exposed-secrets",
        )

        config = ConfigEntity(
            resource_external_id="projects/acme/buckets/exposed-secrets",
            captured_at=datetime.utcnow(),
            normalized_config={
                "is_public": True,
                "objectsSample": [
                    {"key": "config/service_account.json", "size": 2048},
                    {"key": "readme.txt", "size": 128},
                ],
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert "service_account.json" in finding.evidence["matched_objects"][0]["key"]


class TestProducerRegistry:
    """Test producer registry functionality."""

    def test_producer_auto_discovery(self):
        """Test that producers are auto-discovered."""
        from cerebro.findings.producers import producer_registry

        producers = producer_registry.list_producers()

        # Should have discovered our producers
        expected_producers = [
            "PublicRepoNoBranchProtectionProducer",
            "S3BucketPublicProducer",
            "IAMUserWithoutMFAProducer",
            "S3BucketUnencryptedProducer",
            "EC2InstancePublicIPProducer",
            "OktaDormantAdminProducer",
            "M365GuestAdminProducer",
            "M365InactivePrivilegedUserProducer",
            "BucketCleartextKeyProducer",
            "StorageWriteAccessProducer",
            "RepoSecretKeyProducer",
            "GCPBucketPublicWriteProducer",
            "GCPBucketSecretArtifactProducer",
            "M365SharePointAnonymousLinkProducer",
        ]

        for expected in expected_producers:
            assert expected in producers

    def test_get_producers_for_resource(self):
        """Test getting producers for specific resources."""
        from cerebro.findings.producers import producer_registry

        # Test GitHub resource
        github_producers = producer_registry.get_producers_for_resource(
            "github",
            "github.repo",
        )
        assert len(github_producers) > 0
        assert any(
            "github" in {source.lower() for source in producer.desired_sources}
            for producer in github_producers
        )

        # Test AWS S3 resource
        s3_producers = producer_registry.get_producers_for_resource(
            "aws",
            "aws.s3.bucket",
        )


class TestTelemetryProducers:
    """Test telemetry-based producers."""

    def test_repo_secret_key_producer(self):
        producer = RepoSecretKeyProducer()

        resource = ResourceEntity(
            external_id="org/repo",
            resource_type="github.repo",
            provider="github",
            name="repo",
        )

        secret_payload = SecretsScanResult(
            detector_name="trufflehog",
            file_path="config/.env",
            line_number=12,
            secret_type="openai_api_key",
            verified=False,
            raw_result={"redacted": "sk-abc123xyz456", "DetectorType": "openai"},
        )

        config = ConfigEntity(
            resource_external_id="org/repo",
            captured_at=datetime.utcnow(),
            normalized_config={
                "secrets": [
                    {
                        "raw_payload": secret_payload.model_dump(),
                        "commit_sha": "deadbeef",
                    }
                ]
            },
        )

        context = {"rule_id": uuid4(), "detected_at": datetime.utcnow()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert "OpenAI API key" in finding.summary
        assert finding.evidence["validation"]["status"] in {"format_match", "inferred", "verified"}


class TestIdentityProducers:
    """Test identity-focused producers."""

    def test_okta_dormant_admin(self):
        producer = OktaDormantAdminProducer()

        resource = ResourceEntity(
            external_id="00u123",
            resource_type="okta.user",
            provider="okta",
            name="admin@example.com",
        )

        old_login = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
        created = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()

        config = ConfigEntity(
            resource_external_id="00u123",
            captured_at=datetime.utcnow(),
            normalized_config={
                "status": "ACTIVE",
                "admin_roles": ["SUPER_ADMIN"],
                "login": "admin@example.com",
                "email": "admin@example.com",
                "last_login": old_login,
                "created": created,
                "mfa_enrolled": True,
                "applications": [],
                "groups": [],
                "is_service_account": False,
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert "without sign-in activity" in finding.summary.lower()
        assert "SUPER_ADMIN" in finding.evidence["admin_roles"][0]

    def test_okta_dormant_admin_recent_login_no_finding(self):
        producer = OktaDormantAdminProducer()

        resource = ResourceEntity(
            external_id="00u456",
            resource_type="okta.user",
            provider="okta",
            name="ops@example.com",
        )

        recent_login = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()

        config = ConfigEntity(
            resource_external_id="00u456",
            captured_at=datetime.utcnow(),
            normalized_config={
                "status": "ACTIVE",
                "admin_roles": ["ORG_ADMIN"],
                "login": "ops@example.com",
                "last_login": recent_login,
                "is_service_account": False,
            },
        )

        findings = producer.evaluate(resource, config)
        assert len(findings) == 0

    def test_m365_guest_admin(self):
        producer = M365GuestAdminProducer()

        resource = ResourceEntity(
            external_id="user-guest-1",
            resource_type="m365.user",
            provider="m365",
            name="guest-admin@example.com",
        )

        config = ConfigEntity(
            resource_external_id="user-guest-1",
            captured_at=datetime.utcnow(),
            normalized_config={
                "is_guest": True,
                "account_enabled": True,
                "role_names": ["Global Administrator"],
                "directory_roles": [
                    {
                        "id": "role1",
                        "display_name": "Global Administrator",
                        "role_template_id": "62e90394-69f5-4237-9190-012177145e10",
                    }
                ],
                "user_principal_name": "guest-admin@example.com",
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert "guest" in finding.summary.lower()

    def test_m365_inactive_privileged_user(self):
        producer = M365InactivePrivilegedUserProducer()

        resource = ResourceEntity(
            external_id="user-admin-1",
            resource_type="m365.user",
            provider="m365",
            name="admin@example.com",
        )

        stale_login = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()

        config = ConfigEntity(
            resource_external_id="user-admin-1",
            captured_at=datetime.utcnow(),
            normalized_config={
                "account_enabled": True,
                "directory_roles": [
                    {
                        "id": "role1",
                        "display_name": "Global Administrator",
                    }
                ],
                "role_names": ["Global Administrator"],
                "last_login": stale_login,
                "created": (datetime.now(timezone.utc) - timedelta(days=200)).isoformat(),
                "user_principal_name": "admin@example.com",
                "mfa_enrolled": False,
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert "dormant" in finding.title.lower()
        assert "inactive_account" in finding.evidence["risk_factors"]

    def test_m365_inactive_privileged_user_recent_login_no_finding(self):
        producer = M365InactivePrivilegedUserProducer()

        resource = ResourceEntity(
            external_id="user-admin-2",
            resource_type="m365.user",
            provider="m365",
            name="admin2@example.com",
        )

        config = ConfigEntity(
            resource_external_id="user-admin-2",
            captured_at=datetime.utcnow(),
            normalized_config={
                "account_enabled": True,
                "directory_roles": [
                    {
                        "id": "role2",
                        "display_name": "Exchange Administrator",
                    }
                ],
                "last_login": (datetime.now(timezone.utc) - timedelta(days=10)).isoformat(),
            },
        )

        findings = producer.evaluate(resource, config)
        assert len(findings) == 0


class TestM365StorageProducers:
    """Test SharePoint storage exposure producers."""

    def test_sharepoint_anonymous_edit_link(self):
        producer = M365SharePointAnonymousLinkProducer()

        resource = ResourceEntity(
            external_id="site-1",
            resource_type="m365.sharepoint.site",
            provider="m365",
            name="Project Docs",
        )

        config = ConfigEntity(
            resource_external_id="site-1",
            captured_at=datetime.utcnow(),
            normalized_config={
                "web_url": "https://contoso.sharepoint.com/sites/project",
                "permissions": [
                    {
                        "link": {"scope": "anonymous", "type": "edit"},
                        "roles": ["write"],
                    }
                ],
                "sharing_capability": "anonymousAccess",
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert finding.evidence["anonymous_links"][0]["scope"] == "anonymous"
