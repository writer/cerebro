"""Test finding producers."""

import pytest
from datetime import datetime
from uuid import uuid4

from cerebro.domain.entities import ResourceEntity, ConfigEntity, Severity
from cerebro.findings.producers.github.public_repo_no_branch_protection import PublicRepoNoBranchProtectionProducer
from cerebro.findings.producers.aws.s3_bucket_public import S3BucketPublicProducer
from cerebro.findings.producers.aws.iam_user_without_mfa import IAMUserWithoutMFAProducer


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
            "EC2InstancePublicIPProducer"
        ]
        
        for expected in expected_producers:
            assert expected in producers
    
    def test_get_producers_for_resource(self):
        """Test getting producers for specific resources."""
        from cerebro.findings.producers import producer_registry
        
        # Test GitHub resource
        github_producers = producer_registry.get_producers_for_resource("github", "github.repo")
        assert len(github_producers) > 0
        assert any("GitHub" in producer.__class__.__name__ for producer in github_producers)
        
        # Test AWS S3 resource
        s3_producers = producer_registry.get_producers_for_resource("aws", "aws.s3.bucket")
        assert len(s3_producers) > 0
        assert any("S3" in producer.__class__.__name__ for producer in s3_producers)
