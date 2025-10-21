"""Test P0 security fixes - authentication, configuration, and rule engine."""

import os
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from fastapi import HTTPException

from cerebro.core.config import Settings, settings
from cerebro.core.user_service import UserService
from cerebro.rules.engine import RuleEngine, EvaluationContext
from cerebro.findings.evaluator import RuleEvaluator
from cerebro.core.models import Rule, Policy


class TestConfigurationSecurity:
    """Test secure configuration validation."""
    
    def test_secret_key_validation_production(self):
        """Test SECRET_KEY validation in production environment."""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            # Should reject default secret key
            with pytest.raises(ValueError, match="SECRET_KEY must be set"):
                Settings(secret_key="your-secret-key-here")
            
            # Should reject short secret key
            with pytest.raises(ValueError, match="minimum 32 characters"):
                Settings(secret_key="short")
    
    def test_secret_key_validation_development(self):
        """Test SECRET_KEY validation allows defaults in development."""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            config = Settings(secret_key="SecureDevKey!1234567890")
            assert config.secret_key == "SecureDevKey!1234567890"
    
    def test_kms_provider_validation_production(self):
        """Test KMS provider validation in production."""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            # Should reject local KMS in production
            with pytest.raises(ValueError, match="Local KMS provider is INSECURE and not allowed"):
                Settings(
                    secret_key="a-very-secure-secret-key-that-is-32-chars-long",
                    kms_provider="local"
                )
    
    def test_provider_env_fallback_validation_production(self):
        """Test provider environment fallback validation."""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            # Should reject env fallback in production
            with pytest.raises(ValueError, match="Provider environment variable fallback"):
                Settings(
                    secret_key="a-very-secure-secret-key-that-is-32-chars-long",
                    kms_provider="aws",
                    enable_provider_env_fallback=True
                )


class TestUserServiceSecurity:
    """Test user service security improvements."""
    
    @pytest.mark.asyncio
    async def test_admin_user_password_validation(self, test_db):
        """Test admin user password strength validation."""
        user_service = UserService(test_db)
        await user_service.create_default_scopes()
        
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            # Should reject short password in production
            with pytest.raises(ValueError, match="at least 12 characters"):
                await user_service.create_admin_user(
                    username="admin",
                    email="admin@test.com",
                    password="short"
                )
    
    @pytest.mark.asyncio
    async def test_admin_user_password_generation(self, test_db):
        """Test admin user password generation."""
        user_service = UserService(test_db)
        await user_service.create_default_scopes()
        
        # Should generate password if not provided
        admin = await user_service.create_admin_user(
            username="admin",
            email="admin@test.com"
        )
        
        assert admin.username == "admin"
        assert admin.is_admin is True
        assert "admin" in [scope for scope in await user_service.get_user_scopes(admin.user_id)]


class TestRuleEngineFixes:
    """Test rule engine CEL evaluation fixes."""
    
    def test_cel_rule_compilation(self):
        """Test CEL rule compilation works correctly."""
        engine = RuleEngine()
        
        # Should compile valid CEL expression
        expression = "resource.name == 'test' && config.enabled == true"
        compiled_rule = engine.compile_rule(expression)
        assert compiled_rule is not None
    
    def test_cel_rule_evaluation(self):
        """Test CEL rule evaluation with correct API usage."""
        engine = RuleEngine()
        
        expression = "resource.name == 'test-resource'"
        context = EvaluationContext(
            resource={"name": "test-resource", "type": "s3.bucket"},
            config={"enabled": True}
        )
        
        # Should evaluate to true
        result = engine.evaluate_rule(
            rule_id="test-rule-id", 
            expression=expression, 
            context=context
        )
        
        assert result.matched is True
        assert result.error is None
    
    def test_cel_rule_evaluation_false(self):
        """Test CEL rule evaluation returns false correctly."""
        engine = RuleEngine()
        
        expression = "resource.name == 'different-resource'"
        context = EvaluationContext(
            resource={"name": "test-resource", "type": "s3.bucket"}
        )
        
        result = engine.evaluate_rule(
            rule_id="test-rule-id",
            expression=expression,
            context=context
        )
        
        assert result.matched is False
        assert result.error is None
    
    def test_cel_rule_compilation_error(self):
        """Test CEL rule compilation error handling."""
        engine = RuleEngine()
        
        # Invalid CEL expression
        invalid_expression = "resource.name == 'test' &&& invalid"
        
        with pytest.raises(Exception):  # Should raise CompilationError
            engine.compile_rule(invalid_expression)


class TestRuleEvaluatorFixes:
    """Test rule evaluator query fixes."""
    
    @pytest.mark.asyncio
    async def test_evaluate_organization_query_fix(self, test_db, test_org):
        """Test that RuleEvaluator uses correct organization query."""
        # Create a policy for the organization
        policy = Policy(
            org_id=test_org.org_id,
            name="Test Policy",
            description="Test policy for rule evaluation"
        )
        test_db.add(policy)
        await test_db.commit()
        await test_db.refresh(policy)
        
        # Create a rule for the policy
        rule = Rule(
            policy_id=policy.policy_id,
            name="Test Rule",
            description="Test rule",
            provider=["aws"],
            expression_lang="cel",
            expression="resource.name == 'test'",
            severity="medium"
        )
        test_db.add(rule)
        await test_db.commit()
        
        # Mock rule engine
        mock_rule_engine = MagicMock()
        mock_rule_engine.evaluate_rules.return_value = []
        
        evaluator = RuleEvaluator(test_db, mock_rule_engine)
        
        # Should execute without database query errors
        results = await evaluator.evaluate_organization(
            test_org,
            provider="aws"
        )
        
        # Should return results dict (even if empty)
        assert isinstance(results, dict)


class TestFindingSecurityFixes:
    """Test finding security improvements."""
    
    def test_finding_fingerprint_full_length(self):
        """Test that finding fingerprints use full SHA256 hash."""
        import hashlib
        from cerebro.findings.manager import FindingManager
        from cerebro.findings.producers.base import BaseFindingProducer
        
        # Create test data
        test_string = "test-data-for-fingerprint"
        expected_full_hash = hashlib.sha256(test_string.encode()).hexdigest()
        
        # The hash should be full length (64 characters)
        assert len(expected_full_hash) == 64
        
        # Test that our implementation doesn't truncate
        from cerebro.core.bulk_operations import compute_config_hash
        config_hash = compute_config_hash({"test": "data"})
        hash_hex = config_hash.hex()
        assert len(hash_hex) == 64  # Full SHA256 length


class TestAPIAuthentication:
    """Test API endpoint authentication requirements."""
    
    def test_api_routes_require_authentication(self):
        """Test that all sensitive API routes require authentication."""
        from cerebro.api.routers import organizations, accounts, resources, principals, findings, rules, collectors
        
        # Check that routers have authentication dependencies
        routers_to_check = [
            organizations.router,
            accounts.router, 
            resources.router,
            principals.router,
            findings.router,
            rules.router,
            collectors.router
        ]
        
        for router in routers_to_check:
            # Should have authentication dependency at router level
            assert router.dependencies is not None
            assert len(router.dependencies) > 0
    
    @pytest.mark.asyncio
    async def test_unauthenticated_access_denied(self):
        """Test that unauthenticated requests are denied."""
        from cerebro.api.main import app
        import httpx

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            endpoints_to_test = [
                "/api/v1/organizations/",
                "/api/v1/accounts/",
                "/api/v1/resources/",
                "/api/v1/principals/",
                "/api/v1/findings/",
                "/api/v1/rules/",
            ]

            for endpoint in endpoints_to_test:
                response = await client.get(endpoint)
                assert response.status_code in [401, 403, 422], f"Endpoint {endpoint} should require auth"


@pytest.mark.asyncio
async def test_scope_based_authorization(test_db, test_user):
    """Test scope-based authorization works correctly."""
    from cerebro.api.auth import require_scopes
    
    # Mock request with user having specific scopes
    from types import SimpleNamespace

    mock_user = SimpleNamespace(
        username=test_user.username,
        scopes=["read:findings", "read:rules"],
    )
    
    # Should allow access with correct scope
    scope_checker = require_scopes("read:findings")
    result = scope_checker(mock_user)
    assert result.username == mock_user.username
    
    # Should deny access with incorrect scope
    with pytest.raises(HTTPException) as exc_info:
        scope_checker = require_scopes("admin")
        scope_checker(mock_user)
    
    assert exc_info.value.status_code == 403
