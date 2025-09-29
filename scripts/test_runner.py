#!/usr/bin/env python3
"""Comprehensive test runner for Cerebro Security System of Record."""

import os
import sys
import subprocess
import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Any

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestRunner:
    """Comprehensive test runner for all phases of Cerebro improvements."""
    
    def __init__(self):
        self.root_dir = Path(__file__).parent.parent
        self.test_results = {
            "type_checking": False,
            "linting": False, 
            "formatting": False,
            "unit_tests": False,
            "integration_tests": False,
            "security_tests": False,
            "performance_tests": False,
            "coverage": 0.0
        }
        
    def run_command(self, cmd: List[str], description: str) -> bool:
        """Run a command and return success status."""
        logger.info(f"Running {description}...")
        try:
            result = subprocess.run(
                cmd,
                cwd=self.root_dir,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                logger.info(f"✅ {description} passed")
                if result.stdout.strip():
                    logger.debug(f"Output: {result.stdout.strip()}")
                return True
            else:
                logger.error(f"❌ {description} failed")
                if result.stderr.strip():
                    logger.error(f"Error: {result.stderr.strip()}")
                if result.stdout.strip():
                    logger.error(f"Output: {result.stdout.strip()}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error(f"❌ {description} timed out")
            return False
        except Exception as e:
            logger.error(f"❌ {description} failed with exception: {e}")
            return False
    
    def run_type_checking(self) -> bool:
        """Run MyPy type checking."""
        return self.run_command(
            ["python", "-m", "mypy", "src/cerebro"],
            "MyPy type checking"
        )
    
    def run_linting(self) -> bool:
        """Run Ruff linting."""
        return self.run_command(
            ["python", "-m", "ruff", "check", "src/", "tests/"],
            "Ruff linting"
        )
    
    def run_formatting_check(self) -> bool:
        """Check code formatting with Black and isort."""
        black_result = self.run_command(
            ["python", "-m", "black", "--check", "src/", "tests/"],
            "Black formatting check"
        )
        
        isort_result = self.run_command(
            ["python", "-m", "isort", "--check-only", "src/", "tests/"],
            "isort import sorting check"
        )
        
        return black_result and isort_result
    
    def run_unit_tests(self) -> bool:
        """Run unit tests."""
        return self.run_command(
            ["python", "-m", "pytest", "tests/", "-v", "-m", "not slow and not integration"],
            "Unit tests"
        )
    
    def run_integration_tests(self) -> bool:
        """Run integration tests."""
        return self.run_command(
            ["python", "-m", "pytest", "tests/", "-v", "-m", "integration"],
            "Integration tests"
        )
    
    def run_security_tests(self) -> bool:
        """Run security-focused tests."""
        return self.run_command(
            ["python", "-m", "pytest", "tests/test_security_fixes.py", "tests/test_jwt_security.py", "-v"],
            "Security tests"
        )
    
    def run_performance_tests(self) -> bool:
        """Run performance tests."""
        return self.run_command(
            ["python", "-m", "pytest", "tests/test_performance_improvements.py", "-v"],
            "Performance tests"
        )
    
    def run_coverage_analysis(self) -> bool:
        """Run test coverage analysis."""
        result = self.run_command(
            ["python", "-m", "pytest", "--cov=cerebro", "--cov-report=term", "--cov-report=html"],
            "Test coverage analysis"
        )
        
        # Try to extract coverage percentage
        try:
            coverage_result = subprocess.run(
                ["python", "-m", "coverage", "report", "--format=json"],
                cwd=self.root_dir,
                capture_output=True,
                text=True
            )
            
            if coverage_result.returncode == 0:
                import json
                coverage_data = json.loads(coverage_result.stdout)
                self.test_results["coverage"] = coverage_data.get("totals", {}).get("percent_covered", 0.0)
                logger.info(f"Test coverage: {self.test_results['coverage']:.1f}%")
        except Exception as e:
            logger.warning(f"Could not extract coverage percentage: {e}")
        
        return result
    
    def setup_test_environment(self) -> bool:
        """Set up test environment variables."""
        logger.info("Setting up test environment...")
        
        test_env = {
            "ENVIRONMENT": "test",
            "SECRET_KEY": "test-secret-key-that-is-32-characters-long-for-testing",
            "DATABASE_URL": "postgresql://test:test@localhost/cerebro_test",
            "REDIS_URL": "redis://localhost:6379/1",
            "KMS_PROVIDER": "local",
            "ENABLE_PROVIDER_ENV_FALLBACK": "true",
            "LOG_LEVEL": "INFO"
        }
        
        for key, value in test_env.items():
            os.environ[key] = value
        
        return True
    
    def check_dependencies(self) -> bool:
        """Check that required dependencies are available."""
        logger.info("Checking test dependencies...")
        
        required_modules = [
            "pytest",
            "pytest_asyncio", 
            "pytest_cov",
            "mypy",
            "ruff",
            "black",
            "isort"
        ]
        
        missing_modules = []
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing_modules.append(module)
        
        if missing_modules:
            logger.error(f"Missing required test dependencies: {missing_modules}")
            logger.error("Run: pip install -e .[dev] or uv sync --extra dev")
            return False
        
        logger.info("✅ All test dependencies available")
        return True
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run complete test suite."""
        logger.info("🚀 Starting comprehensive Cerebro test suite")
        
        # Setup
        if not self.setup_test_environment():
            return {"error": "Failed to setup test environment"}
        
        if not self.check_dependencies():
            return {"error": "Missing test dependencies"}
        
        # Run all test phases
        test_phases = [
            ("type_checking", self.run_type_checking),
            ("linting", self.run_linting),
            ("formatting", self.run_formatting_check),
            ("unit_tests", self.run_unit_tests),
            ("security_tests", self.run_security_tests),
            ("performance_tests", self.run_performance_tests),
            ("coverage", self.run_coverage_analysis),
        ]
        
        for phase_name, phase_func in test_phases:
            self.test_results[phase_name] = phase_func()
        
        # Summary
        self.print_test_summary()
        
        return self.test_results
    
    def print_test_summary(self):
        """Print comprehensive test results summary."""
        logger.info("\n" + "="*60)
        logger.info("🧪 CEREBRO TEST SUITE RESULTS")
        logger.info("="*60)
        
        passed_tests = sum(1 for result in self.test_results.values() if result is True)
        total_tests = len([k for k in self.test_results.keys() if k != "coverage"])
        
        for test_name, result in self.test_results.items():
            if test_name == "coverage":
                logger.info(f"📊 Coverage: {result:.1f}%")
            else:
                status = "✅ PASS" if result else "❌ FAIL"
                logger.info(f"{status} {test_name.replace('_', ' ').title()}")
        
        logger.info(f"\n🎯 Overall: {passed_tests}/{total_tests} test phases passed")
        
        if passed_tests == total_tests:
            logger.info("🎉 ALL TESTS PASSED - System ready for production!")
        else:
            logger.warning("⚠️  Some tests failed - review and fix before deployment")
        
        logger.info("="*60)


async def test_system_health():
    """Test basic system health and imports."""
    logger.info("🔍 Testing system health and imports...")
    
    try:
        # Test core imports
        from cerebro.core.config import settings
        from cerebro.core.database import engine
        from cerebro.api.main import app
        from cerebro.core.security.jwt import JWTService
        from cerebro.core.security.key_store import JWTKeyStore
        from cerebro.core.bulk_operations import BulkOperations
        from cerebro.metrics.collection_metrics import collection_metrics
        
        logger.info("✅ All core modules import successfully")
        
        # Test configuration validation
        assert settings.secret_key is not None
        assert settings.collection_concurrency_limit > 0
        assert settings.jwt_algorithm in ["RS256", "HS256"]
        
        logger.info("✅ Configuration validation passed")
        
        # Test database engine configuration
        assert engine.pool.pre_ping is True
        assert engine.pool.recycle > 0
        
        logger.info("✅ Database configuration validated")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ System health check failed: {e}")
        return False


def main():
    """Main test runner entry point."""
    runner = TestRunner()
    
    # Run system health check first
    health_ok = asyncio.run(test_system_health())
    if not health_ok:
        logger.error("System health check failed - aborting test suite")
        sys.exit(1)
    
    # Run comprehensive test suite
    results = runner.run_all_tests()
    
    # Exit with error code if any tests failed
    if any(result is False for key, result in results.items() if key != "coverage"):
        sys.exit(1)
    
    logger.info("🎉 All tests completed successfully!")


if __name__ == "__main__":
    main()
