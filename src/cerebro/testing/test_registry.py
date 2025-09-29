"""
Security test registry for automated compliance testing.

Manages security tests, control validation, and test scheduling
following Vanta's test management patterns.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

logger = logging.getLogger(__name__)


class TestStatus(Enum):
    """Status of security tests."""
    ACTIVE = "active"
    INACTIVE = "inactive" 
    DRAFT = "draft"
    DEPRECATED = "deprecated"


class TestType(Enum):
    """Types of security tests."""
    AUTOMATED = "automated"
    MANUAL = "manual"
    HYBRID = "hybrid"


class TestFrequency(Enum):
    """Test execution frequency."""
    CONTINUOUS = "continuous"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ANNUALLY = "annually"
    ON_DEMAND = "on_demand"


@dataclass
class SecurityTest:
    """Security test definition and configuration."""
    test_id: str
    name: str
    description: str
    test_type: TestType
    status: TestStatus
    
    # Test configuration
    sql_query: Optional[str]  # SQL query for automated tests
    manual_steps: List[str]   # Steps for manual tests
    expected_result: str
    pass_criteria: str
    
    # Scheduling
    frequency: TestFrequency
    next_execution: datetime
    last_execution: Optional[datetime]
    
    # Compliance mapping
    control_ids: List[str]
    framework_mappings: Dict[str, str]  # framework -> control_id
    
    # Risk assessment
    risk_level: str  # "low", "medium", "high", "critical"
    impact_of_failure: str
    
    # Execution
    timeout_minutes: int
    retry_count: int
    notification_channels: List[str]
    
    # Results tracking
    last_result: Optional[str]  # "pass", "fail", "error"
    failure_count: int
    consecutive_failures: int
    
    # Metadata
    created_by: str
    created_at: datetime
    updated_at: datetime
    tags: List[str]
    metadata: Dict[str, Any]


class TestRegistry:
    """
    Registry for security tests and validation procedures.
    
    Manages automated and manual security tests for compliance
    control validation and continuous monitoring.
    """
    
    def __init__(self):
        self.tests: Dict[str, SecurityTest] = {}
        self._initialize_default_tests()
    
    def _initialize_default_tests(self):
        """Initialize default security tests."""
        default_tests = [
            # Access Control Tests
            SecurityTest(
                test_id="test_mfa_enforcement",
                name="Multi-Factor Authentication Enforcement",
                description="Verify that MFA is enforced for all user accounts",
                test_type=TestType.AUTOMATED,
                status=TestStatus.ACTIVE,
                sql_query="SELECT COUNT(*) as non_mfa_users FROM okta_user WHERE mfa_enabled = false AND status = 'active'",
                manual_steps=[],
                expected_result="0 users without MFA",
                pass_criteria="non_mfa_users = 0",
                frequency=TestFrequency.DAILY,
                next_execution=datetime.now() + timedelta(days=1),
                last_execution=None,
                control_ids=["CC6.2"],
                framework_mappings={"soc2": "CC6.2", "iso27001": "A.9.2.2"},
                risk_level="high",
                impact_of_failure="Weak authentication controls",
                timeout_minutes=5,
                retry_count=3,
                notification_channels=["security-team"],
                last_result=None,
                failure_count=0,
                consecutive_failures=0,
                created_by="system",
                created_at=datetime.now(),
                updated_at=datetime.now(),
                tags=["access_control", "mfa", "authentication"],
                metadata={}
            ),
            
            # Configuration Security Tests
            SecurityTest(
                test_id="test_public_s3_buckets",
                name="Public S3 Bucket Detection",
                description="Detect S3 buckets with public access permissions",
                test_type=TestType.AUTOMATED,
                status=TestStatus.ACTIVE,
                sql_query="SELECT bucket_name, is_public FROM gcp_storage_bucket WHERE is_public = true",
                manual_steps=[],
                expected_result="No public buckets",
                pass_criteria="COUNT(public_buckets) = 0",
                frequency=TestFrequency.DAILY,
                next_execution=datetime.now() + timedelta(days=1),
                last_execution=None,
                control_ids=["CC6.1"],
                framework_mappings={"soc2": "CC6.1", "pci_dss": "2.1"},
                risk_level="critical",
                impact_of_failure="Data exposure risk",
                timeout_minutes=10,
                retry_count=2,
                notification_channels=["security-team", "infrastructure-team"],
                last_result=None,
                failure_count=0,
                consecutive_failures=0,
                created_by="system",
                created_at=datetime.now(),
                updated_at=datetime.now(),
                tags=["data_protection", "cloud_security", "s3"],
                metadata={}
            ),
            
            # Vulnerability Management Tests
            SecurityTest(
                test_id="test_critical_vulnerabilities",
                name="Critical Vulnerability Detection",
                description="Monitor for critical severity vulnerabilities",
                test_type=TestType.AUTOMATED,
                status=TestStatus.ACTIVE,
                sql_query="SELECT COUNT(*) as critical_vulns FROM github_vulnerability_alert WHERE severity = 'critical' AND state = 'open'",
                manual_steps=[],
                expected_result="No open critical vulnerabilities",
                pass_criteria="critical_vulns = 0",
                frequency=TestFrequency.CONTINUOUS,
                next_execution=datetime.now() + timedelta(hours=1),
                last_execution=None,
                control_ids=["CC7.1"],
                framework_mappings={"soc2": "CC7.1", "iso27001": "A.12.6.1"},
                risk_level="critical",
                impact_of_failure="Unpatched critical vulnerabilities",
                timeout_minutes=15,
                retry_count=3,
                notification_channels=["security-team", "development-team"],
                last_result=None,
                failure_count=0,
                consecutive_failures=0,
                created_by="system",
                created_at=datetime.now(),
                updated_at=datetime.now(),
                tags=["vulnerability_management", "critical", "monitoring"],
                metadata={}
            ),
            
            # Identity Governance Tests
            SecurityTest(
                test_id="test_privileged_access_review",
                name="Privileged Access Review Compliance",
                description="Verify that privileged access reviews are conducted quarterly",
                test_type=TestType.MANUAL,
                status=TestStatus.ACTIVE,
                sql_query=None,
                manual_steps=[
                    "Review list of users with admin privileges",
                    "Verify quarterly access review was completed",
                    "Check for documentation of review decisions",
                    "Validate that unauthorized access was revoked"
                ],
                expected_result="Quarterly access review completed with documentation",
                pass_criteria="Review completed within last 90 days",
                frequency=TestFrequency.QUARTERLY,
                next_execution=datetime.now() + timedelta(days=90),
                last_execution=None,
                control_ids=["CC6.3"],
                framework_mappings={"soc2": "CC6.3", "iso27001": "A.9.2.5"},
                risk_level="medium",
                impact_of_failure="Unreviewed privileged access",
                timeout_minutes=60,
                retry_count=1,
                notification_channels=["compliance-team"],
                last_result=None,
                failure_count=0,
                consecutive_failures=0,
                created_by="system",
                created_at=datetime.now(),
                updated_at=datetime.now(),
                tags=["access_review", "privileged_access", "governance"],
                metadata={}
            )
        ]
        
        for test in default_tests:
            self.tests[test.test_id] = test
    
    async def register_test(self, test: SecurityTest) -> str:
        """Register a new security test."""
        self.tests[test.test_id] = test
        logger.info(f"Registered security test: {test.name}")
        return test.test_id
    
    async def get_tests_by_control(self, control_id: str) -> List[SecurityTest]:
        """Get all tests for a specific control."""
        return [
            test for test in self.tests.values()
            if control_id in test.control_ids
        ]
    
    async def get_tests_by_framework(self, framework: str) -> List[SecurityTest]:
        """Get all tests for a compliance framework."""
        return [
            test for test in self.tests.values()
            if framework in test.framework_mappings
        ]
    
    async def get_overdue_tests(self) -> List[SecurityTest]:
        """Get tests that are overdue for execution."""
        current_time = datetime.now()
        return [
            test for test in self.tests.values()
            if test.next_execution < current_time and test.status == TestStatus.ACTIVE
        ]
    
    async def get_failing_tests(self) -> List[SecurityTest]:
        """Get tests with recent failures."""
        return [
            test for test in self.tests.values()
            if test.last_result == "fail" or test.consecutive_failures > 0
        ]
    
    async def generate_test_summary(self, org_id: str) -> Dict[str, Any]:
        """Generate test execution summary."""
        tests = list(self.tests.values())
        overdue = await self.get_overdue_tests()
        failing = await self.get_failing_tests()
        
        # Status distribution
        status_counts = {}
        for test in tests:
            status_counts[test.status.value] = status_counts.get(test.status.value, 0) + 1
        
        # Type distribution
        type_counts = {}
        for test in tests:
            type_counts[test.test_type.value] = type_counts.get(test.test_type.value, 0) + 1
        
        # Framework coverage
        framework_coverage = {}
        for test in tests:
            for framework in test.framework_mappings.keys():
                framework_coverage[framework] = framework_coverage.get(framework, 0) + 1
        
        return {
            "organization_id": org_id,
            "summary_date": datetime.now().isoformat(),
            "totals": {
                "total_tests": len(tests),
                "active_tests": status_counts.get("active", 0),
                "overdue_tests": len(overdue),
                "failing_tests": len(failing)
            },
            "distribution": {
                "by_status": status_counts,
                "by_type": type_counts,
                "by_framework": framework_coverage
            },
            "health_metrics": {
                "pass_rate": round((len(tests) - len(failing)) / max(len(tests), 1) * 100, 1),
                "overdue_rate": round(len(overdue) / max(len(tests), 1) * 100, 1),
                "automation_rate": round(type_counts.get("automated", 0) / max(len(tests), 1) * 100, 1)
            }
        }


# Global test registry
_test_registry = TestRegistry()


def get_test_registry() -> TestRegistry:
    """Get global test registry."""
    return _test_registry
