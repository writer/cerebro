"""
Tests for compliance evidence generation.
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from cerebro.compliance.evidence import EvidenceCollector, EvidenceItem
from cerebro.compliance.frameworks import (
    ControlType,
    ISO27001Framework,
    PCIDSSFramework,
    SOC2Framework,
    get_framework,
    list_frameworks,
)
from cerebro.compliance.generator import ComplianceEvidenceGenerator


class TestComplianceFrameworks:
    """Test compliance framework definitions."""

    def test_soc2_framework(self):
        """Test SOC 2 framework definition."""
        framework = SOC2Framework.get_framework()

        assert framework.name == "SOC 2 Type II"
        assert framework.version == "2017 TSC"
        assert len(framework.controls) > 0

        # Check specific control
        cc61 = framework.get_control("CC6.1")
        assert cc61 is not None
        assert cc61.title == "Logical Access - Access Rights"
        assert cc61.control_type == ControlType.PREVENTIVE
        assert len(cc61.sql_queries) > 0

    def test_iso27001_framework(self):
        """Test ISO 27001 framework definition."""
        framework = ISO27001Framework.get_framework()

        assert framework.name == "ISO 27001"
        assert framework.version == "2013"
        assert len(framework.controls) > 0

        # Check access control category
        access_controls = framework.get_controls_by_category("Access Control")
        assert len(access_controls) > 0

    def test_pci_dss_framework(self):
        """Test PCI DSS framework definition."""
        framework = PCIDSSFramework.get_framework()

        assert framework.name == "PCI DSS"
        assert framework.version == "4.0"
        assert len(framework.controls) > 0

    def test_framework_registry(self):
        """Test framework registry functions."""
        frameworks = set(list_frameworks())
        assert "soc2" in frameworks
        assert "iso27001" in frameworks

        soc2 = get_framework("soc2")
        assert soc2 is not None
        assert soc2.name == "SOC 2 Type II"

        invalid = get_framework("invalid_framework")
        assert invalid is None

    def test_automated_controls(self):
        """Test automated control identification."""
        framework = SOC2Framework.get_framework()
        automated = framework.get_automated_controls()

        assert len(automated) > 0
        for control in automated:
            automation_level = getattr(
                control.automation_level, "value", control.automation_level
            )
            assert automation_level in {"automated", "semi_automated", "semi-automated"}
            queries = getattr(
                control, "sql_queries", getattr(control, "evidence_queries", [])
            )
            assert len(queries) > 0


@pytest.fixture
def mock_query_engine():
    """Create mock query engine for testing."""
    mock_engine = MagicMock()
    mock_result = MagicMock()
    mock_result.rows = [
        {"username": "john.doe", "mfa_enabled": True, "status": "active"},
        {"username": "jane.smith", "mfa_enabled": False, "status": "active"},
    ]
    mock_result.total_rows = 2
    mock_result.columns = ["username", "mfa_enabled", "status"]
    mock_result.errors = []

    mock_engine.execute_query = AsyncMock(return_value=mock_result)
    return mock_engine


@pytest.mark.asyncio
class TestEvidenceCollector:
    """Test evidence collection functionality."""

    async def test_evidence_collection(self, mock_query_engine):
        """Test collecting evidence for a control."""
        collector = EvidenceCollector()
        collector.query_engine = mock_query_engine

        sql_queries = [
            "SELECT username, mfa_enabled FROM okta_user WHERE status = 'active'",
            "SELECT app_name, sign_on_mode FROM okta_application",
        ]

        evidence = await collector.collect_evidence("CC6.2", sql_queries)

        assert len(evidence) == 2
        assert all(isinstance(item, EvidenceItem) for item in evidence)
        assert all(item.control_id == "CC6.2" for item in evidence)
        assert evidence[0].evidence_type == "sql_query_result"
        assert evidence[0].data["total_rows"] == 2

    async def test_evidence_collection_with_error(self, mock_query_engine):
        """Test evidence collection with SQL error."""
        # Mock an error
        mock_query_engine.execute_query.side_effect = [
            Exception("SQL Error: Invalid query"),
            MagicMock(rows=[], total_rows=0, columns=[], errors=[]),
        ]

        collector = EvidenceCollector()
        collector.query_engine = mock_query_engine

        sql_queries = ["INVALID SQL", "SELECT * FROM valid_table"]
        evidence = await collector.collect_evidence("CC6.1", sql_queries)

        assert len(evidence) == 2
        error_evidence = evidence[0]
        assert error_evidence.evidence_type == "query_error"
        assert "SQL Error" in error_evidence.data["error"]


@pytest.mark.asyncio
class TestComplianceEvidenceGenerator:
    """Test compliance evidence generator."""

    async def test_generate_compliance_report(self, mock_query_engine):
        """Test generating complete compliance report."""
        generator = ComplianceEvidenceGenerator()
        generator.evidence_collector.query_engine = mock_query_engine

        period_start = datetime.now() - timedelta(days=90)
        period_end = datetime.now()

        report = await generator.generate_compliance_report(
            "soc2", "test_org", period_start, period_end
        )

        assert "framework" in report
        assert "organization_id" in report
        assert "summary" in report
        assert "control_results" in report

        assert report["framework"]["name"] == "SOC 2 Type II"
        assert report["organization_id"] == "test_org"
        assert isinstance(report["summary"]["total_controls"], int)
        assert isinstance(report["summary"]["compliance_percentage"], float)

    async def test_generate_invalid_framework(self):
        """Test generating report for invalid framework."""
        generator = ComplianceEvidenceGenerator()

        with pytest.raises(ValueError, match="Unknown framework"):
            await generator.generate_compliance_report(
                "invalid_framework", "test_org", datetime.now(), datetime.now()
            )


class TestControlDefinitions:
    """Test individual control definitions."""

    def test_soc2_access_control_cc61(self):
        """Test SOC 2 CC6.1 access control definition."""
        framework = SOC2Framework.get_framework()
        control = framework.get_control("CC6.1")

        assert control.control_id == "CC6.1"
        assert control.category == "Access Controls"
        assert control.control_type == ControlType.PREVENTIVE
        automation_level = getattr(
            control.automation_level, "value", control.automation_level
        )
        assert automation_level in {"automated", "semi_automated", "semi-automated"}
        queries = getattr(
            control, "sql_queries", getattr(control, "evidence_queries", [])
        )
        assert len(queries) >= 3  # Should have multiple queries

        # Check query content
        queries_text = " ".join(queries)
        assert "okta_user" in queries_text
        assert "aws_iam_user" in queries_text

    def test_iso27001_access_control_a911(self):
        """Test ISO 27001 A.9.1.1 access control definition."""
        framework = ISO27001Framework.get_framework()
        control = framework.get_control("A.9.1.1")

        assert control.control_id == "A.9.1.1"
        assert control.category == "Access Control"
        assert control.control_type == ControlType.ADMINISTRATIVE
        assert "policy" in control.title.lower()

    def test_pci_dss_access_control_71(self):
        """Test PCI DSS 7.1.1 access control definition."""
        framework = PCIDSSFramework.get_framework()
        control = framework.get_control("7.1.1")

        assert control.control_id == "7.1.1"
        assert control.category == "Access Control"
        assert control.control_type == ControlType.PREVENTIVE
        assert "need-to-know" in control.description.lower()


@pytest.mark.asyncio
class TestComplianceIntegration:
    """Test integration scenarios."""

    async def test_end_to_end_soc2_assessment(self, mock_query_engine):
        """Test complete SOC 2 assessment workflow."""
        generator = ComplianceEvidenceGenerator()
        generator.evidence_collector.query_engine = mock_query_engine

        # Generate report
        report = await generator.generate_compliance_report(
            "soc2",
            "integration_test_org",
            datetime.now() - timedelta(days=30),
            datetime.now(),
        )

        # Verify report structure
        assert report["framework"]["name"] == "SOC 2 Type II"
        assert report["organization_id"] == "integration_test_org"

        # Check controls were evaluated
        control_results = report["control_results"]
        assert len(control_results) > 0

        # Verify evidence was collected
        evidence_summary = report["evidence_summary"]
        assert len(evidence_summary) > 0

        for _control_id, summary in evidence_summary.items():
            assert "evidence_items" in summary
            assert "successful_queries" in summary
            assert summary["evidence_items"] >= 0

    async def test_multi_framework_comparison(self, mock_query_engine):
        """Test comparing multiple frameworks."""
        generator = ComplianceEvidenceGenerator()
        generator.evidence_collector.query_engine = mock_query_engine

        frameworks_to_test = ComplianceEvidenceGenerator.available_frameworks()
        assert len(frameworks_to_test) >= 1
        reports = {}

        for fw_name in frameworks_to_test:
            report = await generator.generate_compliance_report(
                fw_name, "test_org", datetime.now() - timedelta(days=30), datetime.now()
            )
            reports[fw_name] = report

        # Verify all reports generated
        assert len(reports) == len(frameworks_to_test)

        # All should have controls defined
        for fw_name, report in reports.items():
            assert report["summary"]["total_controls"] > 0, fw_name

        # Verify framework names are unique
        framework_names = [report["framework"]["name"] for report in reports.values()]
        assert len(set(framework_names)) == len(framework_names)


if __name__ == "__main__":
    pytest.main([__file__])
