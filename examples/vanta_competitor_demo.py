"""
Demonstration of Cerebro's Vanta/Drata-class compliance automation capabilities.

This example shows how Cerebro can compete with tools like Vanta and Drata by providing:
1. Automated control testing with pass/fail semantics
2. Evidence collection and immutable audit trails  
3. Audit workflow management with task assignments
4. Policy management with employee attestations
5. Comprehensive compliance dashboards and reports

Run this to see how Cerebro transforms from a technical security tool
into a compliance automation platform that sells to CFOs and compliance managers.
"""

import asyncio
from datetime import datetime, timedelta
from pathlib import Path

from cerebro.compliance.control_tests import ControlTestRunner, ControlFrequency
from cerebro.compliance.evidence_store import EvidenceStore, EvidenceCategory, EvidenceMetadata
from cerebro.compliance.framework_integration import FrameworkIntegration
from cerebro.compliance.audit_workflows import (
    AuditWorkflowManager, 
    RequestListType,
    create_soc2_type2_request_list
)
from cerebro.compliance.policy_management import (
    PolicyManagementSystem,
    Employee,
    PolicyTemplate
)
from cerebro.rules.engine import RuleEngine  # Mock - would be real implementation
from cerebro.query.engine import QueryEngine  # Mock - would be real implementation


class MockRuleEngine:
    """Mock rule engine for demonstration."""
    pass


class MockQueryEngine:
    """Mock query engine for demonstration."""
    async def execute_query(self, query: str):
        # Mock query result
        class MockResult:
            rows = [{"username": "admin", "mfa_enabled": False}]
            total_rows = 1
            columns = ["username", "mfa_enabled"]
        return MockResult()


async def demonstrate_vanta_competitor_features():
    """
    Comprehensive demonstration showing how Cerebro competes with Vanta/Drata.
    """
    
    print("🚀 CEREBRO COMPLIANCE AUTOMATION DEMO")
    print("=" * 50)
    print("Demonstrating Vanta/Drata-class features that sell to CFOs and compliance managers\n")
    
    # Initialize core systems
    print("1️⃣ INITIALIZING COMPLIANCE INFRASTRUCTURE")
    print("-" * 40)
    
    evidence_store = EvidenceStore(
        storage_path="./demo_evidence_store",
        signing_key_path="./demo_signing_key.pem"
    )
    print("✅ Evidence store with cryptographic integrity initialized")
    
    rule_engine = MockRuleEngine()
    query_engine = MockQueryEngine()
    test_runner = ControlTestRunner(rule_engine, query_engine)
    print("✅ Control test runner with CEL rules and SQL queries ready")
    
    framework_integration = FrameworkIntegration(test_runner)
    print("✅ Framework integration bridging rules to compliance controls")
    
    audit_manager = AuditWorkflowManager(evidence_store)
    print("✅ Audit workflow manager for task assignments and approvals")
    
    policy_system = PolicyManagementSystem(evidence_store)
    print("✅ Policy management with employee attestations")
    print()
    
    # Demonstrate framework coverage analysis
    print("2️⃣ FRAMEWORK COVERAGE ANALYSIS")
    print("-" * 40)
    
    soc2_coverage = framework_integration.get_framework_coverage("soc2")
    print(f"SOC 2 Framework Coverage:")
    print(f"  📊 Total Controls: {soc2_coverage['total_controls']}")
    print(f"  🤖 Automated: {soc2_coverage['automated_controls']} ({soc2_coverage['automation_percentage']:.1f}%)")
    print(f"  ✅ Testable: {soc2_coverage['controls_with_tests']} ({soc2_coverage['coverage_percentage']:.1f}%)")
    print(f"  🎯 Rule Utilization: {soc2_coverage['used_rules']}/{soc2_coverage['framework_mapped_rules']} ({soc2_coverage['rule_utilization']:.1f}%)")
    
    # Show control gaps 
    gaps = framework_integration.get_control_gaps("soc2")
    print(f"  ⚠️  Controls needing attention: {len(gaps)}")
    if gaps:
        print(f"     Example gap: {gaps[0]['control_id']} - {gaps[0]['reason']}")
    print()
    
    # Demonstrate automated control testing  
    print("3️⃣ AUTOMATED CONTROL TESTING")
    print("-" * 40)
    
    control_tests = framework_integration.create_control_tests_for_framework("soc2")
    print(f"Created {len(control_tests)} control tests for SOC 2")
    
    # Run a sample of control tests
    sample_tests = control_tests[:3]  # Run first 3 tests
    period_start = datetime.now() - timedelta(days=90)
    period_end = datetime.now()
    
    results = await test_runner.run_framework_tests("soc2", sample_tests, period_start, period_end)
    
    print("Control Test Results:")
    for result in results:
        status_icon = "✅" if result.passed else "❌"
        print(f"  {status_icon} {result.control_id}: {result.status.value}")
        print(f"     Evidence items: {len(result.evidence_items)}")
        print(f"     Execution time: {result.duration_seconds:.2f}s")
    
    # Calculate coverage metrics
    coverage = await test_runner.calculate_coverage("soc2", [], results)  # Mock empty controls list
    print(f"\nOverall pass rate: {coverage.pass_percentage:.1f}%")
    print()
    
    # Demonstrate evidence store capabilities
    print("4️⃣ IMMUTABLE EVIDENCE STORE")
    print("-" * 40)
    
    # Store sample evidence
    sample_evidence = {
        "control_test": "CC6.1_mfa_enforcement",
        "findings": [
            {"user": "admin@company.com", "mfa_enabled": False, "risk": "high"},
            {"user": "john@company.com", "mfa_enabled": True, "risk": "low"}
        ],
        "timestamp": datetime.now().isoformat(),
        "data_source": "okta_api"
    }
    
    evidence_metadata = EvidenceMetadata(
        id="demo_evidence_001",
        category=EvidenceCategory.CONTROL_TEST,
        content_type="application/json",
        content_hash="",
        content_size=0,
        collector_id="control_test_runner",
        collector_type="system",
        source_system="okta",
        collection_method="api",
        control_id="CC6.1",
        framework_name="soc2"
    )
    
    evidence_id = await evidence_store.store_evidence(
        content=sample_evidence,
        metadata=evidence_metadata,
        seal_immediately=True
    )
    print(f"✅ Evidence stored with cryptographic seal: {evidence_id}")
    
    # Verify evidence integrity
    is_valid = await evidence_store.verify_evidence(evidence_id)
    print(f"✅ Evidence integrity verified: {is_valid}")
    print()
    
    # Demonstrate audit workflow management
    print("5️⃣ AUDIT WORKFLOW MANAGEMENT")
    print("-" * 40)
    
    # Create SOC 2 Type II audit request list
    audit_period_start = datetime(2024, 1, 1)
    audit_period_end = datetime(2024, 12, 31)
    
    request_list = create_soc2_type2_request_list(
        workflow_manager=audit_manager,
        period_start=audit_period_start,
        period_end=audit_period_end,
        audit_firm="Big 4 Accounting",
        lead_auditor="Partner Smith"
    )
    
    print(f"Created SOC 2 Type II audit request: {request_list.name}")
    print(f"  📅 Audit period: {audit_period_start.date()} to {audit_period_end.date()}")
    print(f"  📋 Total tasks: {request_list.total_tasks}")
    print(f"  👥 Audit firm: {request_list.audit_firm}")
    
    # Assign some tasks
    task_ids = request_list.task_ids[:3]  # First 3 tasks
    for i, task_id in enumerate(task_ids):
        assignee = ["alice@company.com", "bob@company.com", "carol@company.com"][i]
        due_date = datetime.now() + timedelta(days=30)
        
        audit_manager.assign_task(
            task_id=task_id, 
            assignee=assignee,
            due_date=due_date,
            reviewer="manager@company.com"
        )
        print(f"  ✅ Task assigned to {assignee}")
    
    # Submit evidence for one task
    audit_manager.submit_task_evidence(
        task_id=task_ids[0],
        evidence_ids=[evidence_id],
        comments="MFA configuration evidence collected from Okta",
        submitted_by="alice@company.com"
    )
    print(f"  📎 Evidence submitted for first task")
    
    # Get audit status
    status = audit_manager.get_request_list_status(request_list.id)
    print(f"  📊 Progress: {status['completion_percentage']}% complete")
    print()
    
    # Demonstrate policy management
    print("6️⃣ POLICY MANAGEMENT & ATTESTATIONS")
    print("-" * 40)
    
    # Add sample employees
    employees = [
        Employee("emp001", "Alice Johnson", "alice@company.com", "Engineering", "Senior Engineer"),
        Employee("emp002", "Bob Smith", "bob@company.com", "Security", "Security Analyst"),
        Employee("emp003", "Carol Davis", "carol@company.com", "HR", "HR Manager")
    ]
    
    for emp in employees:
        policy_system.add_employee(emp)
    print(f"Added {len(employees)} employees to policy system")
    
    # Create policy from template
    security_policy = policy_system.create_policy_from_template(
        template_id="security_policy",
        title="Acme Corp Information Security Policy",
        variables={"company_name": "Acme Corp"},
        created_by="ciso@company.com"
    )
    print(f"Created policy: {security_policy.title}")
    
    # Submit for approval
    policy_system.submit_policy_for_approval(
        policy_id=security_policy.id,
        submitted_by="ciso@company.com",
        submission_notes="Annual security policy review completed"
    )
    print("  📝 Submitted for approval workflow")
    
    # Approve policy
    policy_system.approve_policy(
        policy_id=security_policy.id,
        approver_role="ciso",
        approved_by="ciso@company.com", 
        approved=True,
        notes="Policy approved after legal review"
    )
    
    policy_system.approve_policy(
        policy_id=security_policy.id,
        approver_role="legal",
        approved_by="legal@company.com",
        approved=True,
        notes="Legal review completed - no concerns"
    )
    print("  ✅ Policy approved by CISO and Legal")
    
    # Publish policy
    await policy_system.publish_policy(
        policy_id=security_policy.id,
        published_by="ciso@company.com"
    )
    print("  📢 Policy published and attestations created")
    
    # Simulate employee attestation
    attestations = policy_system.get_employee_attestation_status("emp001")
    if attestations:
        attestation_id = attestations[0]["attestation_id"]
        await policy_system.submit_attestation(
            attestation_id=attestation_id,
            employee_signature="Alice Johnson",
            ip_address="192.168.1.100"
        )
        print("  ✍️  Alice Johnson acknowledged security policy")
    
    # Generate compliance report
    compliance_report = policy_system.get_attestation_compliance_report()
    print(f"  📊 Policy compliance rate: {compliance_report['summary']['compliance_rate']:.1f}%")
    print()
    
    # Create evidence bundle for auditor
    print("7️⃣ AUDITOR EVIDENCE BUNDLE")
    print("-" * 40)
    
    bundle_id = await audit_manager.create_evidence_bundle_for_request(request_list.id)
    if bundle_id:
        print(f"Created evidence bundle: {bundle_id}")
        
        # Export bundle for auditor delivery
        export_path = await evidence_store.export_bundle(
            bundle_id=bundle_id,
            export_path="./audit_delivery",
            format="zip"
        )
        print(f"  📦 Exported to: {export_path}")
        
        # Get auditor portal data
        auditor_data = audit_manager.get_auditor_portal_data(
            request_list_id=request_list.id,
            auditor_email="auditor@big4firm.com"
        )
        if auditor_data:
            print(f"  👨‍💼 Auditor portal ready: {auditor_data['controls_tested']} controls tested")
    print()
    
    # Summary of competitive advantages  
    print("8️⃣ COMPETITIVE ADVANTAGES vs VANTA/DRATA")
    print("-" * 50)
    print("✅ WHAT CEREBRO HAS THAT VANTA/DRATA DOESN'T:")
    print("   • Immutable audit trails with cryptographic integrity")
    print("   • Temporal queries for 'point-in-time' compliance state")
    print("   • Cross-provider identity stitching") 
    print("   • CEL rule portability across frameworks")
    print("   • Forensic replay capabilities")
    print()
    print("✅ WHAT CEREBRO NOW HAS THAT MATCHES VANTA/DRATA:")
    print("   • Automated control testing with pass/fail semantics")
    print("   • Evidence automation and collection pipelines")
    print("   • Audit workflow management with task assignments")
    print("   • Policy management with employee attestations")
    print("   • Framework coverage dashboards")
    print("   • Evidence bundles for auditor delivery")
    print("   • Control exceptions and compensating controls")
    print()
    print("🎯 TARGET MARKET EXPANSION:")
    print("   • Original: Cloud security engineers (CSPM market)")  
    print("   • New: CFOs, compliance managers, audit teams")
    print("   • Unique value: 'System of record + compliance automation'")
    print()
    print("💰 REVENUE OPPORTUNITY:")
    print("   • Vanta/Drata pricing: $2K-50K+ per year")
    print("   • Market size: $2B+ compliance automation")
    print("   • Cerebro advantage: Technical depth + compliance breadth")
    print()
    print("Demo completed successfully! 🚀")
    print("Cerebro is now ready to compete in the compliance automation market.")


if __name__ == "__main__":
    # Create demo directory
    Path("./demo_evidence_store").mkdir(exist_ok=True)
    Path("./audit_delivery").mkdir(exist_ok=True)
    
    # Run the demo
    asyncio.run(demonstrate_vanta_competitor_features())
