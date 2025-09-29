"""
Security testing API endpoints.

Provides REST API for test management, execution, and results
using the evidence data fabric for test validation.
"""

from typing import List, Optional
from uuid import UUID
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
import logging

from ...core.database import get_db
from ...core.models import Organization
from ...api.auth import require_read_findings
from ...testing.test_registry import get_test_registry, TestType, TestFrequency, TestStatus
from ...compliance.evidence_data_fabric import EvidenceDataFabric, EvidenceQuery, EvidenceEntityType

router = APIRouter()
logger = logging.getLogger(__name__)


class TestCreateRequest(BaseModel):
    """Request to create new security test."""
    name: str = Field(..., description="Test name")
    description: str = Field(..., description="Test description")
    test_type: str = Field(..., description="Test type (automated, manual, hybrid)")
    sql_query: Optional[str] = Field(None, description="SQL query for automated tests")
    manual_steps: List[str] = Field(default_factory=list, description="Manual test steps")
    expected_result: str = Field(..., description="Expected test result")
    pass_criteria: str = Field(..., description="Criteria for test to pass")
    frequency: str = Field("monthly", description="Test frequency")
    control_ids: List[str] = Field(default_factory=list, description="Associated control IDs")
    risk_level: str = Field("medium", description="Risk level if test fails")


class TestExecutionRequest(BaseModel):
    """Request to execute security test."""
    test_id: str = Field(..., description="Test ID to execute")
    manual_result: Optional[str] = Field(None, description="Manual test result")
    evidence_references: List[str] = Field(default_factory=list, description="Evidence record IDs")


@router.get("/organizations/{org_id}/tests")
async def list_tests(
    org_id: UUID,
    status: Optional[str] = Query(None, description="Filter by test status"),
    test_type: Optional[str] = Query(None, description="Filter by test type"),
    framework: Optional[str] = Query(None, description="Filter by compliance framework"),
    overdue_only: bool = Query(False, description="Show only overdue tests"),
    failing_only: bool = Query(False, description="Show only failing tests"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """List security tests with filtering options."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        test_registry = get_test_registry()
        all_tests = list(test_registry.tests.values())
        
        # Apply filters
        filtered_tests = all_tests
        
        if status:
            status_enum = TestStatus(status.lower())
            filtered_tests = [t for t in filtered_tests if t.status == status_enum]
        
        if test_type:
            type_enum = TestType(test_type.lower()) 
            filtered_tests = [t for t in filtered_tests if t.test_type == type_enum]
        
        if framework:
            filtered_tests = [t for t in filtered_tests if framework in t.framework_mappings]
        
        if overdue_only:
            current_time = datetime.now()
            filtered_tests = [t for t in filtered_tests if t.next_execution < current_time]
        
        if failing_only:
            filtered_tests = [t for t in filtered_tests if t.last_result == "fail"]
        
        return {
            "organization_id": str(org_id),
            "total_tests": len(all_tests),
            "filtered_count": len(filtered_tests),
            "filters_applied": {
                "status": status,
                "test_type": test_type,
                "framework": framework,
                "overdue_only": overdue_only,
                "failing_only": failing_only
            },
            "tests": [
                {
                    "test_id": test.test_id,
                    "name": test.name,
                    "description": test.description,
                    "test_type": test.test_type.value,
                    "status": test.status.value,
                    "frequency": test.frequency.value,
                    "next_execution": test.next_execution.isoformat(),
                    "last_execution": test.last_execution.isoformat() if test.last_execution else None,
                    "last_result": test.last_result,
                    "consecutive_failures": test.consecutive_failures,
                    "risk_level": test.risk_level,
                    "control_ids": test.control_ids,
                    "framework_mappings": test.framework_mappings,
                    "is_overdue": test.next_execution < datetime.now()
                }
                for test in filtered_tests
            ]
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Test listing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Test listing failed: {str(e)}")


@router.get("/organizations/{org_id}/tests/{test_id}")
async def get_test_details(
    org_id: UUID,
    test_id: str,
    include_entities: bool = Query(False, description="Include test entities"),
    include_history: bool = Query(False, description="Include execution history"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Get detailed test information with optional execution history."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        test_registry = get_test_registry()
        test = test_registry.tests.get(test_id)
        
        if not test:
            raise HTTPException(status_code=404, detail="Test not found")
        
        test_details = {
            "test_id": test.test_id,
            "name": test.name,
            "description": test.description,
            "test_type": test.test_type.value,
            "status": test.status.value,
            "configuration": {
                "sql_query": test.sql_query,
                "manual_steps": test.manual_steps,
                "expected_result": test.expected_result,
                "pass_criteria": test.pass_criteria,
                "timeout_minutes": test.timeout_minutes,
                "retry_count": test.retry_count
            },
            "scheduling": {
                "frequency": test.frequency.value,
                "next_execution": test.next_execution.isoformat(),
                "last_execution": test.last_execution.isoformat() if test.last_execution else None
            },
            "compliance_mapping": {
                "control_ids": test.control_ids,
                "framework_mappings": test.framework_mappings,
                "requirements": []  # Would map to evidence fabric requirements
            },
            "risk_assessment": {
                "risk_level": test.risk_level,
                "impact_of_failure": test.impact_of_failure
            },
            "execution_status": {
                "last_result": test.last_result,
                "failure_count": test.failure_count,
                "consecutive_failures": test.consecutive_failures
            },
            "metadata": {
                "created_by": test.created_by,
                "created_at": test.created_at.isoformat(),
                "updated_at": test.updated_at.isoformat(),
                "tags": test.tags
            }
        }
        
        # Include test entities if requested
        if include_entities:
            # This would query the entities being tested
            test_details["test_entities"] = {
                "total_entities": 0,  # Would count from evidence fabric
                "entity_types": [],
                "sample_entities": []
            }
        
        # Include execution history if requested  
        if include_history:
            # This would query execution history from evidence fabric
            test_details["execution_history"] = {
                "total_executions": 0,
                "recent_executions": [],
                "pass_rate_30_days": 100.0,
                "average_execution_time": 0.0
            }
        
        return {
            "success": True,
            "message": f"Test details retrieved: {test.name}",
            "data": test_details
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Test details retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Test details failed: {str(e)}")


@router.post("/organizations/{org_id}/tests")
async def create_test(
    org_id: UUID,
    request: TestCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Create new security test."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        from ...testing.test_registry import SecurityTest
        
        # Create test object
        test = SecurityTest(
            test_id=f"test_{request.name.lower().replace(' ', '_')}_{int(datetime.now().timestamp())}",
            name=request.name,
            description=request.description,
            test_type=TestType(request.test_type.lower()),
            status=TestStatus.ACTIVE,
            sql_query=request.sql_query,
            manual_steps=request.manual_steps,
            expected_result=request.expected_result,
            pass_criteria=request.pass_criteria,
            frequency=TestFrequency(request.frequency.lower()),
            next_execution=datetime.now() + timedelta(days=1),
            last_execution=None,
            control_ids=request.control_ids,
            framework_mappings={},  # Would populate from control mappings
            risk_level=request.risk_level,
            impact_of_failure=f"Test failure: {request.name}",
            timeout_minutes=30,
            retry_count=3,
            notification_channels=["security-team"],
            last_result=None,
            failure_count=0,
            consecutive_failures=0,
            created_by=current_user.username,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            tags=[],
            metadata={}
        )
        
        # Register test
        test_registry = get_test_registry()
        test_id = await test_registry.register_test(test)
        
        return {
            "success": True,
            "message": f"Security test '{request.name}' created successfully",
            "data": {
                "test_id": test_id,
                "name": test.name,
                "test_type": test.test_type.value,
                "next_execution": test.next_execution.isoformat()
            }
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Test creation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Test creation failed: {str(e)}")


@router.get("/organizations/{org_id}/tests/summary")
async def get_test_summary(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Get test execution summary and health metrics."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        test_registry = get_test_registry()
        summary = await test_registry.generate_test_summary(str(org_id))
        
        return {
            "success": True,
            "message": f"Test summary generated for {summary['totals']['total_tests']} tests",
            "data": summary
        }
        
    except Exception as e:
        logger.error(f"Test summary failed: {e}")
        raise HTTPException(status_code=500, detail=f"Test summary failed: {str(e)}")


# Evidence fabric integration examples
@router.get("/organizations/{org_id}/evidence/query")
async def query_evidence_fabric(
    org_id: UUID,
    entity_type: Optional[str] = Query(None, description="Filter by entity type"),
    entity_id: Optional[str] = Query(None, description="Specific entity ID"),
    source_system: Optional[str] = Query(None, description="Filter by source system"),
    requirements: Optional[List[str]] = Query(None, description="Filter by requirement IDs"),
    since_days: int = Query(30, description="Evidence age limit", ge=1, le=365),
    limit: int = Query(50, description="Maximum results", ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Query the evidence data fabric directly."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        # Build evidence query
        query_filters = {}
        
        if entity_type:
            query_filters["entity_types"] = [EvidenceEntityType(entity_type.lower())]
        
        if entity_id:
            query_filters["entity_ids"] = [entity_id]
        
        if source_system:
            query_filters["source_systems"] = [source_system]
        
        if requirements:
            query_filters["requirements"] = requirements
        
        query_filters["time_range"] = (
            datetime.now() - timedelta(days=since_days),
            datetime.now()
        )
        query_filters["limit"] = limit
        
        evidence_query = EvidenceQuery(**query_filters)

        # Query actual evidence fabric instead of returning mock data
        evidence_fabric = EvidenceDataFabric(db)

        try:
            # Execute real evidence query
            evidence_results = await evidence_fabric.query_evidence(evidence_query)

            # Format results for API response
            formatted_results = [
                {
                    "evidence_id": result.evidence_id,
                    "entity_type": result.entity_type.value if result.entity_type else "unknown",
                    "entity_id": result.entity_id,
                    "source_system": result.source_system,
                    "observed_at": result.observed_at.isoformat(),
                    "quality_score": result.quality_score or 0.0,
                    "requirements": result.requirements or [],
                    "normalized_data": result.normalized_data or {}
                }
                for result in evidence_results.evidence_items
            ]

            return {
                "organization_id": str(org_id),
                "query_parameters": {
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "source_system": source_system,
                    "requirements": requirements,
                    "since_days": since_days,
                    "limit": limit
                },
                "total_results": evidence_results.total_count,
                "evidence_records": formatted_results,
                "query_execution_time_ms": evidence_results.execution_time_ms,
                "cache_hit": evidence_results.from_cache if hasattr(evidence_results, 'from_cache') else False
            }

        except Exception as e:
            logger.error(f"Evidence fabric query failed: {e}")
            # Return error response instead of mock data
            return {
                "organization_id": str(org_id),
                "query_parameters": {
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "source_system": source_system,
                    "requirements": requirements,
                    "since_days": since_days,
                    "limit": limit
                },
                "total_results": 0,
                "evidence_records": [],
                "error": f"Evidence query failed: {str(e)}"
            }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Evidence fabric query failed: {e}")
        raise HTTPException(status_code=500, detail=f"Evidence query failed: {str(e)}")
