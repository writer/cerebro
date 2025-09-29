"""
Vendor management API endpoints.

Provides REST API for vendor registry, security reviews, discovered vendors,
and risk assessments using the evidence data fabric.
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
from ...vendor_management.vendor_registry import get_vendor_registry, VendorCategory, VendorRiskLevel
from ...vendor_management.discovered_vendors import get_discovered_vendor_tracker
from ...compliance.evidence_data_fabric import EvidenceDataFabric, EvidenceQuery, EvidenceEntityType

router = APIRouter()
logger = logging.getLogger(__name__)


class VendorCreateRequest(BaseModel):
    """Request to create new vendor."""
    name: str = Field(..., description="Vendor name")
    website_url: str = Field(..., description="Vendor website URL")
    category: str = Field(..., description="Vendor category")
    primary_contact: str = Field("", description="Primary contact email")
    industry: str = Field("", description="Industry sector")
    country: str = Field("", description="Country of operation")
    data_processing_locations: List[str] = Field(default_factory=list, description="Data processing locations")
    certifications: List[str] = Field(default_factory=list, description="Security certifications")
    data_types_processed: List[str] = Field(default_factory=list, description="Types of data processed")
    business_criticality: str = Field("medium", description="Business criticality level")
    annual_spend: Optional[float] = Field(None, description="Annual spend with vendor")


class VendorUpdateRequest(BaseModel):
    """Request to update vendor information."""
    primary_contact: Optional[str] = None
    certifications: Optional[List[str]] = None
    risk_level: Optional[str] = None
    business_criticality: Optional[str] = None
    tags: Optional[List[str]] = None


@router.post("/organizations/{org_id}/vendors")
async def create_vendor(
    org_id: UUID,
    request: VendorCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Create new vendor in registry."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        vendor_registry = get_vendor_registry()
        
        # Convert category string to enum
        category_enum = VendorCategory(request.category.lower())
        
        vendor = await vendor_registry.register_vendor(
            name=request.name,
            website_url=request.website_url,
            category=category_enum,
            created_by=current_user.username,
            primary_contact=request.primary_contact,
            industry=request.industry,
            country=request.country,
            data_processing_locations=request.data_processing_locations,
            certifications=request.certifications,
            data_types_processed=request.data_types_processed,
            business_criticality=request.business_criticality,
            annual_spend=request.annual_spend
        )
        
        return {
            "success": True,
            "message": f"Vendor '{request.name}' created successfully",
            "data": {
                "vendor_id": vendor.vendor_id,
                "name": vendor.name,
                "risk_level": vendor.risk_level.value,
                "risk_score": vendor.inherent_risk_score,
                "next_review_due": vendor.next_review_due.isoformat()
            }
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Vendor creation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Vendor creation failed: {str(e)}")


@router.get("/organizations/{org_id}/vendors")
async def list_vendors(
    org_id: UUID,
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    category: Optional[str] = Query(None, description="Filter by category"),
    overdue_reviews: bool = Query(False, description="Show only vendors with overdue reviews"),
    limit: int = Query(50, description="Maximum vendors to return", ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """List vendors with filtering options."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        vendor_registry = get_vendor_registry()
        all_vendors = list(vendor_registry.vendors.values())
        
        # Apply filters
        filtered_vendors = all_vendors
        
        if risk_level:
            risk_enum = VendorRiskLevel(risk_level.lower())
            filtered_vendors = [v for v in filtered_vendors if v.risk_level == risk_enum]
        
        if category:
            category_enum = VendorCategory(category.lower())
            filtered_vendors = [v for v in filtered_vendors if v.category == category_enum]
        
        if overdue_reviews:
            current_date = datetime.now()
            filtered_vendors = [v for v in filtered_vendors if v.next_review_due < current_date]
        
        # Limit results
        filtered_vendors = filtered_vendors[:limit]
        
        return {
            "organization_id": str(org_id),
            "total_vendors": len(all_vendors),
            "filtered_count": len(filtered_vendors),
            "filters_applied": {
                "risk_level": risk_level,
                "category": category,
                "overdue_reviews": overdue_reviews
            },
            "vendors": [
                {
                    "vendor_id": vendor.vendor_id,
                    "name": vendor.name,
                    "category": vendor.category.value,
                    "risk_level": vendor.risk_level.value,
                    "risk_score": vendor.inherent_risk_score,
                    "website_url": vendor.website_url,
                    "data_types_processed": vendor.data_types_processed,
                    "certifications": vendor.certifications,
                    "business_criticality": vendor.business_criticality,
                    "next_review_due": vendor.next_review_due.isoformat(),
                    "days_until_review": (vendor.next_review_due - datetime.now()).days,
                    "last_assessment": vendor.last_assessment_date.isoformat()
                }
                for vendor in filtered_vendors
            ]
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Vendor listing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Vendor listing failed: {str(e)}")


@router.get("/organizations/{org_id}/vendors/{vendor_id}")
async def get_vendor_details(
    org_id: UUID,
    vendor_id: str,
    include_evidence: bool = Query(False, description="Include compliance evidence"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Get detailed vendor information with optional evidence."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        vendor_registry = get_vendor_registry()
        vendor = vendor_registry.vendors.get(vendor_id)
        
        if not vendor:
            raise HTTPException(status_code=404, detail="Vendor not found")
        
        vendor_details = {
            "vendor_id": vendor.vendor_id,
            "name": vendor.name,
            "website_url": vendor.website_url,
            "primary_contact": vendor.primary_contact,
            "category": vendor.category.value,
            "industry": vendor.industry,
            "country": vendor.country,
            "data_processing_locations": vendor.data_processing_locations,
            "risk_assessment": {
                "risk_level": vendor.risk_level.value,
                "inherent_risk_score": vendor.inherent_risk_score,
                "residual_risk_score": vendor.residual_risk_score,
                "last_assessment_date": vendor.last_assessment_date.isoformat(),
                "next_review_due": vendor.next_review_due.isoformat()
            },
            "compliance": {
                "certifications": vendor.certifications,
                "compliance_frameworks": vendor.compliance_frameworks,
                "security_questionnaire_completed": vendor.security_questionnaire_completed,
                "incident_response_plan": vendor.incident_response_plan
            },
            "business_relationship": {
                "contract_start_date": vendor.contract_start_date.isoformat(),
                "contract_end_date": vendor.contract_end_date.isoformat() if vendor.contract_end_date else None,
                "annual_spend": vendor.annual_spend,
                "business_criticality": vendor.business_criticality
            },
            "data_handling": {
                "data_types_processed": vendor.data_types_processed,
                "data_retention_period": vendor.data_retention_period,
                "data_deletion_policy": vendor.data_deletion_policy
            },
            "integration": {
                "integration_type": vendor.integration_type,
                "network_access": vendor.network_access,
                "authentication_methods": vendor.authentication_methods,
                "access_monitoring_enabled": vendor.access_monitoring_enabled
            },
            "metadata": {
                "created_at": vendor.created_at.isoformat(),
                "updated_at": vendor.updated_at.isoformat(),
                "created_by": vendor.created_by,
                "tags": vendor.tags
            }
        }
        
        # Include evidence if requested
        if include_evidence:
            # This would query the evidence data fabric for vendor-related evidence
            vendor_details["evidence"] = {
                "total_evidence_records": 0,  # Would query evidence fabric
                "latest_security_assessment": None,
                "compliance_evidence_count": 0,
                "last_evidence_update": None
            }
        
        return {
            "success": True,
            "message": f"Vendor details retrieved: {vendor.name}",
            "data": vendor_details
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Vendor details retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Vendor details failed: {str(e)}")


@router.get("/organizations/{org_id}/vendors/discovered")
async def list_discovered_vendors(
    org_id: UUID,
    reviewed: Optional[bool] = Query(None, description="Filter by review status"),
    confidence_threshold: float = Query(0.7, description="Minimum confidence score", ge=0.0, le=1.0),
    discovery_method: Optional[str] = Query(None, description="Filter by discovery method"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """List automatically discovered vendors."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        tracker = get_discovered_vendor_tracker()
        
        # Discover vendors from OAuth apps and integrations
        oauth_discovered = await tracker.discover_vendors_from_oauth(str(org_id))
        integration_discovered = await tracker.discover_vendors_from_integrations(str(org_id))
        
        all_discovered = oauth_discovered + integration_discovered
        
        # Apply filters
        filtered_discovered = all_discovered
        
        if reviewed is not None:
            filtered_discovered = [v for v in filtered_discovered if v.reviewed == reviewed]
        
        if confidence_threshold > 0:
            filtered_discovered = [v for v in filtered_discovered if v.confidence_score >= confidence_threshold]
        
        if discovery_method:
            filtered_discovered = [v for v in filtered_discovered if v.discovery_method.value == discovery_method]
        
        return {
            "organization_id": str(org_id),
            "total_discovered": len(all_discovered),
            "filtered_count": len(filtered_discovered),
            "filters_applied": {
                "reviewed": reviewed,
                "confidence_threshold": confidence_threshold,
                "discovery_method": discovery_method
            },
            "discovered_vendors": [
                {
                    "discovered_vendor_id": vendor.discovered_vendor_id,
                    "vendor_name": vendor.vendor_name,
                    "domain": vendor.domain,
                    "discovery_method": vendor.discovery_method.value,
                    "discovered_at": vendor.discovered_at.isoformat(),
                    "confidence_score": vendor.confidence_score,
                    "estimated_category": vendor.estimated_category,
                    "risk_indicators": vendor.risk_indicators,
                    "data_access_detected": vendor.data_access_detected,
                    "oauth_apps": vendor.oauth_apps,
                    "integrations": vendor.integrations,
                    "reviewed": vendor.reviewed,
                    "promoted_to_vendor": vendor.promoted_to_vendor
                }
                for vendor in filtered_discovered
            ]
        }
        
    except Exception as e:
        logger.error(f"Discovered vendors listing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Discovered vendors failed: {str(e)}")


@router.get("/organizations/{org_id}/vendors/risk-report")
async def get_vendor_risk_report(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Get comprehensive vendor risk assessment report."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        vendor_registry = get_vendor_registry()
        risk_report = await vendor_registry.generate_vendor_risk_report(str(org_id))
        
        return {
            "success": True,
            "message": f"Vendor risk report generated for {risk_report['summary']['total_vendors']} vendors",
            "data": risk_report
        }
        
    except Exception as e:
        logger.error(f"Vendor risk report failed: {e}")
        raise HTTPException(status_code=500, detail=f"Risk report failed: {str(e)}")


@router.post("/organizations/{org_id}/vendors/discovered/{discovered_vendor_id}/review")
async def review_discovered_vendor(
    org_id: UUID,
    discovered_vendor_id: str,
    promote_to_vendor: bool = Field(..., description="Whether to promote to full vendor"),
    suppression_reason: Optional[str] = Field(None, description="Reason for suppression if not promoting"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Review discovered vendor and decide on promotion or suppression."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        tracker = get_discovered_vendor_tracker()
        
        review_result = await tracker.review_discovered_vendor(
            discovered_vendor_id,
            current_user.username,
            promote_to_vendor,
            suppression_reason
        )
        
        return {
            "success": True,
            "message": f"Discovered vendor reviewed: {'promoted' if promote_to_vendor else 'suppressed'}",
            "data": review_result
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Discovered vendor review failed: {e}")
        raise HTTPException(status_code=500, detail=f"Review failed: {str(e)}")


# Vendor evidence queries (leveraging the evidence data fabric)
@router.get("/organizations/{org_id}/vendors/{vendor_id}/evidence")
async def get_vendor_evidence(
    org_id: UUID,
    vendor_id: str,
    evidence_type: Optional[str] = Query(None, description="Filter by evidence type"),
    since_days: int = Query(90, description="Evidence age limit in days", ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Get compliance evidence related to vendor."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        # Query evidence data fabric for vendor-related evidence
        # This demonstrates the key integration point
        
        evidence_query = EvidenceQuery(
            entity_ids=[vendor_id],
            entity_types=[EvidenceEntityType.DOCUMENT, EvidenceEntityType.CONFIGURATION],
            time_range=(datetime.now() - timedelta(days=since_days), datetime.now()),
            tags={"vendor_id": vendor_id},
            limit=100
        )
        
        # In production, would query actual evidence fabric
        mock_evidence = [
            {
                "evidence_id": f"ev_{vendor_id}_security_assessment",
                "entity_type": "document",
                "observed_at": (datetime.now() - timedelta(days=30)).isoformat(),
                "evidence_type": "security_assessment",
                "source_system": "manual_upload",
                "content_summary": "Annual security assessment questionnaire",
                "quality_score": 0.95,
                "requirements": ["SOC2_CC6.1", "ISO27001_A.15.1.1"]
            },
            {
                "evidence_id": f"ev_{vendor_id}_certification",
                "entity_type": "document", 
                "observed_at": (datetime.now() - timedelta(days=60)).isoformat(),
                "evidence_type": "certification",
                "source_system": "vendor_portal",
                "content_summary": "SOC 2 Type II certification",
                "quality_score": 1.0,
                "requirements": ["SOC2_CC1.1", "SOC2_CC2.1"]
            }
        ]
        
        # Filter by evidence type if specified
        if evidence_type:
            mock_evidence = [e for e in mock_evidence if e["evidence_type"] == evidence_type]
        
        return {
            "vendor_id": vendor_id,
            "evidence_period_days": since_days,
            "total_evidence_records": len(mock_evidence),
            "evidence": mock_evidence
        }
        
    except Exception as e:
        logger.error(f"Vendor evidence retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Evidence retrieval failed: {str(e)}")
