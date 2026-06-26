package grc

import (
	"strconv"
	"strings"
)

var attributeFieldMappings = map[grcFamily][]string{
	familyFramework:                {"framework_id", "id", "display_name", "displayName", "name", "shorthandName", "description", "description", "num_controls_completed", "numControlsCompleted", "num_controls_total", "numControlsTotal", "num_documents_passing", "numDocumentsPassing", "num_documents_total", "numDocumentsTotal", "num_tests_passing", "numTestsPassing", "num_tests_total", "numTestsTotal"},
	familyControl:                  {"control_id", "id", "control_external_id", "externalId", "name", "name", "description", "description", "source", "source", "domains", "domains", "owner_id", "owner.id", "role", "role", "created_at", "creationDate", "modified_at", "modificationDate"},
	familyControlTest:              {"test_id", "id", "name", "name", "description", "description", "control_id", "controlId", "control_ids", "controlIds", "control_external_id", "controlExternalId", "control_external_ids", "controlExternalIds", "last_run_at", "lastTestRunDate", "latest_flip_at", "latestFlipDate", "failure_description", "failureDescription", "remediation_description", "remediationDescription", "version", "version", "category", "category", "integrations", "integrations", "status", "status", "owner_id", "owner.id"},
	familyPolicy:                   {"policy_id", "id", "name", "name", "description", "description", "status", "status", "approved_at", "approvedAtDate", "latest_version_status", "latestVersion.status"},
	familyDocument:                 {"document_id", "id", "owner_id", "ownerId", "category", "category", "description", "description", "is_sensitive", "isSensitive", "title", "title", "upload_status", "uploadStatus", "upload_status_date", "uploadStatusDate", "url", "url"},
	familyContract:                 {"contract_id", "id", "name", "name", "vendor_id", "vendorId", "vendor_name", "vendorName", "owner_id", "ownerId", "business_owner_user_id", "businessOwnerUserId", "control_ids", "controlIds", "evidence_id", "evidenceId", "evidence_cas_uri", "evidenceCasUri", "evidence_type", "evidenceType", "status", "status", "contract_type", "contractType", "agreement_type", "agreementType", "tags", "tags", "data_types", "dataTypes", "jurisdictions", "jurisdictions", "category", "category", "customer_trust_account_id", "customerTrustAccountId", "executed_at", "executedDate", "created_at", "creationDate"},
	familyRegulatoryNotification:   {"notification_id", "id", "title", "title", "framework", "framework", "regulator", "regulator", "incident_id", "incidentId", "case_id", "caseId", "incident_title", "incidentTitle", "notification_type", "notificationType", "report_type", "reportType", "status", "status", "notification_status", "notificationStatus", "owner_id", "ownerId", "control_ids", "controlIds", "evidence_id", "evidenceId", "evidence_cas_uri", "evidenceCasUri", "evidence_type", "evidenceType", "sent_at", "sentAt", "submitted_at", "submittedAt"},
	familyRecoveryObjective:        {"recovery_objective_id", "id", "objective_id", "objectiveId", "bia_id", "biaId", "name", "name", "service_id", "serviceId", "target_id", "targetId", "target_type", "targetType", "resource_id", "resourceId", "asset_id", "assetId", "business_process", "businessProcess", "process_name", "processName", "rto_minutes", "rtoMinutes", "rpo_minutes", "rpoMinutes", "owner_id", "ownerId", "control_ids", "controlIds", "evidence_id", "evidenceId", "evidence_cas_uri", "evidenceCasUri", "impact_tier", "impactTier", "criticality", "criticality", "recovery_priority", "recoveryPriority", "status", "status"},
	familyAuthorizationPackage:     {"authorization_package_id", "id", "package_id", "packageId", "ato_id", "atoId", "ssp_id", "sspId", "name", "name", "system_id", "systemId", "system_name", "systemName", "target_id", "targetId", "target_type", "targetType", "framework", "framework", "impact_level", "impactLevel", "owner_id", "ownerId", "system_owner_user_id", "systemOwnerUserId", "control_ids", "controlIds", "evidence_id", "evidenceId", "evidence_cas_uri", "evidenceCasUri", "status", "status", "authorization_status", "authorizationStatus"},
	familyPOAMItem:                 {"poam_item_id", "id", "weakness_id", "weaknessId", "finding_id", "findingId", "finding_name", "findingName", "title", "title", "weakness_name", "weaknessName", "risk_rating", "riskRating", "severity", "severity", "status", "status", "target_id", "targetId", "target_type", "targetType", "owner_id", "ownerId", "control_ids", "controlIds", "evidence_id", "evidenceId", "evidence_cas_uri", "evidenceCasUri", "evidence_type", "evidenceType", "due_at", "dueAt", "closed_at", "closedAt"},
	familyTrainingAttestation:      {"attestation_id", "id", "training_attestation_id", "trainingAttestationId", "person_id", "personId", "person_name", "personName", "user_id", "userId", "display_name", "displayName", "email", "email", "course_id", "courseId", "course_name", "courseName", "training_type", "trainingType", "course_type", "courseType", "completed_at", "completedAt", "expires_at", "expiresAt", "status", "status", "control_ids", "controlIds", "evidence_id", "evidenceId", "evidence_cas_uri", "evidenceCasUri"},
	familyDiscoveredVendor:         {"discovered_vendor_id", "id", "vendor_id", "id", "name", "name", "normalized_name", "normalizedName", "category", "category.name", "source", "source", "discovered_at", "discoveredDate", "account_count", "numberOfAccounts", "ignored_at", "ignored.ignoredAtDate", "ignored_reason", "ignored.ignoredReason", "ignored_by_user_id", "ignored.ignoredByUserId", "rejected_at", "rejected.rejectedAtDate", "rejected_reason", "rejected.rejectedReason", "rejected_by_user_id", "rejected.rejectedByUserId"},
	familyEventLog:                 {"event_log_id", "id", "action", "action", "actor_type", "actor.type", "actor_id", "actor.id", "occurred_at", "date", "target_ids", "targets"},
	familyGroup:                    {"group_id", "id", "group_name", "name", "name", "name", "created_at", "creationDate"},
	familyVendorRiskAttribute:      {"vendor_risk_attribute_id", "id", "name", "name", "description", "description", "vendor_categories", "vendorCategories", "enabled", "enabled", "risk_level", "riskLevel"},
	familyVendor:                   {"vendor_id", "id", "name", "name", "website_url", "websiteUrl", "account_manager_email", "accountManagerEmail", "services_provided", "servicesProvided", "security_owner_user_id", "securityOwnerUserId", "business_owner_user_id", "businessOwnerUserId", "contract_start_date", "contractStartDate", "contract_renewal_date", "contractRenewalDate", "contract_termination_date", "contractTerminationDate", "next_security_review_due_date", "nextSecurityReviewDueDate", "last_security_review_completion_date", "lastSecurityReviewCompletionDate", "category", "category.displayName", "status", "status", "inherent_risk_level", "inherentRiskLevel", "residual_risk_level", "residualRiskLevel"},
	familyVulnerability:            {"vulnerability_id", "id", "name", "name", "description", "description", "integration_id", "integrationId", "package_identifier", "packageIdentifier", "package", "packageIdentifier", "package_purl", "packageIdentifier", "vulnerability_type", "vulnerabilityType", "target_id", "targetId", "first_detected_at", "firstDetectedDate", "source_detected_at", "sourceDetectedDate", "last_detected_at", "lastDetectedDate", "severity", "severity", "cvss_severity_score", "cvssSeverityScore", "scanner_score", "scannerScore", "is_fixable", "isFixable", "fixed_version", "fixedVersion", "remediate_by_date", "remediateByDate", "external_url", "externalURL", "scan_source", "scanSource"},
	familyVulnerabilityRemediation: {"remediation_id", "id", "vulnerability_id", "vulnerabilityId", "vulnerable_asset_id", "vulnerableAssetId", "target_id", "vulnerableAssetId", "asset_id", "vulnerableAssetId", "severity", "severity", "detected_at", "detectedDate", "sla_deadline_at", "slaDeadlineDate", "remediation_date", "remediationDate", "remediated_at", "remediationDate", "vulnerability_status", "status", "remediation_status", "status"},
	familyMonitoredComputer:        {"computer_id", "id", "device_id", "id", "device_uuid", "udid", "serial_number", "serialNumber", "integration_id", "integrationId", "last_check_at", "lastCheckDate", "screenlock_status", "screenlock.outcome", "disk_encryption_status", "diskEncryption.outcome", "password_manager_status", "passwordManager.outcome", "antivirus_status", "antivirusInstallation.outcome", "os", "operatingSystem.type", "os_name", "operatingSystem.type", "os_version", "operatingSystem.version", "owner_id", "owner.id", "owner_email", "owner.emailAddress", "owner_display_name", "owner.displayName"},
	familyRiskScenario:             {"risk_id", "riskId", "description", "description", "likelihood", "likelihood", "impact", "impact", "residual_likelihood", "residualLikelihood", "residual_impact", "residualImpact", "categories", "categories", "cia_categories", "ciaCategories", "treatment", "treatment", "owner", "owner", "note", "note", "risk_register", "riskRegister", "review_status", "reviewStatus", "type", "type", "identified_at", "identificationDate"},
	familyPerson:                   {"person_id", "id", "user_id", "userId", "email", "emailAddress", "department", "employment.department", "employment_end_date", "employment.endDate", "employee_number", "employment.employeeNumber", "job_title", "employment.jobTitle", "manager", "employment.manager", "manager_id", "employment.managerId", "employment_start_date", "employment.startDate", "employment_status", "employment.status", "group_ids", "groupIds"},
	familyUser:                     {"user_id", "id", "email", "email", "display_name", "displayName", "is_active", "isActive"},
	familyIntegration:              {"integration_id", "integrationId", "display_name", "displayName", "resource_kinds", "resourceKinds"},
}

func attributesFor(settings settings, family grcFamily, record grcRecord) map[string]string {
	values := record.Values
	attrs := map[string]string{
		"provider":        settings.provider,
		"source_provider": settings.provider,
		"external_id":     record.ID,
	}
	copyFieldPairs(attrs, values, attributeFieldMappings[family])
	switch family {
	case familyControlTest:
		copyControlReferenceFields(attrs, values)
	case familyEventLog:
		if targets := eventLogTargets(values); targets != "" {
			attrs["targets"] = targets
		}
	case familyVulnerableAsset:
		copyFirstField(attrs, values, "asset_id", "id", "assetId", "targetId")
		copyFirstField(attrs, values, "target_id", "id", "assetId", "targetId")
		copyFirstField(attrs, values, "target_name", "displayName", "name", "hostname", "host", "url")
		copyFirstField(attrs, values, "resource_name", "displayName", "name", "hostname", "host", "url")
		copyFirstField(attrs, values, "hostname", "hostname", "host", "dnsName", "fqdn")
		copyFirstField(attrs, values, "ip", "ipAddress", "publicIp", "publicIP", "ip")
		copyFirstField(attrs, values, "asset_type", "assetType", "resourceType", "type")
		copyFirstField(attrs, values, "resource_type", "assetType", "resourceType", "type")
		copyFirstField(attrs, values, "integration_id", "integrationId", "integration.id")
		copyFirstField(attrs, values, "external_url", "externalURL", "url")
		copyFirstField(attrs, values, "target_url", "url", "externalURL")
		copyFirstField(attrs, values, "operating_system", "operatingSystem", "os")
		copyFirstField(attrs, values, "last_detected_at", "lastDetectedDate", "lastSeenDate", "updatedAt")
		copyVulnerableAssetPlatformReferences(attrs, values)
		copyVulnerableAssetReferences(attrs, values)
	case familyMonitoredComputer:
		attrs["source_product"] = settings.provider
		attrs["compliance_status"] = monitoredComputerComplianceStatus(attrs)
	case familyIntegration:
		attrs["connection_count"] = strconv.Itoa(len(arrayValue(values, "connections")))
		attrs["disabled_connection_count"] = strconv.Itoa(countConnections(values, true, false))
		attrs["connection_error_count"] = strconv.Itoa(countConnections(values, false, true))
	}
	return trimEmpty(attrs)
}

func copyFieldPairs(attrs map[string]string, values map[string]any, pairs []string) {
	for i := 0; i+1 < len(pairs); i += 2 {
		target, source := pairs[i], pairs[i+1]
		if value := fieldString(values, source); value != "" {
			attrs[target] = value
		}
	}
}

func copyFirstField(attrs map[string]string, values map[string]any, target string, sources ...string) {
	if strings.TrimSpace(attrs[target]) != "" {
		return
	}
	for _, source := range sources {
		if value := fieldString(values, source); value != "" {
			attrs[target] = value
			return
		}
	}
}

func trimEmpty(values map[string]string) map[string]string {
	for key, value := range values {
		if strings.TrimSpace(value) == "" {
			delete(values, key)
		}
	}
	return values
}
