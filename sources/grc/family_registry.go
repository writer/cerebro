package grc

type grcFamilyDescriptor struct {
	Family         grcFamily
	Endpoint       string
	IDKeys         []string
	TimestampKeys  []string
	AttributePairs []string
}

var defaultGRCRecordIDKeys = []string{"id", "externalId", "name"}

func grcFamilyDesc(family grcFamily, endpoint string, idKeys, timestampKeys []string, attributePairs ...string) grcFamilyDescriptor {
	if idKeys == nil {
		idKeys = defaultGRCRecordIDKeys
	}
	return grcFamilyDescriptor{
		Family:         family,
		Endpoint:       endpoint,
		IDKeys:         idKeys,
		TimestampKeys:  timestampKeys,
		AttributePairs: attributePairs,
	}
}

var grcFamilyDescriptors = []grcFamilyDescriptor{
	grcFamilyDesc(familyFramework, "/v1/frameworks", nil, nil, "framework_id", "id", "display_name", "displayName", "name", "shorthandName", "description", "description", "num_controls_completed", "numControlsCompleted", "num_controls_total", "numControlsTotal", "num_documents_passing", "numDocumentsPassing", "num_documents_total", "numDocumentsTotal", "num_tests_passing", "numTestsPassing", "num_tests_total", "numTestsTotal"),
	grcFamilyDesc(familyControl, "/v1/controls", nil, []string{"modificationDate", "creationDate"}, "control_id", "id", "control_external_id", "externalId", "name", "name", "description", "description", "source", "source", "domains", "domains", "owner_id", "owner.id", "role", "role", "created_at", "creationDate", "modified_at", "modificationDate"),
	grcFamilyDesc(familyControlTest, "/v1/tests", nil, []string{"lastTestRunDate", "latestFlipDate"}, "test_id", "id", "name", "name", "description", "description", "control_id", "controlId", "control_ids", "controlIds", "control_external_id", "controlExternalId", "control_external_ids", "controlExternalIds", "last_run_at", "lastTestRunDate", "latest_flip_at", "latestFlipDate", "failure_description", "failureDescription", "remediation_description", "remediationDescription", "version", "version", "category", "category", "integrations", "integrations", "status", "status", "owner_id", "owner.id"),
	grcFamilyDesc(familyPolicy, "/v1/policies", nil, []string{"approvedAtDate"}, "policy_id", "id", "name", "name", "description", "description", "status", "status", "approved_at", "approvedAtDate", "latest_version_status", "latestVersion.status"),
	grcFamilyDesc(familyDocument, "/v1/documents", nil, []string{"uploadStatusDate"}, "document_id", "id", "owner_id", "ownerId", "category", "category", "description", "description", "is_sensitive", "isSensitive", "title", "title", "upload_status", "uploadStatus", "upload_status_date", "uploadStatusDate", "url", "url"),
	grcFamilyDesc(familyContract, "/v1/contracts", nil, []string{"executedDate", "creationDate"}, "contract_id", "id", "name", "name", "vendor_id", "vendorId", "vendor_name", "vendorName", "owner_id", "ownerId", "business_owner_user_id", "businessOwnerUserId", "control_ids", "controlIds", "evidence_id", "evidenceId", "evidence_cas_uri", "evidenceCasUri", "evidence_type", "evidenceType", "status", "status", "contract_type", "contractType", "agreement_type", "agreementType", "tags", "tags", "data_types", "dataTypes", "jurisdictions", "jurisdictions", "category", "category", "customer_trust_account_id", "customerTrustAccountId", "executed_at", "executedDate", "created_at", "creationDate"),
	grcFamilyDesc(familyRegulatoryNotification, "/v1/regulatory-notifications", []string{"id", "notificationId", "externalId"}, []string{"sentAt", "submittedAt", "notificationDate", "createdAt", "updatedAt"}, "notification_id", "id", "title", "title", "framework", "framework", "regulator", "regulator", "incident_id", "incidentId", "case_id", "caseId", "incident_title", "incidentTitle", "notification_type", "notificationType", "report_type", "reportType", "status", "status", "notification_status", "notificationStatus", "owner_id", "ownerId", "control_ids", "controlIds", "evidence_id", "evidenceId", "evidence_cas_uri", "evidenceCasUri", "evidence_type", "evidenceType", "sent_at", "sentAt", "submitted_at", "submittedAt"),
	grcFamilyDesc(familyRecoveryObjective, "/v1/recovery-objectives", []string{"id", "objectiveId", "biaId", "externalId", "name"}, []string{"reviewedAt", "updatedAt", "createdAt"}, "recovery_objective_id", "id", "objective_id", "objectiveId", "bia_id", "biaId", "name", "name", "service_id", "serviceId", "target_id", "targetId", "target_type", "targetType", "resource_id", "resourceId", "asset_id", "assetId", "business_process", "businessProcess", "process_name", "processName", "rto_minutes", "rtoMinutes", "rpo_minutes", "rpoMinutes", "owner_id", "ownerId", "control_ids", "controlIds", "evidence_id", "evidenceId", "evidence_cas_uri", "evidenceCasUri", "impact_tier", "impactTier", "criticality", "criticality", "recovery_priority", "recoveryPriority", "status", "status"),
	grcFamilyDesc(familyAuthorizationPackage, "/v1/authorization-packages", []string{"id", "packageId", "atoId", "sspId", "externalId", "name"}, []string{"authorizedAt", "authorizationDate", "updatedAt", "createdAt"}, "authorization_package_id", "id", "package_id", "packageId", "ato_id", "atoId", "ssp_id", "sspId", "name", "name", "system_id", "systemId", "system_name", "systemName", "target_id", "targetId", "target_type", "targetType", "framework", "framework", "impact_level", "impactLevel", "owner_id", "ownerId", "system_owner_user_id", "systemOwnerUserId", "control_ids", "controlIds", "evidence_id", "evidenceId", "evidence_cas_uri", "evidenceCasUri", "status", "status", "authorization_status", "authorizationStatus"),
	grcFamilyDesc(familyPOAMItem, "/v1/poam-items", []string{"id", "poamItemId", "weaknessId", "findingId", "externalId", "title"}, []string{"closedAt", "openedAt", "identifiedAt", "updatedAt", "createdAt"}, "poam_item_id", "id", "weakness_id", "weaknessId", "finding_id", "findingId", "finding_name", "findingName", "title", "title", "weakness_name", "weaknessName", "risk_rating", "riskRating", "severity", "severity", "status", "status", "target_id", "targetId", "target_type", "targetType", "owner_id", "ownerId", "control_ids", "controlIds", "evidence_id", "evidenceId", "evidence_cas_uri", "evidenceCasUri", "evidence_type", "evidenceType", "due_at", "dueAt", "closed_at", "closedAt"),
	grcFamilyDesc(familyTrainingAttestation, "/v1/training-attestations", []string{"id", "attestationId", "trainingAttestationId", "externalId"}, []string{"completedAt", "completionDate", "updatedAt", "createdAt"}, "attestation_id", "id", "training_attestation_id", "trainingAttestationId", "person_id", "personId", "person_name", "personName", "user_id", "userId", "display_name", "displayName", "email", "email", "course_id", "courseId", "course_name", "courseName", "training_type", "trainingType", "course_type", "courseType", "completed_at", "completedAt", "expires_at", "expiresAt", "status", "status", "control_ids", "controlIds", "evidence_id", "evidenceId", "evidence_cas_uri", "evidenceCasUri"),
	grcFamilyDesc(familyDiscoveredVendor, "/v1/discovered-vendors", nil, []string{"discoveredDate", "ignored.ignoredAtDate", "rejected.rejectedAtDate"}, "discovered_vendor_id", "id", "vendor_id", "id", "name", "name", "normalized_name", "normalizedName", "category", "category.name", "source", "source", "discovered_at", "discoveredDate", "account_count", "numberOfAccounts", "ignored_at", "ignored.ignoredAtDate", "ignored_reason", "ignored.ignoredReason", "ignored_by_user_id", "ignored.ignoredByUserId", "rejected_at", "rejected.rejectedAtDate", "rejected_reason", "rejected.rejectedReason", "rejected_by_user_id", "rejected.rejectedByUserId"),
	grcFamilyDesc(familyEventLog, "/v1/event-logs", nil, []string{"date"}, "event_log_id", "id", "action", "action", "actor_type", "actor.type", "actor_id", "actor.id", "occurred_at", "date", "target_ids", "targets"),
	grcFamilyDesc(familyGroup, "/v1/groups", nil, []string{"creationDate"}, "group_id", "id", "group_name", "name", "name", "name", "created_at", "creationDate"),
	grcFamilyDesc(familyVendorRiskAttribute, "/v1/vendor-risk-attributes", nil, nil, "vendor_risk_attribute_id", "id", "name", "name", "description", "description", "vendor_categories", "vendorCategories", "enabled", "enabled", "risk_level", "riskLevel"),
	grcFamilyDesc(familyVendor, "/v1/vendors", nil, []string{"lastSecurityReviewCompletionDate"}, "vendor_id", "id", "name", "name", "website_url", "websiteUrl", "account_manager_email", "accountManagerEmail", "services_provided", "servicesProvided", "security_owner_user_id", "securityOwnerUserId", "business_owner_user_id", "businessOwnerUserId", "contract_start_date", "contractStartDate", "contract_renewal_date", "contractRenewalDate", "contract_termination_date", "contractTerminationDate", "next_security_review_due_date", "nextSecurityReviewDueDate", "last_security_review_completion_date", "lastSecurityReviewCompletionDate", "category", "category.displayName", "status", "status", "inherent_risk_level", "inherentRiskLevel", "residual_risk_level", "residualRiskLevel"),
	grcFamilyDesc(familyVulnerability, "/v1/vulnerabilities", nil, []string{"lastDetectedDate", "sourceDetectedDate", "firstDetectedDate"}, "vulnerability_id", "id", "name", "name", "description", "description", "integration_id", "integrationId", "package_identifier", "packageIdentifier", "package", "packageIdentifier", "package_purl", "packageIdentifier", "vulnerability_type", "vulnerabilityType", "target_id", "targetId", "first_detected_at", "firstDetectedDate", "source_detected_at", "sourceDetectedDate", "last_detected_at", "lastDetectedDate", "severity", "severity", "cvss_severity_score", "cvssSeverityScore", "scanner_score", "scannerScore", "is_fixable", "isFixable", "fixed_version", "fixedVersion", "remediate_by_date", "remediateByDate", "external_url", "externalURL", "scan_source", "scanSource"),
	grcFamilyDesc(familyVulnerabilityRemediation, "/v1/vulnerability-remediations", nil, []string{"remediationDate", "detectedDate"}, "remediation_id", "id", "vulnerability_id", "vulnerabilityId", "vulnerable_asset_id", "vulnerableAssetId", "target_id", "vulnerableAssetId", "asset_id", "vulnerableAssetId", "severity", "severity", "detected_at", "detectedDate", "sla_deadline_at", "slaDeadlineDate", "remediation_date", "remediationDate", "remediated_at", "remediationDate", "vulnerability_status", "status", "remediation_status", "status"),
	grcFamilyDesc(familyVulnerableAsset, "/v1/vulnerable-assets", []string{"id", "assetId", "targetId", "externalId", "name"}, []string{"lastDetectedDate", "lastSeenDate", "updatedAt"}),
	grcFamilyDesc(familyMonitoredComputer, "/v1/monitored-computers", []string{"id", "serialNumber", "udid"}, []string{"lastCheckDate"}, "computer_id", "id", "device_id", "id", "device_uuid", "udid", "serial_number", "serialNumber", "integration_id", "integrationId", "last_check_at", "lastCheckDate", "screenlock_status", "screenlock.outcome", "disk_encryption_status", "diskEncryption.outcome", "password_manager_status", "passwordManager.outcome", "antivirus_status", "antivirusInstallation.outcome", "os", "operatingSystem.type", "os_name", "operatingSystem.type", "os_version", "operatingSystem.version", "owner_id", "owner.id", "owner_email", "owner.emailAddress", "owner_display_name", "owner.displayName"),
	grcFamilyDesc(familyRiskScenario, "/v1/risk-scenarios", []string{"riskId", "id"}, []string{"identificationDate"}, "risk_id", "riskId", "description", "description", "likelihood", "likelihood", "impact", "impact", "residual_likelihood", "residualLikelihood", "residual_impact", "residualImpact", "categories", "categories", "cia_categories", "ciaCategories", "treatment", "treatment", "owner", "owner", "note", "note", "risk_register", "riskRegister", "review_status", "reviewStatus", "type", "type", "identified_at", "identificationDate"),
	grcFamilyDesc(familyPerson, "/v1/people", []string{"id", "userId", "emailAddress"}, []string{"employment.startDate", "employment.endDate"}, "person_id", "id", "user_id", "userId", "email", "emailAddress", "department", "employment.department", "employment_end_date", "employment.endDate", "employee_number", "employment.employeeNumber", "job_title", "employment.jobTitle", "manager", "employment.manager", "manager_id", "employment.managerId", "employment_start_date", "employment.startDate", "employment_status", "employment.status", "group_ids", "groupIds"),
	grcFamilyDesc(familyUser, "/v1/users", []string{"id", "email"}, nil, "user_id", "id", "email", "email", "display_name", "displayName", "is_active", "isActive"),
	grcFamilyDesc(familyIntegration, "/v1/integrations", []string{"integrationId", "id"}, nil, "integration_id", "integrationId", "display_name", "displayName", "resource_kinds", "resourceKinds"),
}

var grcFamilyDescriptorByFamily = func() map[grcFamily]grcFamilyDescriptor {
	descriptors := make(map[grcFamily]grcFamilyDescriptor, len(grcFamilyDescriptors))
	for _, descriptor := range grcFamilyDescriptors {
		descriptors[descriptor.Family] = descriptor
	}
	return descriptors
}()

func grcDescriptorFor(family grcFamily) grcFamilyDescriptor {
	if descriptor, ok := grcFamilyDescriptorByFamily[family]; ok {
		return descriptor
	}
	return grcFamilyDescriptor{Family: family, IDKeys: defaultGRCRecordIDKeys}
}
