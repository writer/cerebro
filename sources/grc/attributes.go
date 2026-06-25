package grc

import (
	"encoding/json"
	"strconv"
	"strings"
)

var attributeFieldMappings = map[string][]string{
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
	familyRiskScenario:             {"risk_id", "riskId", "description", "description", "likelihood", "likelihood", "impact", "impact", "residual_likelihood", "residualLikelihood", "residual_impact", "residualImpact", "categories", "categories", "cia_categories", "ciaCategories", "treatment", "treatment", "owner", "owner", "note", "note", "risk_register", "riskRegister", "review_status", "reviewStatus", "type", "type", "identified_at", "identificationDate"},
	familyPerson:                   {"person_id", "id", "user_id", "userId", "email", "emailAddress", "department", "employment.department", "employment_end_date", "employment.endDate", "employee_number", "employment.employeeNumber", "job_title", "employment.jobTitle", "manager", "employment.manager", "manager_id", "employment.managerId", "employment_start_date", "employment.startDate", "employment_status", "employment.status", "group_ids", "groupIds"},
	familyUser:                     {"user_id", "id", "email", "email", "display_name", "displayName", "is_active", "isActive"},
	familyIntegration:              {"integration_id", "integrationId", "display_name", "displayName", "resource_kinds", "resourceKinds"},
}

func attributesFor(settings settings, family string, record grcRecord) map[string]string {
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

func copyControlReferenceFields(attrs map[string]string, values map[string]any) {
	copyFirstField(attrs, values, "control_id", "controlID", "control.id")
	copyFirstField(attrs, values, "control_external_id", "controlExternalID", "control.externalId", "control.externalID")
	if references := joinedControlReferences(values, "controls"); references != "" {
		attrs["control_references"] = references
	}
	if ids := joinedObjectFieldValues(values, "controls", "id"); ids != "" {
		attrs["control_ids"] = ids
		if strings.TrimSpace(attrs["control_id"]) == "" {
			attrs["control_id"] = firstDelimitedValue(ids)
		}
	}
	if externalIDs := joinedObjectFieldValues(values, "controls", "externalId", "externalID"); externalIDs != "" {
		attrs["control_external_ids"] = externalIDs
		if strings.TrimSpace(attrs["control_external_id"]) == "" {
			attrs["control_external_id"] = firstDelimitedValue(externalIDs)
		}
	}
}

func eventLogTargets(values map[string]any) string {
	items := arrayValue(values, "targets")
	if len(items) == 0 {
		return ""
	}
	targets := make([]string, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		targetID := valueString(object["id"])
		if targetID == "" {
			continue
		}
		targetType := valueString(object["type"])
		if targetType == "" {
			targets = append(targets, targetID)
			continue
		}
		targets = append(targets, targetType+":"+targetID)
	}
	return strings.Join(targets, ";")
}

type vulnerableAssetPlatformReference struct {
	Provider          string `json:"provider,omitempty"`
	ResourceID        string `json:"resource_id,omitempty"`
	ResourceName      string `json:"resource_name,omitempty"`
	ResourceType      string `json:"resource_type,omitempty"`
	ScannerResourceID string `json:"scanner_resource_id,omitempty"`
	Hostnames         string `json:"hostnames,omitempty"`
	IPs               string `json:"ips,omitempty"`
}

func copyVulnerableAssetPlatformReferences(attrs map[string]string, values map[string]any) {
	refs := vulnerableAssetPlatformReferences(values)
	if len(refs) == 0 {
		return
	}
	if raw, err := json.Marshal(refs); err == nil {
		attrs["platform_asset_refs"] = string(raw)
	}
	first := refs[0]
	addAttrIfMissing(attrs, "platform_provider", first.Provider)
	addAttrIfMissing(attrs, "platform_resource_id", first.ResourceID)
	addAttrIfMissing(attrs, "platform_resource_name", first.ResourceName)
	addAttrIfMissing(attrs, "platform_resource_type", first.ResourceType)
	addAttrIfMissing(attrs, "scanner_resource_id", first.ScannerResourceID)
	hostnames := joinedUniqueDelimitedValues(refs, func(ref vulnerableAssetPlatformReference) string { return ref.Hostnames })
	ips := joinedUniqueDelimitedValues(refs, func(ref vulnerableAssetPlatformReference) string { return ref.IPs })
	if hostnames != "" {
		attrs["hostnames"] = hostnames
		addAttrIfMissing(attrs, "hostname", firstDelimitedValue(hostnames))
	}
	if ips != "" {
		attrs["ip_addresses"] = ips
		addAttrIfMissing(attrs, "ip", firstDelimitedValue(ips))
	}
}

func vulnerableAssetPlatformReferences(values map[string]any) []vulnerableAssetPlatformReference {
	items := arrayValue(values, "scanners")
	refs := make([]vulnerableAssetPlatformReference, 0, len(items))
	seen := map[string]struct{}{}
	resourceName := firstNonEmptyString(fieldString(values, "displayName"), fieldString(values, "name"), fieldString(values, "hostname"), fieldString(values, "host"))
	resourceType := firstNonEmptyString(fieldString(values, "resourceType"), fieldString(values, "assetType"), fieldString(values, "type"))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		provider := firstNonEmptyString(fieldString(object, "integrationId"), fieldString(object, "integration.id"), fieldString(object, "provider"))
		resourceID := firstNonEmptyString(fieldString(object, "targetId"), fieldString(object, "resourceArn"), fieldString(object, "arn"))
		scannerResourceID := fieldString(object, "resourceId")
		if resourceID == "" && platformResourceIDLikelyExternal(scannerResourceID) {
			resourceID = scannerResourceID
		}
		hostnames := joinedPlatformObjectFieldValues(object, "hostnames", "fqdns", "hostname", "fqdn")
		ips := joinedPlatformObjectFieldValues(object, "ipv4s", "ipv6s", "ipAddresses", "ipAddress", "publicIp", "publicIP")
		if provider == "" && resourceID == "" && scannerResourceID == "" && hostnames == "" && ips == "" {
			continue
		}
		ref := vulnerableAssetPlatformReference{
			Provider:          provider,
			ResourceID:        resourceID,
			ResourceName:      resourceName,
			ResourceType:      firstNonEmptyString(fieldString(object, "resourceType"), fieldString(object, "assetType"), resourceType),
			ScannerResourceID: scannerResourceID,
			Hostnames:         normalizeDelimitedValues(hostnames),
			IPs:               normalizeDelimitedValues(ips),
		}
		key := strings.Join([]string{ref.Provider, ref.ResourceID, ref.ScannerResourceID, ref.Hostnames, ref.IPs}, "\x00")
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, ref)
	}
	return refs
}

func addAttrIfMissing(attrs map[string]string, key string, value string) {
	if strings.TrimSpace(attrs[key]) == "" {
		if value = strings.TrimSpace(value); value != "" {
			attrs[key] = value
		}
	}
}

func platformResourceIDLikelyExternal(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "arn:") || strings.Contains(value, "://") || strings.Contains(value, "/")
}

func joinedPlatformObjectFieldValues(object map[string]any, names ...string) string {
	values := make([]string, 0, len(names))
	for _, name := range names {
		values = append(values, splitDelimitedValues(fieldString(object, name))...)
	}
	return strings.Join(uniqueStrings(values), ",")
}

func joinedUniqueDelimitedValues(refs []vulnerableAssetPlatformReference, selectValue func(vulnerableAssetPlatformReference) string) string {
	values := make([]string, 0, len(refs))
	for _, ref := range refs {
		values = append(values, splitDelimitedValues(selectValue(ref))...)
	}
	return strings.Join(uniqueStrings(values), ",")
}

func normalizeDelimitedValues(value string) string {
	return strings.Join(uniqueStrings(splitDelimitedValues(value)), ",")
}

func splitDelimitedValues(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t'
	})
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func copyVulnerableAssetReferences(attrs map[string]string, values map[string]any) {
	if ids := firstNonEmptyString(
		joinedObjectFieldValues(values, "vulnerabilities", "id", "vulnerabilityId"),
		fieldString(values, "vulnerabilityIds"),
	); ids != "" {
		attrs["vulnerability_ids"] = ids
	}
	if names := firstNonEmptyString(
		joinedObjectFieldValues(values, "vulnerabilities", "name", "title"),
		fieldString(values, "vulnerabilityNames"),
	); names != "" {
		attrs["vulnerability_names"] = names
	}
	if packages := firstNonEmptyString(
		joinedObjectFieldValues(values, "vulnerabilities", "packageIdentifier", "package", "packagePurl"),
		fieldString(values, "packageIdentifiers"),
		fieldString(values, "packages"),
	); packages != "" {
		attrs["package_identifiers"] = packages
	}
	if references := joinedVulnerableAssetReferences(values); references != "" {
		attrs["vulnerability_package_refs"] = references
	}
}

func joinedControlReferences(values map[string]any, arrayKey string) string {
	items := arrayValue(values, arrayKey)
	collected := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id := valueString(object["id"])
		externalID := firstNonEmptyString(valueString(object["externalId"]), valueString(object["externalID"]))
		if id == "" && externalID == "" {
			continue
		}
		if id == "" {
			id = externalID
		}
		pair := id + "=" + externalID
		if _, exists := seen[pair]; exists {
			continue
		}
		seen[pair] = struct{}{}
		collected = append(collected, pair)
	}
	return strings.Join(collected, ";")
}

func joinedVulnerableAssetReferences(values map[string]any) string {
	items := arrayValue(values, "vulnerabilities")
	refs := make([]map[string]string, 0, len(items))
	seen := map[string]struct{}{}
	vulnerabilityIDs := splitVulnerableAssetReferenceValues(fieldString(values, "vulnerabilityIds"))
	vulnerabilityNames := splitVulnerableAssetReferenceValues(fieldString(values, "vulnerabilityNames"))
	packageIdentifiers := splitVulnerableAssetReferenceValues(firstNonEmptyString(fieldString(values, "packageIdentifiers"), fieldString(values, "packages")))
	for i, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		vulnerabilityID := firstNonEmptyString(valueString(object["id"]), valueString(object["vulnerabilityId"]), valueAt(vulnerabilityIDs, i))
		vulnerabilityName := firstNonEmptyString(valueString(object["name"]), valueString(object["title"]), valueAt(vulnerabilityNames, i))
		packageIdentifier := firstNonEmptyString(valueString(object["packageIdentifier"]), valueString(object["package"]), valueString(object["packagePurl"]), valueAt(packageIdentifiers, i))
		if vulnerabilityID == "" && vulnerabilityName == "" && packageIdentifier == "" {
			continue
		}
		key := strings.Join([]string{vulnerabilityID, vulnerabilityName, packageIdentifier}, "\x00")
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		ref := map[string]string{}
		if vulnerabilityID != "" {
			ref["vulnerability_id"] = vulnerabilityID
		}
		if vulnerabilityName != "" {
			ref["vulnerability_name"] = vulnerabilityName
		}
		if packageIdentifier != "" {
			ref["package_identifier"] = packageIdentifier
		}
		refs = append(refs, ref)
	}
	for i, ref := range refs {
		if ref["vulnerability_id"] == "" {
			if vulnerabilityID := valueAt(vulnerabilityIDs, i); vulnerabilityID != "" {
				ref["vulnerability_id"] = vulnerabilityID
			}
		}
		if ref["vulnerability_name"] == "" {
			if vulnerabilityName := valueAt(vulnerabilityNames, i); vulnerabilityName != "" {
				ref["vulnerability_name"] = vulnerabilityName
			}
		}
		if ref["package_identifier"] == "" {
			if packageIdentifier := valueAt(packageIdentifiers, i); packageIdentifier != "" {
				ref["package_identifier"] = packageIdentifier
			}
		}
	}
	for i := len(refs); i < maxInt(len(vulnerabilityIDs), len(vulnerabilityNames), len(packageIdentifiers)); i++ {
		vulnerabilityID := valueAt(vulnerabilityIDs, i)
		vulnerabilityName := valueAt(vulnerabilityNames, i)
		packageIdentifier := valueAt(packageIdentifiers, i)
		if vulnerabilityID == "" && vulnerabilityName == "" && packageIdentifier == "" {
			continue
		}
		key := strings.Join([]string{vulnerabilityID, vulnerabilityName, packageIdentifier}, "\x00")
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		ref := map[string]string{}
		if vulnerabilityID != "" {
			ref["vulnerability_id"] = vulnerabilityID
		}
		if vulnerabilityName != "" {
			ref["vulnerability_name"] = vulnerabilityName
		}
		if packageIdentifier != "" {
			ref["package_identifier"] = packageIdentifier
		}
		refs = append(refs, ref)
	}
	if len(refs) == 0 {
		for i := 0; i < maxInt(len(vulnerabilityIDs), len(vulnerabilityNames), len(packageIdentifiers)); i++ {
			vulnerabilityID := valueAt(vulnerabilityIDs, i)
			vulnerabilityName := valueAt(vulnerabilityNames, i)
			packageIdentifier := valueAt(packageIdentifiers, i)
			if vulnerabilityID == "" && vulnerabilityName == "" && packageIdentifier == "" {
				continue
			}
			key := strings.Join([]string{vulnerabilityID, vulnerabilityName, packageIdentifier}, "\x00")
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			ref := map[string]string{}
			if vulnerabilityID != "" {
				ref["vulnerability_id"] = vulnerabilityID
			}
			if vulnerabilityName != "" {
				ref["vulnerability_name"] = vulnerabilityName
			}
			if packageIdentifier != "" {
				ref["package_identifier"] = packageIdentifier
			}
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		return ""
	}
	raw, err := json.Marshal(refs)
	if err != nil {
		return ""
	}
	return string(raw)
}

func splitVulnerableAssetReferenceValues(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t'
	})
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func valueAt(values []string, index int) string {
	if index < 0 || index >= len(values) {
		return ""
	}
	return values[index]
}

func maxInt(values ...int) int {
	max := 0
	for _, value := range values {
		if value > max {
			max = value
		}
	}
	return max
}

func joinedObjectFieldValues(values map[string]any, arrayKey string, fields ...string) string {
	items := arrayValue(values, arrayKey)
	collected := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, field := range fields {
			value := valueString(object[field])
			if value == "" {
				continue
			}
			if _, exists := seen[value]; !exists {
				collected = append(collected, value)
				seen[value] = struct{}{}
			}
			break
		}
	}
	return strings.Join(collected, ",")
}

func firstDelimitedValue(value string) string {
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func trimEmpty(values map[string]string) map[string]string {
	for key, value := range values {
		if strings.TrimSpace(value) == "" {
			delete(values, key)
		}
	}
	return values
}

func countConnections(values map[string]any, disabled bool, errored bool) int {
	count := 0
	for _, item := range arrayValue(values, "connections") {
		connection, ok := item.(map[string]any)
		if !ok {
			continue
		}
		isDisabled, _ := connection["isDisabled"].(bool)
		hasError := strings.TrimSpace(valueString(connection["connectionErrorMessage"])) != ""
		if disabled && isDisabled {
			count++
		}
		if errored && hasError {
			count++
		}
	}
	return count
}
