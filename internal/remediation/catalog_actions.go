package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type catalogActionPlan struct {
	entry             CatalogEntry
	provider          string
	resourceID        string
	resourceName      string
	resourceType      string
	deliveryMode      DeliveryMode
	tool              string
	dryRun            bool
	approvalRequired  bool
	before            map[string]any
	preconditionCheck []map[string]any
}

type accessKeyCandidate struct {
	ID           string
	InactiveDays int
	Source       string
}

func (ex *Executor) executeCatalogAction(ctx context.Context, action Action, execution *Execution) (string, map[string]any, error, bool) {
	switch action.Type {
	case ActionRestrictPublicStorageAccess:
		output, metadata, err := ex.restrictPublicStorageAccess(ctx, action, execution)
		return output, metadata, err, true
	case ActionEnableBucketDefaultEncryption:
		output, metadata, err := ex.enableBucketDefaultEncryption(ctx, action, execution)
		return output, metadata, err, true
	case ActionDisableStaleAccessKey:
		output, metadata, err := ex.disableStaleAccessKey(ctx, action, execution)
		return output, metadata, err, true
	case ActionRestrictPublicSecurityGroupIngress:
		output, metadata, err := ex.restrictPublicSecurityGroupIngress(ctx, action, execution)
		return output, metadata, err, true
	default:
		return "", nil, nil, false
	}
}

func (ex *Executor) restrictPublicStorageAccess(ctx context.Context, action Action, execution *Execution) (string, map[string]any, error) {
	entry, _ := CatalogEntryByAction(action.Type)
	plan := newCatalogActionPlan(action, execution, entry, ex.actionRequiresApproval(action))
	plan.before = captureStorageAccessEvidence(execution)

	publicAccess, detail := publicStorageAccessStillEnabled(execution)
	plan.preconditionCheck = append(plan.preconditionCheck,
		preconditionResult("resource identifier available", plan.resourceID != "", firstNonEmpty(plan.resourceID, "missing resource identifier")),
		preconditionResult("provider supported", plan.provider != "" && plan.tool != "", firstNonEmpty(plan.provider, "missing provider")),
		preconditionResult("resource still public", publicAccess, detail),
	)

	metadata := plan.metadata(nil)
	if !allPreconditionsPassed(plan.preconditionCheck) {
		return "", metadata, fmt.Errorf("restrict public storage access precondition failed")
	}

	enrichExecutionWithCatalogPlan(execution, plan)
	if plan.dryRun {
		metadata["after"] = map[string]any{
			"planned": true,
			"change":  "public access would be removed",
		}
		return fmt.Sprintf("Dry-run: would invoke %s", plan.tool), metadata, nil
	}

	output, err := ex.executeCatalogRemoteAction(ctx, action, execution, plan)
	metadata["after"] = catalogAfterState(output, err)
	if err != nil {
		return "", metadata, err
	}
	return firstNonEmpty(strings.TrimSpace(output), "Public access restricted"), metadata, nil
}

func (ex *Executor) enableBucketDefaultEncryption(ctx context.Context, action Action, execution *Execution) (string, map[string]any, error) {
	entry, _ := CatalogEntryByAction(action.Type)
	plan := newCatalogActionPlan(action, execution, entry, ex.actionRequiresApproval(action))
	sseAlgorithm := firstNonEmpty(strings.TrimSpace(action.Config["sse_algorithm"]), "AES256")
	kmsMasterKeyID := strings.TrimSpace(action.Config["kms_master_key_id"])
	bucketKeyEnabled := configBool(action.Config["bucket_key_enabled"])
	plan.before = captureBucketEncryptionEvidence(execution)

	disabled, detail := bucketDefaultEncryptionStillDisabled(execution)
	plan.preconditionCheck = append(plan.preconditionCheck,
		preconditionResult("resource identifier available", plan.resourceID != "", firstNonEmpty(plan.resourceID, "missing resource identifier")),
		preconditionResult("provider supported", plan.provider == "aws" && (plan.deliveryMode == DeliveryModeTerraform || plan.tool != ""), firstNonEmpty(plan.provider, "missing provider")),
		preconditionResult("bucket default encryption still disabled", disabled, detail),
	)
	metadata := plan.metadata(map[string]any{
		"sse_algorithm":      sseAlgorithm,
		"kms_master_key_id":  kmsMasterKeyID,
		"bucket_key_enabled": bucketKeyEnabled,
	})
	if !catalogSupportsDeliveryMode(entry, plan.deliveryMode) {
		return "", compactAnyMap(metadata), fmt.Errorf("delivery mode %q is not supported for %s", plan.deliveryMode, action.Type)
	}
	metadata = compactAnyMap(metadata)
	if !allPreconditionsPassed(plan.preconditionCheck) {
		return "", metadata, fmt.Errorf("enable bucket default encryption precondition failed")
	}

	enrichExecutionWithCatalogPlan(execution, plan)
	if execution.TriggerData == nil {
		execution.TriggerData = map[string]any{}
	}
	execution.TriggerData["sse_algorithm"] = sseAlgorithm
	if kmsMasterKeyID != "" {
		execution.TriggerData["kms_master_key_id"] = kmsMasterKeyID
	}
	if bucketKeyEnabled {
		execution.TriggerData["bucket_key_enabled"] = true
	}

	if plan.deliveryMode == DeliveryModeTerraform {
		artifact, err := renderTerraformBucketDefaultEncryptionArtifact(execution, sseAlgorithm, kmsMasterKeyID, bucketKeyEnabled)
		if err != nil {
			return "", compactAnyMap(metadata), err
		}
		metadata["artifact"] = terraformArtifactMetadata(artifact)
		metadata["after"] = map[string]any{
			"planned":          true,
			"delivery_mode":    string(plan.deliveryMode),
			"change":           "terraform configuration generated for bucket default encryption",
			"artifact_path":    artifact.Path,
			"resource_address": artifact.ResourceAddress,
		}
		return fmt.Sprintf("Generated Terraform remediation at %s", artifact.Path), compactAnyMap(metadata), nil
	}

	if plan.dryRun {
		metadata["after"] = map[string]any{
			"planned":            true,
			"change":             "bucket default encryption would be enabled",
			"sse_algorithm":      sseAlgorithm,
			"kms_master_key_id":  kmsMasterKeyID,
			"bucket_key_enabled": bucketKeyEnabled,
		}
		return fmt.Sprintf("Dry-run: would invoke %s", plan.tool), compactAnyMap(metadata), nil
	}

	output, err := ex.executeCatalogRemoteAction(ctx, action, execution, plan)
	metadata["after"] = catalogAfterState(output, err)
	if err != nil {
		return "", compactAnyMap(metadata), err
	}
	return firstNonEmpty(strings.TrimSpace(output), fmt.Sprintf("Enabled bucket default encryption using %s", sseAlgorithm)), compactAnyMap(metadata), nil
}

func (ex *Executor) restrictPublicSecurityGroupIngress(ctx context.Context, action Action, execution *Execution) (string, map[string]any, error) {
	entry, _ := CatalogEntryByAction(action.Type)
	plan := newCatalogActionPlan(action, execution, entry, ex.actionRequiresApproval(action))
	matches, detail := publicSecurityGroupIngressMatches(execution)
	plan.before = captureSecurityGroupIngressEvidence(execution, matches)

	matchedPorts := matchedRulePorts(matches)
	matchedCIDRs := matchedRuleCIDRs(matches)
	plan.preconditionCheck = append(plan.preconditionCheck,
		preconditionResult("resource identifier available", plan.resourceID != "", firstNonEmpty(plan.resourceID, "missing resource identifier")),
		preconditionResult("provider supported", plan.provider == "aws" && plan.tool != "", firstNonEmpty(plan.provider, "missing provider")),
		preconditionResult("matching public ingress identified", len(matches) > 0, detail),
	)

	metadata := plan.metadata(map[string]any{
		"matched_rule_count": len(matches),
		"matched_ports":      matchedPorts,
		"matched_cidrs":      matchedCIDRs,
	})
	if !allPreconditionsPassed(plan.preconditionCheck) {
		return "", metadata, fmt.Errorf("restrict public security group ingress precondition failed")
	}

	enrichExecutionWithCatalogPlan(execution, plan)
	if execution.TriggerData == nil {
		execution.TriggerData = map[string]any{}
	}
	execution.TriggerData["security_group_rule_matches"] = cloneMapSlice(matches)
	execution.TriggerData["matched_ports"] = append([]string(nil), matchedPorts...)
	execution.TriggerData["matched_cidrs"] = append([]string(nil), matchedCIDRs...)

	if plan.dryRun {
		metadata["after"] = map[string]any{
			"planned":            true,
			"change":             "public ingress rules would be revoked",
			"matched_rule_count": len(matches),
		}
		return fmt.Sprintf("Dry-run: would invoke %s", plan.tool), metadata, nil
	}

	output, err := ex.executeCatalogRemoteAction(ctx, action, execution, plan)
	metadata["after"] = catalogAfterState(output, err)
	if err != nil {
		return "", metadata, err
	}
	return firstNonEmpty(strings.TrimSpace(output), fmt.Sprintf("Revoked %d public ingress rule(s)", len(matches))), metadata, nil
}

func (ex *Executor) disableStaleAccessKey(ctx context.Context, action Action, execution *Execution) (string, map[string]any, error) {
	entry, _ := CatalogEntryByAction(action.Type)
	plan := newCatalogActionPlan(action, execution, entry, ex.actionRequiresApproval(action))
	threshold := actionIntConfig(action, "inactive_days", 90)
	candidate, candidateOK := staleAccessKeyCandidateFromExecution(execution, threshold)
	plan.before = captureAccessKeyEvidence(execution, candidate, threshold)

	plan.preconditionCheck = append(plan.preconditionCheck,
		preconditionResult("resource identifier available", plan.resourceID != "", firstNonEmpty(plan.resourceID, "missing resource identifier")),
		preconditionResult("provider supported", plan.provider != "" && plan.tool != "", firstNonEmpty(plan.provider, "missing provider")),
		preconditionResult("stale access key identified", candidateOK, firstNonEmpty(candidate.ID, "no stale access key found")),
	)

	metadata := plan.metadata(map[string]any{
		"access_key_id":  candidate.ID,
		"inactive_days":  candidate.InactiveDays,
		"threshold_days": threshold,
	})
	if !allPreconditionsPassed(plan.preconditionCheck) {
		return "", metadata, fmt.Errorf("disable stale access key precondition failed")
	}

	if execution.TriggerData == nil {
		execution.TriggerData = map[string]any{}
	}
	execution.TriggerData["access_key_id"] = candidate.ID
	execution.TriggerData["inactive_days"] = candidate.InactiveDays
	execution.TriggerData["threshold_days"] = threshold
	execution.TriggerData["provider"] = plan.provider

	if plan.dryRun {
		metadata["after"] = map[string]any{
			"planned":        true,
			"change":         "access key would be disabled",
			"access_key_id":  candidate.ID,
			"inactive_days":  candidate.InactiveDays,
			"threshold_days": threshold,
		}
		return fmt.Sprintf("Dry-run: would disable access key %s with %d inactive days", candidate.ID, candidate.InactiveDays), metadata, nil
	}

	output, err := ex.executeCatalogRemoteAction(ctx, action, execution, plan)
	metadata["after"] = catalogAfterState(output, err)
	if err != nil {
		return "", metadata, err
	}
	return firstNonEmpty(strings.TrimSpace(output), fmt.Sprintf("Disabled stale access key %s", candidate.ID)), metadata, nil
}

func (ex *Executor) executeCatalogRemoteAction(ctx context.Context, action Action, execution *Execution, plan catalogActionPlan) (string, error) {
	if ex.ensemble == nil || !ex.ensemble.HasRemoteCaller() {
		return "", fmt.Errorf("remote tool caller not configured")
	}

	cloned := action
	cloned.Config = cloneStringMap(action.Config)
	if cloned.Config == nil {
		cloned.Config = map[string]string{}
	}
	if strings.TrimSpace(cloned.Config["tool"]) == "" {
		cloned.Config["tool"] = plan.tool
	}
	return ex.ensemble.ExecuteWithOutput(ctx, cloned, execution)
}

func newCatalogActionPlan(action Action, execution *Execution, entry CatalogEntry, approvalRequired bool) catalogActionPlan {
	provider := inferProvider(execution)
	deliveryMode := actionDeliveryMode(action, entry)
	tool := ""
	if deliveryMode == DeliveryModeRemoteApply {
		tool = firstNonEmpty(action.Config["tool"], catalogToolForProvider(entry, provider))
	}
	return catalogActionPlan{
		entry:            entry,
		provider:         provider,
		resourceID:       firstNonEmpty(remediationMapValueToString(execution.TriggerData, "entity_id"), remediationMapValueToString(execution.TriggerData, "resource_id"), remediationMapValueToString(execution.TriggerData, "resource_external_id")),
		resourceName:     remediationMapValueToString(execution.TriggerData, "resource_name"),
		resourceType:     remediationMapValueToString(execution.TriggerData, "resource_type"),
		deliveryMode:     deliveryMode,
		tool:             tool,
		dryRun:           dryRunEnabled(action, execution),
		approvalRequired: approvalRequired,
	}
}

func (p catalogActionPlan) metadata(extra map[string]any) map[string]any {
	metadata := map[string]any{
		"catalog_entry_id":    p.entry.ID,
		"catalog_entry_name":  p.entry.Name,
		"provider":            p.provider,
		"resource_id":         p.resourceID,
		"resource_name":       p.resourceName,
		"resource_type":       p.resourceType,
		"delivery_mode":       string(p.deliveryMode),
		"dry_run":             p.dryRun,
		"requires_approval":   p.approvalRequired,
		"blast_radius":        p.entry.BlastRadius,
		"blast_radius_reason": p.entry.BlastRadiusRationale,
		"planned_tool":        p.tool,
		"preconditions":       append([]map[string]any(nil), p.preconditionCheck...),
		"rollback_steps":      append([]string(nil), p.entry.RollbackSteps...),
		"before":              cloneAnyMap(p.before),
	}
	for key, value := range extra {
		metadata[key] = value
	}
	return metadata
}

func enrichExecutionWithCatalogPlan(execution *Execution, plan catalogActionPlan) {
	if execution == nil {
		return
	}
	if execution.TriggerData == nil {
		execution.TriggerData = map[string]any{}
	}
	if plan.provider != "" {
		execution.TriggerData["provider"] = plan.provider
	}
	if plan.resourceName != "" {
		execution.TriggerData["resource_name"] = plan.resourceName
	}
	if plan.resourceType != "" {
		execution.TriggerData["resource_type"] = plan.resourceType
	}
}

func publicStorageAccessStillEnabled(execution *Execution) (bool, string) {
	if execution == nil {
		return false, "missing execution context"
	}
	data := execution.TriggerData
	if resource, ok := data["resource"].(map[string]any); ok {
		if value, detail, ok := publicStorageAccessFromValue(resource, "resource payload"); ok {
			return value, detail
		}
		if value, detail, ok := publicStorageAccessFromValue(resource["resource_json"], "resource payload resource_json"); ok {
			return value, detail
		}
	}
	if value, detail, ok := publicStorageAccessFromValue(data["resource_json"], "trigger data resource_json"); ok {
		return value, detail
	}
	if value, detail, ok := publicStorageAccessFromValue(data, "trigger data"); ok {
		return value, detail
	}
	policyID := strings.ToLower(strings.TrimSpace(remediationMapValueToString(data, "policy_id")))
	if policyID != "" {
		return false, "policy finding indicates public exposure but current resource data does not confirm it"
	}
	return false, "no public exposure signal found in trigger data"
}

func publicStorageAccessFromValue(raw any, source string) (bool, string, bool) {
	values, ok := anyMap(raw)
	if !ok {
		return false, "", false
	}
	value, ok := firstBool(values,
		"public_access",
		"public",
		"publicly_accessible",
		"internet_accessible",
		"all_users_access",
		"all_authenticated_users_access",
		"anonymous_access",
	)
	if !ok {
		return false, "", false
	}
	if value {
		return true, fmt.Sprintf("%s still marks the storage resource as public", source), true
	}
	return false, fmt.Sprintf("%s marks the storage resource as private", source), true
}

func anyMap(raw any) (map[string]any, bool) {
	switch typed := raw.(type) {
	case map[string]any:
		return typed, true
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return nil, false
		}
		var decoded map[string]any
		if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
			return nil, false
		}
		return decoded, true
	case []byte:
		if len(typed) == 0 {
			return nil, false
		}
		var decoded map[string]any
		if err := json.Unmarshal(typed, &decoded); err != nil {
			return nil, false
		}
		return decoded, true
	default:
		return nil, false
	}
}

func captureStorageAccessEvidence(execution *Execution) map[string]any {
	evidence := map[string]any{
		"resource_id":          firstNonEmpty(remediationMapValueToString(execution.TriggerData, "entity_id"), remediationMapValueToString(execution.TriggerData, "resource_id")),
		"resource_name":        remediationMapValueToString(execution.TriggerData, "resource_name"),
		"resource_type":        remediationMapValueToString(execution.TriggerData, "resource_type"),
		"resource_platform":    remediationMapValueToString(execution.TriggerData, "resource_platform"),
		"resource_external_id": remediationMapValueToString(execution.TriggerData, "resource_external_id"),
		"policy_id":            remediationMapValueToString(execution.TriggerData, "policy_id"),
	}
	copyFields(evidence, execution.TriggerData, "public_access", "public", "publicly_accessible", "internet_accessible", "all_users_access", "all_authenticated_users_access", "anonymous_access", "public_access_prevention", "uniform_bucket_level_access")
	if resource, ok := execution.TriggerData["resource"].(map[string]any); ok && len(resource) > 0 {
		evidence["resource"] = cloneAnyMap(resource)
	}
	return compactAnyMap(evidence)
}

func captureBucketEncryptionEvidence(execution *Execution) map[string]any {
	evidence := map[string]any{
		"resource_id":          firstNonEmpty(remediationMapValueToString(execution.TriggerData, "entity_id"), remediationMapValueToString(execution.TriggerData, "resource_id")),
		"resource_name":        remediationMapValueToString(execution.TriggerData, "resource_name"),
		"resource_type":        remediationMapValueToString(execution.TriggerData, "resource_type"),
		"resource_platform":    remediationMapValueToString(execution.TriggerData, "resource_platform"),
		"resource_external_id": remediationMapValueToString(execution.TriggerData, "resource_external_id"),
		"policy_id":            remediationMapValueToString(execution.TriggerData, "policy_id"),
	}
	copyFields(evidence, execution.TriggerData, "encrypted", "default_encryption", "default_encryption_enabled", "encryption_enabled", "server_side_encryption_enabled", "kms_encrypted", "encryption", "sse_algorithm", "encryption_algorithm", "kms_master_key_id", "encryption_key_id", "bucket_key_enabled", "server_side_encryption_configuration", "encryption_configuration")
	if resource, ok := execution.TriggerData["resource"].(map[string]any); ok && len(resource) > 0 {
		evidence["resource"] = cloneAnyMap(resource)
	}
	return compactAnyMap(evidence)
}

func captureSecurityGroupIngressEvidence(execution *Execution, matches []map[string]any) map[string]any {
	evidence := map[string]any{
		"resource_id":          firstNonEmpty(remediationMapValueToString(execution.TriggerData, "entity_id"), remediationMapValueToString(execution.TriggerData, "resource_id")),
		"resource_name":        remediationMapValueToString(execution.TriggerData, "resource_name"),
		"resource_type":        remediationMapValueToString(execution.TriggerData, "resource_type"),
		"resource_platform":    remediationMapValueToString(execution.TriggerData, "resource_platform"),
		"resource_external_id": remediationMapValueToString(execution.TriggerData, "resource_external_id"),
		"policy_id":            remediationMapValueToString(execution.TriggerData, "policy_id"),
		"matched_rule_count":   len(matches),
		"matched_ports":        matchedRulePorts(matches),
		"matched_cidrs":        matchedRuleCIDRs(matches),
	}
	if len(matches) > 0 {
		evidence["matched_rules"] = cloneMapSlice(matches)
	}
	copyFields(evidence, execution.TriggerData, "direction", "protocol", "from_port", "to_port", "ip_ranges", "ipv6_ranges")
	if resource, ok := execution.TriggerData["resource"].(map[string]any); ok && len(resource) > 0 {
		evidence["resource"] = cloneAnyMap(resource)
	}
	return compactAnyMap(evidence)
}

func captureAccessKeyEvidence(execution *Execution, candidate accessKeyCandidate, threshold int) map[string]any {
	evidence := map[string]any{
		"resource_id":          firstNonEmpty(remediationMapValueToString(execution.TriggerData, "entity_id"), remediationMapValueToString(execution.TriggerData, "resource_id")),
		"resource_name":        remediationMapValueToString(execution.TriggerData, "resource_name"),
		"resource_type":        remediationMapValueToString(execution.TriggerData, "resource_type"),
		"policy_id":            remediationMapValueToString(execution.TriggerData, "policy_id"),
		"access_key_id":        candidate.ID,
		"inactive_days":        candidate.InactiveDays,
		"threshold_days":       threshold,
		"access_key_source":    candidate.Source,
		"resource_platform":    remediationMapValueToString(execution.TriggerData, "resource_platform"),
		"resource_external_id": remediationMapValueToString(execution.TriggerData, "resource_external_id"),
	}
	copyFields(evidence, execution.TriggerData, "access_key_metadata", "access_keys")
	if evidence["access_key_id"] == "" {
		copyFields(evidence, execution.TriggerData, "access_key_id")
	}
	if resource, ok := execution.TriggerData["resource"].(map[string]any); ok && len(resource) > 0 {
		evidence["resource"] = cloneAnyMap(resource)
	}
	return compactAnyMap(evidence)
}

func publicSecurityGroupIngressMatches(execution *Execution) ([]map[string]any, string) {
	if execution == nil {
		return nil, "missing execution context"
	}
	data := execution.TriggerData
	policyID := strings.ToLower(strings.TrimSpace(remediationMapValueToString(data, "policy_id")))
	if resource, ok := data["resource"].(map[string]any); ok {
		if matches := securityGroupMatchesFromPermissions(resource["ip_permissions"], policyID); len(matches) > 0 {
			return matches, fmt.Sprintf("resource payload contains %d matching public ingress rule(s)", len(matches))
		}
		if matches := securityGroupMatchesFromRuleValues(resource, policyID); len(matches) > 0 {
			return matches, fmt.Sprintf("resource payload contains %d matching public ingress rule(s)", len(matches))
		}
	}
	if matches := securityGroupMatchesFromPermissions(data["ip_permissions"], policyID); len(matches) > 0 {
		return matches, fmt.Sprintf("trigger data contains %d matching public ingress rule(s)", len(matches))
	}
	if matches := securityGroupMatchesFromRuleValues(data, policyID); len(matches) > 0 {
		return matches, fmt.Sprintf("trigger data contains %d matching public ingress rule(s)", len(matches))
	}
	if policyID != "" {
		return nil, "current security group data does not confirm a matching public ingress rule"
	}
	return nil, "no matching public ingress rule found in trigger data"
}

func bucketDefaultEncryptionStillDisabled(execution *Execution) (bool, string) {
	if execution == nil {
		return false, "missing execution context"
	}
	data := execution.TriggerData
	if value, detail, ok := bucketDefaultEncryptionFromValue(data["resource"], "resource payload"); ok {
		return value, detail
	}
	if resource, ok := anyMap(data["resource"]); ok {
		if value, detail, ok := bucketDefaultEncryptionFromValue(resource["resource_json"], "resource payload resource_json"); ok {
			return value, detail
		}
	}
	if value, detail, ok := bucketDefaultEncryptionFromValue(data["resource_json"], "trigger data resource_json"); ok {
		return value, detail
	}
	if value, detail, ok := bucketDefaultEncryptionFromValue(data, "trigger data"); ok {
		return value, detail
	}
	if strings.EqualFold(strings.TrimSpace(remediationMapValueToString(data, "policy_id")), "aws-s3-bucket-encryption-enabled") {
		return true, "current bucket data does not show default encryption enabled"
	}
	return false, "current bucket data does not confirm default encryption is disabled"
}

func bucketDefaultEncryptionFromValue(raw any, source string) (bool, string, bool) {
	values, ok := anyMap(raw)
	if !ok {
		return false, "", false
	}
	enabled, known := bucketDefaultEncryptionEnabled(values)
	if !known {
		return false, "", false
	}
	if enabled {
		return false, fmt.Sprintf("%s shows default encryption enabled", source), true
	}
	return true, fmt.Sprintf("%s does not show default encryption enabled", source), true
}

func bucketDefaultEncryptionEnabled(values map[string]any) (bool, bool) {
	if len(values) == 0 {
		return false, false
	}
	if enabled, ok := firstBool(values, "encrypted", "default_encryption", "default_encryption_enabled", "encryption_enabled", "server_side_encryption_enabled", "kms_encrypted"); ok {
		return enabled, true
	}
	for _, key := range []string{"server_side_encryption_configuration", "encryption_configuration"} {
		if raw, ok := values[key]; ok {
			return hasStructuredValue(raw), true
		}
	}
	for _, key := range []string{"sse_algorithm", "encryption_algorithm", "kms_master_key_id", "encryption_key_id", "encryption"} {
		if raw, ok := values[key]; ok {
			return strings.TrimSpace(stringValue(raw)) != "", true
		}
	}
	return false, false
}

func securityGroupMatchesFromPermissions(raw any, policyID string) []map[string]any {
	items := anySlice(raw)
	if len(items) == 0 {
		return nil
	}
	matches := make([]map[string]any, 0, len(items))
	for _, item := range items {
		values, ok := anyMap(item)
		if !ok {
			continue
		}
		match, ok := securityGroupIngressMatch(values, policyID)
		if ok {
			matches = append(matches, match)
		}
	}
	return matches
}

func securityGroupMatchesFromRuleValues(values map[string]any, policyID string) []map[string]any {
	if len(values) == 0 {
		return nil
	}
	direction := strings.ToLower(strings.TrimSpace(firstNonEmpty(remediationMapValueToString(values, "direction"), remediationMapValueToString(values, "Direction"))))
	if direction != "" && direction != "ingress" {
		return nil
	}
	match, ok := securityGroupIngressMatch(values, policyID)
	if !ok {
		return nil
	}
	return []map[string]any{match}
}

func securityGroupIngressMatch(values map[string]any, policyID string) (map[string]any, bool) {
	protocol := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		remediationMapValueToString(values, "IpProtocol"),
		remediationMapValueToString(values, "ip_protocol"),
		remediationMapValueToString(values, "protocol"),
	)))
	fromPort, hasFrom := firstInt(values, "FromPort", "from_port")
	toPort, hasTo := firstInt(values, "ToPort", "to_port")
	publicCIDRs := publicCIDRs(values["IpRanges"], values["ip_ranges"], values["Ipv6Ranges"], values["ipv6_ranges"])
	if len(publicCIDRs) == 0 {
		return nil, false
	}
	if !securityGroupPolicyMatchesRule(policyID, protocol, fromPort, toPort, hasFrom, hasTo) {
		return nil, false
	}
	match := map[string]any{
		"direction":    "ingress",
		"protocol":     protocol,
		"public_cidrs": publicCIDRs,
		"port_label":   securityGroupPortLabel(protocol, fromPort, toPort, hasFrom, hasTo),
	}
	if hasFrom {
		match["from_port"] = fromPort
	}
	if hasTo {
		match["to_port"] = toPort
	}
	return compactAnyMap(match), true
}

func securityGroupPolicyMatchesRule(policyID, protocol string, fromPort, toPort int, hasFrom, hasTo bool) bool {
	switch policyID {
	case "aws-security-group-restrict-ssh", "aws-ec2-public-ip-ssh":
		return securityGroupRuleAllowsPort(protocol, fromPort, toPort, hasFrom, hasTo, 22)
	case "aws-security-group-restrict-rdp", "aws-ec2-public-ip-rdp":
		return securityGroupRuleAllowsPort(protocol, fromPort, toPort, hasFrom, hasTo, 3389)
	case "aws-ec2-sg-no-all-traffic-ingress":
		return securityGroupRuleAllowsAllTraffic(protocol, fromPort, toPort, hasFrom, hasTo)
	default:
		return false
	}
}

func securityGroupRuleAllowsPort(protocol string, fromPort, toPort int, hasFrom, hasTo bool, targetPort int) bool {
	switch protocol {
	case "-1", "all":
		return true
	case "":
		if !hasFrom && !hasTo {
			return false
		}
	case "tcp":
	default:
		return false
	}
	if !hasFrom && !hasTo {
		return true
	}
	if !hasFrom {
		fromPort = toPort
	}
	if !hasTo {
		toPort = fromPort
	}
	if fromPort > toPort {
		fromPort, toPort = toPort, fromPort
	}
	return targetPort >= fromPort && targetPort <= toPort
}

func securityGroupRuleAllowsAllTraffic(protocol string, fromPort, toPort int, hasFrom, hasTo bool) bool {
	if protocol == "-1" || protocol == "all" {
		return true
	}
	if !hasFrom && !hasTo {
		return false
	}
	if !hasFrom {
		fromPort = toPort
	}
	if !hasTo {
		toPort = fromPort
	}
	if fromPort > toPort {
		fromPort, toPort = toPort, fromPort
	}
	return fromPort <= 0 && toPort >= 65535
}

func securityGroupPortLabel(protocol string, fromPort, toPort int, hasFrom, hasTo bool) string {
	if protocol == "-1" || protocol == "all" || (!hasFrom && !hasTo) {
		return "all"
	}
	if !hasFrom {
		fromPort = toPort
	}
	if !hasTo {
		toPort = fromPort
	}
	if fromPort == toPort {
		return strconv.Itoa(fromPort)
	}
	return fmt.Sprintf("%d-%d", fromPort, toPort)
}

func publicCIDRs(raws ...any) []string {
	seen := make(map[string]struct{})
	cidrs := make([]string, 0)
	for _, raw := range raws {
		for _, item := range anySlice(raw) {
			values, ok := anyMap(item)
			if !ok {
				continue
			}
			for _, key := range []string{"CidrIp", "cidr_ip", "cidr", "CidrIpv6", "cidr_ipv6"} {
				cidr := strings.TrimSpace(remediationMapValueToString(values, key))
				if cidr != "0.0.0.0/0" && cidr != "::/0" {
					continue
				}
				if _, ok := seen[cidr]; ok {
					continue
				}
				seen[cidr] = struct{}{}
				cidrs = append(cidrs, cidr)
			}
		}
	}
	sort.Strings(cidrs)
	return cidrs
}

func anySlice(raw any) []any {
	switch typed := raw.(type) {
	case []any:
		return append([]any(nil), typed...)
	case []string:
		items := make([]any, 0, len(typed))
		for _, item := range typed {
			items = append(items, item)
		}
		return items
	case []map[string]any:
		items := make([]any, 0, len(typed))
		for _, item := range typed {
			items = append(items, item)
		}
		return items
	default:
		return nil
	}
}

func matchedRulePorts(matches []map[string]any) []string {
	seen := make(map[string]struct{})
	ports := make([]string, 0, len(matches))
	for _, match := range matches {
		port := strings.TrimSpace(remediationMapValueToString(match, "port_label"))
		if port == "" {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	sort.Strings(ports)
	return ports
}

func matchedRuleCIDRs(matches []map[string]any) []string {
	seen := make(map[string]struct{})
	cidrs := make([]string, 0, len(matches))
	for _, match := range matches {
		for _, cidr := range anySlice(match["public_cidrs"]) {
			text := strings.TrimSpace(fmt.Sprintf("%v", cidr))
			if text == "" {
				continue
			}
			if _, ok := seen[text]; ok {
				continue
			}
			seen[text] = struct{}{}
			cidrs = append(cidrs, text)
		}
	}
	sort.Strings(cidrs)
	return cidrs
}

func cloneMapSlice(values []map[string]any) []map[string]any {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]map[string]any, 0, len(values))
	for _, value := range values {
		cloned = append(cloned, cloneAnyMap(value))
	}
	return cloned
}

func staleAccessKeyCandidateFromExecution(execution *Execution, threshold int) (accessKeyCandidate, bool) {
	if execution == nil {
		return accessKeyCandidate{}, false
	}
	if directID := strings.TrimSpace(remediationMapValueToString(execution.TriggerData, "access_key_id")); directID != "" {
		inactiveDays, ok := firstInt(execution.TriggerData, "inactive_days", "unused_key_days", "last_used_days", "access_key_last_used_days")
		if ok && inactiveDays >= threshold {
			return accessKeyCandidate{ID: directID, InactiveDays: inactiveDays, Source: "trigger_data"}, true
		}
	}
	if candidate, ok := candidateFromMetadata(execution.TriggerData["access_key_metadata"], threshold); ok {
		return candidate, true
	}
	if resource, ok := execution.TriggerData["resource"].(map[string]any); ok {
		if candidate, ok := candidateFromMetadata(resource["access_key_metadata"], threshold); ok {
			return candidate, true
		}
		if candidate, ok := candidateFromMetadata(resource["access_keys"], threshold); ok {
			return candidate, true
		}
	}
	return accessKeyCandidate{}, false
}

func candidateFromMetadata(raw any, threshold int) (accessKeyCandidate, bool) {
	var items []any
	switch typed := raw.(type) {
	case []any:
		items = typed
	case []map[string]any:
		items = make([]any, 0, len(typed))
		for _, item := range typed {
			items = append(items, item)
		}
	default:
		return accessKeyCandidate{}, false
	}
	for _, item := range items {
		values, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id := firstNonEmpty(
			stringValue(values["id"]),
			stringValue(values["key_id"]),
			stringValue(values["access_key_id"]),
			stringValue(values["name"]),
		)
		if id == "" {
			continue
		}
		inactiveDays, ok := firstInt(values, "inactive_days", "last_used_days", "unused_days", "days_since_last_use", "age_days")
		if !ok || inactiveDays < threshold {
			continue
		}
		return accessKeyCandidate{
			ID:           id,
			InactiveDays: inactiveDays,
			Source:       "access_key_metadata",
		}, true
	}
	return accessKeyCandidate{}, false
}

func inferProvider(execution *Execution) string {
	if execution == nil {
		return ""
	}
	data := execution.TriggerData
	for _, key := range []string{"provider", "resource_platform", "cloud_provider"} {
		if value := strings.ToLower(strings.TrimSpace(remediationMapValueToString(data, key))); value != "" {
			switch value {
			case "aws", "gcp", "azure":
				return value
			case "amazon_web_services":
				return "aws"
			case "google_cloud_platform":
				return "gcp"
			}
		}
	}
	policyID := strings.ToLower(strings.TrimSpace(remediationMapValueToString(data, "policy_id")))
	switch {
	case strings.HasPrefix(policyID, "aws-"):
		return "aws"
	case strings.HasPrefix(policyID, "gcp-"):
		return "gcp"
	case strings.HasPrefix(policyID, "azure-"):
		return "azure"
	}
	resourceID := strings.ToLower(firstNonEmpty(remediationMapValueToString(data, "resource_external_id"), remediationMapValueToString(data, "resource_id"), remediationMapValueToString(data, "entity_id")))
	switch {
	case strings.HasPrefix(resourceID, "arn:aws:"), strings.HasPrefix(resourceID, "s3://"):
		return "aws"
	case strings.HasPrefix(resourceID, "gs://"), strings.Contains(resourceID, "storage.googleapis.com"), strings.HasPrefix(resourceID, "projects/"):
		return "gcp"
	case strings.HasPrefix(resourceID, "/subscriptions/"), strings.Contains(resourceID, "blob.core.windows.net"):
		return "azure"
	default:
		return ""
	}
}

func dryRunEnabled(action Action, execution *Execution) bool {
	if configBool(action.Config["dry_run"]) {
		return true
	}
	if execution == nil {
		return false
	}
	if raw, ok := execution.TriggerData["dry_run"]; ok {
		switch typed := raw.(type) {
		case bool:
			return typed
		case string:
			return configBool(typed)
		}
	}
	return false
}

func actionIntConfig(action Action, key string, defaultValue int) int {
	if action.Config == nil {
		return defaultValue
	}
	raw := strings.TrimSpace(action.Config[key])
	if raw == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return defaultValue
	}
	return value
}

func catalogAfterState(output string, err error) map[string]any {
	state := map[string]any{}
	if trimmed := strings.TrimSpace(output); trimmed != "" {
		var parsed any
		if json.Unmarshal([]byte(trimmed), &parsed) == nil {
			state["tool_output"] = parsed
		} else {
			state["tool_output"] = trimmed
		}
	}
	if err != nil {
		state["error"] = err.Error()
	}
	return compactAnyMap(state)
}

func preconditionResult(name string, passed bool, detail string) map[string]any {
	return map[string]any{
		"name":   name,
		"passed": passed,
		"detail": detail,
	}
}

func allPreconditionsPassed(checks []map[string]any) bool {
	for _, check := range checks {
		passed, _ := check["passed"].(bool)
		if !passed {
			return false
		}
	}
	return true
}

func firstBool(values map[string]any, keys ...string) (bool, bool) {
	for _, key := range keys {
		raw, ok := values[key]
		if !ok {
			continue
		}
		switch typed := raw.(type) {
		case bool:
			return typed, true
		case string:
			text := strings.ToLower(strings.TrimSpace(typed))
			switch text {
			case "true", "1", "yes", "on", "enabled", "public", "allusers", "all_authenticated_users", "container":
				return true, true
			case "false", "0", "no", "off", "disabled", "private", "":
				return false, true
			}
		}
	}
	return false, false
}

func firstInt(values map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		raw, ok := values[key]
		if !ok {
			continue
		}
		switch typed := raw.(type) {
		case int:
			return typed, true
		case int32:
			return int(typed), true
		case int64:
			return int(typed), true
		case float64:
			return int(typed), true
		case string:
			value, err := strconv.Atoi(strings.TrimSpace(typed))
			if err == nil {
				return value, true
			}
		}
	}
	return 0, false
}

func stringValue(raw any) string {
	if raw == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", raw))
}

func copyFields(target map[string]any, source map[string]any, keys ...string) {
	for _, key := range keys {
		if value, ok := source[key]; ok {
			target[key] = value
		}
	}
}

func compactAnyMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	compacted := make(map[string]any, len(values))
	for key, value := range values {
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) == "" {
				continue
			}
		case nil:
			continue
		}
		compacted[key] = value
	}
	if len(compacted) == 0 {
		return nil
	}
	return compacted
}

func configBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func hasStructuredValue(raw any) bool {
	switch typed := raw.(type) {
	case nil:
		return false
	case string:
		text := strings.TrimSpace(typed)
		return text != "" && text != "null"
	case []any:
		return len(typed) > 0
	case []map[string]any:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	default:
		return strings.TrimSpace(stringValue(raw)) != ""
	}
}
