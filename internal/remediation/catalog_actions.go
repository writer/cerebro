package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type catalogActionPlan struct {
	entry             CatalogEntry
	provider          string
	resourceID        string
	resourceName      string
	resourceType      string
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
	case ActionDisableStaleAccessKey:
		output, metadata, err := ex.disableStaleAccessKey(ctx, action, execution)
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
	return catalogActionPlan{
		entry:            entry,
		provider:         provider,
		resourceID:       firstNonEmpty(remediationMapValueToString(execution.TriggerData, "entity_id"), remediationMapValueToString(execution.TriggerData, "resource_id"), remediationMapValueToString(execution.TriggerData, "resource_external_id")),
		resourceName:     remediationMapValueToString(execution.TriggerData, "resource_name"),
		resourceType:     remediationMapValueToString(execution.TriggerData, "resource_type"),
		tool:             firstNonEmpty(action.Config["tool"], catalogToolForProvider(entry, provider)),
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
