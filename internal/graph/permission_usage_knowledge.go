package graph

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	awsIAMPermissionUsageSourceSystem = "aws_identity_center_scan"
	gcpIAMPermissionUsageSourceSystem = "gcp_iam_permission_scan"

	iamPermissionUsageClaimType  = "iam_permission_usage"
	iamPermissionUsagePredicate  = "permission_usage_status"
	iamPermissionUsageClaimState = "active"
)

var (
	awsIAMPermissionUsageKnowledgeQuery = `
		SELECT
			_cq_id,
			account_id,
			account_ids,
			account_count,
			region,
			identity_center_instance_arn,
			permission_set_arn,
			permission_set_name,
			sso_role_arns,
			action,
			action_last_accessed,
			usage_status,
			days_unused,
			unused_since,
			lookback_days,
			removal_threshold_days,
			recommendation,
			evidence_source,
			confidence,
			coverage,
			scan_window_start,
			scan_window_end,
			history_day,
			assignment_count
		FROM aws_identitycenter_permission_set_permission_usage_history
	`

	gcpIAMPermissionUsageKnowledgeQuery = `
		SELECT
			_cq_id,
			project_id,
			"group" AS group_email,
			permission,
			granted_roles,
			permission_last_used,
			usage_status,
			days_unused,
			unused_since,
			lookback_days,
			removal_threshold_days,
			member_count,
			members_observed,
			recommendation,
			evidence_source,
			confidence,
			coverage,
			scan_window_start,
			scan_window_end,
			history_day
		FROM gcp_iam_group_permission_usage_history
	`
)

func (b *Builder) buildIAMPermissionUsageKnowledge(ctx context.Context) {
	if b == nil || b.graph == nil {
		return
	}

	awsClaims, awsObservations := b.buildAWSIAMPermissionUsageKnowledge(ctx)
	gcpClaims, gcpObservations := b.buildGCPIAMPermissionUsageKnowledge(ctx)

	if awsClaims+awsObservations+gcpClaims+gcpObservations == 0 {
		return
	}

	b.logger.Info("normalized IAM permission usage into graph knowledge layer",
		"aws_claims", awsClaims,
		"aws_observations", awsObservations,
		"gcp_claims", gcpClaims,
		"gcp_observations", gcpObservations,
	)
}

func (b *Builder) buildAWSIAMPermissionUsageKnowledge(ctx context.Context) (int, int) {
	result, err := b.queryIfExists(ctx, "aws_identitycenter_permission_set_permission_usage_history", awsIAMPermissionUsageKnowledgeQuery)
	if err != nil {
		b.logger.Warn("failed to query AWS IAM permission usage table", "error", err)
		return 0, 0
	}

	claimsWritten := 0
	observationsWritten := 0

	for _, row := range result.Rows {
		subjectID := b.ensureAWSIAMPermissionUsageSubject(row)
		if subjectID == "" {
			continue
		}

		permission := strings.TrimSpace(queryRowString(row, "action"))
		if permission == "" {
			continue
		}

		rowKey := firstNonEmpty(strings.TrimSpace(queryRowString(row, "_cq_id")), subjectID+"|"+permission)
		observedAt := permissionUsageTimeOr(queryRow(row, "scan_window_end"), time.Now().UTC())
		validFrom := permissionUsageTimeOr(queryRow(row, "history_day"), observedAt)
		lastUsed, hasLastUsed := permissionUsageTime(queryRow(row, "action_last_accessed"))
		unusedSince, hasUnusedSince := permissionUsageTime(queryRow(row, "unused_since"))

		lookbackDays := permissionUsageInt(queryRow(row, "lookback_days"))
		if lookbackDays <= 0 {
			lookbackDays = 90
		}
		removalThresholdDays := permissionUsageInt(queryRow(row, "removal_threshold_days"))
		if removalThresholdDays <= 0 {
			removalThresholdDays = 180
		}
		daysUnused := permissionUsageInt(queryRow(row, "days_unused"))
		usageStatus := normalizePermissionUsageStatus(queryRowString(row, "usage_status"))
		recommendation := strings.TrimSpace(queryRowString(row, "recommendation"))
		evidenceSource := firstNonEmpty(strings.TrimSpace(queryRowString(row, "evidence_source")), "aws_identity_center_permission_usage")
		confidence := permissionUsageConfidenceScore(queryRow(row, "confidence"))

		metadata := map[string]any{
			"provider":                     "aws",
			"permission":                   permission,
			"usage_status":                 usageStatus,
			"days_unused":                  daysUnused,
			"lookback_days":                lookbackDays,
			"removal_threshold_days":       removalThresholdDays,
			"coverage":                     strings.TrimSpace(queryRowString(row, "coverage")),
			"identity_center_instance_arn": strings.TrimSpace(queryRowString(row, "identity_center_instance_arn")),
			"permission_set_arn":           strings.TrimSpace(queryRowString(row, "permission_set_arn")),
			"permission_set_name":          strings.TrimSpace(queryRowString(row, "permission_set_name")),
			"assignment_count":             permissionUsageInt(queryRow(row, "assignment_count")),
			"account_ids":                  permissionUsageStringSlice(queryRow(row, "account_ids")),
			"account_count":                permissionUsageInt(queryRow(row, "account_count")),
			"sso_role_arns":                permissionUsageStringSlice(queryRow(row, "sso_role_arns")),
		}
		if hasLastUsed {
			metadata["last_used_at"] = lastUsed
		}
		if hasUnusedSince {
			metadata["unused_since"] = unusedSince
		}
		if recommendation != "" {
			metadata["recommendation"] = recommendation
		}

		summary := permissionUsageSummary("aws", permission, subjectID, usageStatus, daysUnused, lookbackDays, recommendation)
		observationID := permissionUsageObservationID("aws", rowKey, observedAt)
		if _, exists := b.graph.GetNode(observationID); !exists {
			if _, obsErr := WriteObservation(b.graph, ObservationWriteRequest{
				ID:              observationID,
				SubjectID:       subjectID,
				ObservationType: "aws_identity_center_permission_usage",
				Summary:         summary,
				SourceSystem:    awsIAMPermissionUsageSourceSystem,
				SourceEventID:   permissionUsageSourceEventID("aws", rowKey, observedAt),
				ObservedAt:      observedAt,
				ValidFrom:       validFrom,
				RecordedAt:      observedAt,
				TransactionFrom: observedAt,
				Confidence:      confidence,
				Metadata:        metadata,
			}); obsErr != nil {
				b.logger.Warn("failed to write AWS IAM permission usage observation", "subject_id", subjectID, "permission", permission, "error", obsErr)
				continue
			}
			observationsWritten++
		}

		claimID := permissionUsageClaimID("aws", rowKey, observedAt)
		if _, exists := b.graph.GetNode(claimID); exists {
			continue
		}

		if _, claimErr := WriteClaim(b.graph, ClaimWriteRequest{
			ID:              claimID,
			ClaimType:       iamPermissionUsageClaimType,
			SubjectID:       subjectID,
			Predicate:       iamPermissionUsagePredicate,
			ObjectValue:     usageStatus,
			Status:          iamPermissionUsageClaimState,
			Summary:         summary,
			EvidenceIDs:     []string{observationID},
			SourceName:      evidenceSource,
			SourceType:      "scanner",
			SourceSystem:    awsIAMPermissionUsageSourceSystem,
			SourceEventID:   permissionUsageSourceEventID("aws", rowKey, observedAt),
			ObservedAt:      observedAt,
			ValidFrom:       validFrom,
			RecordedAt:      observedAt,
			TransactionFrom: observedAt,
			Confidence:      confidence,
			Metadata:        metadata,
		}); claimErr != nil {
			b.logger.Warn("failed to write AWS IAM permission usage claim", "subject_id", subjectID, "permission", permission, "error", claimErr)
			continue
		}
		claimsWritten++
	}

	return claimsWritten, observationsWritten
}

func (b *Builder) buildGCPIAMPermissionUsageKnowledge(ctx context.Context) (int, int) {
	result, err := b.queryIfExists(ctx, "gcp_iam_group_permission_usage_history", gcpIAMPermissionUsageKnowledgeQuery)
	if err != nil {
		b.logger.Warn("failed to query GCP IAM permission usage table", "error", err)
		return 0, 0
	}

	claimsWritten := 0
	observationsWritten := 0

	for _, row := range result.Rows {
		projectID := strings.TrimSpace(queryRowString(row, "project_id"))
		groupEmail := strings.ToLower(strings.TrimSpace(queryRowString(row, "group_email")))
		subjectID := b.ensureGCPIAMGroupPermissionUsageSubject(projectID, groupEmail)
		if subjectID == "" {
			continue
		}

		permission := strings.TrimSpace(queryRowString(row, "permission"))
		if permission == "" {
			continue
		}

		rowKey := firstNonEmpty(strings.TrimSpace(queryRowString(row, "_cq_id")), subjectID+"|"+permission)
		observedAt := permissionUsageTimeOr(queryRow(row, "scan_window_end"), time.Now().UTC())
		validFrom := permissionUsageTimeOr(queryRow(row, "history_day"), observedAt)
		lastUsed, hasLastUsed := permissionUsageTime(queryRow(row, "permission_last_used"))
		unusedSince, hasUnusedSince := permissionUsageTime(queryRow(row, "unused_since"))

		lookbackDays := permissionUsageInt(queryRow(row, "lookback_days"))
		if lookbackDays <= 0 {
			lookbackDays = 90
		}
		removalThresholdDays := permissionUsageInt(queryRow(row, "removal_threshold_days"))
		if removalThresholdDays <= 0 {
			removalThresholdDays = 180
		}
		daysUnused := permissionUsageInt(queryRow(row, "days_unused"))
		usageStatus := normalizePermissionUsageStatus(queryRowString(row, "usage_status"))
		recommendation := strings.TrimSpace(queryRowString(row, "recommendation"))
		evidenceSource := firstNonEmpty(strings.TrimSpace(queryRowString(row, "evidence_source")), "gcp_iam_permission_usage")
		confidence := permissionUsageConfidenceScore(queryRow(row, "confidence"))

		metadata := map[string]any{
			"provider":               "gcp",
			"project_id":             projectID,
			"group_email":            groupEmail,
			"permission":             permission,
			"usage_status":           usageStatus,
			"days_unused":            daysUnused,
			"lookback_days":          lookbackDays,
			"removal_threshold_days": removalThresholdDays,
			"coverage":               strings.TrimSpace(queryRowString(row, "coverage")),
			"member_count":           permissionUsageInt(queryRow(row, "member_count")),
			"members_observed":       permissionUsageInt(queryRow(row, "members_observed")),
			"granted_roles":          permissionUsageStringSlice(queryRow(row, "granted_roles")),
		}
		if hasLastUsed {
			metadata["last_used_at"] = lastUsed
		}
		if hasUnusedSince {
			metadata["unused_since"] = unusedSince
		}
		if recommendation != "" {
			metadata["recommendation"] = recommendation
		}

		summary := permissionUsageSummary("gcp", permission, subjectID, usageStatus, daysUnused, lookbackDays, recommendation)
		observationID := permissionUsageObservationID("gcp", rowKey, observedAt)
		if _, exists := b.graph.GetNode(observationID); !exists {
			if _, obsErr := WriteObservation(b.graph, ObservationWriteRequest{
				ID:              observationID,
				SubjectID:       subjectID,
				ObservationType: "gcp_group_permission_usage",
				Summary:         summary,
				SourceSystem:    gcpIAMPermissionUsageSourceSystem,
				SourceEventID:   permissionUsageSourceEventID("gcp", rowKey, observedAt),
				ObservedAt:      observedAt,
				ValidFrom:       validFrom,
				RecordedAt:      observedAt,
				TransactionFrom: observedAt,
				Confidence:      confidence,
				Metadata:        metadata,
			}); obsErr != nil {
				b.logger.Warn("failed to write GCP IAM permission usage observation", "subject_id", subjectID, "permission", permission, "error", obsErr)
				continue
			}
			observationsWritten++
		}

		claimID := permissionUsageClaimID("gcp", rowKey, observedAt)
		if _, exists := b.graph.GetNode(claimID); exists {
			continue
		}

		if _, claimErr := WriteClaim(b.graph, ClaimWriteRequest{
			ID:              claimID,
			ClaimType:       iamPermissionUsageClaimType,
			SubjectID:       subjectID,
			Predicate:       iamPermissionUsagePredicate,
			ObjectValue:     usageStatus,
			Status:          iamPermissionUsageClaimState,
			Summary:         summary,
			EvidenceIDs:     []string{observationID},
			SourceName:      evidenceSource,
			SourceType:      "scanner",
			SourceSystem:    gcpIAMPermissionUsageSourceSystem,
			SourceEventID:   permissionUsageSourceEventID("gcp", rowKey, observedAt),
			ObservedAt:      observedAt,
			ValidFrom:       validFrom,
			RecordedAt:      observedAt,
			TransactionFrom: observedAt,
			Confidence:      confidence,
			Metadata:        metadata,
		}); claimErr != nil {
			b.logger.Warn("failed to write GCP IAM permission usage claim", "subject_id", subjectID, "permission", permission, "error", claimErr)
			continue
		}
		claimsWritten++
	}

	return claimsWritten, observationsWritten
}

func (b *Builder) ensureAWSIAMPermissionUsageSubject(row map[string]any) string {
	subjectID := strings.TrimSpace(queryRowString(row, "permission_set_arn"))
	if subjectID == "" {
		return ""
	}
	if _, exists := b.graph.GetNode(subjectID); exists {
		return subjectID
	}

	name := firstNonEmpty(strings.TrimSpace(queryRowString(row, "permission_set_name")), subjectID)
	accountIDs := permissionUsageStringSlice(queryRow(row, "account_ids"))
	accountID := strings.TrimSpace(queryRowString(row, "account_id"))
	if accountID == "" && len(accountIDs) == 1 {
		accountID = accountIDs[0]
	}
	b.graph.AddNode(&Node{
		ID:       subjectID,
		Kind:     NodeKindRole,
		Name:     name,
		Provider: "aws",
		Account:  accountID,
		Region:   strings.TrimSpace(queryRowString(row, "region")),
		Properties: map[string]any{
			"permission_set_arn":  strings.TrimSpace(queryRowString(row, "permission_set_arn")),
			"permission_set_name": strings.TrimSpace(queryRowString(row, "permission_set_name")),
			"account_ids":         accountIDs,
			"account_count":       permissionUsageInt(queryRow(row, "account_count")),
			"sso_role_arns":       permissionUsageStringSlice(queryRow(row, "sso_role_arns")),
			"identity_center":     true,
		},
	})
	return subjectID
}

func (b *Builder) ensureGCPIAMGroupPermissionUsageSubject(projectID, groupEmail string) string {
	groupEmail = strings.ToLower(strings.TrimSpace(groupEmail))
	if groupEmail == "" {
		return ""
	}

	candidateIDs := []string{"group:" + groupEmail, groupEmail}
	for _, candidateID := range candidateIDs {
		if _, exists := b.graph.GetNode(candidateID); exists {
			return candidateID
		}
	}

	subjectID := "group:" + groupEmail
	b.graph.AddNode(&Node{
		ID:       subjectID,
		Kind:     NodeKindGroup,
		Name:     groupEmail,
		Provider: "gcp",
		Account:  projectID,
		Properties: map[string]any{
			"email":     groupEmail,
			"principal": subjectID,
		},
	})

	return subjectID
}

func permissionUsageObservationID(provider, rowKey string, observedAt time.Time) string {
	return fmt.Sprintf("observation:%s:iam_permission_usage:%s:%d", provider, slugifyKnowledgeKey(firstNonEmpty(strings.TrimSpace(rowKey), provider)), observedAt.UnixNano())
}

func permissionUsageClaimID(provider, rowKey string, observedAt time.Time) string {
	return fmt.Sprintf("claim:%s:iam_permission_usage:%s:%d", provider, slugifyKnowledgeKey(firstNonEmpty(strings.TrimSpace(rowKey), provider)), observedAt.UnixNano())
}

func permissionUsageSourceEventID(provider, rowKey string, observedAt time.Time) string {
	return fmt.Sprintf("%s-iam-permission-usage:%s:%d", provider, slugifyKnowledgeKey(firstNonEmpty(strings.TrimSpace(rowKey), provider)), observedAt.UnixNano())
}

func permissionUsageSummary(provider, permission, subjectID, usageStatus string, daysUnused, lookbackDays int, recommendation string) string {
	if usageStatus == "used" {
		return fmt.Sprintf("%s permission %s for %s was observed within the %d-day lookback window.", strings.ToUpper(provider), permission, subjectID, lookbackDays)
	}
	if usageStatus == "attribution_uncertain" {
		return fmt.Sprintf("%s permission %s for %s was observed within the %d-day lookback window, but attribution remains uncertain.", strings.ToUpper(provider), permission, subjectID, lookbackDays)
	}
	if usageStatus == "unknown" {
		return fmt.Sprintf("%s permission %s for %s could not be authoritatively classified during the %d-day lookback window.", strings.ToUpper(provider), permission, subjectID, lookbackDays)
	}
	if recommendation != "" {
		return recommendation
	}
	if daysUnused > 0 {
		return fmt.Sprintf("%s permission %s for %s appears unused for %d days.", strings.ToUpper(provider), permission, subjectID, daysUnused)
	}
	return fmt.Sprintf("%s permission %s for %s appears unused.", strings.ToUpper(provider), permission, subjectID)
}

func normalizePermissionUsageStatus(status string) string {
	status = strings.ToLower(strings.TrimSpace(status))
	switch status {
	case "used", "unused", "attribution_uncertain":
		return status
	default:
		return "unknown"
	}
}

func permissionUsageConfidenceScore(value any) float64 {
	switch typed := value.(type) {
	case float64:
		if typed >= 0 && typed <= 1 {
			return typed
		}
	case float32:
		normalized := float64(typed)
		if normalized >= 0 && normalized <= 1 {
			return normalized
		}
	case int:
		if typed >= 0 && typed <= 1 {
			return float64(typed)
		}
	}

	raw := strings.ToLower(strings.TrimSpace(toString(value)))
	switch raw {
	case "high":
		return 0.9
	case "medium":
		return 0.7
	case "low":
		return 0.5
	case "", "unknown":
		return 0.6
	}
	if parsed, err := strconv.ParseFloat(raw, 64); err == nil && parsed >= 0 && parsed <= 1 {
		return parsed
	}
	return 0.6
}

func permissionUsageStringSlice(value any) []string {
	items := toAnySlice(value)
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		normalized := strings.TrimSpace(toString(item))
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}

	if len(out) == 0 {
		raw := strings.TrimSpace(toString(value))
		if raw != "" && !strings.HasPrefix(raw, "[") {
			for _, part := range strings.Split(raw, ",") {
				normalized := strings.TrimSpace(part)
				if normalized == "" {
					continue
				}
				if _, exists := seen[normalized]; exists {
					continue
				}
				seen[normalized] = struct{}{}
				out = append(out, normalized)
			}
		}
	}

	sort.Strings(out)
	return out
}

func permissionUsageInt(value any) int {
	maxInt := int(^uint(0) >> 1)
	minInt := -maxInt - 1

	switch typed := value.(type) {
	case int:
		return typed
	case int8:
		return int(typed)
	case int16:
		return int(typed)
	case int32:
		return int(typed)
	case int64:
		if typed > int64(maxInt) {
			return maxInt
		}
		if typed < int64(minInt) {
			return minInt
		}
		return int(typed)
	case uint:
		if uint64(typed) > uint64(maxInt) {
			return maxInt
		}
		parsed, err := strconv.Atoi(strconv.FormatUint(uint64(typed), 10))
		if err == nil {
			return parsed
		}
		return maxInt
	case uint8:
		return int(typed)
	case uint16:
		return int(typed)
	case uint32:
		if uint64(typed) > uint64(maxInt) {
			return maxInt
		}
		parsed, err := strconv.Atoi(strconv.FormatUint(uint64(typed), 10))
		if err == nil {
			return parsed
		}
		return maxInt
	case uint64:
		if typed > uint64(maxInt) {
			return maxInt
		}
		parsed, err := strconv.Atoi(strconv.FormatUint(typed, 10))
		if err == nil {
			return parsed
		}
		return maxInt
	case float32:
		if float64(typed) > float64(maxInt) {
			return maxInt
		}
		if float64(typed) < float64(minInt) {
			return minInt
		}
		return int(typed)
	case float64:
		if typed > float64(maxInt) {
			return maxInt
		}
		if typed < float64(minInt) {
			return minInt
		}
		return int(typed)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil {
			return parsed
		}
	case []byte:
		parsed, err := strconv.Atoi(strings.TrimSpace(string(typed)))
		if err == nil {
			return parsed
		}
	}
	return 0
}

func permissionUsageTime(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case time.Time:
		if typed.IsZero() {
			return time.Time{}, false
		}
		return typed.UTC(), true
	case *time.Time:
		if typed == nil || typed.IsZero() {
			return time.Time{}, false
		}
		return typed.UTC(), true
	case string:
		raw := strings.TrimSpace(typed)
		if raw == "" {
			return time.Time{}, false
		}
		if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			return parsed.UTC(), true
		}
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
			return parsed.UTC(), true
		}
		if parsed, err := time.Parse("2006-01-02 15:04:05", raw); err == nil {
			return parsed.UTC(), true
		}
	case []byte:
		return permissionUsageTime(string(typed))
	}
	return time.Time{}, false
}

func permissionUsageTimeOr(value any, fallback time.Time) time.Time {
	if parsed, ok := permissionUsageTime(value); ok {
		return parsed
	}
	if fallback.IsZero() {
		return time.Now().UTC()
	}
	return fallback.UTC()
}
