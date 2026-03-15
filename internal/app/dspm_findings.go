package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/dspm"
)

func (a *App) scanAndPersistDSPMFindings(ctx context.Context, table string, assets []map[string]interface{}) int64 {
	if a == nil || a.DSPM == nil || len(assets) == 0 {
		return 0
	}

	targets := dspmTargetsFromAssets(table, assets)
	if len(targets) == 0 {
		return 0
	}

	var findingCount int64
	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}
		result, err := a.DSPM.Scan(ctx, target)
		if err != nil {
			if a.Logger != nil && ctx.Err() == nil {
				a.Logger.Debug("dspm scan failed", "target_id", target.ID, "table", table, "error", err)
			}
			continue
		}
		for _, finding := range result.ToPolicyFindings(target) {
			if a.upsertFindingAndRemediate(ctx, finding) != nil {
				findingCount++
			}
		}
		a.enrichSecurityGraphWithDSPMResult(target, result)
	}

	return findingCount
}

func dspmTargetsFromAssets(table string, assets []map[string]interface{}) []*dspm.ScanTarget {
	if !isDSPMScannableTable(table) || len(assets) == 0 {
		return nil
	}

	targets := make([]*dspm.ScanTarget, 0, len(assets))
	seenIDs := make(map[string]struct{}, len(assets))
	for _, asset := range assets {
		target := dspmTargetFromAsset(table, asset)
		if target == nil || target.ID == "" {
			continue
		}
		if _, ok := seenIDs[target.ID]; ok {
			continue
		}
		seenIDs[target.ID] = struct{}{}
		targets = append(targets, target)
	}

	return targets
}

func isDSPMScannableTable(table string) bool {
	name := strings.ToLower(strings.TrimSpace(table))
	if name == "" {
		return false
	}
	if strings.Contains(name, "s3_bucket") {
		return true
	}
	if strings.Contains(name, "storage_bucket") {
		return true
	}
	if strings.Contains(name, "blob_container") {
		return true
	}
	if strings.Contains(name, "storage_account") {
		return true
	}
	if strings.Contains(name, "object_storage") {
		return true
	}
	if strings.Contains(name, "bucket") && strings.Contains(name, "storage") {
		return true
	}
	return false
}

func dspmTargetFromAsset(table string, asset map[string]interface{}) *dspm.ScanTarget {
	if len(asset) == 0 {
		return nil
	}

	id := firstNonEmptyString(asset,
		"_cq_id",
		"arn",
		"resource_id",
		"id",
		"bucket_name",
		"name",
	)
	if id == "" {
		return nil
	}
	name := firstNonEmptyString(asset, "name", "bucket_name", "id")
	if name == "" {
		name = id
	}

	isPublic := firstBool(asset,
		"is_public",
		"public",
		"public_access",
		"publicly_accessible",
		"allow_blob_public_access",
		"anonymous_access",
		"all_users",
	)
	if firstBool(asset, "block_public_access", "public_access_block", "public_access_blocked") {
		isPublic = false
	}

	isEncrypted := firstBool(asset,
		"is_encrypted",
		"encrypted",
		"encryption_enabled",
		"default_encryption_enabled",
		"kms_encrypted",
		"server_side_encryption_enabled",
	)
	if !isEncrypted {
		if value, ok := asset["server_side_encryption_configuration"]; ok {
			isEncrypted = hasValue(value)
		}
	}

	provider := firstNonEmptyString(asset, "_cq_source_name", "provider")
	if provider == "" {
		provider = inferProviderFromTable(table)
	}

	target := &dspm.ScanTarget{
		ID:           id,
		Type:         inferTargetType(table),
		Provider:     provider,
		Account:      firstNonEmptyString(asset, "account_id", "subscription_id", "project_id", "account"),
		Region:       firstNonEmptyString(asset, "region", "location", "aws_region"),
		Name:         name,
		ARN:          firstNonEmptyString(asset, "arn", "resource_arn"),
		Properties:   asset,
		Tags:         extractTags(asset),
		IsPublic:     isPublic,
		IsEncrypted:  isEncrypted,
		LastModified: firstTime(asset, "last_modified", "_cq_sync_time"),
	}
	return target
}

func inferProviderFromTable(table string) string {
	name := strings.ToLower(strings.TrimSpace(table))
	switch {
	case strings.HasPrefix(name, "aws_"):
		return "aws"
	case strings.HasPrefix(name, "azure_"):
		return "azure"
	case strings.HasPrefix(name, "gcp_"):
		return "gcp"
	default:
		return ""
	}
}

func inferTargetType(table string) string {
	name := strings.ToLower(strings.TrimSpace(table))
	switch {
	case strings.Contains(name, "s3"):
		return "s3_bucket"
	case strings.Contains(name, "blob"):
		return "azure_blob_container"
	case strings.Contains(name, "storage_account"):
		return "azure_storage_account"
	case strings.Contains(name, "storage_bucket"):
		return "gcs_bucket"
	default:
		return "object_storage"
	}
}

func firstNonEmptyString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		value, ok := m[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed)
			}
		case []byte:
			if strings.TrimSpace(string(typed)) != "" {
				return strings.TrimSpace(string(typed))
			}
		}
	}
	return ""
}

func firstBool(m map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		value, ok := m[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case bool:
			if typed {
				return true
			}
		case string:
			if parseBool(typed) {
				return true
			}
		case int:
			if typed != 0 {
				return true
			}
		case int64:
			if typed != 0 {
				return true
			}
		case float64:
			if typed != 0 {
				return true
			}
		}
	}
	return false
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "public", "enabled", "allow", "allusers", "all_users":
		return true
	default:
		return false
	}
}

func hasValue(value interface{}) bool {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed) != ""
	case []interface{}:
		return len(typed) > 0
	case map[string]interface{}:
		return len(typed) > 0
	default:
		return value != nil
	}
}

func extractTags(asset map[string]interface{}) map[string]string {
	value, ok := asset["tags"]
	if !ok || value == nil {
		return nil
	}

	switch typed := value.(type) {
	case map[string]string:
		if len(typed) == 0 {
			return nil
		}
		out := make(map[string]string, len(typed))
		for k, v := range typed {
			key := strings.TrimSpace(k)
			if key == "" {
				continue
			}
			out[key] = strings.TrimSpace(v)
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case map[string]interface{}:
		if len(typed) == 0 {
			return nil
		}
		out := make(map[string]string, len(typed))
		for k, v := range typed {
			key := strings.TrimSpace(k)
			if key == "" || v == nil {
				continue
			}
			out[key] = fmt.Sprint(v)
		}
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		return nil
	}
}

func firstTime(m map[string]interface{}, keys ...string) time.Time {
	for _, key := range keys {
		value, ok := m[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case time.Time:
			if !typed.IsZero() {
				return typed
			}
		case string:
			if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(typed)); err == nil {
				return parsed
			}
		}
	}
	return time.Time{}
}
