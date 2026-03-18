package builders

import (
	"context"
	"sort"
	"strings"
	"time"
)

func (b *Builder) enrichAWSIAMUserCredentials(ctx context.Context) {
	rows, err := b.queryIfExists(ctx, "aws_iam_user_access_keys", `
		SELECT account_id, user_name, access_key_id, status, create_date, last_used_date, last_used_service, last_used_region
		FROM aws_iam_user_access_keys
	`)
	if err != nil || len(rows.Rows) == 0 {
		return
	}

	users := make(map[string]*Node)
	for _, node := range b.graph.GetNodesByKind(NodeKindUser) {
		if node == nil || node.Provider != "aws" {
			continue
		}
		key := identityLookupKey(node.Account, node.Name)
		if key != "" {
			users[key] = node
		}
	}

	type aggregate struct {
		ids       []string
		idSet     map[string]struct{}
		metadata  []any
		oldestKey time.Time
	}
	aggregates := make(map[string]*aggregate)

	for _, row := range rows.Rows {
		accountID := strings.TrimSpace(queryRowString(row, "account_id"))
		userName := strings.TrimSpace(queryRowString(row, "user_name"))
		accessKeyID := strings.TrimSpace(queryRowString(row, "access_key_id"))
		if accountID == "" || userName == "" || accessKeyID == "" {
			continue
		}
		key := identityLookupKey(accountID, userName)
		if users[key] == nil {
			continue
		}
		agg := aggregates[key]
		if agg == nil {
			agg = &aggregate{idSet: make(map[string]struct{})}
			aggregates[key] = agg
		}
		if _, exists := agg.idSet[accessKeyID]; !exists {
			agg.idSet[accessKeyID] = struct{}{}
			agg.ids = append(agg.ids, accessKeyID)
			metadata := map[string]any{
				"access_key_id": accessKeyID,
				"status":        strings.TrimSpace(queryRowString(row, "status")),
			}
			if createdAt := parseCDCEventTime(queryRow(row, "create_date")); !createdAt.IsZero() {
				metadata["create_date"] = createdAt
				if agg.oldestKey.IsZero() || createdAt.Before(agg.oldestKey) {
					agg.oldestKey = createdAt
				}
			}
			if lastUsed := parseCDCEventTime(queryRow(row, "last_used_date")); !lastUsed.IsZero() {
				metadata["last_used_date"] = lastUsed
			}
			if service := strings.TrimSpace(queryRowString(row, "last_used_service")); service != "" {
				metadata["last_used_service"] = service
			}
			if region := strings.TrimSpace(queryRowString(row, "last_used_region")); region != "" {
				metadata["last_used_region"] = region
			}
			agg.metadata = append(agg.metadata, metadata)
		}
	}

	now := temporalNowUTC()
	for key, agg := range aggregates {
		node := users[key]
		if node == nil {
			continue
		}
		sort.Strings(agg.ids)
		updated := *node
		props := cloneAnyMap(node.Properties)
		if props == nil {
			props = make(map[string]any)
		}
		props["access_keys"] = stringSliceToAny(agg.ids)
		props["has_access_keys"] = len(agg.ids) > 0
		props["access_key_count"] = len(agg.ids)
		props["access_key_metadata"] = agg.metadata
		if !agg.oldestKey.IsZero() {
			props["oldest_key_age_days"] = int(now.Sub(agg.oldestKey.UTC()).Hours() / 24)
		}
		updated.Properties = props
		b.graph.AddNode(&updated)
	}
}

func (b *Builder) enrichGCPIAMServiceAccounts(ctx context.Context) {
	rows, err := b.queryIfExists(ctx, "gcp_iam_service_accounts", `
		SELECT project_id, email, keys, roles, has_admin_role, has_high_privilege
		FROM gcp_iam_service_accounts
	`)
	if err != nil || len(rows.Rows) == 0 {
		return
	}

	accounts := make(map[string]*Node)
	for _, node := range b.graph.GetNodesByKind(NodeKindServiceAccount) {
		if node == nil || node.Provider != "gcp" {
			continue
		}
		email := strings.TrimSpace(queryNodeString(node, "email"))
		if email == "" {
			email = node.Name
		}
		key := identityLookupKey(node.Account, email)
		if key != "" {
			accounts[key] = node
		}
	}

	now := temporalNowUTC()
	for _, row := range rows.Rows {
		projectID := strings.TrimSpace(queryRowString(row, "project_id"))
		email := strings.ToLower(strings.TrimSpace(queryRowString(row, "email")))
		if projectID == "" || email == "" {
			continue
		}
		node := accounts[identityLookupKey(projectID, email)]
		if node == nil {
			continue
		}

		var accessKeys []string
		var accessKeyMetadata []any
		var oldestKey time.Time
		for _, item := range toAnySlice(queryRow(row, "keys")) {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			keyName := strings.TrimSpace(queryRowString(entry, "name"))
			if keyName == "" {
				continue
			}
			accessKeys = append(accessKeys, keyName)
			metadata := map[string]any{
				"name":          keyName,
				"key_type":      strings.TrimSpace(queryRowString(entry, "key_type")),
				"key_algorithm": strings.TrimSpace(queryRowString(entry, "key_algorithm")),
				"key_origin":    strings.TrimSpace(queryRowString(entry, "key_origin")),
				"disabled":      queryRow(entry, "disabled"),
			}
			if validAfter := parseCDCEventTime(queryRow(entry, "valid_after")); !validAfter.IsZero() {
				metadata["valid_after"] = validAfter
				if oldestKey.IsZero() || validAfter.Before(oldestKey) {
					oldestKey = validAfter
				}
			}
			if validBefore := parseCDCEventTime(queryRow(entry, "valid_before")); !validBefore.IsZero() {
				metadata["valid_before"] = validBefore
			}
			accessKeyMetadata = append(accessKeyMetadata, metadata)
		}
		sort.Strings(accessKeys)

		updated := *node
		props := cloneAnyMap(node.Properties)
		if props == nil {
			props = make(map[string]any)
		}
		props["roles"] = stringSliceToAny(extractGCPRoleNames(queryRow(row, "roles")))
		props["has_admin_role"] = toBool(queryRow(row, "has_admin_role"))
		props["has_high_privilege"] = toBool(queryRow(row, "has_high_privilege"))
		props["access_keys"] = stringSliceToAny(accessKeys)
		props["has_access_keys"] = len(accessKeys) > 0
		props["access_key_count"] = len(accessKeys)
		props["access_key_metadata"] = accessKeyMetadata
		if !oldestKey.IsZero() {
			props["oldest_key_age_days"] = int(now.Sub(oldestKey.UTC()).Hours() / 24)
		}
		updated.Properties = props
		b.graph.AddNode(&updated)
	}
}

func identityLookupKey(accountID, name string) string {
	accountID = strings.TrimSpace(accountID)
	name = strings.ToLower(strings.TrimSpace(name))
	if accountID == "" || name == "" {
		return ""
	}
	return accountID + "\x00" + name
}

func queryNodeString(node *Node, key string) string {
	if node == nil || node.Properties == nil {
		return ""
	}
	return strings.TrimSpace(toString(node.Properties[key]))
}

func stringSliceToAny(values []string) []any {
	if len(values) == 0 {
		return nil
	}
	out := make([]any, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
