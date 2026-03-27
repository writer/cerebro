package sync

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	admin "cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/logging"
	"cloud.google.com/go/logging/logadmin"
	"github.com/writer/cerebro/internal/warehouse"
	"google.golang.org/api/iterator"
	auditpb "google.golang.org/genproto/googleapis/cloud/audit"
)

const (
	gcpIAMGroupPermissionUsageTable = "gcp_iam_group_permission_usage"
	gcpIAMGroupUsageStatePrefix     = "gcp_iam_group_permission_usage"
	gcpIAMUsageStatusUncertain      = "attribution_uncertain"
)

var errSkipGCPIAMGroupPermissionUsage = errors.New("gcp IAM group permission usage scan skipped: no target groups configured")

func (e *GCPSyncEngine) gcpIAMGroupPermissionUsageTable() GCPTableSpec {
	return GCPTableSpec{
		Name: gcpIAMGroupPermissionUsageTable,
		Columns: []string{
			"project_id",
			"id",
			"group",
			"permission",
			"granted_roles",
			"permission_last_used",
			"usage_status",
			"days_unused",
			"unused_since",
			"lookback_days",
			"removal_threshold_days",
			"member_count",
			"members_observed",
			"recommendation",
			"evidence_source",
			"confidence",
			"coverage",
			"scan_window_start",
			"scan_window_end",
		},
		Fetch: e.fetchGCPIAMGroupPermissionUsage,
	}
}

func (e *GCPSyncEngine) fetchGCPIAMGroupPermissionUsage(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	if len(e.gcpIAMTargetGroups) == 0 {
		e.logger.Info("gcp IAM group permission usage table skipped: no target groups configured")
		return nil, errSkipGCPIAMGroupPermissionUsage
	}

	lookbackDays := clampPermissionUsageWindowDays(e.permissionUsageLookbackDays)
	removalThresholdDays := clampPermissionRemovalThresholdDays(e.permissionUsageRemovalThresholdDays)
	now := time.Now().UTC()
	usageCutoff := now.Add(-time.Duration(lookbackDays) * 24 * time.Hour)

	policy, err := e.fetchGCPProjectIAMPolicy(ctx, projectID)
	if err != nil {
		return nil, err
	}

	groupRoleBindings := extractTargetGroupRoles(policy, e.gcpIAMTargetGroups)
	if len(groupRoleBindings) == 0 {
		e.logger.Info("gcp IAM group permission usage table skipped: target groups have no IAM bindings", "project_id", projectID)
		return nil, errSkipGCPIAMGroupPermissionUsage
	}

	workspaceMembers, hasWorkspaceData := e.fetchWorkspaceGroupMembers(ctx, mapKeys(groupRoleBindings))

	iamClient, err := admin.NewIamClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create IAM admin client: %w", err)
	}
	defer func() { _ = iamClient.Close() }()

	rolePermissionCache := make(map[string][]string)
	roleResolutionErrors := make(map[string]error)
	roleLookup := func(lookupCtx context.Context, req *adminpb.GetRoleRequest) (*adminpb.Role, error) {
		return iamClient.GetRole(lookupCtx, req)
	}

	loggingClient, logErr := logadmin.NewClient(ctx, projectID, gcpClientOptionsFromContext(ctx)...)
	if logErr != nil {
		e.logger.Warn("failed to create cloud logging client for IAM usage analysis", "project_id", projectID, "error", logErr)
	}
	if loggingClient != nil {
		defer func() { _ = loggingClient.Close() }()
	}

	rows := make([]map[string]interface{}, 0, 256)
	hasResolvableTargetGrants := false

	groups := mapKeys(groupRoleBindings)
	sort.Strings(groups)
	for _, group := range groups {
		roles := groupRoleBindings[group]
		if len(roles) == 0 {
			continue
		}

		groupRoleResolutionErr := false

		grantedPermissions := make(map[string]map[string]struct{})
		for _, role := range roles {
			permissions, resolveErr := fetchGCPRolePermissions(ctx, roleLookup, role, rolePermissionCache)
			if resolveErr != nil {
				roleResolutionErrors[role] = resolveErr
				groupRoleResolutionErr = true
				continue
			}
			for _, permission := range permissions {
				normalized := strings.TrimSpace(permission)
				if normalized == "" {
					continue
				}
				roleSet := grantedPermissions[normalized]
				if roleSet == nil {
					roleSet = make(map[string]struct{})
					grantedPermissions[normalized] = roleSet
				}
				roleSet[role] = struct{}{}
			}
		}

		if len(grantedPermissions) == 0 {
			continue
		}
		hasResolvableTargetGrants = true

		outsideGrantedPermissions, outsideRoleResolutionErr := e.resolvePermissionsGrantedOutsideGroup(
			ctx,
			roleLookup,
			policy,
			group,
			rolePermissionCache,
			roleResolutionErrors,
		)

		cursorKey := fmt.Sprintf("%s:%s:%s", gcpIAMGroupUsageStatePrefix, projectID, group)
		cursor, _ := e.loadPermissionUsageCursor(ctx, cursorKey)
		windowStart := permissionUsageWindowStart(now, lookbackDays, cursor)

		usedPermissions := make(map[string]time.Time)
		ambiguousPermissions := make(map[string]time.Time)
		membersObserved := make(map[string]struct{})
		nextCursor := cursor
		memberQueryFailed := false

		members := workspaceMembers[group]
		logsAvailable := loggingClient != nil && len(members) > 0
		if logsAvailable {
			for _, member := range members {
				if strings.TrimSpace(member) == "" {
					continue
				}
				memberUsage, memberCursor, usageErr := fetchGCPGroupMemberPermissionUsage(ctx, loggingClient, projectID, member, windowStart)
				if usageErr != nil {
					memberQueryFailed = true
					e.logger.Warn("failed to fetch group member permission usage", "project_id", projectID, "group", group, "member", member, "error", usageErr)
					continue
				}
				nextCursor = cursorAfter(nextCursor, memberCursor)
				if len(memberUsage) > 0 {
					membersObserved[member] = struct{}{}
				}
				for permission, lastUsed := range memberUsage {
					if _, granted := grantedPermissions[permission]; !granted {
						continue
					}
					if _, ambiguous := outsideGrantedPermissions[permission]; ambiguous {
						if existing, ok := ambiguousPermissions[permission]; !ok || lastUsed.After(existing) {
							ambiguousPermissions[permission] = lastUsed
						}
						continue
					}
					if existing, ok := usedPermissions[permission]; !ok || lastUsed.After(existing) {
						usedPermissions[permission] = lastUsed
					}
				}
			}
		}

		existingStates := e.loadExistingGCPGroupPermissionState(ctx, projectID, group)

		permissions := mapKeys(grantedPermissions)
		sort.Strings(permissions)
		for _, permission := range permissions {
			previousState := existingStates[permission]
			lastSeen := usedPermissions[permission]
			ambiguousLastSeen := ambiguousPermissions[permission]
			if ambiguousLastSeen.After(lastSeen) {
				lastSeen = ambiguousLastSeen
			}
			if previousState.LastUsed.After(lastSeen) {
				lastSeen = previousState.LastUsed
			}

			usageStatus := "unused"
			recommendation := ""

			if !lastSeen.IsZero() {
				if ambiguousLastSeen.After(usageCutoff) {
					usageStatus = gcpIAMUsageStatusUncertain
					recommendation = fmt.Sprintf("Permission %s was observed in audit logs for members of group %s, but this permission is also granted outside the group bindings in project %s; verify attribution before removing the role grant.", permission, group, projectID)
				} else if lastSeen.After(usageCutoff) {
					usageStatus = "used"
				}
			}

			coverage := "full"
			confidence := "high"
			authoritativeCoverage := true
			if !hasWorkspaceData || len(members) == 0 || loggingClient == nil {
				coverage = "partial"
				confidence = "low"
				authoritativeCoverage = false
			}
			if memberQueryFailed && confidence != "low" {
				coverage = "partial"
				confidence = "medium"
				authoritativeCoverage = false
			}
			if groupRoleResolutionErr && confidence != "low" {
				coverage = "partial"
				confidence = "medium"
				authoritativeCoverage = false
			}
			if outsideRoleResolutionErr && confidence != "low" {
				coverage = "partial"
				confidence = "medium"
				authoritativeCoverage = false
			}
			if usageStatus == gcpIAMUsageStatusUncertain && confidence == "high" {
				coverage = "partial"
				confidence = "medium"
				authoritativeCoverage = false
			}
			if usageStatus == "unused" && !authoritativeCoverage {
				usageStatus = "unknown"
			}

			currentState := derivePermissionUsageCurrentState(now, windowStart, lastSeen, previousState, usageStatus)
			daysUnused := permissionUsageDaysUnused(now, currentState, lookbackDays)
			if permissionUsageShouldRecommendRemoval(usageStatus, daysUnused, removalThresholdDays, authoritativeCoverage) {
				recommendation = fmt.Sprintf("Permission %s appears unused for group %s in project %s for %d consecutive days; consider removing the granting IAM role(s).", permission, group, projectID, daysUnused)
			}

			grantingRoles := mapKeys(grantedPermissions[permission])
			sort.Strings(grantingRoles)
			rowID := fmt.Sprintf("%s|%s|%s", projectID, strings.ToLower(group), strings.ToLower(permission))
			row := map[string]interface{}{
				"_cq_id":                 rowID,
				"id":                     rowID,
				"project_id":             projectID,
				"group":                  group,
				"permission":             permission,
				"granted_roles":          grantingRoles,
				"usage_status":           usageStatus,
				"days_unused":            daysUnused,
				"lookback_days":          lookbackDays,
				"removal_threshold_days": removalThresholdDays,
				"member_count":           len(members),
				"members_observed":       len(membersObserved),
				"recommendation":         recommendation,
				"evidence_source":        "gcp_cloud_audit_logs_authorization_info",
				"confidence":             confidence,
				"coverage":               coverage,
				"scan_window_start":      windowStart,
				"scan_window_end":        now,
			}
			if !lastSeen.IsZero() {
				row["permission_last_used"] = lastSeen
			}
			if !currentState.UnusedSince.IsZero() {
				row["unused_since"] = currentState.UnusedSince
			}
			rows = append(rows, row)
		}

		if !memberQueryFailed {
			if err := e.savePermissionUsageCursor(ctx, cursorKey, nextCursor); err != nil {
				e.logger.Warn("failed to save GCP IAM group permission usage cursor", "state_key", cursorKey, "error", err)
			}
		}
	}

	roleResolutionErr := summarizeGCPIAMRoleResolutionErrors(roleResolutionErrors)
	if roleResolutionErr != nil {
		for role, resolveErr := range roleResolutionErrors {
			e.logger.Warn("failed to resolve IAM role permissions", "role", role, "error", resolveErr)
		}
	}

	if !hasResolvableTargetGrants {
		e.logger.Info("gcp IAM group permission usage table skipped: target group grants could not be resolved", "project_id", projectID)
		return nil, errSkipGCPIAMGroupPermissionUsage
	}
	if roleResolutionErr != nil && len(rows) > 0 {
		return rows, newPartialFetchError(roleResolutionErr)
	}

	return rows, nil
}

func summarizeGCPIAMRoleResolutionErrors(roleResolutionErrors map[string]error) error {
	if len(roleResolutionErrors) == 0 {
		return nil
	}

	roles := make([]string, 0, len(roleResolutionErrors))
	for role := range roleResolutionErrors {
		roles = append(roles, role)
	}
	sort.Strings(roles)

	parts := make([]string, 0, len(roles))
	for _, role := range roles {
		parts = append(parts, fmt.Sprintf("%s: %v", role, roleResolutionErrors[role]))
	}

	return errors.New("failed to resolve IAM role permissions: " + strings.Join(parts, "; "))
}

func (e *GCPSyncEngine) resolvePermissionsGrantedOutsideGroup(
	ctx context.Context,
	roleLookup gcpRoleLookupFunc,
	policy *iampb.Policy,
	targetGroup string,
	rolePermissionCache map[string][]string,
	roleResolutionErrors map[string]error,
) (map[string]struct{}, bool) {
	outsidePermissions := make(map[string]struct{})
	if policy == nil {
		return outsidePermissions, false
	}

	hadResolutionError := false
	for _, binding := range policy.Bindings {
		if binding == nil || strings.TrimSpace(binding.Role) == "" {
			continue
		}
		if bindingIsExclusiveToGroup(binding, targetGroup) {
			continue
		}

		permissions, resolveErr := fetchGCPRolePermissions(ctx, roleLookup, binding.Role, rolePermissionCache)
		if resolveErr != nil {
			roleResolutionErrors[binding.Role] = resolveErr
			hadResolutionError = true
			continue
		}

		for _, permission := range permissions {
			normalized := strings.TrimSpace(permission)
			if normalized == "" {
				continue
			}
			outsidePermissions[normalized] = struct{}{}
		}
	}

	return outsidePermissions, hadResolutionError
}

func bindingIsExclusiveToGroup(binding *iampb.Binding, targetGroup string) bool {
	targetGroup = strings.ToLower(strings.TrimSpace(targetGroup))
	if binding == nil || targetGroup == "" || len(binding.Members) == 0 {
		return false
	}

	hasTargetGroup := false
	for _, member := range binding.Members {
		memberType, email := parseGCPMember(member)
		if !strings.EqualFold(memberType, "group") {
			return false
		}
		normalizedGroup := strings.ToLower(strings.TrimSpace(email))
		if normalizedGroup != targetGroup {
			return false
		}
		hasTargetGroup = true
	}

	return hasTargetGroup
}

func extractTargetGroupRoles(policy *iampb.Policy, targets map[string]struct{}) map[string][]string {
	roleSetByGroup := make(map[string]map[string]struct{})
	if policy == nil {
		return nil
	}

	for _, binding := range policy.Bindings {
		if binding == nil || strings.TrimSpace(binding.Role) == "" {
			continue
		}
		for _, member := range binding.Members {
			memberType, email := parseGCPMember(member)
			if !strings.EqualFold(memberType, "group") || email == "" {
				continue
			}
			group := strings.ToLower(strings.TrimSpace(email))
			if len(targets) > 0 {
				if _, ok := targets[group]; !ok {
					continue
				}
			}
			roleSet := roleSetByGroup[group]
			if roleSet == nil {
				roleSet = make(map[string]struct{})
				roleSetByGroup[group] = roleSet
			}
			roleSet[binding.Role] = struct{}{}
		}
	}

	rolesByGroup := make(map[string][]string, len(roleSetByGroup))
	for group, roles := range roleSetByGroup {
		if len(roles) == 0 {
			rolesByGroup[group] = nil
			continue
		}
		values := make([]string, 0, len(roles))
		for role := range roles {
			values = append(values, role)
		}
		sort.Strings(values)
		rolesByGroup[group] = values
	}

	return rolesByGroup
}

type gcpRoleLookupFunc func(context.Context, *adminpb.GetRoleRequest) (*adminpb.Role, error)

func fetchGCPRolePermissions(ctx context.Context, roleLookup gcpRoleLookupFunc, role string, cache map[string][]string) ([]string, error) {
	if cached, ok := cache[role]; ok {
		return cached, nil
	}
	out, err := roleLookup(ctx, &adminpb.GetRoleRequest{Name: role})
	if err != nil {
		return nil, err
	}
	permissions := append([]string(nil), out.IncludedPermissions...)
	sort.Strings(permissions)
	cache[role] = permissions
	return permissions, nil
}

func fetchGCPGroupMemberPermissionUsage(
	ctx context.Context,
	logClient *logadmin.Client,
	projectID string,
	memberEmail string,
	startTime time.Time,
) (map[string]time.Time, permissionUsageCursor, error) {
	result := make(map[string]time.Time)
	cursor := permissionUsageCursor{}

	filter := fmt.Sprintf(
		`timestamp >= "%s" AND protoPayload.authenticationInfo.principalEmail="%s" AND protoPayload.authorizationInfo.permission:*`,
		startTime.Format(time.RFC3339),
		strings.TrimSpace(memberEmail),
	)

	it := logClient.Entries(ctx, logadmin.Filter(filter), logadmin.NewestFirst())
	for {
		entry, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, permissionUsageCursor{}, fmt.Errorf("list audit log entries for %s in project %s: %w", memberEmail, projectID, err)
		}

		entryTime := entry.Timestamp.UTC()
		if entryTime.IsZero() {
			entryTime = time.Now().UTC()
		}
		cursor = cursorAfter(cursor, permissionUsageCursor{Time: entryTime, ID: entry.InsertID})

		permissions := extractGrantedPermissionsFromAuditEntry(entry)
		for _, permission := range permissions {
			normalized := strings.TrimSpace(permission)
			if normalized == "" {
				continue
			}
			if existing, ok := result[normalized]; !ok || entryTime.After(existing) {
				result[normalized] = entryTime
			}
		}
	}

	return result, cursor, nil
}

func extractGrantedPermissionsFromAuditEntry(entry *logging.Entry) []string {
	if entry == nil {
		return nil
	}

	permissions := make(map[string]struct{})
	switch payload := entry.Payload.(type) {
	case *auditpb.AuditLog:
		for _, info := range payload.AuthorizationInfo {
			if info == nil || !info.Granted {
				continue
			}
			permission := strings.TrimSpace(info.Permission)
			if permission != "" {
				permissions[permission] = struct{}{}
			}
		}
	case map[string]interface{}:
		authorizationInfo, ok := payload["authorizationInfo"].([]interface{})
		if !ok {
			break
		}
		for _, raw := range authorizationInfo {
			info, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			granted, _ := info["granted"].(bool)
			if !granted {
				continue
			}
			permission, _ := info["permission"].(string)
			permission = strings.TrimSpace(permission)
			if permission != "" {
				permissions[permission] = struct{}{}
			}
		}
	}

	result := make([]string, 0, len(permissions))
	for permission := range permissions {
		result = append(result, permission)
	}
	sort.Strings(result)
	return result
}

type workspaceGroupMember struct {
	Email string
	Type  string
}

func (e *GCPSyncEngine) fetchWorkspaceGroupMembers(ctx context.Context, groups []string) (map[string][]string, bool) {
	result := make(map[string][]string, len(groups))
	if len(groups) == 0 || e.sf == nil {
		return result, false
	}

	hasWorkspaceData := false
	for _, group := range groups {
		root := strings.ToLower(strings.TrimSpace(group))
		if root == "" {
			continue
		}

		seenGroups := map[string]struct{}{root: {}}
		membersSet := make(map[string]struct{})
		frontier := []string{root}

		for len(frontier) > 0 {
			membersByGroup, ok := e.loadWorkspaceGroupMemberships(ctx, frontier)
			if !ok {
				return result, false
			}
			hasWorkspaceData = true

			nextFrontier := make([]string, 0)
			for _, currentGroup := range frontier {
				for _, member := range membersByGroup[currentGroup] {
					email := strings.ToLower(strings.TrimSpace(member.Email))
					if email == "" {
						continue
					}
					if member.Type == "group" {
						if _, seen := seenGroups[email]; seen {
							continue
						}
						seenGroups[email] = struct{}{}
						nextFrontier = append(nextFrontier, email)
						continue
					}
					membersSet[email] = struct{}{}
				}
			}

			frontier = nextFrontier
		}

		members := make([]string, 0, len(membersSet))
		for member := range membersSet {
			members = append(members, member)
		}
		sort.Strings(members)
		result[root] = members
	}

	return result, hasWorkspaceData
}

func (e *GCPSyncEngine) loadWorkspaceGroupMemberships(ctx context.Context, groups []string) (map[string][]workspaceGroupMember, bool) {
	result := make(map[string][]workspaceGroupMember, len(groups))
	if len(groups) == 0 || e.sf == nil {
		return result, false
	}

	placeholders := strings.Join(warehouse.Placeholders(e.sf, 1, len(groups)), ",")
	args := make([]interface{}, 0, len(groups))
	for _, group := range groups {
		args = append(args, strings.ToLower(strings.TrimSpace(group)))
	}

	query := fmt.Sprintf(`
		SELECT LOWER(g.email) AS group_email, LOWER(m.email) AS member_email, COALESCE(LOWER(m.type), 'user') AS member_type
		FROM google_workspace_groups g
		JOIN google_workspace_group_members m ON LOWER(m.group_id) = LOWER(g.id)
		WHERE LOWER(g.email) IN (%s)
		  AND COALESCE(m.email, '') <> ''
	`, placeholders)

	rows, err := e.sf.Query(ctx, query, args...)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "does not exist") {
			return result, false
		}
		e.logger.Warn("failed to load workspace group members for IAM usage analysis", "error", err)
		return result, false
	}

	for _, row := range rows.Rows {
		group := strings.ToLower(strings.TrimSpace(queryRowString(row, "group_email")))
		member := strings.ToLower(strings.TrimSpace(queryRowString(row, "member_email")))
		memberType := strings.ToLower(strings.TrimSpace(queryRowString(row, "member_type")))
		if group == "" || member == "" {
			continue
		}
		if memberType == "" {
			memberType = "user"
		}
		result[group] = append(result[group], workspaceGroupMember{Email: member, Type: memberType})
	}

	return result, true
}

func (e *GCPSyncEngine) loadExistingGCPGroupPermissionState(ctx context.Context, projectID, group string) map[string]permissionUsageCurrentState {
	result := make(map[string]permissionUsageCurrentState)
	if e.sf == nil {
		return result
	}

	rows, err := e.sf.Query(ctx, `
		SELECT permission, permission_last_used, unused_since, usage_status
		FROM `+gcpIAMGroupPermissionUsageTable+`
		WHERE project_id = `+warehouse.Placeholder(e.sf, 1)+` AND LOWER("group") = `+warehouse.Placeholder(e.sf, 2)+`
	`, projectID, strings.ToLower(group))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "does not exist") {
			return result
		}
		return result
	}

	for _, row := range rows.Rows {
		permission := strings.TrimSpace(queryRowString(row, "permission"))
		if permission == "" {
			continue
		}
		state := permissionUsageCurrentState{Status: strings.ToLower(strings.TrimSpace(queryRowString(row, "usage_status")))}
		if ts, ok := parseAnyTime(queryRow(row, "permission_last_used")); ok {
			state.LastUsed = ts.UTC()
		}
		if ts, ok := parseAnyTime(queryRow(row, "unused_since")); ok {
			state.UnusedSince = ts.UTC()
		}
		result[permission] = state
	}

	return result
}

func mapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}
