package sync

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssoadmintypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/writer/cerebro/internal/graph"
)

const (
	awsIdentityCenterPermissionUsageTable = "aws_identitycenter_permission_set_permission_usage"
	awsIdentityCenterStatePrefix          = "aws_identitycenter_permission_usage"
	awsReservedSSORolePathPrefix          = "/aws-reserved/sso.amazonaws.com/"
	awsIdentityCenterIncrementalLookback  = 5 * time.Minute
)

type awsTrackedActionUsage struct {
	LastAccessedTime   time.Time
	LastAccessedEntity string
	LastAccessedRegion string
}

func (e *SyncEngine) awsIdentityCenterPermissionSetUsageTable() TableSpec {
	return TableSpec{
		Name: awsIdentityCenterPermissionUsageTable,
		Columns: []string{
			"arn",
			"account_id",
			"region",
			"identity_center_instance_arn",
			"identity_store_id",
			"permission_set_arn",
			"permission_set_name",
			"sso_role_name",
			"sso_role_arn",
			"assignment_count",
			"action",
			"action_last_accessed",
			"last_authenticated_entity",
			"last_authenticated_region",
			"usage_status",
			"days_unused",
			"lookback_days",
			"recommendation",
			"evidence_source",
			"confidence",
			"coverage",
			"scan_window_start",
			"scan_window_end",
		},
		Fetch:               e.fetchAWSIdentityCenterPermissionSetUsage,
		Mode:                TableSyncModeIncremental,
		IncrementalLookback: awsIdentityCenterIncrementalLookback,
	}
}

func (e *SyncEngine) fetchAWSIdentityCenterPermissionSetUsage(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	lookbackDays := clampPermissionUsageLookbackDays(e.permissionUsageLookbackDays)
	now := time.Now().UTC()
	usageCutoff := now.Add(-time.Duration(lookbackDays) * 24 * time.Hour)

	accountID := e.getAccountIDFromConfig(ctx, cfg)
	if accountID == "" {
		return nil, nil
	}

	adminClient := ssoadmin.NewFromConfig(cfg)
	iamClient := iam.NewFromConfig(cfg)

	instances, err := listIdentityCenterInstances(ctx, adminClient)
	if err != nil {
		e.logger.Warn("identity center instance listing failed, skipping table", "table", awsIdentityCenterPermissionUsageTable, "error", err)
		return nil, nil
	}
	if len(instances) == 0 {
		return nil, nil
	}

	reservedRoles, err := listReservedSSORoles(ctx, iamClient)
	if err != nil {
		e.logger.Warn("failed to list AWS reserved SSO roles", "error", err)
		return nil, nil
	}

	managedPolicyActions := make(map[string][]string)
	customerPolicyActions := make(map[string][]string)
	rows := make([]map[string]interface{}, 0, 256)

	for _, instance := range instances {
		instanceArn := aws.ToString(instance.InstanceArn)
		identityStoreID := aws.ToString(instance.IdentityStoreId)
		if instanceArn == "" {
			continue
		}

		permissionSetArns, psErr := listPermissionSetARNs(ctx, adminClient, instanceArn)
		if psErr != nil {
			e.logger.Warn("failed to list identity center permission sets", "instance_arn", instanceArn, "error", psErr)
			continue
		}

		for _, permissionSetArn := range permissionSetArns {
			permissionSet, descErr := describePermissionSet(ctx, adminClient, instanceArn, permissionSetArn)
			if descErr != nil || permissionSet == nil {
				e.logger.Warn("failed to describe permission set", "instance_arn", instanceArn, "permission_set_arn", permissionSetArn, "error", descErr)
				continue
			}

			permissionSetName := aws.ToString(permissionSet.Name)
			if !e.shouldIncludePermissionSet(permissionSetName, permissionSetArn) {
				continue
			}

			provisionedAccounts, accountErr := listProvisionedAccountsForPermissionSet(ctx, adminClient, instanceArn, permissionSetArn)
			if accountErr != nil {
				e.logger.Warn("failed to list provisioned accounts for permission set", "permission_set_arn", permissionSetArn, "error", accountErr)
				continue
			}
			if !containsStringValue(provisionedAccounts, accountID) {
				e.deleteIdentityCenterUsageRowsByPermissionSet(ctx, permissionSetArn, accountID)
				continue
			}

			assignmentCount, assignmentErr := countPermissionSetAssignments(ctx, adminClient, instanceArn, permissionSetArn, accountID)
			if assignmentErr != nil {
				e.logger.Warn("failed to count permission set assignments", "permission_set_arn", permissionSetArn, "account_id", accountID, "error", assignmentErr)
			}

			role := resolveReservedSSORole(reservedRoles, permissionSetName)
			if role == nil {
				e.logger.Warn("no AWSReservedSSO role found for permission set in account", "permission_set_name", permissionSetName, "permission_set_arn", permissionSetArn, "account_id", accountID)
				e.deleteIdentityCenterUsageRowsByPermissionSet(ctx, permissionSetArn, accountID)
				continue
			}

			roleArn := aws.ToString(role.Arn)
			roleName := aws.ToString(role.RoleName)
			if roleArn == "" || roleName == "" {
				continue
			}

			grantedActions, grantErr := e.resolvePermissionSetGrantedActions(
				ctx,
				adminClient,
				iamClient,
				instanceArn,
				permissionSetArn,
				accountID,
				managedPolicyActions,
				customerPolicyActions,
			)
			if grantErr != nil {
				e.logger.Warn("failed to resolve granted actions for permission set", "permission_set_arn", permissionSetArn, "error", grantErr)
				continue
			}
			if len(grantedActions) == 0 {
				e.deleteStaleIdentityCenterUsageRows(ctx, permissionSetArn, roleArn, nil)
				continue
			}

			stateKey := fmt.Sprintf("%s:%s:%s:%s", awsIdentityCenterStatePrefix, accountID, instanceArn, permissionSetArn)
			cursor, _ := e.loadPermissionUsageCursor(ctx, stateKey)
			windowStart := permissionUsageWindowStart(now, lookbackDays, cursor)

			trackedActions, usageErr := fetchRoleActionLastAccess(ctx, iamClient, roleArn)
			if usageErr != nil {
				e.logger.Warn("failed to fetch role action usage from access advisor", "role_arn", roleArn, "error", usageErr)
				continue
			}

			existingLastSeen := e.loadExistingAWSPermissionActionLastSeen(ctx, permissionSetArn, roleArn)
			nextCursor := permissionUsageCursor{Time: now, ID: roleArn}

			sort.Strings(grantedActions)
			for _, action := range grantedActions {
				usage, wildcardMatch := resolveTrackedActionUsage(action, trackedActions)
				lastSeen := usage.LastAccessedTime.UTC()
				if existing := existingLastSeen[strings.ToLower(action)]; existing.After(lastSeen) {
					lastSeen = existing
				}

				if !lastSeen.IsZero() {
					nextCursor = cursorAfter(nextCursor, permissionUsageCursor{Time: lastSeen, ID: strings.ToLower(action)})
				}

				usageStatus := "unused"
				recommendation := ""
				daysUnused := lookbackDays
				coverage := "full"
				confidence := "high"

				if wildcardMatch {
					coverage = "partial"
					confidence = "medium"
				}

				if !lastSeen.IsZero() {
					daysUnused = int(now.Sub(lastSeen).Hours() / 24)
					if lastSeen.After(usageCutoff) {
						usageStatus = "used"
					}
				}

				if usageStatus == "unused" {
					recommendation = fmt.Sprintf("Permission %s appears unused for this permission set in the last %d days; consider removing it from the Identity Center permission set.", action, lookbackDays)
				}

				rowID := fmt.Sprintf("%s|%s|%s|%s", instanceArn, permissionSetArn, roleArn, strings.ToLower(action))
				row := map[string]interface{}{
					"_cq_id":                       rowID,
					"arn":                          rowID,
					"account_id":                   accountID,
					"region":                       region,
					"identity_center_instance_arn": instanceArn,
					"identity_store_id":            identityStoreID,
					"permission_set_arn":           permissionSetArn,
					"permission_set_name":          permissionSetName,
					"sso_role_name":                roleName,
					"sso_role_arn":                 roleArn,
					"assignment_count":             assignmentCount,
					"action":                       action,
					"usage_status":                 usageStatus,
					"days_unused":                  daysUnused,
					"lookback_days":                lookbackDays,
					"recommendation":               recommendation,
					"evidence_source":              "aws_iam_access_advisor_action_level",
					"confidence":                   confidence,
					"coverage":                     coverage,
					"scan_window_start":            windowStart,
					"scan_window_end":              now,
				}

				if !lastSeen.IsZero() {
					row["action_last_accessed"] = lastSeen
				}
				if usage.LastAccessedEntity != "" {
					row["last_authenticated_entity"] = usage.LastAccessedEntity
				}
				if usage.LastAccessedRegion != "" {
					row["last_authenticated_region"] = usage.LastAccessedRegion
				}

				rows = append(rows, row)
			}

			if err := e.savePermissionUsageCursor(ctx, stateKey, nextCursor); err != nil {
				e.logger.Warn("failed to persist identity center usage cursor", "state_key", stateKey, "error", err)
			}

			e.deleteStaleIdentityCenterUsageRows(ctx, permissionSetArn, roleArn, grantedActions)
		}
	}

	return rows, nil
}

func (e *SyncEngine) deleteStaleIdentityCenterUsageRows(ctx context.Context, permissionSetArn, roleArn string, currentActions []string) {
	if e.sf == nil || permissionSetArn == "" || roleArn == "" {
		return
	}

	var query string
	var args []interface{}

	if len(currentActions) == 0 {
		query = fmt.Sprintf(
			"DELETE FROM %s WHERE permission_set_arn = ? AND sso_role_arn = ?",
			awsIdentityCenterPermissionUsageTable,
		)
		args = []interface{}{permissionSetArn, roleArn}
	} else {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(currentActions)), ",")
		args = make([]interface{}, 0, len(currentActions)+2)
		args = append(args, permissionSetArn, roleArn)
		for _, action := range currentActions {
			args = append(args, strings.ToLower(action))
		}
		query = fmt.Sprintf(
			"DELETE FROM %s WHERE permission_set_arn = ? AND sso_role_arn = ? AND LOWER(action) NOT IN (%s)",
			awsIdentityCenterPermissionUsageTable, placeholders,
		)
	}

	if _, err := e.sf.Exec(ctx, query, args...); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "does not exist") {
			e.logger.Warn("failed to clean stale identity center usage rows", "permission_set_arn", permissionSetArn, "error", err)
		}
	}
}

func (e *SyncEngine) deleteIdentityCenterUsageRowsByPermissionSet(ctx context.Context, permissionSetArn, accountID string) {
	if e.sf == nil || permissionSetArn == "" || accountID == "" {
		return
	}

	query := fmt.Sprintf(
		"DELETE FROM %s WHERE permission_set_arn = ? AND account_id = ?",
		awsIdentityCenterPermissionUsageTable,
	)
	if _, err := e.sf.Exec(ctx, query, permissionSetArn, accountID); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "does not exist") {
			e.logger.Warn("failed to clean stale identity center usage rows for permission set",
				"permission_set_arn", permissionSetArn, "account_id", accountID, "error", err)
		}
	}
}

func (e *SyncEngine) shouldIncludePermissionSet(name, arn string) bool {
	if len(e.identityCenterPermissionSetInclude) > 0 && !identityFilterMatches(e.identityCenterPermissionSetInclude, name, arn) {
		return false
	}
	if len(e.identityCenterPermissionSetExclude) > 0 && identityFilterMatches(e.identityCenterPermissionSetExclude, name, arn) {
		return false
	}
	return true
}

func (e *SyncEngine) resolvePermissionSetGrantedActions(
	ctx context.Context,
	adminClient *ssoadmin.Client,
	iamClient *iam.Client,
	instanceArn string,
	permissionSetArn string,
	accountID string,
	managedPolicyActions map[string][]string,
	customerPolicyActions map[string][]string,
) ([]string, error) {
	actionsSet := make(map[string]struct{})

	managedPolicies, err := listManagedPoliciesForPermissionSet(ctx, adminClient, instanceArn, permissionSetArn)
	if err != nil {
		return nil, err
	}
	for _, policy := range managedPolicies {
		policyArn := aws.ToString(policy.Arn)
		if policyArn == "" {
			continue
		}
		actions, ok := managedPolicyActions[policyArn]
		if !ok {
			doc, docErr := fetchIAMPolicyDocument(ctx, iamClient, policyArn)
			if docErr != nil {
				continue
			}
			actions = extractAllowActionsFromPolicyDocument(doc)
			managedPolicyActions[policyArn] = actions
		}
		for _, action := range actions {
			actionsSet[action] = struct{}{}
		}
	}

	customerManagedPolicies, err := listCustomerManagedPoliciesForPermissionSet(ctx, adminClient, instanceArn, permissionSetArn)
	if err != nil {
		return nil, err
	}
	for _, policy := range customerManagedPolicies {
		policyArn := customerManagedPolicyARN(accountID, aws.ToString(policy.Path), aws.ToString(policy.Name))
		if policyArn == "" {
			continue
		}
		actions, ok := customerPolicyActions[policyArn]
		if !ok {
			doc, docErr := fetchIAMPolicyDocument(ctx, iamClient, policyArn)
			if docErr != nil {
				continue
			}
			actions = extractAllowActionsFromPolicyDocument(doc)
			customerPolicyActions[policyArn] = actions
		}
		for _, action := range actions {
			actionsSet[action] = struct{}{}
		}
	}

	inlinePolicy, err := getInlinePolicyForPermissionSet(ctx, adminClient, instanceArn, permissionSetArn)
	if err != nil {
		return nil, err
	}
	for _, action := range extractAllowActionsFromPolicyDocument(inlinePolicy) {
		actionsSet[action] = struct{}{}
	}

	actions := make([]string, 0, len(actionsSet))
	for action := range actionsSet {
		actions = append(actions, action)
	}
	sort.Strings(actions)
	return actions, nil
}

func (e *SyncEngine) loadExistingAWSPermissionActionLastSeen(ctx context.Context, permissionSetArn, roleArn string) map[string]time.Time {
	result := make(map[string]time.Time)
	if e.sf == nil {
		return result
	}

	query := `
		SELECT action, action_last_accessed
		FROM ` + awsIdentityCenterPermissionUsageTable + `
		WHERE permission_set_arn = ? AND sso_role_arn = ?
	`
	rows, err := e.sf.Query(ctx, query, permissionSetArn, roleArn)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "does not exist") {
			return result
		}
		return result
	}

	for _, row := range rows.Rows {
		action := strings.ToLower(strings.TrimSpace(queryRowString(row, "action")))
		if action == "" {
			continue
		}
		if ts, ok := parseAnyTime(queryRow(row, "action_last_accessed")); ok {
			result[action] = ts.UTC()
		}
	}

	return result
}

func listIdentityCenterInstances(ctx context.Context, client *ssoadmin.Client) ([]ssoadmintypes.InstanceMetadata, error) {
	instances := make([]ssoadmintypes.InstanceMetadata, 0)
	var token *string
	for {
		out, err := client.ListInstances(ctx, &ssoadmin.ListInstancesInput{
			MaxResults: aws.Int32(100),
			NextToken:  token,
		})
		if err != nil {
			return nil, err
		}
		instances = append(instances, out.Instances...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return instances, nil
}

func listPermissionSetARNs(ctx context.Context, client *ssoadmin.Client, instanceArn string) ([]string, error) {
	arns := make([]string, 0)
	var token *string
	for {
		out, err := client.ListPermissionSets(ctx, &ssoadmin.ListPermissionSetsInput{
			InstanceArn: aws.String(instanceArn),
			MaxResults:  aws.Int32(100),
			NextToken:   token,
		})
		if err != nil {
			return nil, err
		}
		arns = append(arns, out.PermissionSets...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return arns, nil
}

func describePermissionSet(ctx context.Context, client *ssoadmin.Client, instanceArn, permissionSetArn string) (*ssoadmintypes.PermissionSet, error) {
	out, err := client.DescribePermissionSet(ctx, &ssoadmin.DescribePermissionSetInput{
		InstanceArn:      aws.String(instanceArn),
		PermissionSetArn: aws.String(permissionSetArn),
	})
	if err != nil {
		return nil, err
	}
	return out.PermissionSet, nil
}

func listProvisionedAccountsForPermissionSet(ctx context.Context, client *ssoadmin.Client, instanceArn, permissionSetArn string) ([]string, error) {
	accounts := make([]string, 0)
	var token *string
	for {
		out, err := client.ListAccountsForProvisionedPermissionSet(ctx, &ssoadmin.ListAccountsForProvisionedPermissionSetInput{
			InstanceArn:      aws.String(instanceArn),
			PermissionSetArn: aws.String(permissionSetArn),
			MaxResults:       aws.Int32(100),
			NextToken:        token,
		})
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, out.AccountIds...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return accounts, nil
}

func countPermissionSetAssignments(ctx context.Context, client *ssoadmin.Client, instanceArn, permissionSetArn, accountID string) (int, error) {
	count := 0
	var token *string
	for {
		out, err := client.ListAccountAssignments(ctx, &ssoadmin.ListAccountAssignmentsInput{
			InstanceArn:      aws.String(instanceArn),
			PermissionSetArn: aws.String(permissionSetArn),
			AccountId:        aws.String(accountID),
			MaxResults:       aws.Int32(100),
			NextToken:        token,
		})
		if err != nil {
			return 0, err
		}
		count += len(out.AccountAssignments)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return count, nil
}

func listManagedPoliciesForPermissionSet(ctx context.Context, client *ssoadmin.Client, instanceArn, permissionSetArn string) ([]ssoadmintypes.AttachedManagedPolicy, error) {
	policies := make([]ssoadmintypes.AttachedManagedPolicy, 0)
	var token *string
	for {
		out, err := client.ListManagedPoliciesInPermissionSet(ctx, &ssoadmin.ListManagedPoliciesInPermissionSetInput{
			InstanceArn:      aws.String(instanceArn),
			PermissionSetArn: aws.String(permissionSetArn),
			MaxResults:       aws.Int32(100),
			NextToken:        token,
		})
		if err != nil {
			return nil, err
		}
		policies = append(policies, out.AttachedManagedPolicies...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return policies, nil
}

func listCustomerManagedPoliciesForPermissionSet(ctx context.Context, client *ssoadmin.Client, instanceArn, permissionSetArn string) ([]ssoadmintypes.CustomerManagedPolicyReference, error) {
	policies := make([]ssoadmintypes.CustomerManagedPolicyReference, 0)
	var token *string
	for {
		out, err := client.ListCustomerManagedPolicyReferencesInPermissionSet(ctx, &ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetInput{
			InstanceArn:      aws.String(instanceArn),
			PermissionSetArn: aws.String(permissionSetArn),
			MaxResults:       aws.Int32(100),
			NextToken:        token,
		})
		if err != nil {
			return nil, err
		}
		policies = append(policies, out.CustomerManagedPolicyReferences...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return policies, nil
}

func getInlinePolicyForPermissionSet(ctx context.Context, client *ssoadmin.Client, instanceArn, permissionSetArn string) (string, error) {
	out, err := client.GetInlinePolicyForPermissionSet(ctx, &ssoadmin.GetInlinePolicyForPermissionSetInput{
		InstanceArn:      aws.String(instanceArn),
		PermissionSetArn: aws.String(permissionSetArn),
	})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(aws.ToString(out.InlinePolicy)), nil
}

func fetchIAMPolicyDocument(ctx context.Context, client *iam.Client, policyArn string) (string, error) {
	policyOut, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(policyArn)})
	if err != nil || policyOut.Policy == nil {
		return "", err
	}
	versionID := aws.ToString(policyOut.Policy.DefaultVersionId)
	if versionID == "" {
		return "", nil
	}
	versionOut, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyArn),
		VersionId: aws.String(versionID),
	})
	if err != nil || versionOut.PolicyVersion == nil {
		return "", err
	}
	return aws.ToString(versionOut.PolicyVersion.Document), nil
}

func extractAllowActionsFromPolicyDocument(document string) []string {
	statements, err := graph.ParseAWSPolicy(document)
	if err != nil {
		return nil
	}
	actions := make(map[string]struct{})
	for _, statement := range statements {
		if !strings.EqualFold(strings.TrimSpace(statement.Effect), "allow") {
			continue
		}
		for _, action := range statement.Actions {
			normalized := strings.TrimSpace(action)
			if normalized == "" {
				continue
			}
			actions[normalized] = struct{}{}
		}
	}
	result := make([]string, 0, len(actions))
	for action := range actions {
		result = append(result, action)
	}
	sort.Strings(result)
	return result
}

func listReservedSSORoles(ctx context.Context, client *iam.Client) ([]iamtypes.Role, error) {
	roles := make([]iamtypes.Role, 0)
	paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{
		PathPrefix: aws.String(awsReservedSSORolePathPrefix),
	})
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		roles = append(roles, out.Roles...)
	}
	return roles, nil
}

func resolveReservedSSORole(roles []iamtypes.Role, permissionSetName string) *iamtypes.Role {
	if len(roles) == 0 || permissionSetName == "" {
		return nil
	}
	prefix := reservedSSORolePrefix(permissionSetName)
	for i := range roles {
		roleName := aws.ToString(roles[i].RoleName)
		if strings.HasPrefix(roleName, prefix) {
			return &roles[i]
		}
	}
	return nil
}

func reservedSSORolePrefix(permissionSetName string) string {
	b := strings.Builder{}
	b.WriteString("AWSReservedSSO_")
	for _, r := range strings.TrimSpace(permissionSetName) {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '-', r == '_', r == '+', r == '=', r == ',', r == '.', r == '@':
			b.WriteRune(r)
		case unicode.IsSpace(r):
			b.WriteRune('_')
		default:
			b.WriteRune('_')
		}
	}
	b.WriteRune('_')
	return b.String()
}

func fetchRoleActionLastAccess(ctx context.Context, client *iam.Client, roleArn string) (map[string]awsTrackedActionUsage, error) {
	jobOut, err := client.GenerateServiceLastAccessedDetails(ctx, &iam.GenerateServiceLastAccessedDetailsInput{
		Arn:         aws.String(roleArn),
		Granularity: iamtypes.AccessAdvisorUsageGranularityTypeActionLevel,
	})
	if err != nil {
		return nil, err
	}

	jobID := aws.ToString(jobOut.JobId)
	if jobID == "" {
		return nil, nil
	}

	var details *iam.GetServiceLastAccessedDetailsOutput
	for i := 0; i < 12; i++ {
		out, getErr := client.GetServiceLastAccessedDetails(ctx, &iam.GetServiceLastAccessedDetailsInput{JobId: aws.String(jobID)})
		if getErr != nil {
			return nil, getErr
		}
		if out.JobStatus == iamtypes.JobStatusTypeCompleted {
			details = out
			break
		}
		if out.JobStatus == iamtypes.JobStatusTypeFailed {
			return nil, fmt.Errorf("access advisor action-level job failed for %s", roleArn)
		}
		time.Sleep(2 * time.Second)
	}

	if details == nil {
		return nil, fmt.Errorf("access advisor action-level job did not complete in time for %s", roleArn)
	}

	tracked := make(map[string]awsTrackedActionUsage)
	for _, service := range details.ServicesLastAccessed {
		namespace := strings.ToLower(strings.TrimSpace(aws.ToString(service.ServiceNamespace)))
		if namespace == "" {
			continue
		}
		for _, action := range service.TrackedActionsLastAccessed {
			actionName := strings.ToLower(strings.TrimSpace(aws.ToString(action.ActionName)))
			if actionName == "" {
				continue
			}
			key := namespace + ":" + actionName
			usage := tracked[key]
			if action.LastAccessedTime != nil {
				timeValue := action.LastAccessedTime.UTC()
				if usage.LastAccessedTime.IsZero() || timeValue.After(usage.LastAccessedTime) {
					usage.LastAccessedTime = timeValue
					usage.LastAccessedEntity = aws.ToString(action.LastAccessedEntity)
					usage.LastAccessedRegion = aws.ToString(action.LastAccessedRegion)
				}
			}
			tracked[key] = usage
		}
	}

	return tracked, nil
}

func resolveTrackedActionUsage(action string, tracked map[string]awsTrackedActionUsage) (awsTrackedActionUsage, bool) {
	normalized := strings.ToLower(strings.TrimSpace(action))
	if normalized == "" {
		return awsTrackedActionUsage{}, false
	}
	if usage, ok := tracked[normalized]; ok {
		return usage, false
	}

	if normalized == "*" {
		return maxTrackedActionUsage("", tracked), true
	}
	if strings.HasSuffix(normalized, ":*") {
		prefix := strings.TrimSuffix(normalized, "*")
		return maxTrackedActionUsage(prefix, tracked), true
	}

	return awsTrackedActionUsage{}, false
}

func maxTrackedActionUsage(prefix string, tracked map[string]awsTrackedActionUsage) awsTrackedActionUsage {
	best := awsTrackedActionUsage{}
	for action, usage := range tracked {
		if prefix != "" && !strings.HasPrefix(action, prefix) {
			continue
		}
		if usage.LastAccessedTime.After(best.LastAccessedTime) {
			best = usage
		}
	}
	return best
}

func customerManagedPolicyARN(accountID, path, name string) string {
	name = strings.TrimSpace(name)
	if accountID == "" || name == "" {
		return ""
	}
	path = strings.TrimSpace(path)
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	return fmt.Sprintf("arn:aws:iam::%s:policy%s%s", accountID, path, name)
}

func containsStringValue(values []string, target string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}

func parseAnyTime(value interface{}) (time.Time, bool) {
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC(), true
	case *time.Time:
		if typed == nil {
			return time.Time{}, false
		}
		return typed.UTC(), true
	case string:
		if parsed, err := time.Parse(time.RFC3339Nano, typed); err == nil {
			return parsed.UTC(), true
		}
		if parsed, err := time.Parse(time.RFC3339, typed); err == nil {
			return parsed.UTC(), true
		}
	case []byte:
		return parseAnyTime(string(typed))
	}
	return time.Time{}, false
}
