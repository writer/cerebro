package sync

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	admin "cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"cloud.google.com/go/iam/apiv1/iampb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	"google.golang.org/api/iterator"
	exprpb "google.golang.org/genproto/googleapis/type/expr"
)

func (e *GCPSyncEngine) gcpIAMServiceAccountTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_iam_service_accounts",
		Columns: []string{"project_id", "name", "email", "unique_id", "display_name", "description", "oauth2_client_id", "disabled", "keys", "roles", "has_admin_role", "has_high_privilege"},
		Fetch:   e.fetchGCPIAMServiceAccounts,
	}
}

func (e *GCPSyncEngine) gcpIAMServiceAccountKeyTable() GCPTableSpec {
	return GCPTableSpec{
		Name: "gcp_iam_service_account_keys",
		Columns: []string{
			"project_id",
			"service_account_name",
			"service_account_email",
			"name",
			"key_type",
			"key_algorithm",
			"key_origin",
			"valid_after_time",
			"valid_before_time",
			"disabled",
		},
		Fetch: e.fetchGCPIAMServiceAccountKeys,
	}
}

func (e *GCPSyncEngine) gcpIAMPolicyTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_iam_policies",
		Columns: []string{"project_id", "id", "version", "etag", "bindings", "audit_configs"},
		Fetch:   e.fetchGCPIAMPolicies,
	}
}

func (e *GCPSyncEngine) gcpIAMMemberTable() GCPTableSpec {
	return GCPTableSpec{
		Name: "gcp_iam_members",
		Columns: []string{
			"project_id",
			"id",
			"member",
			"member_type",
			"email",
			"roles",
			"has_admin_role",
			"has_high_privilege",
		},
		Fetch: e.fetchGCPIAMMembers,
	}
}

func (e *GCPSyncEngine) fetchGCPIAMServiceAccounts(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := admin.NewIamClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create IAM client: %w", err)
	}
	defer func() { _ = client.Close() }()

	serviceAccountRoleMetadata := e.fetchGCPServiceAccountRoleMetadata(ctx, projectID)

	rows := make([]map[string]interface{}, 0, 100)

	req := &adminpb.ListServiceAccountsRequest{
		Name: fmt.Sprintf("projects/%s", projectID),
	}

	it := client.ListServiceAccounts(ctx, req)
	for {
		sa, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list service accounts: %w", err)
		}

		row := map[string]interface{}{
			"_cq_id":             sa.Name,
			"project_id":         projectID,
			"name":               sa.Name,
			"email":              sa.Email,
			"unique_id":          sa.UniqueId,
			"display_name":       sa.DisplayName,
			"description":        sa.Description,
			"oauth2_client_id":   sa.Oauth2ClientId,
			"disabled":           sa.Disabled,
			"roles":              []string{},
			"has_admin_role":     false,
			"has_high_privilege": false,
		}
		if metadata, ok := serviceAccountRoleMetadata[strings.ToLower(sa.Email)]; ok {
			row["roles"] = metadata.Roles
			row["has_admin_role"] = metadata.HasAdminRole
			row["has_high_privilege"] = metadata.HasHighPrivilege
		}

		// Get service account keys
		keysReq := &adminpb.ListServiceAccountKeysRequest{
			Name: sa.Name,
		}
		keysResp, err := client.ListServiceAccountKeys(ctx, keysReq)
		if err == nil && keysResp != nil {
			var keys []map[string]interface{}
			for _, key := range keysResp.Keys {
				keyInfo := map[string]interface{}{
					"name":          key.Name,
					"key_algorithm": key.KeyAlgorithm.String(),
					"key_origin":    key.KeyOrigin.String(),
					"key_type":      key.KeyType.String(),
					"valid_after":   key.ValidAfterTime.AsTime(),
					"valid_before":  key.ValidBeforeTime.AsTime(),
					"disabled":      key.Disabled,
				}
				keys = append(keys, keyInfo)
			}
			row["keys"] = keys
		}

		rows = append(rows, row)
	}

	return rows, nil
}

type gcpServiceAccountRoleMetadata struct {
	Roles            []string
	HasAdminRole     bool
	HasHighPrivilege bool
}

func (e *GCPSyncEngine) fetchGCPProjectIAMPolicy(ctx context.Context, projectID string) (*iampb.Policy, error) {
	client, err := resourcemanager.NewProjectsClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("create resource manager client: %w", err)
	}
	defer func() { _ = client.Close() }()

	policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
		Resource: fmt.Sprintf("projects/%s", projectID),
	})
	if err != nil {
		return nil, fmt.Errorf("get iam policy: %w", err)
	}

	return policy, nil
}

func (e *GCPSyncEngine) fetchGCPServiceAccountRoleMetadata(ctx context.Context, projectID string) map[string]gcpServiceAccountRoleMetadata {
	policy, err := e.fetchGCPProjectIAMPolicy(ctx, projectID)
	if err != nil {
		return nil
	}
	return buildGCPServiceAccountRoleMetadata(policy)
}

func buildGCPServiceAccountRoleMetadata(policy *iampb.Policy) map[string]gcpServiceAccountRoleMetadata {
	if policy == nil {
		return nil
	}

	roleSets := make(map[string]map[string]struct{})
	for _, binding := range policy.Bindings {
		if binding == nil || binding.Role == "" {
			continue
		}
		for _, member := range binding.Members {
			memberType, email := parseGCPMember(member)
			if !strings.EqualFold(memberType, "serviceAccount") || email == "" {
				continue
			}
			key := strings.ToLower(email)
			roles := roleSets[key]
			if roles == nil {
				roles = make(map[string]struct{})
				roleSets[key] = roles
			}
			roles[binding.Role] = struct{}{}
		}
	}

	metadata := make(map[string]gcpServiceAccountRoleMetadata, len(roleSets))
	for email, roles := range roleSets {
		roleNames := make([]string, 0, len(roles))
		hasAdmin := false
		hasHigh := false
		for role := range roles {
			roleNames = append(roleNames, role)
			if isGCPAdminRole(role) {
				hasAdmin = true
			}
			if isGCPHighPrivilegeRole(role) {
				hasHigh = true
			}
		}
		sort.Strings(roleNames)
		metadata[email] = gcpServiceAccountRoleMetadata{
			Roles:            roleNames,
			HasAdminRole:     hasAdmin,
			HasHighPrivilege: hasHigh,
		}
	}

	return metadata
}

func (e *GCPSyncEngine) fetchGCPIAMServiceAccountKeys(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := admin.NewIamClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create IAM client: %w", err)
	}
	defer func() { _ = client.Close() }()

	rows := make([]map[string]interface{}, 0, 200)
	req := &adminpb.ListServiceAccountsRequest{
		Name: fmt.Sprintf("projects/%s", projectID),
	}

	it := client.ListServiceAccounts(ctx, req)
	for {
		sa, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list service accounts: %w", err)
		}

		keysReq := &adminpb.ListServiceAccountKeysRequest{
			Name: sa.Name,
			KeyTypes: []adminpb.ListServiceAccountKeysRequest_KeyType{
				adminpb.ListServiceAccountKeysRequest_USER_MANAGED,
				adminpb.ListServiceAccountKeysRequest_SYSTEM_MANAGED,
			},
		}
		keysResp, err := client.ListServiceAccountKeys(ctx, keysReq)
		if err != nil || keysResp == nil {
			continue
		}

		for _, key := range keysResp.Keys {
			row := map[string]interface{}{
				"_cq_id":                key.Name,
				"project_id":            projectID,
				"service_account_name":  sa.Name,
				"service_account_email": sa.Email,
				"name":                  key.Name,
				"key_type":              key.KeyType.String(),
				"key_algorithm":         key.KeyAlgorithm.String(),
				"key_origin":            key.KeyOrigin.String(),
				"disabled":              key.Disabled,
			}
			if key.ValidAfterTime != nil {
				row["valid_after_time"] = key.ValidAfterTime.AsTime()
			}
			if key.ValidBeforeTime != nil {
				row["valid_before_time"] = key.ValidBeforeTime.AsTime()
			}
			rows = append(rows, row)
		}
	}

	return rows, nil
}

func (e *GCPSyncEngine) fetchGCPIAMPolicies(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	policy, err := e.fetchGCPProjectIAMPolicy(ctx, projectID)
	if err != nil {
		return nil, err
	}

	var bindings []map[string]interface{}
	for _, binding := range policy.Bindings {
		bindings = append(bindings, map[string]interface{}{
			"role":      binding.Role,
			"members":   binding.Members,
			"condition": serializePolicyCondition(binding.Condition),
		})
	}

	auditConfigs := serializeAuditConfigs(policy.AuditConfigs)

	row := map[string]interface{}{
		"_cq_id":        fmt.Sprintf("%s/iam-policy", projectID),
		"project_id":    projectID,
		"id":            fmt.Sprintf("%s/iam-policy", projectID),
		"version":       policy.Version,
		"etag":          string(policy.Etag),
		"bindings":      bindings,
		"audit_configs": auditConfigs,
	}

	return []map[string]interface{}{row}, nil
}

func (e *GCPSyncEngine) fetchGCPIAMMembers(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	policy, err := e.fetchGCPProjectIAMPolicy(ctx, projectID)
	if err != nil {
		return nil, err
	}

	memberRoles := make(map[string]map[string]struct{})
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if member == "" {
				continue
			}
			roles := memberRoles[member]
			if roles == nil {
				roles = make(map[string]struct{})
				memberRoles[member] = roles
			}
			roles[binding.Role] = struct{}{}
		}
	}

	rows := make([]map[string]interface{}, 0, len(memberRoles))
	for member, roles := range memberRoles {
		roleNames := make([]string, 0, len(roles))
		for role := range roles {
			roleNames = append(roleNames, role)
		}
		sort.Strings(roleNames)

		roleEntries := make([]map[string]interface{}, 0, len(roleNames))
		hasAdmin := false
		hasHigh := false
		for _, role := range roleNames {
			roleEntries = append(roleEntries, map[string]interface{}{
				"name": role,
			})
			if isGCPAdminRole(role) {
				hasAdmin = true
			}
			if isGCPHighPrivilegeRole(role) {
				hasHigh = true
			}
		}

		memberType, email := parseGCPMember(member)
		row := map[string]interface{}{
			"_cq_id":             fmt.Sprintf("%s/%s", projectID, member),
			"project_id":         projectID,
			"id":                 fmt.Sprintf("%s/%s", projectID, member),
			"member":             member,
			"member_type":        memberType,
			"email":              email,
			"roles":              roleEntries,
			"has_admin_role":     hasAdmin,
			"has_high_privilege": hasHigh,
		}
		rows = append(rows, row)
	}

	return rows, nil
}

func serializePolicyCondition(condition *exprpb.Expr) map[string]interface{} {
	if condition == nil {
		return nil
	}
	return map[string]interface{}{
		"title":       condition.Title,
		"description": condition.Description,
		"expression":  condition.Expression,
		"location":    condition.Location,
	}
}

func serializeAuditConfigs(configs []*iampb.AuditConfig) []map[string]interface{} {
	if len(configs) == 0 {
		return nil
	}
	entries := make([]map[string]interface{}, 0, len(configs))
	for _, config := range configs {
		entries = append(entries, map[string]interface{}{
			"service":           config.Service,
			"audit_log_configs": serializeAuditLogConfigs(config.AuditLogConfigs),
		})
	}
	return entries
}

func serializeAuditLogConfigs(configs []*iampb.AuditLogConfig) []map[string]interface{} {
	if len(configs) == 0 {
		return nil
	}
	entries := make([]map[string]interface{}, 0, len(configs))
	for _, config := range configs {
		entries = append(entries, map[string]interface{}{
			"log_type":         config.LogType.String(),
			"exempted_members": config.ExemptedMembers,
		})
	}
	return entries
}

func parseGCPMember(member string) (string, string) {
	parts := strings.SplitN(member, ":", 2)
	if len(parts) != 2 {
		return "", member
	}
	memberType := parts[0]
	value := parts[1]
	if strings.Contains(value, "@") {
		return memberType, value
	}
	return memberType, ""
}

func isGCPAdminRole(role string) bool {
	value := strings.ToLower(role)
	return strings.Contains(value, "admin") || strings.Contains(value, "owner")
}

func isGCPHighPrivilegeRole(role string) bool {
	value := strings.ToLower(role)
	if strings.Contains(value, "editor") {
		return true
	}
	return isGCPAdminRole(role)
}
