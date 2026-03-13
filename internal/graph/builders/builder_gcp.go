package builders

import (
	"context"
	"encoding/json"
	"strings"
)

const maxGCPIAMPolicyJSONBytes = 1 << 20

// GCP Builder Methods

func (b *Builder) buildGCPNodes(ctx context.Context) {
	queries := []nodeQuery{
		{
			table: "gcp_iam_service_accounts",
			query: `SELECT unique_id, email, project_id, display_name FROM gcp_iam_service_accounts`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, sa := range rows {
					nodes = append(nodes, &Node{
						ID: toString(sa["unique_id"]), Kind: NodeKindServiceAccount, Name: toString(sa["email"]),
						Provider: "gcp", Account: toString(sa["project_id"]),
						Properties: map[string]any{"email": sa["email"], "display_name": sa["display_name"]},
					})
				}
				return nodes
			},
		},
		{
			table: "gcp_compute_instances",
			query: `SELECT id, name, project_id, zone, status, service_accounts FROM gcp_compute_instances`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, inst := range rows {
					saEmail := extractGCPServiceAccountEmail(inst["service_accounts"])
					isDefaultSA := strings.HasSuffix(saEmail, "-compute@developer.gserviceaccount.com")
					nodes = append(nodes, &Node{
						ID: toString(inst["id"]), Kind: NodeKindInstance, Name: toString(inst["name"]),
						Provider: "gcp", Account: toString(inst["project_id"]), Region: toString(inst["zone"]),
						Properties: map[string]any{
							"status":                inst["status"],
							"service_accounts":      inst["service_accounts"],
							"service_account_email": saEmail,
							"uses_default_sa":       isDefaultSA,
						},
					})
				}
				return nodes
			},
		},
		{
			table: "gcp_storage_buckets",
			query: `SELECT name, project_id, location, iam_policy, public_access_prevention, uniform_bucket_level_access FROM gcp_storage_buckets`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, bucket := range rows {
					iamStr := toString(bucket["iam_policy"])
					allUsers := strings.Contains(iamStr, "allUsers")
					allAuthUsers := strings.Contains(iamStr, "allAuthenticatedUsers")
					isPublic := allUsers || allAuthUsers
					risk := RiskNone
					if isPublic {
						risk = RiskCritical
					}
					nodes = append(nodes, &Node{
						ID: toString(bucket["name"]), Kind: NodeKindBucket, Name: toString(bucket["name"]),
						Provider: "gcp", Account: toString(bucket["project_id"]), Region: toString(bucket["location"]),
						Risk: risk, Properties: map[string]any{
							"iam_policy":                     bucket["iam_policy"],
							"public":                         isPublic,
							"public_access":                  isPublic,
							"all_users_access":               allUsers,
							"all_authenticated_users_access": allAuthUsers,
							"public_access_prevention":       bucket["public_access_prevention"],
						},
					})
				}
				return nodes
			},
		},
		{
			table: "gcp_sql_instances",
			query: `SELECT name, project_id, region, database_version, ip_addresses, settings FROM gcp_sql_instances`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, db := range rows {
					ipStr := toString(db["ip_addresses"])
					// A Cloud SQL instance is publicly accessible if it has a PRIMARY
					// IP type AND the settings authorize 0.0.0.0/0. Having both PRIMARY
					// and PRIVATE addresses doesn't negate public exposure.
					hasPublicIP := strings.Contains(ipStr, "PRIMARY")
					settingsStr := toString(db["settings"])
					hasOpenAuthNetwork := strings.Contains(settingsStr, "0.0.0.0/0")
					isPublic := hasPublicIP && hasOpenAuthNetwork
					risk := RiskNone
					if isPublic {
						risk = RiskCritical
					}
					nodes = append(nodes, &Node{
						ID: toString(db["name"]), Kind: NodeKindDatabase, Name: toString(db["name"]),
						Provider: "gcp", Account: toString(db["project_id"]), Region: toString(db["region"]),
						Risk: risk, Properties: map[string]any{
							"database_version": db["database_version"],
							"ip_addresses":     db["ip_addresses"],
							"public":           isPublic,
						},
					})
				}
				return nodes
			},
		},
		{
			table: "gcp_cloudfunctions_functions",
			query: `SELECT name, project_id, location, service_config, build_config FROM gcp_cloudfunctions_functions`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, fn := range rows {
					nodes = append(nodes, &Node{
						ID: toString(fn["name"]), Kind: NodeKindFunction, Name: toString(fn["name"]),
						Provider: "gcp", Account: toString(fn["project_id"]), Region: toString(fn["location"]),
						Properties: map[string]any{"service_config": fn["service_config"], "build_config": fn["build_config"]},
					})
				}
				return nodes
			},
		},
		{
			table: "gcp_cloudrun_services",
			query: `SELECT name, project_id, location, ingress, uri FROM gcp_cloudrun_services`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, svc := range rows {
					nodes = append(nodes, &Node{
						ID: toString(svc["name"]), Kind: NodeKindFunction, Name: toString(svc["name"]),
						Provider: "gcp", Account: toString(svc["project_id"]), Region: toString(svc["location"]),
						Properties: map[string]any{"ingress": svc["ingress"], "uri": svc["uri"]},
					})
				}
				return nodes
			},
		},
	}

	b.runNodeQueries(ctx, queries)
}

func (b *Builder) buildGCPEdges(ctx context.Context) {
	edgeCount, policyProjects := b.buildGCPEdgesFromPolicies(ctx)
	edgeCount += b.buildGCPEdgesFromMembers(ctx, policyProjects)
	edgeCount += b.buildGCPBucketIAMPolicyEdges(ctx)
	b.logger.Debug("processed GCP IAM bindings", "count", edgeCount)

	b.buildGCPServiceAccountEdges(ctx)
	b.buildGCPFirewallEdges(ctx)
}

func (b *Builder) buildGCPEdgesFromMembers(ctx context.Context, policyProjects map[string]struct{}) int {
	members, err := b.queryIfExists(ctx, "gcp_iam_members",
		`SELECT project_id, member, roles FROM gcp_iam_members`)
	if err != nil {
		b.logger.Debug("failed to query GCP IAM members", "error", err)
		return 0
	}

	count := 0
	for _, row := range members.Rows {
		projectID := toString(row["project_id"])
		member := toString(row["member"])
		if projectID == "" || member == "" {
			continue
		}
		if _, ok := policyProjects[projectID]; ok {
			continue
		}

		roles := extractGCPRoleNames(row["roles"])
		if len(roles) == 0 {
			continue
		}

		projectNodes := b.graph.GetNodesByAccountIndexed(projectID)
		for _, role := range roles {
			edgeKind := gcpRoleToEdgeKind(role)
			sourceID := b.resolveGCPPrincipalID(projectID, member)
			for _, node := range projectNodes {
				if node.Provider != "gcp" || !node.IsResource() {
					continue
				}
				b.graph.AddEdge(&Edge{
					ID:     sourceID + "->" + node.ID + ":" + role,
					Source: sourceID,
					Target: node.ID,
					Kind:   edgeKind,
					Effect: EdgeEffectAllow,
					Properties: map[string]any{
						"role":    role,
						"binding": "project",
						"member":  member,
						"scope":   "project",
					},
				})
				count++
			}
		}
	}

	return count
}

func (b *Builder) buildGCPEdgesFromPolicies(ctx context.Context) (int, map[string]struct{}) {
	policies, err := b.queryIfExists(ctx, "gcp_iam_policies",
		`SELECT project_id, bindings FROM gcp_iam_policies`)
	if err != nil {
		b.logger.Debug("failed to query GCP IAM policies", "error", err)
		return 0, nil
	}

	count := 0
	policyProjects := make(map[string]struct{})
	for _, policy := range policies.Rows {
		projectID := toString(policy["project_id"])
		if projectID == "" {
			continue
		}
		projectNodes := b.graph.GetNodesByAccountIndexed(projectID)

		for _, bindingMap := range gcpIAMBindingsFromPolicy(policy["bindings"]) {
			role := toString(bindingMap["role"])
			if role == "" {
				continue
			}

			members := toAnySlice(bindingMap["members"])
			if len(members) == 0 {
				continue
			}
			policyProjects[projectID] = struct{}{}
			edgeKind := gcpRoleToEdgeKind(role)
			condition := gcpIAMBindingCondition(bindingMap)
			for _, memberValue := range members {
				member := toString(memberValue)
				if member == "" {
					continue
				}
				sourceID := b.resolveGCPPrincipalID(projectID, member)
				for _, node := range projectNodes {
					if node.Provider != "gcp" || !node.IsResource() {
						continue
					}
					b.graph.AddEdge(&Edge{
						ID:     sourceID + "->" + node.ID + ":" + role,
						Source: sourceID,
						Target: node.ID,
						Kind:   edgeKind,
						Effect: EdgeEffectAllow,
						Properties: map[string]any{
							"role":      role,
							"binding":   "project",
							"member":    member,
							"scope":     "project",
							"condition": condition,
						},
					})
					count++
				}
			}
		}
	}

	return count, policyProjects
}

func (b *Builder) buildGCPBucketIAMPolicyEdges(ctx context.Context) int {
	rows, err := b.queryIfExists(ctx, "gcp_storage_buckets",
		`SELECT name, project_id, location, iam_policy, public_access_prevention, uniform_bucket_level_access FROM gcp_storage_buckets`)
	if err != nil {
		b.logger.Debug("failed to query GCP storage buckets for IAM bindings", "error", err)
		return 0
	}

	count := 0
	for _, row := range rows.Rows {
		bucketID := toString(row["name"])
		projectID := toString(row["project_id"])
		if bucketID == "" || projectID == "" {
			continue
		}
		bucketNode, ok := b.graph.GetNode(bucketID)
		if !ok || bucketNode == nil {
			continue
		}

		for _, bindingMap := range gcpIAMBindingsFromPolicy(row["iam_policy"]) {
			role := strings.TrimSpace(toString(bindingMap["role"]))
			if role == "" {
				continue
			}
			edgeKind := gcpRoleToEdgeKind(role)
			condition := gcpIAMBindingCondition(bindingMap)
			members := toAnySlice(bindingMap["members"])
			for _, memberValue := range members {
				member := strings.TrimSpace(toString(memberValue))
				if member == "" {
					continue
				}
				sourceID := b.resolveGCPPrincipalID(projectID, member)
				properties := map[string]any{
					"role":      role,
					"binding":   "resource",
					"member":    member,
					"scope":     "resource",
					"resource":  bucketID,
					"condition": condition,
					"mechanism": "resource_policy",
				}
				b.graph.AddEdge(&Edge{
					ID:         sourceID + "->" + bucketNode.ID + ":" + role + ":bucket_iam",
					Source:     sourceID,
					Target:     bucketNode.ID,
					Kind:       edgeKind,
					Effect:     EdgeEffectAllow,
					Properties: properties,
				})
				count++
			}
		}
	}

	return count
}

func extractGCPRoleNames(v any) []string {
	items := toAnySlice(v)
	if len(items) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(items))
	roles := make([]string, 0, len(items))
	for _, item := range items {
		var role string
		switch typed := item.(type) {
		case map[string]any:
			role = strings.TrimSpace(toString(typed["name"]))
		default:
			role = strings.TrimSpace(toString(typed))
		}
		if role == "" {
			continue
		}
		if _, ok := seen[role]; ok {
			continue
		}
		seen[role] = struct{}{}
		roles = append(roles, role)
	}

	return roles
}

func toAnySlice(v any) []any {
	if v == nil {
		return nil
	}

	switch values := v.(type) {
	case []any:
		return values
	case []map[string]any:
		out := make([]any, 0, len(values))
		for _, value := range values {
			out = append(out, value)
		}
		return out
	case []string:
		out := make([]any, 0, len(values))
		for _, value := range values {
			out = append(out, value)
		}
		return out
	case string:
		raw := strings.TrimSpace(values)
		if raw == "" {
			return nil
		}
		var parsed []any
		if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
			return parsed
		}
	}

	return nil
}

func (b *Builder) resolveGCPPrincipalID(projectID, member string) string {
	member = strings.TrimSpace(member)
	if member == "" {
		return ""
	}
	switch strings.ToLower(member) {
	case "allusers":
		return "internet"
	case "allauthenticatedusers":
		b.ensureGCPAuthenticatedUsersNode()
		return "allAuthenticatedUsers"
	}

	parts := strings.SplitN(member, ":", 2)
	if len(parts) != 2 {
		return member
	}
	if strings.EqualFold(parts[0], "serviceaccount") {
		return b.resolveGCPServiceAccountNodeID(projectID, parts[1])
	}

	return member
}

func (b *Builder) resolveGCPServiceAccountNodeID(projectID, email string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		return ""
	}

	projectNodes := b.graph.GetNodesByAccountIndexed(projectID)
	for _, candidate := range projectNodes {
		if candidate.Provider != "gcp" || candidate.Kind != NodeKindServiceAccount {
			continue
		}
		if strings.EqualFold(toString(candidate.Properties["email"]), email) || strings.EqualFold(candidate.Name, email) {
			return candidate.ID
		}
	}

	return email
}

func (b *Builder) ensureGCPAuthenticatedUsersNode() {
	b.graph.AddNode(&Node{
		ID:       "allAuthenticatedUsers",
		Kind:     NodeKindGroup,
		Name:     "All Authenticated Users",
		Provider: "external",
		Account:  "global",
		Risk:     RiskHigh,
		Properties: map[string]any{
			"broad_principal": true,
			"principal_scope": "authenticated_public",
		},
	})
}

func gcpIAMBindingsFromPolicy(policy any) []map[string]any {
	switch typed := policy.(type) {
	case map[string]any:
		if bindings, ok := typed["bindings"]; ok {
			return gcpIAMBindingsFromPolicy(bindings)
		}
		if len(typed) == 0 {
			return nil
		}
		if _, hasRole := typed["role"]; hasRole {
			return []map[string]any{cloneAnyMap(typed)}
		}
		return nil
	case []any:
		result := make([]map[string]any, 0, len(typed))
		for _, binding := range typed {
			if bindingMap, ok := binding.(map[string]any); ok {
				result = append(result, cloneAnyMap(bindingMap))
			}
		}
		return result
	case []map[string]any:
		result := make([]map[string]any, 0, len(typed))
		for _, binding := range typed {
			result = append(result, cloneAnyMap(binding))
		}
		return result
	case string:
		raw := strings.TrimSpace(typed)
		if raw == "" {
			return nil
		}
		if len(raw) > maxGCPIAMPolicyJSONBytes {
			return nil
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
			return gcpIAMBindingsFromPolicy(parsed)
		}
		var parsedBindings []any
		if err := json.Unmarshal([]byte(raw), &parsedBindings); err == nil {
			return gcpIAMBindingsFromPolicy(parsedBindings)
		}
		return nil
	default:
		return nil
	}
}

func gcpIAMBindingCondition(binding map[string]any) map[string]any {
	raw, ok := binding["condition"]
	if !ok || raw == nil {
		return nil
	}
	condition, ok := raw.(map[string]any)
	if !ok || len(condition) == 0 {
		return nil
	}
	return cloneAnyMap(condition)
}

func (b *Builder) buildGCPServiceAccountEdges(_ context.Context) {
	// Link compute instances to their service accounts
	for _, node := range b.graph.GetAllNodes() {
		if node.Provider != "gcp" || node.Kind != NodeKindInstance {
			continue
		}

		saList, ok := node.Properties["service_accounts"].([]any)
		if !ok {
			continue
		}

		for _, sa := range saList {
			saMap, ok := sa.(map[string]any)
			if !ok {
				continue
			}
			saEmail := toString(saMap["email"])
			if saEmail != "" {
				targetID := b.resolveGCPServiceAccountNodeID(node.Account, saEmail)
				b.graph.AddEdge(&Edge{
					ID:     node.ID + "->runs_as->" + targetID,
					Source: node.ID,
					Target: targetID,
					Kind:   EdgeKindCanAssume,
					Effect: EdgeEffectAllow,
					Properties: map[string]any{
						"mechanism":             "instance_service_account",
						"service_account_email": saEmail,
					},
				})
			}
		}
	}
}

func gcpRoleToEdgeKind(role string) EdgeKind {
	switch {
	case contains(role, "admin"), contains(role, "owner"):
		return EdgeKindCanAdmin
	case contains(role, "editor"), contains(role, "writer"):
		return EdgeKindCanWrite
	case contains(role, "deleter"):
		return EdgeKindCanDelete
	default:
		return EdgeKindCanRead
	}
}

func (b *Builder) buildGCPFirewallEdges(ctx context.Context) {
	firewalls, err := b.queryIfExists(ctx, "gcp_compute_firewalls",
		`SELECT name, project_id, direction, source_ranges, allowed, target_tags, network FROM gcp_compute_firewalls`)
	if err != nil {
		b.logger.Debug("failed to query GCP firewalls", "error", err)
		return
	}

	count := 0
	for _, fw := range firewalls.Rows {
		direction := toString(fw["direction"])
		if direction != "INGRESS" && direction != "\"INGRESS\"" {
			continue
		}
		sourceRanges := toString(fw["source_ranges"])
		if !strings.Contains(sourceRanges, "0.0.0.0/0") {
			continue
		}

		// This firewall allows internet ingress. Find matching instances by target_tags or all instances in the project.
		projectID := toString(fw["project_id"])
		targetTags := toString(fw["target_tags"])

		for _, node := range b.graph.GetNodesByAccountIndexed(projectID) {
			if node.Provider != "gcp" || node.Kind != NodeKindInstance {
				continue
			}
			// If firewall has target_tags, only match instances with those tags
			// For now, if no target_tags, it applies to all instances in the network
			if targetTags != "" && targetTags != "[]" && targetTags != "null" {
				// Check if instance has matching tags (simplified: check name containment)
				// Full implementation would match instance tags against firewall target_tags
				continue
			}
			node.Properties["public"] = true
			b.graph.AddEdge(&Edge{
				ID:     "internet->fw:" + toString(fw["name"]) + "->" + node.ID,
				Source: "internet",
				Target: node.ID,
				Kind:   EdgeKindExposedTo,
				Effect: EdgeEffectAllow,
				Risk:   RiskHigh,
				Properties: map[string]any{
					"firewall":  fw["name"],
					"allowed":   fw["allowed"],
					"mechanism": "gcp_firewall",
				},
			})
			count++
		}
	}
	b.logger.Debug("added GCP firewall exposure edges", "count", count)
}
