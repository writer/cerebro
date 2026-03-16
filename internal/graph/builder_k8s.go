package graph

import (
	"context"
	"encoding/json"
	"strings"
)

func (b *Builder) buildK8sNodes(ctx context.Context) {
	queries := []nodeQuery{
		{
			table: "k8s_core_pods",
			query: `
		SELECT _cq_id, uid, name, namespace, cluster_name, node_name, service_account_name, spec, status, labels, annotations
		FROM k8s_core_pods
	`,
			parse: func(rows []map[string]any) []*Node { return k8sNodesFromRows("k8s_core_pods", rows) },
		},
		{
			table: "k8s_core_namespaces",
			query: `
		SELECT _cq_id, uid, name, cluster_name, labels, annotations, status_phase, status_conditions,
		       network_policies, network_policy_count, network_policies_with_selector, network_policies_without_selector
		FROM k8s_core_namespaces
	`,
			parse: func(rows []map[string]any) []*Node { return k8sNodesFromRows("k8s_core_namespaces", rows) },
		},
		{
			table: "k8s_core_service_accounts",
			query: `
		SELECT _cq_id, uid, name, namespace, cluster_name, automount_service_account_token, secrets,
		       image_pull_secrets, labels, annotations
		FROM k8s_core_service_accounts
	`,
			parse: func(rows []map[string]any) []*Node { return k8sNodesFromRows("k8s_core_service_accounts", rows) },
		},
		{
			table: "k8s_apps_deployments",
			query: `
		SELECT _cq_id, uid, name, namespace, cluster_name, replicas, available_replicas, strategy,
		       selector, template, labels, annotations
		FROM k8s_apps_deployments
	`,
			parse: func(rows []map[string]any) []*Node { return k8sNodesFromRows("k8s_apps_deployments", rows) },
		},
		{
			table: "k8s_rbac_cluster_roles",
			query: `
		SELECT _cq_id, uid, name, cluster_name, rules, labels, annotations
		FROM k8s_rbac_cluster_roles
	`,
			parse: func(rows []map[string]any) []*Node { return k8sNodesFromRows("k8s_rbac_cluster_roles", rows) },
		},
		{
			table: "k8s_rbac_roles",
			query: `
		SELECT _cq_id, uid, name, namespace, cluster_name, rules, labels, annotations
		FROM k8s_rbac_roles
	`,
			parse: func(rows []map[string]any) []*Node { return k8sNodesFromRows("k8s_rbac_roles", rows) },
		},
		{
			table: "k8s_rbac_cluster_role_bindings",
			query: `
			SELECT _cq_id, uid, name, cluster_name, role_ref, subjects, labels, annotations
			FROM k8s_rbac_cluster_role_bindings
		`,
			parse: func(rows []map[string]any) []*Node { return k8sNodesFromRows("k8s_rbac_cluster_role_bindings", rows) },
		},
		{
			table: "k8s_rbac_role_bindings",
			query: `
			SELECT _cq_id, uid, name, namespace, cluster_name, role_ref, subjects, labels, annotations
			FROM k8s_rbac_role_bindings
		`,
			parse: func(rows []map[string]any) []*Node { return k8sNodesFromRows("k8s_rbac_role_bindings", rows) },
		},
		{
			table: "k8s_core_configmaps",
			query: `
		SELECT _cq_id, uid, name, namespace, cluster_name, immutable, data_keys, binary_data_keys, labels, annotations
		FROM k8s_core_configmaps
	`,
			parse: func(rows []map[string]any) []*Node { return k8sNodesFromRows("k8s_core_configmaps", rows) },
		},
		{
			table: "k8s_core_persistent_volumes",
			query: `
		SELECT _cq_id, uid, name, cluster_name, storage_class_name, phase, access_modes, capacity,
		       reclaim_policy, volume_mode, claim_ref, labels, annotations
		FROM k8s_core_persistent_volumes
	`,
			parse: func(rows []map[string]any) []*Node { return k8sNodesFromRows("k8s_core_persistent_volumes", rows) },
		},
	}

	b.runNodeQueries(ctx, queries)
}

func (b *Builder) buildKubernetesEdges(ctx context.Context) {
	pods, err := b.queryIfExists(ctx, "k8s_core_pods", `
		SELECT _cq_id, name, namespace, cluster_name, service_account_name
		FROM k8s_core_pods
	`)
	if err != nil {
		b.logger.Warn("failed to query k8s pods for edge build", "error", err)
	} else {
		for _, row := range pods.Rows {
			podID := k8sNodeID("k8s_core_pods", row, toString(row["_cq_id"]))
			if podID == "" {
				continue
			}
			serviceAccountName := strings.TrimSpace(queryRowString(row, "service_account_name"))
			if serviceAccountName == "" {
				continue
			}
			serviceAccountID := k8sTypedNamespacedID(queryRowString(row, "cluster_name"), "serviceaccount", queryRowString(row, "namespace"), serviceAccountName)
			if !k8sNodesExist(b.graph, podID, serviceAccountID) {
				continue
			}
			b.addEdgeIfMissing(&Edge{
				ID:     "k8s-pod-sa:" + podID + "->" + serviceAccountID,
				Source: podID,
				Target: serviceAccountID,
				Kind:   EdgeKindCanAssume,
				Effect: EdgeEffectAllow,
				Properties: map[string]any{
					"mechanism": "pod_service_account",
				},
			})
		}
	}

	bindings, err := b.queryIfExists(ctx, "k8s_rbac_service_account_bindings", `
		SELECT cluster_name, binding_kind, binding_name, binding_namespace, service_account_name,
		       service_account_namespace, role_ref_kind, role_ref_name, role_ref_api_group
		FROM k8s_rbac_service_account_bindings
	`)
	if err != nil {
		b.logger.Warn("failed to query k8s service account bindings", "error", err)
		return
	}

	for _, row := range bindings.Rows {
		serviceAccountID := k8sTypedNamespacedID(
			queryRowString(row, "cluster_name"),
			"serviceaccount",
			queryRowString(row, "service_account_namespace"),
			queryRowString(row, "service_account_name"),
		)
		roleID := k8sRoleRefNodeID(row)
		if serviceAccountID == "" || roleID == "" || !k8sNodesExist(b.graph, serviceAccountID, roleID) {
			continue
		}

		b.addEdgeIfMissing(&Edge{
			ID:     "k8s-sa-role:" + serviceAccountID + "->" + roleID,
			Source: serviceAccountID,
			Target: roleID,
			Kind:   EdgeKindCanAssume,
			Effect: EdgeEffectAllow,
			Properties: map[string]any{
				"binding_kind":       strings.TrimSpace(queryRowString(row, "binding_kind")),
				"binding_name":       strings.TrimSpace(queryRowString(row, "binding_name")),
				"binding_namespace":  strings.TrimSpace(queryRowString(row, "binding_namespace")),
				"role_ref_kind":      strings.TrimSpace(queryRowString(row, "role_ref_kind")),
				"role_ref_name":      strings.TrimSpace(queryRowString(row, "role_ref_name")),
				"role_ref_api_group": strings.TrimSpace(queryRowString(row, "role_ref_api_group")),
			},
		})
	}
}

func k8sNodesFromRows(table string, rows []map[string]any) []*Node {
	nodes := make([]*Node, 0, len(rows))
	for _, row := range rows {
		if node := k8sNodeFromRecord(table, row, toString(row["_cq_id"])); node != nil {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func k8sNodeFromRecord(table string, record map[string]any, fallbackID string) *Node {
	table = strings.ToLower(strings.TrimSpace(table))
	id := k8sNodeID(table, record, fallbackID)
	if id == "" {
		return nil
	}
	clusterName := strings.TrimSpace(queryRowString(record, "cluster_name"))
	account := k8sNormalizeClusterName(clusterName)

	switch table {
	case "k8s_core_pods":
		spec := normalizeStructuredValue(record["spec"])
		properties := map[string]any{
			"uid":                  queryRow(record, "uid"),
			"namespace":            queryRow(record, "namespace"),
			"cluster_name":         clusterName,
			"node_name":            queryRow(record, "node_name"),
			"service_account_name": queryRow(record, "service_account_name"),
			"spec":                 spec,
			"status":               normalizeStructuredValue(record["status"]),
			"labels":               normalizeStructuredValue(record["labels"]),
			"annotations":          normalizeStructuredValue(record["annotations"]),
		}
		for key, value := range deriveK8sPodSignals(spec) {
			properties[key] = value
		}
		return &Node{
			ID:         id,
			Kind:       NodeKindPod,
			Name:       firstNonEmpty(queryRowString(record, "name"), id),
			Provider:   "k8s",
			Account:    account,
			Properties: properties,
			Risk:       deriveK8sPodRisk(properties),
		}
	case "k8s_core_namespaces":
		return &Node{
			ID:       id,
			Kind:     NodeKindNamespace,
			Name:     firstNonEmpty(queryRowString(record, "name"), id),
			Provider: "k8s",
			Account:  account,
			Properties: map[string]any{
				"uid":                               queryRow(record, "uid"),
				"cluster_name":                      clusterName,
				"labels":                            normalizeStructuredValue(record["labels"]),
				"annotations":                       normalizeStructuredValue(record["annotations"]),
				"status_phase":                      queryRow(record, "status_phase"),
				"status_conditions":                 normalizeStructuredValue(record["status_conditions"]),
				"network_policies":                  normalizeStructuredValue(record["network_policies"]),
				"network_policy_count":              queryRow(record, "network_policy_count"),
				"network_policies_with_selector":    queryRow(record, "network_policies_with_selector"),
				"network_policies_without_selector": queryRow(record, "network_policies_without_selector"),
			},
		}
	case "k8s_core_service_accounts":
		return &Node{
			ID:       id,
			Kind:     NodeKindServiceAccount,
			Name:     firstNonEmpty(queryRowString(record, "name"), id),
			Provider: "k8s",
			Account:  account,
			Properties: map[string]any{
				"uid":                             queryRow(record, "uid"),
				"namespace":                       queryRow(record, "namespace"),
				"cluster_name":                    clusterName,
				"automount_service_account_token": record["automount_service_account_token"],
				"secrets":                         normalizeStructuredValue(record["secrets"]),
				"image_pull_secrets":              normalizeStructuredValue(record["image_pull_secrets"]),
				"labels":                          normalizeStructuredValue(record["labels"]),
				"annotations":                     normalizeStructuredValue(record["annotations"]),
			},
		}
	case "k8s_apps_deployments":
		return &Node{
			ID:       id,
			Kind:     NodeKindDeployment,
			Name:     firstNonEmpty(queryRowString(record, "name"), id),
			Provider: "k8s",
			Account:  account,
			Properties: map[string]any{
				"uid":                queryRow(record, "uid"),
				"namespace":          queryRow(record, "namespace"),
				"cluster_name":       clusterName,
				"replicas":           queryRow(record, "replicas"),
				"available_replicas": queryRow(record, "available_replicas"),
				"strategy":           normalizeStructuredValue(record["strategy"]),
				"selector":           normalizeStructuredValue(record["selector"]),
				"template":           normalizeStructuredValue(record["template"]),
				"labels":             normalizeStructuredValue(record["labels"]),
				"annotations":        normalizeStructuredValue(record["annotations"]),
			},
		}
	case "k8s_rbac_cluster_roles":
		rules := normalizeStructuredValue(record["rules"])
		return &Node{
			ID:       id,
			Kind:     NodeKindClusterRole,
			Name:     firstNonEmpty(queryRowString(record, "name"), id),
			Provider: "k8s",
			Account:  account,
			Properties: map[string]any{
				"uid":          queryRow(record, "uid"),
				"cluster_name": clusterName,
				"rules":        rules,
				"labels":       normalizeStructuredValue(record["labels"]),
				"annotations":  normalizeStructuredValue(record["annotations"]),
			},
			Risk: deriveK8sClusterRoleRisk(rules),
		}
	case "k8s_rbac_roles":
		return &Node{
			ID:       id,
			Kind:     NodeKindRole,
			Name:     firstNonEmpty(queryRowString(record, "name"), id),
			Provider: "k8s",
			Account:  account,
			Properties: map[string]any{
				"uid":          queryRow(record, "uid"),
				"namespace":    queryRow(record, "namespace"),
				"cluster_name": clusterName,
				"rules":        normalizeStructuredValue(record["rules"]),
				"labels":       normalizeStructuredValue(record["labels"]),
				"annotations":  normalizeStructuredValue(record["annotations"]),
			},
		}
	case "k8s_rbac_cluster_role_bindings":
		return &Node{
			ID:       id,
			Kind:     NodeKindClusterRoleBinding,
			Name:     firstNonEmpty(queryRowString(record, "name"), id),
			Provider: "k8s",
			Account:  account,
			Properties: map[string]any{
				"uid":          queryRow(record, "uid"),
				"cluster_name": clusterName,
				"role_ref":     normalizeStructuredValue(record["role_ref"]),
				"subjects":     normalizeStructuredValue(record["subjects"]),
				"labels":       normalizeStructuredValue(record["labels"]),
				"annotations":  normalizeStructuredValue(record["annotations"]),
			},
		}
	case "k8s_rbac_role_bindings":
		return &Node{
			ID:       id,
			Kind:     NodeKindRoleBinding,
			Name:     firstNonEmpty(queryRowString(record, "name"), id),
			Provider: "k8s",
			Account:  account,
			Properties: map[string]any{
				"uid":          queryRow(record, "uid"),
				"namespace":    queryRow(record, "namespace"),
				"cluster_name": clusterName,
				"role_ref":     normalizeStructuredValue(record["role_ref"]),
				"subjects":     normalizeStructuredValue(record["subjects"]),
				"labels":       normalizeStructuredValue(record["labels"]),
				"annotations":  normalizeStructuredValue(record["annotations"]),
			},
		}
	case "k8s_core_configmaps":
		return &Node{
			ID:       id,
			Kind:     NodeKindConfigMap,
			Name:     firstNonEmpty(queryRowString(record, "name"), id),
			Provider: "k8s",
			Account:  account,
			Properties: map[string]any{
				"uid":              queryRow(record, "uid"),
				"namespace":        queryRow(record, "namespace"),
				"cluster_name":     clusterName,
				"immutable":        record["immutable"],
				"data_keys":        normalizeStructuredValue(record["data_keys"]),
				"binary_data_keys": normalizeStructuredValue(record["binary_data_keys"]),
				"labels":           normalizeStructuredValue(record["labels"]),
				"annotations":      normalizeStructuredValue(record["annotations"]),
			},
		}
	case "k8s_core_persistent_volumes":
		return &Node{
			ID:       id,
			Kind:     NodeKindPersistentVolume,
			Name:     firstNonEmpty(queryRowString(record, "name"), id),
			Provider: "k8s",
			Account:  account,
			Properties: map[string]any{
				"uid":                queryRow(record, "uid"),
				"cluster_name":       clusterName,
				"storage_class_name": queryRow(record, "storage_class_name"),
				"phase":              queryRow(record, "phase"),
				"access_modes":       normalizeStructuredValue(record["access_modes"]),
				"capacity":           normalizeStructuredValue(record["capacity"]),
				"reclaim_policy":     queryRow(record, "reclaim_policy"),
				"volume_mode":        queryRow(record, "volume_mode"),
				"claim_ref":          normalizeStructuredValue(record["claim_ref"]),
				"labels":             normalizeStructuredValue(record["labels"]),
				"annotations":        normalizeStructuredValue(record["annotations"]),
			},
		}
	default:
		return nil
	}
}

func k8sNodeID(table string, record map[string]any, fallbackID string) string {
	table = strings.ToLower(strings.TrimSpace(table))
	if id := strings.TrimSpace(queryRowString(record, "_cq_id")); id != "" && k8sIDMatchesTable(table, id) {
		return id
	}
	if id := strings.TrimSpace(fallbackID); id != "" && k8sIDMatchesTable(table, id) {
		return id
	}
	clusterName := queryRowString(record, "cluster_name")
	name := queryRowString(record, "name")
	namespace := queryRowString(record, "namespace")

	switch table {
	case "k8s_core_pods":
		return k8sTypedNamespacedID(clusterName, "pod", namespace, name)
	case "k8s_core_namespaces":
		return k8sClusterScopedID(clusterName, "namespace", name)
	case "k8s_core_service_accounts":
		return k8sTypedNamespacedID(clusterName, "serviceaccount", namespace, name)
	case "k8s_apps_deployments":
		return k8sTypedNamespacedID(clusterName, "deployment", namespace, name)
	case "k8s_rbac_roles":
		return k8sTypedNamespacedID(clusterName, "role", namespace, name)
	case "k8s_rbac_role_bindings":
		return k8sTypedNamespacedID(clusterName, "rolebinding", namespace, name)
	case "k8s_core_configmaps":
		return k8sTypedNamespacedID(clusterName, "configmap", namespace, name)
	case "k8s_rbac_cluster_roles":
		return k8sClusterScopedID(clusterName, "clusterrole", name)
	case "k8s_rbac_cluster_role_bindings":
		return k8sClusterScopedID(clusterName, "clusterrolebinding", name)
	case "k8s_core_persistent_volumes":
		return k8sClusterScopedID(clusterName, "persistentvolume", name)
	default:
		return firstNonEmpty(queryRowString(record, "_cq_id"), fallbackID, queryRowString(record, "id"), name)
	}
}

func k8sRoleRefNodeID(record map[string]any) string {
	clusterName := queryRowString(record, "cluster_name")
	roleName := queryRowString(record, "role_ref_name")
	switch strings.ToLower(strings.TrimSpace(queryRowString(record, "role_ref_kind"))) {
	case "clusterrole":
		return k8sClusterScopedID(clusterName, "clusterrole", roleName)
	case "role":
		namespace := firstNonEmpty(queryRowString(record, "binding_namespace"), queryRowString(record, "service_account_namespace"))
		return k8sTypedNamespacedID(clusterName, "role", namespace, roleName)
	default:
		return ""
	}
}

func deriveK8sPodSignals(spec any) map[string]any {
	specMap, ok := spec.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	out := map[string]any{
		"privileged":        k8sPodAnyPrivileged(specMap),
		"host_path_volumes": toBool(specMap["uses_host_path_volume"]),
		"run_as_root":       k8sPodRunsAsRoot(specMap),
	}
	if value, exists := specMap["automount_service_account_token"]; exists {
		if boolean, ok := asOptionalBool(value); ok {
			out["automount_service_account_token"] = boolean
		}
	}
	return out
}

func deriveK8sPodRisk(properties map[string]any) RiskLevel {
	if toBool(properties["privileged"]) && toBool(properties["host_path_volumes"]) {
		if toBool(properties["run_as_root"]) {
			return RiskCritical
		}
		return RiskHigh
	}
	if toBool(properties["privileged"]) || toBool(properties["run_as_root"]) {
		return RiskHigh
	}
	if toBool(properties["host_path_volumes"]) {
		return RiskMedium
	}
	return RiskNone
}

func deriveK8sClusterRoleRisk(rules any) RiskLevel {
	if k8sHasSecretsWildcard(rules) {
		return RiskCritical
	}
	return RiskNone
}

func k8sPodAnyPrivileged(spec map[string]any) bool {
	for _, container := range k8sSpecContainers(spec) {
		security, _ := container["security_context"].(map[string]any)
		if toBool(security["privileged"]) {
			return true
		}
	}
	return false
}

func k8sPodRunsAsRoot(spec map[string]any) bool {
	if security, _ := spec["security_context"].(map[string]any); security != nil {
		if toBool(security["run_as_non_root"]) {
			return false
		}
		if runAsUser, ok := numericValue(security["run_as_user"]); ok && runAsUser == 0 {
			return true
		}
	}
	for _, container := range k8sSpecContainers(spec) {
		security, _ := container["security_context"].(map[string]any)
		if security == nil {
			continue
		}
		if toBool(security["run_as_non_root"]) {
			continue
		}
		if runAsUser, ok := numericValue(security["run_as_user"]); ok && runAsUser == 0 {
			return true
		}
	}
	return false
}

func k8sSpecContainers(spec map[string]any) []map[string]any {
	raw, ok := spec["containers"]
	if !ok {
		return nil
	}
	switch typed := raw.(type) {
	case []map[string]any:
		return typed
	case []any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if mapped, ok := item.(map[string]any); ok {
				out = append(out, mapped)
			}
		}
		return out
	default:
		return nil
	}
}

func k8sHasSecretsWildcard(rules any) bool {
	ruleList, ok := rules.([]any)
	if !ok {
		return false
	}
	for _, rawRule := range ruleList {
		rule, ok := rawRule.(map[string]any)
		if !ok {
			continue
		}
		resources := anySlice(rule["resources"])
		verbs := anySlice(rule["verbs"])
		hasSecrets := false
		hasWildcardVerb := false
		for _, resource := range resources {
			resourceName := strings.TrimSpace(toString(resource))
			if resourceName == "secrets" || resourceName == "*" {
				hasSecrets = true
				break
			}
		}
		for _, verb := range verbs {
			if strings.TrimSpace(toString(verb)) == "*" {
				hasWildcardVerb = true
				break
			}
		}
		if hasSecrets && hasWildcardVerb {
			return true
		}
	}
	return false
}

func anySlice(value any) []any {
	switch typed := value.(type) {
	case []any:
		return typed
	case []string:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	default:
		return nil
	}
}

func asOptionalBool(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return false, false
		}
		return toBool(trimmed), true
	case float64:
		return typed != 0, true
	case int:
		return typed != 0, true
	default:
		return false, false
	}
}

func numericValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	default:
		return 0, false
	}
}

func normalizeStructuredValue(value any) any {
	switch typed := value.(type) {
	case string:
		return decodeStructuredJSON(strings.TrimSpace(typed), typed)
	case []byte:
		return decodeStructuredJSON(strings.TrimSpace(string(typed)), string(typed))
	default:
		return value
	}
}

func decodeStructuredJSON(raw string, fallback any) any {
	if raw == "" {
		return fallback
	}
	if !strings.HasPrefix(raw, "{") && !strings.HasPrefix(raw, "[") {
		return fallback
	}
	var decoded any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return fallback
	}
	return decoded
}

func k8sNodesExist(g *Graph, ids ...string) bool {
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			return false
		}
		if _, ok := g.GetNode(id); !ok {
			return false
		}
	}
	return true
}

func k8sIDMatchesTable(table, id string) bool {
	expected := k8sExpectedResourceType(table)
	if expected == "" {
		return true
	}
	parts := strings.Split(strings.TrimSpace(id), "/")
	if k8sTableUsesNamespacedID(table) {
		return len(parts) >= 4 && parts[len(parts)-3] == expected
	}
	return len(parts) >= 3 && parts[len(parts)-2] == expected
}

func k8sExpectedResourceType(table string) string {
	switch strings.ToLower(strings.TrimSpace(table)) {
	case "k8s_core_pods":
		return "pod"
	case "k8s_core_namespaces":
		return "namespace"
	case "k8s_core_service_accounts":
		return "serviceaccount"
	case "k8s_apps_deployments":
		return "deployment"
	case "k8s_rbac_cluster_roles":
		return "clusterrole"
	case "k8s_rbac_roles":
		return "role"
	case "k8s_rbac_cluster_role_bindings":
		return "clusterrolebinding"
	case "k8s_rbac_role_bindings":
		return "rolebinding"
	case "k8s_core_configmaps":
		return "configmap"
	case "k8s_core_persistent_volumes":
		return "persistentvolume"
	default:
		return ""
	}
}

func k8sNormalizeClusterName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "kubernetes"
	}
	return name
}

const k8sMissingNamespaceSegment = "_missing_namespace"

func k8sTypedNamespacedID(clusterName, resourceType, namespace, name string) string {
	clusterName = k8sNormalizeClusterName(clusterName)
	parts := []string{clusterName}
	if resourceType = strings.ToLower(strings.TrimSpace(resourceType)); resourceType != "" {
		parts = append(parts, resourceType)
	}
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		namespace = k8sMissingNamespaceSegment
	}
	parts = append(parts, namespace)
	if name = strings.TrimSpace(name); name != "" {
		parts = append(parts, name)
	}
	return strings.Join(parts, "/")
}

func k8sClusterScopedID(clusterName, resourceType, name string) string {
	clusterName = k8sNormalizeClusterName(clusterName)
	parts := []string{clusterName}
	if resourceType = strings.ToLower(strings.TrimSpace(resourceType)); resourceType != "" {
		parts = append(parts, resourceType)
	}
	if name = strings.TrimSpace(name); name != "" {
		parts = append(parts, name)
	}
	return strings.Join(parts, "/")
}

func k8sTableUsesNamespacedID(table string) bool {
	switch strings.ToLower(strings.TrimSpace(table)) {
	case "k8s_core_pods",
		"k8s_core_service_accounts",
		"k8s_apps_deployments",
		"k8s_rbac_roles",
		"k8s_rbac_role_bindings",
		"k8s_core_configmaps":
		return true
	default:
		return false
	}
}
