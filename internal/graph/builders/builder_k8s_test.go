package builders

import (
	"context"
	"testing"
)

func TestBuilderBuild_KubernetesOntologyAndEdges(t *testing.T) {
	source := newCDCRoutingSource()
	source.routes["from k8s_core_pods"] = &DataQueryResult{Rows: []map[string]any{{
		"_cq_id":               "prod-cluster/pod/payments/payments-api",
		"uid":                  "pod-uid-1",
		"name":                 "payments-api",
		"namespace":            "payments",
		"cluster_name":         "prod-cluster",
		"node_name":            "node-a",
		"service_account_name": "payments-sa",
		"spec": map[string]any{
			"automount_service_account_token": true,
			"uses_host_path_volume":           true,
			"containers": []map[string]any{{
				"name":  "app",
				"image": "payments:v1",
				"security_context": map[string]any{
					"privileged":  true,
					"run_as_user": float64(0),
				},
			}},
		},
		"status": map[string]any{"phase": "Running"},
		"labels": map[string]any{"app": "payments"},
	}}}
	source.routes["from k8s_core_namespaces"] = &DataQueryResult{Rows: []map[string]any{{
		"_cq_id":                            "prod-cluster/namespace/payments",
		"uid":                               "ns-uid-1",
		"name":                              "payments",
		"cluster_name":                      "prod-cluster",
		"status_phase":                      "Active",
		"network_policy_count":              2,
		"network_policies_with_selector":    1,
		"network_policies_without_selector": 1,
	}}}
	source.routes["from k8s_core_service_accounts"] = &DataQueryResult{Rows: []map[string]any{{
		"_cq_id":                          "prod-cluster/serviceaccount/payments/payments-sa",
		"uid":                             "sa-uid-1",
		"name":                            "payments-sa",
		"namespace":                       "payments",
		"cluster_name":                    "prod-cluster",
		"automount_service_account_token": true,
		"secrets":                         []any{"payments-token"},
	}}}
	source.routes["from k8s_apps_deployments"] = &DataQueryResult{Rows: []map[string]any{{
		"_cq_id":             "prod-cluster/deployment/payments/payments-api",
		"uid":                "deploy-uid-1",
		"name":               "payments-api",
		"namespace":          "payments",
		"cluster_name":       "prod-cluster",
		"replicas":           3,
		"available_replicas": 3,
		"template":           map[string]any{"spec": map[string]any{"service_account_name": "payments-sa"}},
	}}}
	source.routes["from k8s_rbac_cluster_roles"] = &DataQueryResult{Rows: []map[string]any{{
		"_cq_id":       "prod-cluster/clusterrole/cluster-admin",
		"uid":          "cr-uid-1",
		"name":         "cluster-admin",
		"cluster_name": "prod-cluster",
		"rules": []any{
			map[string]any{
				"resources": []any{"secrets"},
				"verbs":     []any{"*"},
			},
		},
	}}}
	source.routes["from k8s_rbac_roles"] = &DataQueryResult{Rows: []map[string]any{{
		"_cq_id":       "prod-cluster/role/payments/payments-reader",
		"uid":          "role-uid-1",
		"name":         "payments-reader",
		"namespace":    "payments",
		"cluster_name": "prod-cluster",
		"rules": []any{
			map[string]any{
				"resources": []any{"configmaps"},
				"verbs":     []any{"get", "list"},
			},
		},
	}}}
	source.routes["from k8s_rbac_cluster_role_bindings"] = &DataQueryResult{Rows: []map[string]any{{
		"_cq_id":       "prod-cluster/clusterrolebinding/payments-admins",
		"uid":          "crb-uid-1",
		"name":         "payments-admins",
		"cluster_name": "prod-cluster",
		"role_ref":     map[string]any{"kind": "ClusterRole", "name": "cluster-admin"},
		"subjects": []any{
			map[string]any{"kind": "ServiceAccount", "namespace": "payments", "name": "payments-sa"},
		},
	}}}
	source.routes["from k8s_rbac_role_bindings"] = &DataQueryResult{Rows: []map[string]any{{
		"_cq_id":       "prod-cluster/rolebinding/payments/payments-readers",
		"uid":          "rb-uid-1",
		"name":         "payments-readers",
		"namespace":    "payments",
		"cluster_name": "prod-cluster",
		"role_ref":     map[string]any{"kind": "Role", "name": "payments-reader"},
		"subjects": []any{
			map[string]any{"kind": "ServiceAccount", "namespace": "payments", "name": "payments-sa"},
		},
	}}}
	source.routes["from k8s_core_configmaps"] = &DataQueryResult{Rows: []map[string]any{{
		"_cq_id":           "prod-cluster/configmap/payments/payments-config",
		"uid":              "cfg-uid-1",
		"name":             "payments-config",
		"namespace":        "payments",
		"cluster_name":     "prod-cluster",
		"immutable":        true,
		"data_keys":        []any{"LOG_LEVEL", "TIMEOUT"},
		"binary_data_keys": []any{},
	}}}
	source.routes["from k8s_core_persistent_volumes"] = &DataQueryResult{Rows: []map[string]any{{
		"_cq_id":             "prod-cluster/persistentvolume/payments-pv",
		"uid":                "pv-uid-1",
		"name":               "payments-pv",
		"cluster_name":       "prod-cluster",
		"storage_class_name": "gp3",
		"phase":              "Bound",
		"access_modes":       []any{"ReadWriteOnce"},
		"capacity":           map[string]any{"storage": "50Gi"},
		"reclaim_policy":     "Delete",
		"volume_mode":        "Filesystem",
		"claim_ref":          map[string]any{"namespace": "payments", "name": "payments-pvc"},
	}}}
	source.routes["from k8s_rbac_service_account_bindings"] = &DataQueryResult{Rows: []map[string]any{{
		"cluster_name":              "prod-cluster",
		"binding_kind":              "ClusterRoleBinding",
		"binding_name":              "payments-admins",
		"binding_namespace":         "",
		"service_account_name":      "payments-sa",
		"service_account_namespace": "payments",
		"role_ref_kind":             "ClusterRole",
		"role_ref_name":             "cluster-admin",
		"role_ref_api_group":        "rbac.authorization.k8s.io",
	}, {
		"cluster_name":              "prod-cluster",
		"binding_kind":              "RoleBinding",
		"binding_name":              "payments-readers",
		"binding_namespace":         "payments",
		"service_account_name":      "payments-sa",
		"service_account_namespace": "payments",
		"role_ref_kind":             "Role",
		"role_ref_name":             "payments-reader",
		"role_ref_api_group":        "rbac.authorization.k8s.io",
	}}}

	builder := NewBuilder(source, nil)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	g := builder.Graph()
	requiredNodes := map[string]NodeKind{
		"prod-cluster/pod/payments/payments-api":             NodeKindPod,
		"prod-cluster/deployment/payments/payments-api":      NodeKindDeployment,
		"prod-cluster/namespace/payments":                    NodeKindNamespace,
		"prod-cluster/serviceaccount/payments/payments-sa":   NodeKindServiceAccount,
		"prod-cluster/clusterrole/cluster-admin":             NodeKindClusterRole,
		"prod-cluster/role/payments/payments-reader":         NodeKindRole,
		"prod-cluster/clusterrolebinding/payments-admins":    NodeKindClusterRoleBinding,
		"prod-cluster/rolebinding/payments/payments-readers": NodeKindRoleBinding,
		"prod-cluster/configmap/payments/payments-config":    NodeKindConfigMap,
		"prod-cluster/persistentvolume/payments-pv":          NodeKindPersistentVolume,
	}
	for id, kind := range requiredNodes {
		node, ok := g.GetNode(id)
		if !ok {
			t.Fatalf("expected node %q to exist", id)
		}
		if node.Kind != kind {
			t.Fatalf("expected node %q kind %q, got %q", id, kind, node.Kind)
		}
	}

	pod, ok := g.GetNode("prod-cluster/pod/payments/payments-api")
	if !ok {
		t.Fatal("expected pod/deployment id to exist")
	}
	if pod.Properties["privileged"] != true {
		t.Fatalf("expected privileged pod signal, got %#v", pod.Properties)
	}
	if pod.Properties["host_path_volumes"] != true {
		t.Fatalf("expected host_path_volumes signal, got %#v", pod.Properties)
	}
	if pod.Properties["run_as_root"] != true {
		t.Fatalf("expected run_as_root signal, got %#v", pod.Properties)
	}

	assertHasEdge(t, g, "prod-cluster/pod/payments/payments-api", "prod-cluster/serviceaccount/payments/payments-sa", EdgeKindCanAssume)
	assertHasEdge(t, g, "prod-cluster/serviceaccount/payments/payments-sa", "prod-cluster/clusterrole/cluster-admin", EdgeKindCanAssume)
	assertHasEdge(t, g, "prod-cluster/serviceaccount/payments/payments-sa", "prod-cluster/role/payments/payments-reader", EdgeKindCanAssume)

	combos := NewToxicCombinationEngine().Analyze(g)
	if !containsToxicCombination(combos, "TC-K8S-003-prod-cluster/serviceaccount/payments/payments-sa") {
		t.Fatalf("expected cluster-admin service account toxic combination, got %#v", combos)
	}
}

func assertHasEdge(t *testing.T, g *Graph, source, target string, kind EdgeKind) {
	t.Helper()
	for _, edge := range g.GetOutEdges(source) {
		if edge == nil {
			continue
		}
		if edge.Target == target && edge.Kind == kind {
			return
		}
	}
	t.Fatalf("expected edge %q -[%s]-> %q", source, kind, target)
}

func containsToxicCombination(combos []*ToxicCombination, id string) bool {
	for _, combo := range combos {
		if combo != nil && combo.ID == id {
			return true
		}
	}
	return false
}

func TestK8sClusterScopedID_NormalizesResourceType(t *testing.T) {
	got := k8sClusterScopedID("prod-cluster", "ClusterRole", "cluster-admin")
	if got != "prod-cluster/clusterrole/cluster-admin" {
		t.Fatalf("expected lowercase typed id, got %q", got)
	}
}

func TestK8sTypedNamespacedID_UsesNamespacePlaceholderWhenMissing(t *testing.T) {
	got := k8sTypedNamespacedID("prod-cluster", "Pod", "", "payments-api")
	if got != "prod-cluster/pod/_missing_namespace/payments-api" {
		t.Fatalf("expected placeholder namespace segment, got %q", got)
	}
}

func TestK8sIDMatchesTable_UsesResourceTypeSuffixPosition(t *testing.T) {
	if !k8sIDMatchesTable("k8s_core_pods", "prod/cluster/pod/payments/payments-api") {
		t.Fatal("expected suffix-based typed id match for namespaced resource")
	}
	if !k8sIDMatchesTable("k8s_core_namespaces", "prod/cluster/namespace/payments") {
		t.Fatal("expected suffix-based typed id match for cluster-scoped resource")
	}
}
