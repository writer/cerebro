package sync

import (
	"context"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// getK8sTables returns all Kubernetes table definitions.
func (e *K8sSyncEngine) getK8sTables() []K8sTableSpec {
	return []K8sTableSpec{
		e.k8sClusterInventoryTable(),
		e.k8sPodTable(),
		e.k8sNamespaceTable(),
		e.k8sNodeTable(),
		e.k8sServiceTable(),
		e.k8sServiceAccountTable(),
		e.k8sDeploymentTable(),
		e.k8sIngressTable(),
		e.k8sRoleTable(),
		e.k8sRoleBindingTable(),
		e.k8sClusterRoleTable(),
		e.k8sClusterRoleBindingTable(),
		e.k8sServiceAccountBindingTable(),
		e.k8sRBACRiskyBindingTable(),
		e.k8sAuditEventTable(),
	}
}

func (e *K8sSyncEngine) k8sClusterInventoryTable() K8sTableSpec {
	return K8sTableSpec{
		Name: "k8s_cluster_inventory",
		Columns: []string{
			"cluster_name",
			"kubernetes_version",
			"major",
			"minor",
			"platform",
			"go_version",
			"git_version",
			"git_commit",
			"git_tree_state",
			"build_date",
			"node_count",
			"namespace_count",
			"pod_count",
			"service_count",
		},
		Fetch: func(ctx context.Context, client kubernetes.Interface, _ string, clusterName string) ([]map[string]interface{}, error) {
			version, err := client.Discovery().ServerVersion()
			if err != nil {
				return nil, err
			}

			nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			pods, err := client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			services, err := client.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			clusterName = normalizeClusterName(clusterName)
			row := map[string]interface{}{
				"_cq_id":             buildClusterScopedID(clusterName, "cluster", "inventory"),
				"cluster_name":       clusterName,
				"kubernetes_version": version.String(),
				"major":              version.Major,
				"minor":              version.Minor,
				"platform":           version.Platform,
				"go_version":         version.GoVersion,
				"git_version":        version.GitVersion,
				"git_commit":         version.GitCommit,
				"git_tree_state":     version.GitTreeState,
				"build_date":         version.BuildDate,
				"node_count":         len(nodes.Items),
				"namespace_count":    len(namespaces.Items),
				"pod_count":          len(pods.Items),
				"service_count":      len(services.Items),
			}

			return []map[string]interface{}{row}, nil
		},
	}
}

func (e *K8sSyncEngine) k8sPodTable() K8sTableSpec {
	return K8sTableSpec{
		Name: "k8s_core_pods",
		Columns: []string{
			"uid",
			"name",
			"namespace",
			"cluster_name",
			"node_name",
			"service_account_name",
			"spec",
			"status",
			"labels",
			"annotations",
		},
		Fetch: func(ctx context.Context, client kubernetes.Interface, namespace, clusterName string) ([]map[string]interface{}, error) {
			if namespace == "" {
				namespace = metav1.NamespaceAll
			}

			pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			clusterName = normalizeClusterName(clusterName)
			rows := make([]map[string]interface{}, 0, len(pods.Items))
			for _, pod := range pods.Items {
				spec := podSpecToMap(pod.Spec)
				row := map[string]interface{}{
					"_cq_id":               buildPodID(clusterName, pod.Namespace, pod.Name),
					"uid":                  string(pod.UID),
					"name":                 pod.Name,
					"namespace":            pod.Namespace,
					"cluster_name":         clusterName,
					"node_name":            pod.Spec.NodeName,
					"service_account_name": pod.Spec.ServiceAccountName,
					"spec":                 spec,
					"status":               pod.Status,
					"labels":               pod.Labels,
					"annotations":          pod.Annotations,
				}
				rows = append(rows, row)
			}

			return rows, nil
		},
	}
}

func (e *K8sSyncEngine) k8sNamespaceTable() K8sTableSpec {
	return K8sTableSpec{
		Name: "k8s_core_namespaces",
		Columns: []string{
			"uid",
			"name",
			"cluster_name",
			"labels",
			"annotations",
			"status_phase",
			"status_conditions",
			"network_policies",
			"network_policy_count",
			"network_policies_with_selector",
			"network_policies_without_selector",
		},
		Fetch: func(ctx context.Context, client kubernetes.Interface, _ string, clusterName string) ([]map[string]interface{}, error) {
			namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			networkPolicies, err := client.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			networkPoliciesByNamespace := make(map[string][]map[string]interface{})
			networkPoliciesWithSelector := make(map[string]int)
			networkPoliciesWithoutSelector := make(map[string]int)
			for _, policy := range networkPolicies.Items {
				namespace := strings.TrimSpace(policy.Namespace)
				if namespace == "" {
					continue
				}

				hasSelector := len(policy.Spec.PodSelector.MatchLabels) > 0 || len(policy.Spec.PodSelector.MatchExpressions) > 0
				if hasSelector {
					networkPoliciesWithSelector[namespace]++
				} else {
					networkPoliciesWithoutSelector[namespace]++
				}

				networkPoliciesByNamespace[namespace] = append(networkPoliciesByNamespace[namespace], map[string]interface{}{
					"name": policy.Name,
					"spec": map[string]interface{}{
						"pod_selector": map[string]interface{}{
							"match_labels":      policy.Spec.PodSelector.MatchLabels,
							"match_expressions": policy.Spec.PodSelector.MatchExpressions,
						},
						"policy_types": policy.Spec.PolicyTypes,
						"ingress":      policy.Spec.Ingress,
						"egress":       policy.Spec.Egress,
					},
				})
			}

			for namespace := range networkPoliciesByNamespace {
				sort.Slice(networkPoliciesByNamespace[namespace], func(i, j int) bool {
					return toString(networkPoliciesByNamespace[namespace][i]["name"]) < toString(networkPoliciesByNamespace[namespace][j]["name"])
				})
			}

			clusterName = normalizeClusterName(clusterName)
			rows := make([]map[string]interface{}, 0, len(namespaces.Items))
			for _, ns := range namespaces.Items {
				networkPolicies := networkPoliciesByNamespace[ns.Name]
				row := map[string]interface{}{
					"_cq_id":                            buildClusterScopedID(clusterName, "namespace", ns.Name),
					"uid":                               string(ns.UID),
					"name":                              ns.Name,
					"cluster_name":                      clusterName,
					"labels":                            ns.Labels,
					"annotations":                       ns.Annotations,
					"status_phase":                      string(ns.Status.Phase),
					"status_conditions":                 ns.Status.Conditions,
					"network_policies":                  networkPolicies,
					"network_policy_count":              len(networkPolicies),
					"network_policies_with_selector":    networkPoliciesWithSelector[ns.Name],
					"network_policies_without_selector": networkPoliciesWithoutSelector[ns.Name],
				}
				rows = append(rows, row)
			}

			return rows, nil
		},
	}
}

func (e *K8sSyncEngine) k8sNodeTable() K8sTableSpec {
	return K8sTableSpec{
		Name: "k8s_core_nodes",
		Columns: []string{
			"uid",
			"name",
			"cluster_name",
			"labels",
			"annotations",
			"taints",
			"addresses",
			"capacity",
			"allocatable",
			"unschedulable",
			"conditions",
		},
		Fetch: func(ctx context.Context, client kubernetes.Interface, _ string, clusterName string) ([]map[string]interface{}, error) {
			nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			clusterName = normalizeClusterName(clusterName)
			rows := make([]map[string]interface{}, 0, len(nodes.Items))
			for _, node := range nodes.Items {
				row := map[string]interface{}{
					"_cq_id":        buildClusterScopedID(clusterName, "node", node.Name),
					"uid":           string(node.UID),
					"name":          node.Name,
					"cluster_name":  clusterName,
					"labels":        node.Labels,
					"annotations":   node.Annotations,
					"taints":        node.Spec.Taints,
					"addresses":     node.Status.Addresses,
					"capacity":      resourceListToMap(node.Status.Capacity),
					"allocatable":   resourceListToMap(node.Status.Allocatable),
					"unschedulable": node.Spec.Unschedulable,
					"conditions":    node.Status.Conditions,
				}
				rows = append(rows, row)
			}

			return rows, nil
		},
	}
}

func (e *K8sSyncEngine) k8sServiceTable() K8sTableSpec {
	return K8sTableSpec{
		Name: "k8s_core_services",
		Columns: []string{
			"uid",
			"name",
			"namespace",
			"cluster_name",
			"type",
			"cluster_ip",
			"external_ips",
			"load_balancer_ingress",
			"ports",
			"selector",
			"labels",
			"annotations",
		},
		Fetch: func(ctx context.Context, client kubernetes.Interface, namespace, clusterName string) ([]map[string]interface{}, error) {
			if namespace == "" {
				namespace = metav1.NamespaceAll
			}

			services, err := client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			clusterName = normalizeClusterName(clusterName)
			rows := make([]map[string]interface{}, 0, len(services.Items))
			for _, svc := range services.Items {
				row := map[string]interface{}{
					"_cq_id":                buildNamespacedID(clusterName, svc.Namespace, svc.Name),
					"uid":                   string(svc.UID),
					"name":                  svc.Name,
					"namespace":             svc.Namespace,
					"cluster_name":          clusterName,
					"type":                  string(svc.Spec.Type),
					"cluster_ip":            svc.Spec.ClusterIP,
					"external_ips":          svc.Spec.ExternalIPs,
					"load_balancer_ingress": svc.Status.LoadBalancer.Ingress,
					"ports":                 svc.Spec.Ports,
					"selector":              svc.Spec.Selector,
					"labels":                svc.Labels,
					"annotations":           svc.Annotations,
				}
				rows = append(rows, row)
			}

			return rows, nil
		},
	}
}

func (e *K8sSyncEngine) k8sServiceAccountTable() K8sTableSpec {
	return K8sTableSpec{
		Name: "k8s_core_service_accounts",
		Columns: []string{
			"uid",
			"name",
			"namespace",
			"cluster_name",
			"automount_service_account_token",
			"secrets",
			"image_pull_secrets",
			"labels",
			"annotations",
		},
		Fetch: func(ctx context.Context, client kubernetes.Interface, namespace, clusterName string) ([]map[string]interface{}, error) {
			if namespace == "" {
				namespace = metav1.NamespaceAll
			}

			serviceAccounts, err := client.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			clusterName = normalizeClusterName(clusterName)
			rows := make([]map[string]interface{}, 0, len(serviceAccounts.Items))
			for _, serviceAccount := range serviceAccounts.Items {
				row := map[string]interface{}{
					"_cq_id":                          buildNamespacedID(clusterName, serviceAccount.Namespace, serviceAccount.Name),
					"uid":                             string(serviceAccount.UID),
					"name":                            serviceAccount.Name,
					"namespace":                       serviceAccount.Namespace,
					"cluster_name":                    clusterName,
					"automount_service_account_token": boolPtrValue(serviceAccount.AutomountServiceAccountToken),
					"secrets":                         objectReferencesToNames(serviceAccount.Secrets),
					"image_pull_secrets":              localObjectReferencesToNames(serviceAccount.ImagePullSecrets),
					"labels":                          serviceAccount.Labels,
					"annotations":                     serviceAccount.Annotations,
				}
				rows = append(rows, row)
			}

			return rows, nil
		},
	}
}

func (e *K8sSyncEngine) k8sDeploymentTable() K8sTableSpec {
	return K8sTableSpec{
		Name: "k8s_apps_deployments",
		Columns: []string{
			"uid",
			"name",
			"namespace",
			"cluster_name",
			"replicas",
			"available_replicas",
			"strategy",
			"selector",
			"template",
			"labels",
			"annotations",
		},
		Fetch: func(ctx context.Context, client kubernetes.Interface, namespace, clusterName string) ([]map[string]interface{}, error) {
			if namespace == "" {
				namespace = metav1.NamespaceAll
			}

			deployments, err := client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			clusterName = normalizeClusterName(clusterName)
			rows := make([]map[string]interface{}, 0, len(deployments.Items))
			for _, deployment := range deployments.Items {
				row := map[string]interface{}{
					"_cq_id":             buildNamespacedID(clusterName, deployment.Namespace, deployment.Name),
					"uid":                string(deployment.UID),
					"name":               deployment.Name,
					"namespace":          deployment.Namespace,
					"cluster_name":       clusterName,
					"replicas":           int32Value(deployment.Spec.Replicas),
					"available_replicas": deployment.Status.AvailableReplicas,
					"selector":           deployment.Spec.Selector,
					"labels":             deployment.Labels,
					"annotations":        deployment.Annotations,
				}

				if deployment.Spec.Strategy.Type != "" {
					row["strategy"] = deployment.Spec.Strategy
				}
				if deployment.Spec.Template.Name != "" || deployment.Spec.Template.Spec.Containers != nil {
					row["template"] = serializePodTemplate(deployment.Spec.Template)
				}

				rows = append(rows, row)
			}

			return rows, nil
		},
	}
}

func (e *K8sSyncEngine) k8sIngressTable() K8sTableSpec {
	return K8sTableSpec{
		Name: "k8s_networking_ingresses",
		Columns: []string{
			"uid",
			"name",
			"namespace",
			"cluster_name",
			"ingress_class_name",
			"rules",
			"tls",
			"wildcard_host",
			"load_balancer",
			"labels",
			"annotations",
		},
		Fetch: func(ctx context.Context, client kubernetes.Interface, namespace, clusterName string) ([]map[string]interface{}, error) {
			if namespace == "" {
				namespace = metav1.NamespaceAll
			}

			ingresses, err := client.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			clusterName = normalizeClusterName(clusterName)
			rows := make([]map[string]interface{}, 0, len(ingresses.Items))
			for _, ingress := range ingresses.Items {
				wildcardHost := false
				for _, rule := range ingress.Spec.Rules {
					host := strings.TrimSpace(rule.Host)
					if host == "*" || strings.HasPrefix(host, "*.") {
						wildcardHost = true
						break
					}
				}

				row := map[string]interface{}{
					"_cq_id":             buildNamespacedID(clusterName, ingress.Namespace, ingress.Name),
					"uid":                string(ingress.UID),
					"name":               ingress.Name,
					"namespace":          ingress.Namespace,
					"cluster_name":       clusterName,
					"ingress_class_name": ptrValue(ingress.Spec.IngressClassName),
					"rules":              ingress.Spec.Rules,
					"tls":                ingress.Spec.TLS,
					"wildcard_host":      wildcardHost,
					"load_balancer":      ingress.Status.LoadBalancer,
					"labels":             ingress.Labels,
					"annotations":        ingress.Annotations,
				}
				rows = append(rows, row)
			}

			return rows, nil
		},
	}
}

func (e *K8sSyncEngine) k8sClusterRoleTable() K8sTableSpec {
	return K8sTableSpec{
		Name: "k8s_rbac_cluster_roles",
		Columns: []string{
			"uid",
			"name",
			"cluster_name",
			"rules",
			"labels",
			"annotations",
		},
		Fetch: func(ctx context.Context, client kubernetes.Interface, _ string, clusterName string) ([]map[string]interface{}, error) {
			roles, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			clusterName = normalizeClusterName(clusterName)
			rows := make([]map[string]interface{}, 0, len(roles.Items))
			for _, role := range roles.Items {
				row := map[string]interface{}{
					"_cq_id":       buildClusterScopedID(clusterName, "clusterrole", role.Name),
					"uid":          string(role.UID),
					"name":         role.Name,
					"cluster_name": clusterName,
					"rules":        serializePolicyRules(role.Rules),
					"labels":       role.Labels,
					"annotations":  role.Annotations,
				}
				rows = append(rows, row)
			}

			return rows, nil
		},
	}
}

func (e *K8sSyncEngine) k8sRoleTable() K8sTableSpec {
	return K8sTableSpec{
		Name: "k8s_rbac_roles",
		Columns: []string{
			"uid",
			"name",
			"namespace",
			"cluster_name",
			"rules",
			"labels",
			"annotations",
		},
		Fetch: func(ctx context.Context, client kubernetes.Interface, namespace, clusterName string) ([]map[string]interface{}, error) {
			if namespace == "" {
				namespace = metav1.NamespaceAll
			}

			roles, err := client.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			clusterName = normalizeClusterName(clusterName)
			rows := make([]map[string]interface{}, 0, len(roles.Items))
			for _, role := range roles.Items {
				row := map[string]interface{}{
					"_cq_id":       buildNamespacedID(clusterName, role.Namespace, role.Name),
					"uid":          string(role.UID),
					"name":         role.Name,
					"namespace":    role.Namespace,
					"cluster_name": clusterName,
					"rules":        serializePolicyRules(role.Rules),
					"labels":       role.Labels,
					"annotations":  role.Annotations,
				}
				rows = append(rows, row)
			}

			return rows, nil
		},
	}
}

func (e *K8sSyncEngine) k8sClusterRoleBindingTable() K8sTableSpec {
	return K8sTableSpec{
		Name: "k8s_rbac_cluster_role_bindings",
		Columns: []string{
			"uid",
			"name",
			"cluster_name",
			"role_ref",
			"subjects",
			"labels",
			"annotations",
		},
		Fetch: func(ctx context.Context, client kubernetes.Interface, _ string, clusterName string) ([]map[string]interface{}, error) {
			bindings, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			clusterName = normalizeClusterName(clusterName)
			rows := make([]map[string]interface{}, 0, len(bindings.Items))
			for _, binding := range bindings.Items {
				row := map[string]interface{}{
					"_cq_id":       buildClusterScopedID(clusterName, "clusterrolebinding", binding.Name),
					"uid":          string(binding.UID),
					"name":         binding.Name,
					"cluster_name": clusterName,
					"role_ref":     serializeRoleRef(binding.RoleRef),
					"subjects":     serializeSubjects(binding.Subjects),
					"labels":       binding.Labels,
					"annotations":  binding.Annotations,
				}
				rows = append(rows, row)
			}

			return rows, nil
		},
	}
}

func (e *K8sSyncEngine) k8sRoleBindingTable() K8sTableSpec {
	return K8sTableSpec{
		Name: "k8s_rbac_role_bindings",
		Columns: []string{
			"uid",
			"name",
			"namespace",
			"cluster_name",
			"role_ref",
			"subjects",
			"labels",
			"annotations",
		},
		Fetch: func(ctx context.Context, client kubernetes.Interface, namespace, clusterName string) ([]map[string]interface{}, error) {
			if namespace == "" {
				namespace = metav1.NamespaceAll
			}

			bindings, err := client.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			clusterName = normalizeClusterName(clusterName)
			rows := make([]map[string]interface{}, 0, len(bindings.Items))
			for _, binding := range bindings.Items {
				row := map[string]interface{}{
					"_cq_id":       buildNamespacedID(clusterName, binding.Namespace, binding.Name),
					"uid":          string(binding.UID),
					"name":         binding.Name,
					"namespace":    binding.Namespace,
					"cluster_name": clusterName,
					"role_ref":     serializeRoleRef(binding.RoleRef),
					"subjects":     serializeSubjects(binding.Subjects),
					"labels":       binding.Labels,
					"annotations":  binding.Annotations,
				}
				rows = append(rows, row)
			}

			return rows, nil
		},
	}
}

func (e *K8sSyncEngine) k8sServiceAccountBindingTable() K8sTableSpec {
	return K8sTableSpec{
		Name: "k8s_rbac_service_account_bindings",
		Columns: []string{
			"cluster_name",
			"binding_kind",
			"binding_name",
			"binding_namespace",
			"service_account_name",
			"service_account_namespace",
			"role_ref_kind",
			"role_ref_name",
			"role_ref_api_group",
		},
		Fetch: func(ctx context.Context, client kubernetes.Interface, namespace, clusterName string) ([]map[string]interface{}, error) {
			if namespace == "" {
				namespace = metav1.NamespaceAll
			}

			clusterName = normalizeClusterName(clusterName)
			rows := make([]map[string]interface{}, 0)

			roleBindings, err := client.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			for _, binding := range roleBindings.Items {
				subjects := serviceAccountSubjects(binding.Subjects, binding.Namespace)
				for _, subject := range subjects {
					row := map[string]interface{}{
						"_cq_id":                    buildServiceAccountBindingID(clusterName, "rolebinding", binding.Namespace, binding.Name, subject.Namespace, subject.Name),
						"cluster_name":              clusterName,
						"binding_kind":              "RoleBinding",
						"binding_name":              binding.Name,
						"binding_namespace":         binding.Namespace,
						"service_account_name":      subject.Name,
						"service_account_namespace": subject.Namespace,
						"role_ref_kind":             binding.RoleRef.Kind,
						"role_ref_name":             binding.RoleRef.Name,
						"role_ref_api_group":        binding.RoleRef.APIGroup,
					}
					rows = append(rows, row)
				}
			}

			clusterRoleBindings, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			for _, binding := range clusterRoleBindings.Items {
				subjects := serviceAccountSubjects(binding.Subjects, "")
				for _, subject := range subjects {
					row := map[string]interface{}{
						"_cq_id":                    buildServiceAccountBindingID(clusterName, "clusterrolebinding", "", binding.Name, subject.Namespace, subject.Name),
						"cluster_name":              clusterName,
						"binding_kind":              "ClusterRoleBinding",
						"binding_name":              binding.Name,
						"binding_namespace":         "",
						"service_account_name":      subject.Name,
						"service_account_namespace": subject.Namespace,
						"role_ref_kind":             binding.RoleRef.Kind,
						"role_ref_name":             binding.RoleRef.Name,
						"role_ref_api_group":        binding.RoleRef.APIGroup,
					}
					rows = append(rows, row)
				}
			}

			return rows, nil
		},
	}
}

func (e *K8sSyncEngine) k8sRBACRiskyBindingTable() K8sTableSpec {
	return K8sTableSpec{
		Name: "k8s_rbac_risky_bindings",
		Columns: []string{
			"cluster_name",
			"binding_kind",
			"binding_name",
			"binding_namespace",
			"role_ref_kind",
			"role_ref_name",
			"subject_kind",
			"subject_name",
			"subject_namespace",
			"risk_level",
			"risk_reasons",
			"wildcard_verbs",
			"wildcard_resources",
		},
		Fetch: func(ctx context.Context, client kubernetes.Interface, namespace, clusterName string) ([]map[string]interface{}, error) {
			if namespace == "" {
				namespace = metav1.NamespaceAll
			}

			roles, err := client.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			clusterRoles, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			roleBindings, err := client.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			clusterRoleBindings, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			clusterName = normalizeClusterName(clusterName)

			roleRules := make(map[string][]rbacv1.PolicyRule, len(roles.Items))
			for _, role := range roles.Items {
				roleRules[k8sRoleRulesKey(role.Namespace, role.Name)] = role.Rules
			}

			clusterRoleRules := make(map[string][]rbacv1.PolicyRule, len(clusterRoles.Items))
			for _, role := range clusterRoles.Items {
				clusterRoleRules[strings.TrimSpace(role.Name)] = role.Rules
			}

			resolveRules := func(bindingNamespace string, roleRef rbacv1.RoleRef) []rbacv1.PolicyRule {
				roleName := strings.TrimSpace(roleRef.Name)
				if roleName == "" {
					return nil
				}

				switch strings.ToLower(strings.TrimSpace(roleRef.Kind)) {
				case "clusterrole":
					return clusterRoleRules[roleName]
				case "role":
					return roleRules[k8sRoleRulesKey(bindingNamespace, roleName)]
				default:
					return nil
				}
			}

			rows := make([]map[string]interface{}, 0)
			appendRows := func(bindingKind, bindingNamespace, bindingName string, roleRef rbacv1.RoleRef, subjects []rbacv1.Subject) {
				riskLevel, reasons, wildcardVerbs, wildcardResources := evaluateK8sRBACRisk(resolveRules(bindingNamespace, roleRef))
				if riskLevel == "low" {
					return
				}

				for _, subject := range subjects {
					subjectName := strings.TrimSpace(subject.Name)
					if subjectName == "" {
						continue
					}

					subjectKind := normalizeK8sSubjectKind(subject.Kind)
					subjectNamespace := strings.TrimSpace(subject.Namespace)
					if subjectKind == "ServiceAccount" && subjectNamespace == "" {
						subjectNamespace = strings.TrimSpace(bindingNamespace)
					}

					row := map[string]interface{}{
						"_cq_id":             buildK8sRBACRiskBindingID(clusterName, bindingKind, bindingNamespace, bindingName, subjectKind, subjectNamespace, subjectName),
						"cluster_name":       clusterName,
						"binding_kind":       bindingKind,
						"binding_name":       bindingName,
						"binding_namespace":  bindingNamespace,
						"role_ref_kind":      strings.TrimSpace(roleRef.Kind),
						"role_ref_name":      strings.TrimSpace(roleRef.Name),
						"subject_kind":       subjectKind,
						"subject_name":       subjectName,
						"subject_namespace":  subjectNamespace,
						"risk_level":         riskLevel,
						"risk_reasons":       reasons,
						"wildcard_verbs":     wildcardVerbs,
						"wildcard_resources": wildcardResources,
					}
					rows = append(rows, row)
				}
			}

			for _, binding := range roleBindings.Items {
				appendRows("RoleBinding", binding.Namespace, binding.Name, binding.RoleRef, binding.Subjects)
			}

			for _, binding := range clusterRoleBindings.Items {
				appendRows("ClusterRoleBinding", "", binding.Name, binding.RoleRef, binding.Subjects)
			}

			sort.Slice(rows, func(i, j int) bool {
				return toString(rows[i]["_cq_id"]) < toString(rows[j]["_cq_id"])
			})

			return rows, nil
		},
	}
}

func (e *K8sSyncEngine) k8sAuditEventTable() K8sTableSpec {
	return K8sTableSpec{
		Name: "k8s_audit_events",
		Columns: []string{
			"uid",
			"name",
			"namespace",
			"cluster_name",
			"reason",
			"message",
			"type",
			"action",
			"verb",
			"resource",
			"event_time",
			"first_timestamp",
			"last_timestamp",
			"count",
			"involved_object",
			"source",
			"reporting_component",
			"reporting_instance",
			"related",
			"series",
			"annotations",
			"labels",
		},
		Fetch: func(ctx context.Context, client kubernetes.Interface, namespace, clusterName string) ([]map[string]interface{}, error) {
			if namespace == "" {
				namespace = metav1.NamespaceAll
			}

			events, err := client.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			clusterName = normalizeClusterName(clusterName)
			rows := make([]map[string]interface{}, 0, len(events.Items))
			for _, event := range events.Items {
				verb := strings.ToLower(event.Action)
				resource := strings.ToLower(event.InvolvedObject.Kind)
				row := map[string]interface{}{
					"_cq_id":              buildNamespacedID(clusterName, event.Namespace, event.Name),
					"uid":                 string(event.UID),
					"name":                event.Name,
					"namespace":           event.Namespace,
					"cluster_name":        clusterName,
					"reason":              event.Reason,
					"message":             event.Message,
					"type":                event.Type,
					"action":              event.Action,
					"verb":                verb,
					"resource":            resource,
					"event_time":          event.EventTime,
					"first_timestamp":     event.FirstTimestamp,
					"last_timestamp":      event.LastTimestamp,
					"count":               event.Count,
					"involved_object":     serializeObjectReference(event.InvolvedObject),
					"source":              serializeEventSource(event.Source),
					"reporting_component": event.ReportingController,
					"reporting_instance":  event.ReportingInstance,
					"related":             serializeObjectReferencePtr(event.Related),
					"series":              serializeEventSeries(event.Series),
					"annotations":         event.Annotations,
					"labels":              event.Labels,
				}
				rows = append(rows, row)
			}

			return rows, nil
		},
	}
}

func buildPodID(clusterName, namespace, name string) string {
	clusterName = normalizeClusterName(clusterName)
	parts := []string{clusterName}
	if namespace != "" {
		parts = append(parts, namespace)
	}
	if name != "" {
		parts = append(parts, name)
	}
	return strings.Join(parts, "/")
}

func buildClusterScopedID(clusterName, resourceType, name string) string {
	clusterName = normalizeClusterName(clusterName)
	parts := []string{clusterName}
	if resourceType != "" {
		parts = append(parts, resourceType)
	}
	if name != "" {
		parts = append(parts, name)
	}
	return strings.Join(parts, "/")
}

func buildNamespacedID(clusterName, namespace, name string) string {
	clusterName = normalizeClusterName(clusterName)
	parts := []string{clusterName}
	if namespace != "" {
		parts = append(parts, namespace)
	}
	if name != "" {
		parts = append(parts, name)
	}
	return strings.Join(parts, "/")
}

func buildServiceAccountBindingID(clusterName, bindingType, bindingNamespace, bindingName, subjectNamespace, subjectName string) string {
	clusterName = normalizeClusterName(clusterName)
	parts := []string{clusterName}
	if bindingType != "" {
		parts = append(parts, strings.ToLower(bindingType))
	}
	if bindingNamespace != "" {
		parts = append(parts, bindingNamespace)
	}
	if bindingName != "" {
		parts = append(parts, bindingName)
	}
	if subjectNamespace != "" {
		parts = append(parts, subjectNamespace)
	}
	if subjectName != "" {
		parts = append(parts, subjectName)
	}
	return strings.Join(parts, "/")
}

func buildK8sRBACRiskBindingID(clusterName, bindingKind, bindingNamespace, bindingName, subjectKind, subjectNamespace, subjectName string) string {
	clusterName = normalizeClusterName(clusterName)
	parts := []string{clusterName, "rbac-risk"}
	if bindingKind != "" {
		parts = append(parts, strings.ToLower(strings.TrimSpace(bindingKind)))
	}
	if bindingNamespace != "" {
		parts = append(parts, strings.TrimSpace(bindingNamespace))
	}
	if bindingName != "" {
		parts = append(parts, strings.TrimSpace(bindingName))
	}
	if subjectKind != "" {
		parts = append(parts, strings.ToLower(strings.TrimSpace(subjectKind)))
	}
	if subjectNamespace != "" {
		parts = append(parts, strings.TrimSpace(subjectNamespace))
	}
	if subjectName != "" {
		parts = append(parts, strings.TrimSpace(subjectName))
	}
	return strings.Join(parts, "/")
}

func k8sRoleRulesKey(namespace, roleName string) string {
	return strings.TrimSpace(namespace) + "/" + strings.TrimSpace(roleName)
}

func normalizeK8sSubjectKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "serviceaccount":
		return "ServiceAccount"
	case "user":
		return "User"
	case "group":
		return "Group"
	default:
		return strings.TrimSpace(kind)
	}
}

func evaluateK8sRBACRisk(rules []rbacv1.PolicyRule) (string, []string, bool, bool) {
	if len(rules) == 0 {
		return "low", nil, false, false
	}

	wildcardVerbs := false
	wildcardResources := false
	hasEscalationVerb := false
	hasRBACWrite := false
	hasSecretAccess := false
	hasPodExec := false
	hasPodCreate := false

	for _, rule := range rules {
		if containsAnyFold(rule.Verbs, "*") {
			wildcardVerbs = true
		}
		if containsAnyFold(rule.Resources, "*") || containsAnyFold(rule.NonResourceURLs, "*") {
			wildcardResources = true
		}
		if containsAnyFold(rule.Verbs, "bind", "escalate", "impersonate") {
			hasEscalationVerb = true
		}
		if containsAnyFold(rule.Resources, "roles", "clusterroles", "rolebindings", "clusterrolebindings") &&
			containsAnyFold(rule.Verbs, "create", "update", "patch", "delete", "bind", "escalate", "*") {
			hasRBACWrite = true
		}
		if containsAnyFold(rule.Resources, "secrets", "serviceaccounts/token") &&
			containsAnyFold(rule.Verbs, "get", "list", "watch", "create", "update", "patch", "delete", "*") {
			hasSecretAccess = true
		}
		if containsAnyFold(rule.Resources, "pods/exec", "pods/attach", "pods/portforward") &&
			containsAnyFold(rule.Verbs, "create", "get", "*") {
			hasPodExec = true
		}
		if containsAnyFold(rule.Resources, "pods") &&
			containsAnyFold(rule.Verbs, "create", "*") {
			hasPodCreate = true
		}
	}

	riskLevel := "low"
	if hasEscalationVerb || hasRBACWrite || (wildcardVerbs && wildcardResources) {
		riskLevel = "high"
	} else if wildcardVerbs || wildcardResources || hasSecretAccess || hasPodExec || hasPodCreate {
		riskLevel = "medium"
	}

	if riskLevel == "low" {
		return "low", nil, wildcardVerbs, wildcardResources
	}

	reasons := make([]string, 0, 7)
	if wildcardVerbs {
		reasons = append(reasons, "wildcard_verbs")
	}
	if wildcardResources {
		reasons = append(reasons, "wildcard_resources")
	}
	if hasEscalationVerb {
		reasons = append(reasons, "privilege_escalation_verbs")
	}
	if hasRBACWrite {
		reasons = append(reasons, "rbac_write_access")
	}
	if hasSecretAccess {
		reasons = append(reasons, "secret_access")
	}
	if hasPodExec {
		reasons = append(reasons, "pod_exec_access")
	}
	if hasPodCreate {
		reasons = append(reasons, "pod_create_access")
	}
	sort.Strings(reasons)

	return riskLevel, reasons, wildcardVerbs, wildcardResources
}

func containsAnyFold(values []string, targets ...string) bool {
	if len(values) == 0 || len(targets) == 0 {
		return false
	}

	for _, value := range values {
		for _, target := range targets {
			if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(target)) {
				return true
			}
		}
	}

	return false
}

func podSpecToMap(spec corev1.PodSpec) map[string]interface{} {
	analysisContainers := make([]corev1.Container, 0, len(spec.Containers)+len(spec.InitContainers))
	analysisContainers = append(analysisContainers, spec.Containers...)
	analysisContainers = append(analysisContainers, spec.InitContainers...)

	allowsPrivilegeEscalation := false
	usesLatestImageTag := false
	allImagesPinnedByDigest := len(analysisContainers) > 0
	allContainersHaveLivenessProbe := len(analysisContainers) > 0
	allContainersHaveReadinessProbe := len(analysisContainers) > 0
	allContainersRuntimeDefaultSeccomp := len(analysisContainers) > 0

	podSeccompType := ""
	if spec.SecurityContext != nil && spec.SecurityContext.SeccompProfile != nil {
		podSeccompType = string(spec.SecurityContext.SeccompProfile.Type)
	}

	for _, container := range analysisContainers {
		if imageUsesLatestTag(container.Image) {
			usesLatestImageTag = true
		}
		if !imagePinnedByDigest(container.Image) {
			allImagesPinnedByDigest = false
		}
		if container.LivenessProbe == nil {
			allContainersHaveLivenessProbe = false
		}
		if container.ReadinessProbe == nil {
			allContainersHaveReadinessProbe = false
		}
		if containerAllowsPrivilegeEscalation(container.SecurityContext) {
			allowsPrivilegeEscalation = true
		}

		effectiveSeccompType := podSeccompType
		if container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil {
			effectiveSeccompType = string(container.SecurityContext.SeccompProfile.Type)
		}
		if !strings.EqualFold(effectiveSeccompType, string(corev1.SeccompProfileTypeRuntimeDefault)) {
			allContainersRuntimeDefaultSeccomp = false
		}
	}

	usesHostPathVolume := false
	for _, volume := range spec.Volumes {
		if volume.HostPath != nil {
			usesHostPathVolume = true
			break
		}
	}

	containers := make([]map[string]interface{}, 0, len(spec.Containers))
	for _, container := range spec.Containers {
		entry := map[string]interface{}{
			"name":  container.Name,
			"image": container.Image,
		}

		if resources := resourcesToMap(container.Resources); resources != nil {
			entry["resources"] = resources
		}
		if security := containerSecurityContextToMap(container.SecurityContext); security != nil {
			entry["security_context"] = security
		}
		if env := envVarsToMap(container.Env); env != nil {
			entry["env"] = env
		}

		containers = append(containers, entry)
	}

	specMap := map[string]interface{}{
		"containers":                             containers,
		"host_network":                           spec.HostNetwork,
		"host_pid":                               spec.HostPID,
		"host_ipc":                               spec.HostIPC,
		"service_account_name":                   spec.ServiceAccountName,
		"automount_service_account_token":        boolPtrValue(spec.AutomountServiceAccountToken),
		"uses_host_path_volume":                  usesHostPathVolume,
		"allows_privilege_escalation":            allowsPrivilegeEscalation,
		"uses_latest_image_tag":                  usesLatestImageTag,
		"all_images_pinned_by_digest":            allImagesPinnedByDigest,
		"all_containers_have_liveness_probe":     allContainersHaveLivenessProbe,
		"all_containers_have_readiness_probe":    allContainersHaveReadinessProbe,
		"all_containers_runtime_default_seccomp": allContainersRuntimeDefaultSeccomp,
	}

	if security := podSecurityContextToMap(spec.SecurityContext); security != nil {
		specMap["security_context"] = security
	}

	return specMap
}

func serializePodTemplate(template corev1.PodTemplateSpec) map[string]interface{} {
	result := map[string]interface{}{
		"labels":      template.Labels,
		"annotations": template.Annotations,
	}
	if spec := podSpecToMap(template.Spec); spec != nil {
		result["spec"] = spec
	}
	return result
}

func resourcesToMap(resources corev1.ResourceRequirements) map[string]interface{} {
	limits := resourceListToMap(resources.Limits)
	requests := resourceListToMap(resources.Requests)
	if limits == nil && requests == nil {
		return nil
	}

	result := make(map[string]interface{})
	if limits != nil {
		result["limits"] = limits
	}
	if requests != nil {
		result["requests"] = requests
	}
	return result
}

func resourceListToMap(list corev1.ResourceList) map[string]interface{} {
	if len(list) == 0 {
		return nil
	}
	result := make(map[string]interface{}, len(list))
	for name, quantity := range list {
		result[strings.ToLower(string(name))] = quantity.String()
	}
	return result
}

func serializePolicyRules(rules []rbacv1.PolicyRule) []map[string]interface{} {
	if len(rules) == 0 {
		return nil
	}
	result := make([]map[string]interface{}, 0, len(rules))
	for _, rule := range rules {
		entry := map[string]interface{}{
			"verbs":             rule.Verbs,
			"api_groups":        rule.APIGroups,
			"resources":         rule.Resources,
			"resource_names":    rule.ResourceNames,
			"non_resource_urls": rule.NonResourceURLs,
		}
		result = append(result, entry)
	}
	return result
}

func serializeRoleRef(ref rbacv1.RoleRef) map[string]interface{} {
	return map[string]interface{}{
		"api_group": ref.APIGroup,
		"kind":      ref.Kind,
		"name":      ref.Name,
	}
}

func serializeSubjects(subjects []rbacv1.Subject) []map[string]interface{} {
	if len(subjects) == 0 {
		return nil
	}
	result := make([]map[string]interface{}, 0, len(subjects))
	for _, subject := range subjects {
		result = append(result, map[string]interface{}{
			"api_group": subject.APIGroup,
			"kind":      subject.Kind,
			"name":      subject.Name,
			"namespace": subject.Namespace,
		})
	}
	return result
}

func serviceAccountSubjects(subjects []rbacv1.Subject, defaultNamespace string) []rbacv1.Subject {
	if len(subjects) == 0 {
		return nil
	}
	result := make([]rbacv1.Subject, 0, len(subjects))
	for _, subject := range subjects {
		if !strings.EqualFold(subject.Kind, "ServiceAccount") {
			continue
		}
		namespace := strings.TrimSpace(subject.Namespace)
		if namespace == "" {
			namespace = strings.TrimSpace(defaultNamespace)
		}
		name := strings.TrimSpace(subject.Name)
		if namespace == "" || name == "" {
			continue
		}
		result = append(result, rbacv1.Subject{
			Kind:      "ServiceAccount",
			Name:      name,
			Namespace: namespace,
			APIGroup:  subject.APIGroup,
		})
	}
	if len(result) == 0 {
		return nil
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Namespace == result[j].Namespace {
			return result[i].Name < result[j].Name
		}
		return result[i].Namespace < result[j].Namespace
	})
	return result
}

func objectReferencesToNames(refs []corev1.ObjectReference) []string {
	if len(refs) == 0 {
		return nil
	}
	result := make([]string, 0, len(refs))
	for _, ref := range refs {
		name := strings.TrimSpace(ref.Name)
		if name == "" {
			continue
		}
		result = append(result, name)
	}
	if len(result) == 0 {
		return nil
	}
	sort.Strings(result)
	return result
}

func localObjectReferencesToNames(refs []corev1.LocalObjectReference) []string {
	if len(refs) == 0 {
		return nil
	}
	result := make([]string, 0, len(refs))
	for _, ref := range refs {
		name := strings.TrimSpace(ref.Name)
		if name == "" {
			continue
		}
		result = append(result, name)
	}
	if len(result) == 0 {
		return nil
	}
	sort.Strings(result)
	return result
}

func serializeObjectReference(ref corev1.ObjectReference) map[string]interface{} {
	return map[string]interface{}{
		"api_version":      ref.APIVersion,
		"kind":             ref.Kind,
		"namespace":        ref.Namespace,
		"name":             ref.Name,
		"uid":              string(ref.UID),
		"resource_version": ref.ResourceVersion,
		"field_path":       ref.FieldPath,
	}
}

func serializeObjectReferencePtr(ref *corev1.ObjectReference) map[string]interface{} {
	if ref == nil {
		return nil
	}
	return serializeObjectReference(*ref)
}

func serializeEventSource(source corev1.EventSource) map[string]interface{} {
	if source.Component == "" && source.Host == "" {
		return nil
	}
	return map[string]interface{}{
		"component": source.Component,
		"host":      source.Host,
	}
}

func serializeEventSeries(series *corev1.EventSeries) map[string]interface{} {
	if series == nil {
		return nil
	}
	return map[string]interface{}{
		"count":              series.Count,
		"last_observed_time": series.LastObservedTime,
	}
}

func ptrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func int32Value(value *int32) int32 {
	if value == nil {
		return 0
	}
	return *value
}

func podSecurityContextToMap(ctx *corev1.PodSecurityContext) map[string]interface{} {
	if ctx == nil {
		return nil
	}
	result := make(map[string]interface{})
	if ctx.RunAsNonRoot != nil {
		result["run_as_non_root"] = *ctx.RunAsNonRoot
	}
	if ctx.RunAsUser != nil {
		result["run_as_user"] = *ctx.RunAsUser
	}
	if ctx.SeccompProfile != nil {
		result["seccomp_profile_type"] = string(ctx.SeccompProfile.Type)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func containerSecurityContextToMap(ctx *corev1.SecurityContext) map[string]interface{} {
	if ctx == nil {
		return nil
	}
	result := make(map[string]interface{})
	if ctx.Privileged != nil {
		result["privileged"] = *ctx.Privileged
	}
	if ctx.ReadOnlyRootFilesystem != nil {
		result["read_only_root_filesystem"] = *ctx.ReadOnlyRootFilesystem
	}
	if ctx.RunAsUser != nil {
		result["run_as_user"] = *ctx.RunAsUser
	}
	if ctx.AllowPrivilegeEscalation != nil {
		result["allow_privilege_escalation"] = *ctx.AllowPrivilegeEscalation
	}
	if ctx.SeccompProfile != nil {
		result["seccomp_profile_type"] = string(ctx.SeccompProfile.Type)
	}
	if ctx.Capabilities != nil {
		result["capabilities"] = capabilitiesToMap(ctx.Capabilities)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func capabilitiesToMap(capabilities *corev1.Capabilities) map[string]interface{} {
	if capabilities == nil {
		return nil
	}
	drops := capabilitiesToString(capabilities.Drop)
	return map[string]interface{}{
		"drop": drops,
	}
}

func capabilitiesToString(caps []corev1.Capability) string {
	if len(caps) == 0 {
		return ""
	}
	values := make([]string, 0, len(caps))
	for _, cap := range caps {
		values = append(values, string(cap))
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func envVarsToMap(env []corev1.EnvVar) []map[string]interface{} {
	if len(env) == 0 {
		return nil
	}
	result := make([]map[string]interface{}, 0, len(env))
	for _, item := range env {
		entry := map[string]interface{}{
			"name": item.Name,
		}
		if item.ValueFrom != nil {
			entry["value_from"] = envVarSourceToMap(item.ValueFrom)
		} else {
			entry["value_from"] = nil
		}
		result = append(result, entry)
	}
	return result
}

func envVarSourceToMap(source *corev1.EnvVarSource) map[string]interface{} {
	if source == nil {
		return nil
	}
	result := make(map[string]interface{})
	if source.SecretKeyRef != nil {
		result["secret_key_ref"] = secretKeyRefToMap(source.SecretKeyRef)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func secretKeyRefToMap(ref *corev1.SecretKeySelector) map[string]interface{} {
	if ref == nil {
		return nil
	}
	entry := map[string]interface{}{
		"name": ref.Name,
		"key":  ref.Key,
	}
	if ref.Optional != nil {
		entry["optional"] = *ref.Optional
	}
	return entry
}

func boolPtrValue(value *bool) interface{} {
	if value == nil {
		return nil
	}
	return *value
}

func containerAllowsPrivilegeEscalation(ctx *corev1.SecurityContext) bool {
	if ctx == nil || ctx.AllowPrivilegeEscalation == nil {
		return true
	}
	return *ctx.AllowPrivilegeEscalation
}

func imageUsesLatestTag(image string) bool {
	image = strings.TrimSpace(image)
	if image == "" {
		return false
	}
	if strings.Contains(image, "@") {
		return false
	}

	withoutDigest := image
	if digestIndex := strings.Index(withoutDigest, "@"); digestIndex >= 0 {
		withoutDigest = withoutDigest[:digestIndex]
	}

	tag := ""
	lastColon := strings.LastIndex(withoutDigest, ":")
	lastSlash := strings.LastIndex(withoutDigest, "/")
	if lastColon > lastSlash {
		tag = withoutDigest[lastColon+1:]
	}

	if tag == "" {
		return true
	}

	return strings.EqualFold(tag, "latest")
}

func imagePinnedByDigest(image string) bool {
	image = strings.TrimSpace(image)
	if image == "" {
		return false
	}
	return strings.Contains(strings.ToLower(image), "@sha256:")
}
