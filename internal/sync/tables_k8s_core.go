package sync

import (
	"context"
	"sort"
	"strings"

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
