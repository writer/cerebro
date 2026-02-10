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
		e.k8sPodTable(),
		e.k8sNamespaceTable(),
		e.k8sNodeTable(),
		e.k8sServiceTable(),
		e.k8sDeploymentTable(),
		e.k8sIngressTable(),
		e.k8sClusterRoleTable(),
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
		},
		Fetch: func(ctx context.Context, client kubernetes.Interface, _ string, clusterName string) ([]map[string]interface{}, error) {
			namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			clusterName = normalizeClusterName(clusterName)
			rows := make([]map[string]interface{}, 0, len(namespaces.Items))
			for _, ns := range namespaces.Items {
				row := map[string]interface{}{
					"_cq_id":            buildClusterScopedID(clusterName, "namespace", ns.Name),
					"uid":               string(ns.UID),
					"name":              ns.Name,
					"cluster_name":      clusterName,
					"labels":            ns.Labels,
					"annotations":       ns.Annotations,
					"status_phase":      string(ns.Status.Phase),
					"status_conditions": ns.Status.Conditions,
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
				row := map[string]interface{}{
					"_cq_id":             buildNamespacedID(clusterName, ingress.Namespace, ingress.Name),
					"uid":                string(ingress.UID),
					"name":               ingress.Name,
					"namespace":          ingress.Namespace,
					"cluster_name":       clusterName,
					"ingress_class_name": ptrValue(ingress.Spec.IngressClassName),
					"rules":              ingress.Spec.Rules,
					"tls":                ingress.Spec.TLS,
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

func podSpecToMap(spec corev1.PodSpec) map[string]interface{} {
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
		"containers":                      containers,
		"host_network":                    spec.HostNetwork,
		"host_pid":                        spec.HostPID,
		"host_ipc":                        spec.HostIPC,
		"service_account_name":            spec.ServiceAccountName,
		"automount_service_account_token": boolPtrValue(spec.AutomountServiceAccountToken),
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
