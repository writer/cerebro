package kubernetesinternal

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *Source) discoverPods(ctx context.Context, st settings) ([]sourcecdk.URN, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return nil, err
	}
	items, _, err := listPods(ctx, client, st.perPage, "")
	if err != nil {
		return nil, err
	}
	urns := make([]string, 0, len(items))
	for _, item := range items {
		urns = append(urns, workloadURN(st, string(item.UID), item.Namespace, item.Name))
	}
	return parseURNs(urns...)
}

func (s *Source) discoverServices(ctx context.Context, st settings) ([]sourcecdk.URN, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return nil, err
	}
	items, _, err := listServices(ctx, client, st.perPage, "")
	if err != nil {
		return nil, err
	}
	urns := make([]string, 0, len(items))
	for _, item := range items {
		urns = append(urns, serviceURN(st, item.Namespace, item.Name))
	}
	return parseURNs(urns...)
}

func (s *Source) discoverServiceAccounts(ctx context.Context, st settings) ([]sourcecdk.URN, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return nil, err
	}
	items, _, err := listServiceAccounts(ctx, client, st.perPage, "")
	if err != nil {
		return nil, err
	}
	urns := make([]string, 0, len(items))
	for _, item := range items {
		urns = append(urns, serviceAccountURN(st, item.Namespace, item.Name))
	}
	return parseURNs(urns...)
}

func (s *Source) readPods(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.readPodLike(ctx, st, cursor, "kubernetes.pod", "kubernetes/pod/v1")
}

func (s *Source) readWorkloads(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.readPodLike(ctx, st, cursor, "kubernetes.workload", "kubernetes/workload/v1")
}

func (s *Source) readPodLike(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor, kind string, schemaRef string) (sourcecdk.Pull, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	items, next, err := listPods(ctx, client, st.perPage, cursor.GetOpaque())
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	events := make([]*primitives.Event, 0, len(items))
	for _, pod := range items {
		payload := podPayload(pod)
		attrs := podAttributes(st, pod)
		id := "kubernetes-pod-" + firstNonEmpty(string(pod.UID), stableID(pod.Namespace+"/"+pod.Name))
		event, err := s.event(st, id, kind, schemaRef, payload, attrs, objectTime(pod.CreationTimestamp, s.now()))
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	return pullWithCursor(events, next), nil
}

func (s *Source) readServices(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	items, next, err := listServices(ctx, client, st.perPage, cursor.GetOpaque())
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	events := make([]*primitives.Event, 0, len(items))
	for _, item := range items {
		payload := servicePayload(item)
		attrs := serviceAttributes(st, item)
		id := "kubernetes-service-" + stableID(st.clusterIdentity()+"/"+item.Namespace+"/"+item.Name)
		event, err := s.event(st, id, "kubernetes.service", "kubernetes/service/v1", payload, attrs, objectTime(item.CreationTimestamp, s.now()))
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	return pullWithCursor(events, next), nil
}

func (s *Source) readContainers(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	pods, next, err := listPods(ctx, client, st.perPage, cursor.GetOpaque())
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	events := []*primitives.Event{}
	for _, pod := range pods {
		statuses := containerStatusesByName(pod)
		for _, container := range pod.Spec.Containers {
			status := statuses[container.Name]
			payload := containerPayload(pod, container, status)
			attrs := containerAttributes(st, pod, container, status)
			id := "kubernetes-container-" + stableID(firstNonEmpty(string(pod.UID), pod.Namespace+"/"+pod.Name)+"/"+container.Name)
			event, err := s.event(st, id, "kubernetes.container", "kubernetes/container/v1", payload, attrs, objectTime(pod.CreationTimestamp, s.now()))
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			events = append(events, event)
		}
	}
	return pullWithCursor(events, next), nil
}

func (s *Source) readServiceAccounts(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	items, next, err := listServiceAccounts(ctx, client, st.perPage, cursor.GetOpaque())
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	events := make([]*primitives.Event, 0, len(items))
	for _, item := range items {
		payload := serviceAccountPayload(item)
		attrs := serviceAccountAttributes(st, item)
		id := "kubernetes-service-account-" + stableID(st.clusterIdentity()+"/"+item.Namespace+"/"+item.Name)
		event, err := s.event(st, id, "kubernetes.service_account", "kubernetes/service_account/v1", payload, attrs, objectTime(item.CreationTimestamp, s.now()))
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	return pullWithCursor(events, next), nil
}

func (s *Source) readWorkloadIdentityBindings(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	items, next, err := listServiceAccounts(ctx, client, st.perPage, cursor.GetOpaque())
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	events := []*primitives.Event{}
	for _, item := range items {
		for _, binding := range workloadIdentityBindings(st, item) {
			id := "kubernetes-workload-identity-binding-" + stableID(st.clusterIdentity()+"/"+item.Namespace+"/"+item.Name+"/"+binding["cloud_provider"]+"/"+binding["target_id"])
			event, err := s.event(st, id, "kubernetes.workload_identity_binding", "kubernetes/workload_identity_binding/v1", binding, binding, objectTime(item.CreationTimestamp, s.now()))
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			events = append(events, event)
		}
	}
	return pullWithCursor(events, next), nil
}

func listPods(ctx context.Context, client clientset, limit int64, cursor string) ([]v1.Pod, string, error) {
	out, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{Limit: limit, Continue: strings.TrimSpace(cursor)})
	if err != nil {
		return nil, "", fmt.Errorf("list kubernetes pods: %w", err)
	}
	return out.Items, out.Continue, nil
}

func listServices(ctx context.Context, client clientset, limit int64, cursor string) ([]v1.Service, string, error) {
	out, err := client.CoreV1().Services("").List(ctx, metav1.ListOptions{Limit: limit, Continue: strings.TrimSpace(cursor)})
	if err != nil {
		return nil, "", fmt.Errorf("list kubernetes services: %w", err)
	}
	return out.Items, out.Continue, nil
}

func listServiceAccounts(ctx context.Context, client clientset, limit int64, cursor string) ([]v1.ServiceAccount, string, error) {
	out, err := client.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{Limit: limit, Continue: strings.TrimSpace(cursor)})
	if err != nil {
		return nil, "", fmt.Errorf("list kubernetes service accounts: %w", err)
	}
	return out.Items, out.Continue, nil
}

func podAttributes(st settings, pod v1.Pod) map[string]string {
	attrs := resourceAttributes(st, "pod", string(pod.UID), pod.Name, pod.Namespace)
	attrs["uid"] = string(pod.UID)
	attrs["workload_uid"] = string(pod.UID)
	attrs["workload_kind"] = "Pod"
	attrs["workload_name"] = pod.Name
	attrs["service_account_name"] = firstNonEmpty(pod.Spec.ServiceAccountName, "default")
	attrs["node_name"] = pod.Spec.NodeName
	attrs["host_network"] = boolString(pod.Spec.HostNetwork)
	attrs["host_pid"] = boolString(pod.Spec.HostPID)
	attrs["host_ipc"] = boolString(pod.Spec.HostIPC)
	attrs["image"] = strings.Join(podImages(pod), ",")
	attrs["image_digest"] = strings.Join(podImageDigests(pod), ",")
	return attrs
}

func containerAttributes(st settings, pod v1.Pod, container v1.Container, status *v1.ContainerStatus) map[string]string {
	attrs := podAttributes(st, pod)
	attrs["resource_type"] = "container"
	attrs["container_name"] = container.Name
	attrs["image"] = container.Image
	attrs["image_pull_policy"] = string(container.ImagePullPolicy)
	if status != nil {
		attrs["status_ready"] = boolString(status.Ready)
		attrs["status_started"] = boolString(status.Started != nil && *status.Started)
		attrs["status_image_id"] = status.ImageID
		attrs["image_digest"] = imageDigest(status.ImageID)
		attrs["status_state"] = containerState(status.State)
	}
	if container.SecurityContext != nil {
		if container.SecurityContext.AllowPrivilegeEscalation != nil {
			attrs["allow_privilege_escalation"] = boolString(*container.SecurityContext.AllowPrivilegeEscalation)
		}
		if container.SecurityContext.RunAsNonRoot != nil {
			attrs["run_as_non_root"] = boolString(*container.SecurityContext.RunAsNonRoot)
		}
		if container.SecurityContext.RunAsUser != nil {
			attrs["run_as_user"] = strconv.FormatInt(*container.SecurityContext.RunAsUser, 10)
		}
		if container.SecurityContext.Privileged != nil {
			attrs["privileged"] = boolString(*container.SecurityContext.Privileged)
		}
	}
	return attrs
}

func serviceAttributes(st settings, service v1.Service) map[string]string {
	attrs := resourceAttributes(st, "service", firstNonEmpty(string(service.UID), service.Namespace+"/"+service.Name), service.Name, service.Namespace)
	attrs["uid"] = string(service.UID)
	attrs["service_name"] = service.Name
	attrs["service_type"] = string(service.Spec.Type)
	add(attrs, "cluster_ip", service.Spec.ClusterIP)
	add(attrs, "cluster_ips", strings.Join(service.Spec.ClusterIPs, ","))
	add(attrs, "external_name", service.Spec.ExternalName)
	add(attrs, "external_ips", strings.Join(service.Spec.ExternalIPs, ","))
	add(attrs, "load_balancer_ips", strings.Join(serviceLoadBalancerIPs(service), ","))
	add(attrs, "load_balancer_hostnames", strings.Join(serviceLoadBalancerHostnames(service), ","))
	add(attrs, "ports", jsonAttribute(servicePortSummaries(service.Spec.Ports)))
	add(attrs, "selector", jsonAttribute(service.Spec.Selector))
	return attrs
}

func serviceAccountAttributes(st settings, account v1.ServiceAccount) map[string]string {
	attrs := resourceAttributes(st, "service_account", firstNonEmpty(string(account.UID), account.Namespace+"/"+account.Name), account.Name, account.Namespace)
	attrs["service_account_name"] = account.Name
	attrs["uid"] = string(account.UID)
	if account.AutomountServiceAccountToken != nil {
		attrs["automount_token"] = boolString(*account.AutomountServiceAccountToken)
	}
	if role := strings.TrimSpace(account.Annotations["eks.amazonaws.com/role-arn"]); role != "" {
		attrs["aws_role_arn"] = role
	}
	if email := strings.TrimSpace(account.Annotations["iam.gke.io/gcp-service-account"]); email != "" {
		attrs["gcp_service_account"] = email
	}
	return attrs
}

func podPayload(pod v1.Pod) map[string]any {
	return map[string]any{
		"uid":                             string(pod.UID),
		"name":                            pod.Name,
		"namespace":                       pod.Namespace,
		"workload_uid":                    string(pod.UID),
		"workload_kind":                   "Pod",
		"workload_name":                   pod.Name,
		"service_account_name":            firstNonEmpty(pod.Spec.ServiceAccountName, "default"),
		"node_name":                       pod.Spec.NodeName,
		"host_network":                    pod.Spec.HostNetwork,
		"host_pid":                        pod.Spec.HostPID,
		"host_ipc":                        pod.Spec.HostIPC,
		"automount_service_account_token": pod.Spec.AutomountServiceAccountToken,
		"phase":                           string(pod.Status.Phase),
		"labels":                          pod.Labels,
		"images":                          podImages(pod),
		"image_digests":                   podImageDigests(pod),
	}
}

func containerPayload(pod v1.Pod, container v1.Container, status *v1.ContainerStatus) map[string]any {
	payload := map[string]any{
		"pod_uid":           string(pod.UID),
		"pod_name":          pod.Name,
		"namespace":         pod.Namespace,
		"container_name":    container.Name,
		"image":             container.Image,
		"image_pull_policy": string(container.ImagePullPolicy),
	}
	if status != nil {
		payload["status_image_id"] = status.ImageID
		payload["image_digest"] = imageDigest(status.ImageID)
		payload["ready"] = status.Ready
		payload["restart_count"] = status.RestartCount
	}
	return payload
}

func servicePayload(service v1.Service) map[string]any {
	return map[string]any{
		"uid":                     string(service.UID),
		"name":                    service.Name,
		"namespace":               service.Namespace,
		"type":                    string(service.Spec.Type),
		"cluster_ip":              service.Spec.ClusterIP,
		"cluster_ips":             service.Spec.ClusterIPs,
		"external_ips":            service.Spec.ExternalIPs,
		"external_name":           service.Spec.ExternalName,
		"ip_families":             service.Spec.IPFamilies,
		"ports":                   servicePayloadPorts(service.Spec.Ports),
		"selector":                service.Spec.Selector,
		"load_balancer_ingress":   service.Status.LoadBalancer.Ingress,
		"load_balancer_ips":       serviceLoadBalancerIPs(service),
		"load_balancer_hostnames": serviceLoadBalancerHostnames(service),
		"labels":                  service.Labels,
		"annotations":             service.Annotations,
	}
}

func servicePayloadPorts(ports []v1.ServicePort) []v1.ServicePort {
	if ports == nil {
		return []v1.ServicePort{}
	}
	return ports
}

func serviceAccountPayload(account v1.ServiceAccount) map[string]any {
	return map[string]any{
		"uid":                             string(account.UID),
		"name":                            account.Name,
		"namespace":                       account.Namespace,
		"automount_service_account_token": account.AutomountServiceAccountToken,
		"annotations":                     account.Annotations,
	}
}

func workloadIdentityBindings(st settings, account v1.ServiceAccount) []map[string]string {
	base := serviceAccountAttributes(st, account)
	bindings := []map[string]string{}
	if role := strings.TrimSpace(account.Annotations["eks.amazonaws.com/role-arn"]); role != "" {
		next := clone(base)
		next["cloud_provider"] = "aws"
		next["target_type"] = "role"
		next["target_id"] = role
		next["cloud_principal_arn"] = role
		next["relationship"] = "irsa"
		bindings = append(bindings, next)
	}
	if email := strings.TrimSpace(account.Annotations["iam.gke.io/gcp-service-account"]); email != "" {
		next := clone(base)
		next["cloud_provider"] = "gcp"
		next["target_type"] = "service_account"
		next["target_id"] = email
		next["target_email"] = email
		next["cloud_principal_email"] = email
		next["relationship"] = "gke_workload_identity"
		bindings = append(bindings, next)
	}
	return bindings
}

func workloadURN(st settings, uid string, namespace string, name string) string {
	return fmt.Sprintf("urn:cerebro:%s:kubernetes_workload:%s:%s:%s", url.PathEscape(st.tenantID), url.PathEscape(st.clusterIdentity()), url.PathEscape(namespace), url.PathEscape(firstNonEmpty(uid, name)))
}

func serviceURN(st settings, namespace string, name string) string {
	return fmt.Sprintf("urn:cerebro:%s:kubernetes_service:%s:%s:%s", url.PathEscape(st.tenantID), url.PathEscape(st.clusterIdentity()), url.PathEscape(namespace), url.PathEscape(name))
}

func serviceAccountURN(st settings, namespace string, name string) string {
	return fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:%s:%s:%s", url.PathEscape(st.tenantID), url.PathEscape(st.clusterIdentity()), url.PathEscape(namespace), url.PathEscape(name))
}

func podImages(pod v1.Pod) []string {
	images := make([]string, 0, len(pod.Spec.Containers))
	for _, container := range pod.Spec.Containers {
		if strings.TrimSpace(container.Image) != "" {
			images = append(images, strings.TrimSpace(container.Image))
		}
	}
	return images
}

func podImageDigests(pod v1.Pod) []string {
	statuses := containerStatusesByName(pod)
	values := []string{}
	for _, status := range statuses {
		if digest := imageDigest(status.ImageID); digest != "" {
			values = append(values, digest)
		}
	}
	sort.Strings(values)
	return values
}

func containerStatusesByName(pod v1.Pod) map[string]*v1.ContainerStatus {
	statuses := map[string]*v1.ContainerStatus{}
	for i := range pod.Status.ContainerStatuses {
		status := &pod.Status.ContainerStatuses[i]
		statuses[status.Name] = status
	}
	return statuses
}

func imageDigest(value string) string {
	value = strings.TrimSpace(value)
	if idx := strings.LastIndex(value, "@sha256:"); idx >= 0 {
		return value[idx+1:]
	}
	if idx := strings.LastIndex(value, "sha256:"); idx >= 0 {
		return value[idx:]
	}
	return ""
}

func containerState(state v1.ContainerState) string {
	switch {
	case state.Running != nil:
		return "running"
	case state.Waiting != nil:
		return "waiting"
	case state.Terminated != nil:
		return "terminated"
	default:
		return ""
	}
}

func serviceLoadBalancerIPs(service v1.Service) []string {
	values := []string{}
	for _, ingress := range service.Status.LoadBalancer.Ingress {
		values = append(values, ingress.IP)
	}
	return sortedUnique(values)
}

func serviceLoadBalancerHostnames(service v1.Service) []string {
	values := []string{}
	for _, ingress := range service.Status.LoadBalancer.Ingress {
		values = append(values, ingress.Hostname)
	}
	return sortedUnique(values)
}

func servicePortSummaries(ports []v1.ServicePort) []map[string]string {
	values := make([]map[string]string, 0, len(ports))
	for _, port := range ports {
		value := map[string]string{
			"name":        port.Name,
			"protocol":    string(port.Protocol),
			"port":        strconv.Itoa(int(port.Port)),
			"target_port": port.TargetPort.String(),
		}
		if port.NodePort != 0 {
			value["node_port"] = strconv.Itoa(int(port.NodePort))
		}
		values = append(values, value)
	}
	sort.Slice(values, func(i int, j int) bool {
		if values[i]["port"] != values[j]["port"] {
			return values[i]["port"] < values[j]["port"]
		}
		return values[i]["name"] < values[j]["name"]
	})
	return values
}
