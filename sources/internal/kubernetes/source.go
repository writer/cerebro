package kubernetesinternal

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"google.golang.org/protobuf/types/known/timestamppb"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

//go:embed catalog.internal.yaml
var catalogFS embed.FS

const (
	sourceID = "kubernetes"

	familyCluster                 = "cluster"
	familyNamespace               = "namespace"
	familyPod                     = "pod"
	familyContainer               = "container"
	familyServiceAccount          = "service_account"
	familyWorkload                = "workload"
	familyWorkloadIdentityBinding = "workload_identity_binding"

	defaultFamily   = familyWorkload
	defaultPageSize = 100
	maxPageSize     = 500
)

type clientset interface {
	Discovery() discovery.DiscoveryInterface
	CoreV1() corev1client.CoreV1Interface
}

type settings struct {
	tenantID       string
	family         string
	kubeconfigPath string
	contextName    string
	inCluster      bool
	clusterID      string
	clusterName    string
	externalID     string
	cloudProvider  string
	cloudAccountID string
	perPage        int64
}

// Source is the Kubernetes inventory source.
type Source struct {
	spec          *cerebrov1.SourceSpec
	families      *sourcecdk.FamilyEngine[settings]
	clientFactory func(settings) (clientset, error)
	now           func() time.Time
}

// New constructs the Kubernetes source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{spec: spec, now: func() time.Time { return time.Now().UTC() }}
	source.clientFactory = source.defaultClientset
	families, err := source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	source.families = families
	return source, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.spec }

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	return sourcecdk.NewFamilyEngine(s.parseSettings, func(st settings) string { return st.family },
		sourcecdk.Family[settings]{Name: familyCluster, Check: s.check, Discover: s.discoverCluster, Read: s.readCluster},
		sourcecdk.Family[settings]{Name: familyNamespace, Check: s.check, Discover: s.discoverNamespaces, Read: s.readNamespaces},
		sourcecdk.Family[settings]{Name: familyPod, Check: s.check, Discover: s.discoverPods, Read: s.readPods},
		sourcecdk.Family[settings]{Name: familyContainer, Check: s.check, Discover: s.discoverPods, Read: s.readContainers},
		sourcecdk.Family[settings]{Name: familyServiceAccount, Check: s.check, Discover: s.discoverServiceAccounts, Read: s.readServiceAccounts},
		sourcecdk.Family[settings]{Name: familyWorkload, Check: s.check, Discover: s.discoverPods, Read: s.readWorkloads},
		sourcecdk.Family[settings]{Name: familyWorkloadIdentityBinding, Check: s.check, Discover: s.discoverServiceAccounts, Read: s.readWorkloadIdentityBindings},
	)
}

func (s *Source) parseSettings(cfg sourcecdk.Config) (settings, error) {
	st := settings{
		tenantID:       firstNonEmpty(configValue(cfg, "tenant_id"), configValue(cfg, sourceconfig.RuntimeTenantIDKey)),
		family:         strings.TrimSpace(configValue(cfg, "family")),
		kubeconfigPath: strings.TrimSpace(firstNonEmpty(configValue(cfg, "kubeconfig_path"), configValue(cfg, "kubeconfig"))),
		contextName:    strings.TrimSpace(configValue(cfg, "context")),
		clusterID:      strings.TrimSpace(configValue(cfg, "cluster_id")),
		clusterName:    strings.TrimSpace(configValue(cfg, "cluster_name")),
		externalID:     strings.TrimSpace(configValue(cfg, "external_id")),
		cloudProvider:  normalizeIdentifier(firstNonEmpty(configValue(cfg, "cloud_provider"), configValue(cfg, "provider"))),
		cloudAccountID: strings.TrimSpace(firstNonEmpty(configValue(cfg, "cloud_account_id"), configValue(cfg, "account_id"), configValue(cfg, "project_id"), configValue(cfg, "subscription_id"))),
		perPage:        defaultPageSize,
	}
	if st.family == "" {
		st.family = defaultFamily
	}
	switch st.family {
	case familyCluster, familyNamespace, familyPod, familyContainer, familyServiceAccount, familyWorkload, familyWorkloadIdentityBinding:
	default:
		return st, fmt.Errorf("kubernetes family must be one of cluster, namespace, pod, container, service_account, workload, or workload_identity_binding")
	}
	if st.tenantID == "" {
		return st, fmt.Errorf("kubernetes tenant_id is required")
	}
	st.inCluster = parseBool(configValue(cfg, "in_cluster"))
	if !st.inCluster && st.kubeconfigPath == "" {
		return st, fmt.Errorf("kubernetes kubeconfig_path is required unless in_cluster=true")
	}
	if raw := strings.TrimSpace(configValue(cfg, "per_page")); raw != "" {
		perPage, err := strconv.ParseInt(raw, 10, 32)
		if err != nil {
			return st, fmt.Errorf("parse kubernetes per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return st, fmt.Errorf("kubernetes per_page must be between 1 and %d", maxPageSize)
		}
		st.perPage = perPage
	}
	return st, nil
}

func (s *Source) defaultClientset(st settings) (clientset, error) {
	var cfg *rest.Config
	var err error
	if st.inCluster {
		cfg, err = rest.InClusterConfig()
	} else {
		loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: st.kubeconfigPath}
		overrides := &clientcmd.ConfigOverrides{CurrentContext: st.contextName}
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides).ClientConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("load kubernetes client config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}
	return client, nil
}

func (s *Source) check(_ context.Context, st settings) error {
	client, err := s.clientFactory(st)
	if err != nil {
		return err
	}
	if _, err := client.Discovery().ServerVersion(); err != nil {
		return fmt.Errorf("read kubernetes server version: %w", err)
	}
	return nil
}

func (s *Source) discoverCluster(ctx context.Context, st settings) ([]sourcecdk.URN, error) {
	info, err := s.clusterInfo(ctx, st)
	if err != nil {
		return nil, err
	}
	return parseURNs(clusterURN(st, info.ClusterID))
}

func (s *Source) discoverNamespaces(ctx context.Context, st settings) ([]sourcecdk.URN, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return nil, err
	}
	items, _, err := listNamespaces(ctx, client, st.perPage, "")
	if err != nil {
		return nil, err
	}
	urns := make([]string, 0, len(items))
	for _, item := range items {
		urns = append(urns, namespaceURN(st, string(item.UID), item.Name))
	}
	return parseURNs(urns...)
}

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

func (s *Source) readCluster(ctx context.Context, st settings, _ *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	info, err := s.clusterInfo(ctx, st)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	event, err := s.event(st, "kubernetes-cluster-"+info.ClusterID, "kubernetes.cluster", "kubernetes/cluster/v1", info, clusterAttributes(st, info), s.now())
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	return sourcecdk.Pull{Events: []*primitives.Event{event}}, nil
}

func (s *Source) readNamespaces(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	items, next, err := listNamespaces(ctx, client, st.perPage, cursor.GetOpaque())
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	events := make([]*primitives.Event, 0, len(items))
	for _, item := range items {
		payload := map[string]any{"uid": string(item.UID), "name": item.Name, "status": string(item.Status.Phase)}
		attrs := resourceAttributes(st, "namespace", string(item.UID), item.Name, item.Name)
		attrs["namespace"] = item.Name
		event, err := s.event(st, "kubernetes-namespace-"+string(item.UID), "kubernetes.namespace", "kubernetes/namespace/v1", payload, attrs, objectTime(item.CreationTimestamp, s.now()))
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	return pullWithCursor(events, next), nil
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

type clusterInfo struct {
	ClusterID      string `json:"cluster_id"`
	ClusterName    string `json:"cluster_name"`
	ExternalID     string `json:"external_id,omitempty"`
	GitVersion     string `json:"git_version,omitempty"`
	Major          string `json:"major,omitempty"`
	Minor          string `json:"minor,omitempty"`
	Platform       string `json:"platform,omitempty"`
	CloudProvider  string `json:"cloud_provider,omitempty"`
	CloudAccountID string `json:"cloud_account_id,omitempty"`
}

func (s *Source) clusterInfo(ctx context.Context, st settings) (clusterInfo, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return clusterInfo{}, err
	}
	version, err := client.Discovery().ServerVersion()
	if err != nil {
		return clusterInfo{}, fmt.Errorf("read kubernetes server version: %w", err)
	}
	clusterName := firstNonEmpty(st.clusterName, st.contextName, st.externalID, "cluster")
	clusterID := firstNonEmpty(st.clusterID, st.externalID)
	if clusterID == "" {
		if ns, err := client.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{}); err == nil {
			clusterID = string(ns.UID)
		}
	}
	clusterID = firstNonEmpty(clusterID, stableID(clusterName))
	return clusterInfo{ClusterID: clusterID, ClusterName: clusterName, ExternalID: st.externalID, GitVersion: version.GitVersion, Major: version.Major, Minor: version.Minor, Platform: version.Platform, CloudProvider: st.cloudProvider, CloudAccountID: st.cloudAccountID}, nil
}

func listNamespaces(ctx context.Context, client clientset, limit int64, cursor string) ([]v1.Namespace, string, error) {
	out, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: limit, Continue: strings.TrimSpace(cursor)})
	if err != nil {
		return nil, "", fmt.Errorf("list kubernetes namespaces: %w", err)
	}
	return out.Items, out.Continue, nil
}

func listPods(ctx context.Context, client clientset, limit int64, cursor string) ([]v1.Pod, string, error) {
	out, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{Limit: limit, Continue: strings.TrimSpace(cursor)})
	if err != nil {
		return nil, "", fmt.Errorf("list kubernetes pods: %w", err)
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

func (s *Source) event(st settings, id string, kind string, schemaRef string, payload any, attrs map[string]string, occurredAt time.Time) (*primitives.Event, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal %s payload: %w", kind, err)
	}
	event := &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   st.tenantID,
		SourceId:   sourceID,
		Kind:       kind,
		SchemaRef:  schemaRef,
		Payload:    raw,
		Attributes: compact(attrs),
		OccurredAt: timestamppb.New(occurredAt.UTC()),
	}
	if err := sourcecdk.ValidateEventEnvelope(event); err != nil {
		return nil, err
	}
	return event, nil
}

func clusterAttributes(st settings, info clusterInfo) map[string]string {
	attrs := map[string]string{"cluster_id": info.ClusterID, "cluster_name": info.ClusterName}
	add(attrs, "external_id", info.ExternalID)
	add(attrs, "cloud_provider", firstNonEmpty(info.CloudProvider, st.cloudProvider))
	add(attrs, "cloud_account_id", firstNonEmpty(info.CloudAccountID, st.cloudAccountID))
	add(attrs, "git_version", info.GitVersion)
	add(attrs, "version_major", info.Major)
	add(attrs, "version_minor", info.Minor)
	add(attrs, "platform", info.Platform)
	return attrs
}

func resourceAttributes(st settings, resourceType string, resourceID string, resourceName string, namespace string) map[string]string {
	attrs := map[string]string{
		"cluster_id":    st.clusterIdentity(),
		"cluster_name":  st.displayClusterName(),
		"resource_id":   resourceID,
		"resource_name": resourceName,
		"resource_type": resourceType,
	}
	add(attrs, "namespace", namespace)
	add(attrs, "external_id", st.externalID)
	add(attrs, "cloud_provider", st.cloudProvider)
	add(attrs, "cloud_account_id", st.cloudAccountID)
	return attrs
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

func pullWithCursor(events []*primitives.Event, next string) sourcecdk.Pull {
	pull := sourcecdk.Pull{Events: events}
	if strings.TrimSpace(next) != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
		pull.Checkpoint = &cerebrov1.SourceCheckpoint{CursorOpaque: next}
	}
	return pull
}

func (st settings) clusterIdentity() string {
	return firstNonEmpty(st.clusterID, st.externalID, scopedClusterID(st.cloudAccountID, st.clusterName), st.clusterName, st.contextName, "cluster")
}

func (st settings) displayClusterName() string {
	return firstNonEmpty(st.clusterName, st.contextName, st.externalID, st.clusterID, "cluster")
}

func scopedClusterID(accountID string, clusterName string) string {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(clusterName) == "" {
		return ""
	}
	return strings.TrimSpace(accountID) + ":" + strings.TrimSpace(clusterName)
}

func clusterURN(st settings, id string) string {
	return fmt.Sprintf("urn:cerebro:%s:kubernetes_cluster:%s", url.PathEscape(st.tenantID), url.PathEscape(id))
}

func namespaceURN(st settings, uid string, name string) string {
	return fmt.Sprintf("urn:cerebro:%s:kubernetes_namespace:%s:%s", url.PathEscape(st.tenantID), url.PathEscape(st.clusterIdentity()), url.PathEscape(firstNonEmpty(uid, name)))
}

func workloadURN(st settings, uid string, namespace string, name string) string {
	return fmt.Sprintf("urn:cerebro:%s:kubernetes_workload:%s:%s:%s", url.PathEscape(st.tenantID), url.PathEscape(st.clusterIdentity()), url.PathEscape(namespace), url.PathEscape(firstNonEmpty(uid, name)))
}

func serviceAccountURN(st settings, namespace string, name string) string {
	return fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:%s:%s:%s", url.PathEscape(st.tenantID), url.PathEscape(st.clusterIdentity()), url.PathEscape(namespace), url.PathEscape(name))
}

func parseURNs(raw ...string) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(raw))
	for _, value := range raw {
		urn, err := sourcecdk.ParseURN(value)
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
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

func objectTime(value metav1.Time, fallback time.Time) time.Time {
	if !value.IsZero() {
		return value.UTC()
	}
	return fallback.UTC()
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	specBytes, err := catalogFS.ReadFile("catalog.internal.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return spec, nil
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func add(attrs map[string]string, key string, value string) {
	if value = strings.TrimSpace(value); value != "" {
		attrs[key] = value
	}
}

func compact(attrs map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range attrs {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			out[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return out
}

func clone(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs))
	for key, value := range attrs {
		out[key] = value
	}
	return out
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y":
		return true
	default:
		return false
	}
}

func stableID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func normalizeIdentifier(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "_")
	value = strings.ReplaceAll(value, "-", "_")
	return value
}
