package kubernetesinternal

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

func TestPodImageDigestsAreSorted(t *testing.T) {
	pod := v1.Pod{Status: v1.PodStatus{ContainerStatuses: []v1.ContainerStatus{
		{Name: "b", ImageID: "registry.example/app@sha256:bbbb"},
		{Name: "a", ImageID: "registry.example/app@sha256:aaaa"},
	}}}
	got := podImageDigests(pod)
	want := []string{"sha256:aaaa", "sha256:bbbb"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("podImageDigests() = %#v, want %#v", got, want)
	}
}

func TestReadNodesEmitsKubeletPosture(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.clientFactory = func(settings) (clientset, error) {
		return fake.NewSimpleClientset(&v1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "ip-10-0-1-10",
				UID:               types.UID("node-1"),
				CreationTimestamp: metav1.NewTime(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)),
				Labels:            map[string]string{"kubernetes.io/os": "linux"},
			},
			Spec: v1.NodeSpec{
				ProviderID:    "aws:///us-east-1a/i-1234567890abcdef0",
				PodCIDR:       "10.244.0.0/24",
				PodCIDRs:      []string{"10.244.0.0/24"},
				Unschedulable: true,
				Taints:        []v1.Taint{{Key: "dedicated", Value: "gpu", Effect: v1.TaintEffectNoSchedule}},
			},
			Status: v1.NodeStatus{
				Addresses: []v1.NodeAddress{
					{Type: v1.NodeInternalIP, Address: "10.0.1.10"},
					{Type: v1.NodeExternalIP, Address: "198.51.100.10"},
				},
				Conditions:  []v1.NodeCondition{{Type: v1.NodeReady, Status: v1.ConditionTrue}},
				Capacity:    v1.ResourceList{v1.ResourceCPU: resource.MustParse("4")},
				Allocatable: v1.ResourceList{v1.ResourceCPU: resource.MustParse("3900m")},
				NodeInfo: v1.NodeSystemInfo{
					Architecture:            "amd64",
					ContainerRuntimeVersion: "containerd://1.7.0",
					KernelVersion:           "6.1.0",
					KubeletVersion:          "v1.35.0",
					OperatingSystem:         "linux",
					OSImage:                 "Bottlerocket OS",
				},
			},
		}), nil
	}

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "writer", "family": familyNode, "kubeconfig_path": "/tmp/kubeconfig", "cluster_id": "prod-cluster"}), nil)
	if err != nil {
		t.Fatalf("Read(node) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "kubernetes.node" || event.Attributes["node_name"] != "ip-10-0-1-10" || event.Attributes["ready"] != "true" {
		t.Fatalf("node event = %#v", event)
	}
	for key, want := range map[string]string{
		"container_runtime_version": "containerd://1.7.0",
		"external_ip":               "198.51.100.10",
		"internal_ip":               "10.0.1.10",
		"kubelet_version":           "v1.35.0",
		"provider_id":               "aws:///us-east-1a/i-1234567890abcdef0",
		"unschedulable":             "true",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
	var payload struct {
		Ready    bool           `json:"ready"`
		NodeInfo map[string]any `json:"node_info"`
	}
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatalf("unmarshal node payload: %v", err)
	}
	if !payload.Ready || payload.NodeInfo["kubeletVersion"] != "v1.35.0" {
		t.Fatalf("node payload = %#v", payload)
	}
}

func TestReadServicesEmitsExternalEndpointDetails(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.clientFactory = func(settings) (clientset, error) {
		return fake.NewSimpleClientset(&v1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "payments", Namespace: "payments", UID: types.UID("service-1")},
			Spec: v1.ServiceSpec{
				Type:        v1.ServiceTypeLoadBalancer,
				ClusterIP:   "10.96.0.10",
				ClusterIPs:  []string{"10.96.0.10"},
				ExternalIPs: []string{"203.0.113.10"},
				Ports: []v1.ServicePort{{
					Name:       "https",
					Protocol:   v1.ProtocolTCP,
					Port:       443,
					TargetPort: intstr.FromInt(8443),
					NodePort:   30443,
				}},
				Selector: map[string]string{"app": "payments"},
			},
			Status: v1.ServiceStatus{LoadBalancer: v1.LoadBalancerStatus{Ingress: []v1.LoadBalancerIngress{{IP: "198.51.100.20"}, {Hostname: "payments.example.net"}}}},
		}), nil
	}

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "writer", "family": familyService, "kubeconfig_path": "/tmp/kubeconfig", "cluster_id": "prod-cluster"}), nil)
	if err != nil {
		t.Fatalf("Read(service) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "kubernetes.service" || event.Attributes["service_name"] != "payments" || event.Attributes["service_type"] != "LoadBalancer" {
		t.Fatalf("service event = %#v", event)
	}
	if got := event.Attributes["external_ips"]; got != "203.0.113.10" {
		t.Fatalf("external_ips = %q", got)
	}
	if got := event.Attributes["load_balancer_hostnames"]; got != "payments.example.net" {
		t.Fatalf("load_balancer_hostnames = %q", got)
	}
	var ports []map[string]string
	if err := json.Unmarshal([]byte(event.Attributes["ports"]), &ports); err != nil {
		t.Fatalf("unmarshal service ports: %v", err)
	}
	if len(ports) != 1 || ports[0]["node_port"] != "30443" || ports[0]["target_port"] != "8443" {
		t.Fatalf("ports = %#v", ports)
	}
}

func TestReadServicesEmitsEmptyPortsPayload(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.clientFactory = func(settings) (clientset, error) {
		return fake.NewSimpleClientset(&v1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "catalog", Namespace: "payments", UID: types.UID("service-external-name")},
			Spec:       v1.ServiceSpec{Type: v1.ServiceTypeExternalName, ExternalName: "catalog.example.com"},
		}), nil
	}

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "writer", "family": familyService, "kubeconfig_path": "/tmp/kubeconfig", "cluster_id": "prod-cluster"}), nil)
	if err != nil {
		t.Fatalf("Read(service) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	var payload struct {
		Ports []v1.ServicePort `json:"ports"`
	}
	if err := json.Unmarshal(pull.Events[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal service payload: %v", err)
	}
	if payload.Ports == nil {
		t.Fatalf("payload ports = nil, want empty array; payload=%s", string(pull.Events[0].Payload))
	}
	if len(payload.Ports) != 0 {
		t.Fatalf("len(payload.Ports) = %d, want 0", len(payload.Ports))
	}
}

func TestReadIngressesEmitsTLSRulesAndBackends(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	pathType := networkingv1.PathTypePrefix
	ingressClassName := "nginx"
	source.clientFactory = func(settings) (clientset, error) {
		return fake.NewSimpleClientset(&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "payments", Namespace: "payments", UID: types.UID("ingress-1")},
			Spec: networkingv1.IngressSpec{
				IngressClassName: &ingressClassName,
				DefaultBackend: &networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
					Name: "default-backend",
					Port: networkingv1.ServiceBackendPort{Number: 80},
				}},
				TLS: []networkingv1.IngressTLS{{Hosts: []string{"payments.example.com"}, SecretName: "payments-tls"}},
				Rules: []networkingv1.IngressRule{{
					Host: "payments.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
						Path:     "/",
						PathType: &pathType,
						Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
							Name: "payments",
							Port: networkingv1.ServiceBackendPort{Number: 443},
						}},
					}}}},
				}},
			},
			Status: networkingv1.IngressStatus{LoadBalancer: networkingv1.IngressLoadBalancerStatus{Ingress: []networkingv1.IngressLoadBalancerIngress{{IP: "198.51.100.30"}, {Hostname: "ingress.example.net"}}}},
		}), nil
	}

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "writer", "family": familyIngress, "kubeconfig_path": "/tmp/kubeconfig", "cluster_id": "prod-cluster"}), nil)
	if err != nil {
		t.Fatalf("Read(ingress) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "kubernetes.ingress" || event.Attributes["ingress_name"] != "payments" || event.Attributes["ingress_class_name"] != "nginx" {
		t.Fatalf("ingress event = %#v", event)
	}
	for key, want := range map[string]string{
		"hosts":                   "payments.example.com",
		"load_balancer_hostnames": "ingress.example.net",
		"load_balancer_ips":       "198.51.100.30",
		"tls_hosts":               "payments.example.com",
		"tls_secret_names":        "payments-tls",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
	if got := event.Attributes["backend_services"]; !strings.Contains(got, "payments:443") || !strings.Contains(got, "default-backend:80") {
		t.Fatalf("backend_services = %q", got)
	}
	if got := event.Attributes["rules"]; !strings.Contains(got, "payments.example.com:/-") || !strings.Contains(got, "payments:443") {
		t.Fatalf("rules = %q", got)
	}
}

func TestReadIngressesEmitsEmptyRulesPayload(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.clientFactory = func(settings) (clientset, error) {
		return fake.NewSimpleClientset(&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "default-only", Namespace: "payments", UID: types.UID("ingress-default-only")},
			Spec: networkingv1.IngressSpec{DefaultBackend: &networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
				Name: "default-backend",
				Port: networkingv1.ServiceBackendPort{Number: 80},
			}}},
		}), nil
	}

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "writer", "family": familyIngress, "kubeconfig_path": "/tmp/kubeconfig", "cluster_id": "prod-cluster"}), nil)
	if err != nil {
		t.Fatalf("Read(ingress) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	var payload struct {
		Rules []networkingv1.IngressRule `json:"rules"`
	}
	if err := json.Unmarshal(pull.Events[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal ingress payload: %v", err)
	}
	if payload.Rules == nil {
		t.Fatalf("payload rules = nil, want empty array; payload=%s", string(pull.Events[0].Payload))
	}
	if len(payload.Rules) != 0 {
		t.Fatalf("len(payload.Rules) = %d, want 0", len(payload.Rules))
	}
	if got := pull.Events[0].Attributes["backend_services"]; got != "default-backend:80" {
		t.Fatalf("backend_services = %q, want default-backend:80", got)
	}
}

func TestReadRBACRolesEmitsRolesAndClusterRoles(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.clientFactory = func(settings) (clientset, error) {
		return fake.NewSimpleClientset(
			&rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "secret-reader", Namespace: "payments", UID: types.UID("role-1"), CreationTimestamp: metav1.NewTime(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))},
				Rules: []rbacv1.PolicyRule{{
					APIGroups: []string{""},
					Resources: []string{"secrets"},
					Verbs:     []string{"get", "list"},
				}},
			},
			&rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin", UID: types.UID("cluster-role-1")},
				Rules: []rbacv1.PolicyRule{{
					APIGroups: []string{"*"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				}},
			},
		), nil
	}

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "writer", "family": familyRBACRole, "kubeconfig_path": "/tmp/kubeconfig", "cluster_id": "prod-cluster"}), nil)
	if err != nil {
		t.Fatalf("Read(rbac_role) error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want 2", len(pull.Events))
	}
	role := pull.Events[0]
	if role.Kind != "kubernetes.rbac_role" || role.Attributes["role_kind"] != "Role" || role.Attributes["role_name"] != "secret-reader" || role.Attributes["namespace"] != "payments" {
		t.Fatalf("role event = %#v", role)
	}
	if got := role.Attributes["verbs"]; got != "get,list" {
		t.Fatalf("role verbs = %q, want get,list", got)
	}
	clusterRole := pull.Events[1]
	if clusterRole.Attributes["role_kind"] != "ClusterRole" || clusterRole.Attributes["role_scope"] != "cluster" {
		t.Fatalf("cluster role event = %#v", clusterRole)
	}
}

func TestReadRBACRoleWithoutRulesEmitsEmptyRulesArray(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.clientFactory = func(settings) (clientset, error) {
		return fake.NewSimpleClientset(
			&rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "empty-role", Namespace: "payments", UID: types.UID("role-empty")},
			},
		), nil
	}

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "writer", "family": familyRBACRole, "kubeconfig_path": "/tmp/kubeconfig", "cluster_id": "prod-cluster"}), nil)
	if err != nil {
		t.Fatalf("Read(rbac_role) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	var payload struct {
		Rules []rbacv1.PolicyRule `json:"rules"`
	}
	if err := json.Unmarshal(pull.Events[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.Rules == nil {
		t.Fatalf("payload rules = nil, want empty array; payload=%s", string(pull.Events[0].Payload))
	}
	if len(payload.Rules) != 0 {
		t.Fatalf("len(payload.Rules) = %d, want 0", len(payload.Rules))
	}
}

func TestReadRBACBindingsEmitsBindingsAndSubjects(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.clientFactory = func(settings) (clientset, error) {
		return fake.NewSimpleClientset(
			&rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "secret-reader-binding", Namespace: "payments", UID: types.UID("binding-1")},
				RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "secret-reader"},
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "api", Namespace: "payments"},
					{Kind: "User", Name: "alice@example.com"},
					{Kind: "User", Name: "arn:aws:sts::123456789012:assumed-role/Admin/alice@example.com"},
				},
			},
			&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin-binding", UID: types.UID("cluster-binding-1")},
				RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"},
				Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "system:masters"}},
			},
		), nil
	}

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "writer", "family": familyRBACBinding, "kubeconfig_path": "/tmp/kubeconfig", "cluster_id": "prod-cluster"}), nil)
	if err != nil {
		t.Fatalf("Read(rbac_binding) error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want 2", len(pull.Events))
	}
	binding := pull.Events[0]
	if binding.Kind != "kubernetes.rbac_binding" || binding.Attributes["binding_kind"] != "RoleBinding" || binding.Attributes["role_name"] != "secret-reader" {
		t.Fatalf("binding event = %#v", binding)
	}
	wantRefs := []rbacSubjectRef{
		{Kind: "ServiceAccount", Namespace: "payments", Name: "api"},
		{Kind: "User", Name: "alice@example.com"},
		{Kind: "User", Name: "arn:aws:sts::123456789012:assumed-role/Admin/alice@example.com"},
	}
	var gotRefs []rbacSubjectRef
	if err := json.Unmarshal([]byte(binding.Attributes["subject_refs"]), &gotRefs); err != nil {
		t.Fatalf("unmarshal subject_refs: %v", err)
	}
	if !reflect.DeepEqual(gotRefs, wantRefs) {
		t.Fatalf("subject_refs = %#v, want %#v", gotRefs, wantRefs)
	}
	clusterBinding := pull.Events[1]
	var gotClusterRefs []rbacSubjectRef
	if err := json.Unmarshal([]byte(clusterBinding.Attributes["subject_refs"]), &gotClusterRefs); err != nil {
		t.Fatalf("unmarshal cluster subject_refs: %v", err)
	}
	wantClusterRefs := []rbacSubjectRef{{Kind: "Group", Name: "system:masters"}}
	if clusterBinding.Attributes["binding_kind"] != "ClusterRoleBinding" || !reflect.DeepEqual(gotClusterRefs, wantClusterRefs) {
		t.Fatalf("cluster binding event = %#v", clusterBinding)
	}
}
