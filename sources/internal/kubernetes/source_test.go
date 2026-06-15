package kubernetesinternal

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
	if got := binding.Attributes["subject_refs"]; got != "ServiceAccount:payments/api;User:alice@example.com;User:arn:aws:sts::123456789012:assumed-role/Admin/alice@example.com" {
		t.Fatalf("subject_refs = %q, want service account and slash-bearing user refs", got)
	}
	clusterBinding := pull.Events[1]
	if clusterBinding.Attributes["binding_kind"] != "ClusterRoleBinding" || clusterBinding.Attributes["subject_refs"] != "Group:system:masters" {
		t.Fatalf("cluster binding event = %#v", clusterBinding)
	}
}
