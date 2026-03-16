package sync

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestK8sTables(t *testing.T) {
	e := &K8sSyncEngine{}
	tables := e.getK8sTables()

	if len(tables) == 0 {
		t.Fatal("getK8sTables should return at least one table")
	}

	found := false
	for _, table := range tables {
		if table.Name == "k8s_core_pods" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected k8s_core_pods table")
	}

	required := map[string]bool{
		"k8s_cluster_inventory":             false,
		"k8s_core_configmaps":               false,
		"k8s_core_persistent_volumes":       false,
		"k8s_core_service_accounts":         false,
		"k8s_rbac_service_account_bindings": false,
		"k8s_rbac_risky_bindings":           false,
	}
	for _, table := range tables {
		if _, ok := required[table.Name]; ok {
			required[table.Name] = true
		}
	}
	for name, present := range required {
		if !present {
			t.Errorf("expected %s table", name)
		}
	}
}

func TestWithK8sOptions(t *testing.T) {
	e := &K8sSyncEngine{}
	WithK8sKubeconfig("/tmp/kubeconfig")(e)
	WithK8sContext("prod")(e)
	WithK8sNamespace("kube-system")(e)
	WithK8sConcurrency(5)(e)
	WithK8sTableFilter([]string{"k8s_core_pods"})(e)

	if e.kubeconfig != "/tmp/kubeconfig" {
		t.Errorf("expected kubeconfig to be set, got %q", e.kubeconfig)
	}
	if e.kubeContext != "prod" {
		t.Errorf("expected kubeContext to be set, got %q", e.kubeContext)
	}
	if e.namespace != "kube-system" {
		t.Errorf("expected namespace to be set, got %q", e.namespace)
	}
	if e.concurrency != 5 {
		t.Errorf("expected concurrency 5, got %d", e.concurrency)
	}
	if _, ok := e.tableFilter["k8s_core_pods"]; !ok {
		t.Error("expected table filter to include k8s_core_pods")
	}
}

func TestPodSpecToMap(t *testing.T) {
	privileged := true
	readOnly := true
	runAsUser := int64(0)
	runAsNonRoot := true
	automount := false

	spec := corev1.PodSpec{
		HostNetwork:                  true,
		HostPID:                      true,
		ServiceAccountName:           "service-account",
		AutomountServiceAccountToken: &automount,
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot: &runAsNonRoot,
		},
		Containers: []corev1.Container{
			{
				Name:  "app",
				Image: "nginx",
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("100m"),
						corev1.ResourceMemory: resource.MustParse("128Mi"),
					},
				},
				SecurityContext: &corev1.SecurityContext{
					Privileged:             &privileged,
					ReadOnlyRootFilesystem: &readOnly,
					RunAsUser:              &runAsUser,
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				},
				Env: []corev1.EnvVar{
					{
						Name:  "PASSWORD",
						Value: "plain-text",
					},
					{
						Name: "API_TOKEN",
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: "secret"},
								Key:                  "token",
							},
						},
					},
				},
			},
		},
	}

	specMap := podSpecToMap(spec)
	if specMap["host_network"] != true {
		t.Error("expected host_network to be true")
	}
	if specMap["host_pid"] != true {
		t.Error("expected host_pid to be true")
	}
	if specMap["service_account_name"] != "service-account" {
		t.Error("expected service_account_name to be set")
	}
	if specMap["automount_service_account_token"] != false {
		t.Error("expected automount_service_account_token to be false")
	}

	podSecurity, ok := specMap["security_context"].(map[string]interface{})
	if !ok {
		t.Fatal("expected pod security context map")
	}
	if podSecurity["run_as_non_root"] != true {
		t.Error("expected run_as_non_root to be true")
	}

	containers, ok := specMap["containers"].([]map[string]interface{})
	if !ok || len(containers) != 1 {
		t.Fatalf("expected 1 container, got %v", specMap["containers"])
	}

	container := containers[0]
	security, ok := container["security_context"].(map[string]interface{})
	if !ok {
		t.Fatal("expected container security context map")
	}
	if security["privileged"] != true {
		t.Error("expected privileged to be true")
	}
	if security["read_only_root_filesystem"] != true {
		t.Error("expected read_only_root_filesystem to be true")
	}
	if security["run_as_user"] != int64(0) {
		t.Errorf("expected run_as_user to be 0, got %v", security["run_as_user"])
	}

	caps, ok := security["capabilities"].(map[string]interface{})
	if !ok {
		t.Fatal("expected capabilities map")
	}
	drop, ok := caps["drop"].(string)
	if !ok || !strings.Contains(drop, "ALL") {
		t.Errorf("expected capabilities drop to include ALL, got %v", caps["drop"])
	}

	resourcesMap, ok := container["resources"].(map[string]interface{})
	if !ok {
		t.Fatal("expected resources map")
	}
	limits, ok := resourcesMap["limits"].(map[string]interface{})
	if !ok {
		t.Fatal("expected limits map")
	}
	if limits["cpu"] != "100m" {
		t.Errorf("expected cpu limit 100m, got %v", limits["cpu"])
	}
	if limits["memory"] != "128Mi" {
		t.Errorf("expected memory limit 128Mi, got %v", limits["memory"])
	}

	env, ok := container["env"].([]map[string]interface{})
	if !ok || len(env) != 2 {
		t.Fatalf("expected 2 env entries, got %v", container["env"])
	}
	if env[0]["value_from"] != nil {
		t.Error("expected first env value_from to be nil")
	}
	valueFrom, ok := env[1]["value_from"].(map[string]interface{})
	if !ok {
		t.Fatal("expected value_from map for secret env var")
	}
	if valueFrom["secret_key_ref"] == nil {
		t.Error("expected secret_key_ref to be set")
	}
}

func TestPodSpecToMapDerivedSignals(t *testing.T) {
	t.Run("risky pod spec", func(t *testing.T) {
		spec := corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:latest",
			}},
			Volumes: []corev1.Volume{{
				Name: "host",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"},
				},
			}},
		}

		specMap := podSpecToMap(spec)
		if specMap["uses_host_path_volume"] != true {
			t.Error("expected uses_host_path_volume to be true")
		}
		if specMap["allows_privilege_escalation"] != true {
			t.Error("expected allows_privilege_escalation to be true")
		}
		if specMap["uses_latest_image_tag"] != true {
			t.Error("expected uses_latest_image_tag to be true")
		}
		if specMap["all_images_pinned_by_digest"] != false {
			t.Error("expected all_images_pinned_by_digest to be false")
		}
		if specMap["all_containers_have_liveness_probe"] != false {
			t.Error("expected all_containers_have_liveness_probe to be false")
		}
		if specMap["all_containers_have_readiness_probe"] != false {
			t.Error("expected all_containers_have_readiness_probe to be false")
		}
		if specMap["all_containers_runtime_default_seccomp"] != false {
			t.Error("expected all_containers_runtime_default_seccomp to be false")
		}
	})

	t.Run("hardened pod spec", func(t *testing.T) {
		allowPrivilegeEscalation := false
		spec := corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{
				Name:           "app",
				Image:          "registry.example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				LivenessProbe:  &corev1.Probe{},
				ReadinessProbe: &corev1.Probe{},
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: &allowPrivilegeEscalation,
				},
			}},
		}

		specMap := podSpecToMap(spec)
		if specMap["uses_host_path_volume"] != false {
			t.Error("expected uses_host_path_volume to be false")
		}
		if specMap["allows_privilege_escalation"] != false {
			t.Error("expected allows_privilege_escalation to be false")
		}
		if specMap["uses_latest_image_tag"] != false {
			t.Error("expected uses_latest_image_tag to be false")
		}
		if specMap["all_images_pinned_by_digest"] != true {
			t.Error("expected all_images_pinned_by_digest to be true")
		}
		if specMap["all_containers_have_liveness_probe"] != true {
			t.Error("expected all_containers_have_liveness_probe to be true")
		}
		if specMap["all_containers_have_readiness_probe"] != true {
			t.Error("expected all_containers_have_readiness_probe to be true")
		}
		if specMap["all_containers_runtime_default_seccomp"] != true {
			t.Error("expected all_containers_runtime_default_seccomp to be true")
		}
	})
}

func TestBuildTypedNamespacedID_UsesMissingNamespacePlaceholder(t *testing.T) {
	got := buildTypedNamespacedID("prod-cluster", "Pod", "", "payments-api")
	if got != "prod-cluster/pod/_missing_namespace/payments-api" {
		t.Fatalf("expected placeholder namespace segment, got %q", got)
	}
}

func TestServiceAccountSubjects(t *testing.T) {
	subjects := []rbacv1.Subject{
		{Kind: "User", Name: "alice"},
		{Kind: "ServiceAccount", Name: "sa-1", Namespace: "team-a"},
		{Kind: "serviceaccount", Name: "sa-2"},
		{Kind: "ServiceAccount", Name: "", Namespace: "team-a"},
	}

	result := serviceAccountSubjects(subjects, "default")
	if len(result) != 2 {
		t.Fatalf("expected 2 service account subjects, got %d", len(result))
	}
	if result[0].Namespace != "default" || result[0].Name != "sa-2" {
		t.Fatalf("expected default/sa-2 first after sort, got %s/%s", result[0].Namespace, result[0].Name)
	}
	if result[1].Namespace != "team-a" || result[1].Name != "sa-1" {
		t.Fatalf("expected team-a/sa-1 second after sort, got %s/%s", result[1].Namespace, result[1].Name)
	}
}

func TestReferenceNameHelpers(t *testing.T) {
	if got := objectReferencesToNames([]corev1.ObjectReference{{Name: "b"}, {Name: "a"}, {Name: ""}}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("unexpected object reference names: %v", got)
	}
	if got := localObjectReferencesToNames([]corev1.LocalObjectReference{{Name: "pull-b"}, {Name: "pull-a"}, {Name: " "}}); len(got) != 2 || got[0] != "pull-a" || got[1] != "pull-b" {
		t.Fatalf("unexpected local object reference names: %v", got)
	}
}

func TestEvaluateK8sRBACRisk(t *testing.T) {
	rules := []rbacv1.PolicyRule{{
		Verbs:     []string{"*"},
		Resources: []string{"*"},
	}}

	risk, reasons, wildcardVerbs, wildcardResources := evaluateK8sRBACRisk(rules)
	if risk != "high" {
		t.Fatalf("expected high risk, got %s", risk)
	}
	if !wildcardVerbs || !wildcardResources {
		t.Fatalf("expected wildcard flags to be true, got verbs=%v resources=%v", wildcardVerbs, wildcardResources)
	}
	if len(reasons) == 0 {
		t.Fatal("expected non-empty risk reasons")
	}

	mediumRisk, mediumReasons, _, _ := evaluateK8sRBACRisk([]rbacv1.PolicyRule{{
		Verbs:     []string{"get", "list"},
		Resources: []string{"secrets"},
	}})
	if mediumRisk != "medium" {
		t.Fatalf("expected medium risk, got %s", mediumRisk)
	}
	if len(mediumReasons) == 0 {
		t.Fatal("expected medium risk reasons")
	}
	if !containsString(mediumReasons, "secret_access") {
		t.Fatalf("expected secret_access reason, got %v", mediumReasons)
	}

	podCreateRisk, podCreateReasons, _, _ := evaluateK8sRBACRisk([]rbacv1.PolicyRule{{
		Verbs:     []string{"create"},
		Resources: []string{"pods"},
	}})
	if podCreateRisk != "medium" {
		t.Fatalf("expected medium risk for pod create, got %s", podCreateRisk)
	}
	if !containsString(podCreateReasons, "pod_create_access") {
		t.Fatalf("expected pod_create_access reason, got %v", podCreateReasons)
	}

	lowRisk, lowReasons, _, _ := evaluateK8sRBACRisk([]rbacv1.PolicyRule{{
		Verbs:     []string{"get", "list"},
		Resources: []string{"configmaps"},
	}})
	if lowRisk != "low" {
		t.Fatalf("expected low risk, got %s", lowRisk)
	}
	if len(lowReasons) != 0 {
		t.Fatalf("expected no low risk reasons, got %v", lowReasons)
	}
}

func TestK8sRBACRiskBindingHelpers(t *testing.T) {
	id := buildK8sRBACRiskBindingID("cluster-a", "RoleBinding", "team-a", "binding-a", "ServiceAccount", "team-a", "sa-a")
	if id != "cluster-a/rbac-risk/rolebinding/team-a/binding-a/serviceaccount/team-a/sa-a" {
		t.Fatalf("unexpected risk binding id: %s", id)
	}

	if kind := normalizeK8sSubjectKind("serviceaccount"); kind != "ServiceAccount" {
		t.Fatalf("unexpected subject kind normalization: %s", kind)
	}
	if kind := normalizeK8sSubjectKind("User"); kind != "User" {
		t.Fatalf("unexpected user subject kind normalization: %s", kind)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
