package k8s

import (
	"context"
	"testing"
)

func TestWorkloadSecurityAnalyzer_AnalyzeWorkload(t *testing.T) {
	analyzer := NewWorkloadSecurityAnalyzer(DefaultAnalyzerConfig())
	ctx := context.Background()

	t.Run("privileged container", func(t *testing.T) {
		wc := &WorkloadContext{
			PodID:        "pod-1",
			PodName:      "privileged-pod",
			Namespace:    "default",
			IsPrivileged: true,
		}

		analysis := analyzer.AnalyzeWorkload(ctx, wc)

		if analysis.RiskScore < 40 {
			t.Errorf("expected risk score >= 40 for privileged container, got %f", analysis.RiskScore)
		}

		found := false
		for _, f := range analysis.Findings {
			if f.Type == "privileged_container" {
				found = true
				if f.Severity != "critical" {
					t.Errorf("expected critical severity, got %s", f.Severity)
				}
				break
			}
		}
		if !found {
			t.Error("expected privileged_container finding")
		}
	})

	t.Run("host network access", func(t *testing.T) {
		wc := &WorkloadContext{
			PodID:          "pod-2",
			PodName:        "host-network-pod",
			Namespace:      "default",
			HasHostNetwork: true,
		}

		analysis := analyzer.AnalyzeWorkload(ctx, wc)

		found := false
		for _, f := range analysis.Findings {
			if f.Type == "host_network" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected host_network finding")
		}
	})

	t.Run("sensitive host path mount", func(t *testing.T) {
		wc := &WorkloadContext{
			PodID:          "pod-3",
			PodName:        "host-path-pod",
			Namespace:      "default",
			HostPathMounts: []string{"/var/run/docker.sock"},
		}

		analysis := analyzer.AnalyzeWorkload(ctx, wc)

		found := false
		for _, f := range analysis.Findings {
			if f.Type == "sensitive_host_path" {
				found = true
				if f.Severity != "critical" {
					t.Errorf("expected critical severity, got %s", f.Severity)
				}
				break
			}
		}
		if !found {
			t.Error("expected sensitive_host_path finding")
		}
	})

	t.Run("dangerous capabilities", func(t *testing.T) {
		wc := &WorkloadContext{
			PodID:     "pod-4",
			PodName:   "cap-pod",
			Namespace: "default",
			Capabilities: SecurityCapabilities{
				Added: []string{"SYS_ADMIN", "NET_ADMIN"},
			},
		}

		analysis := analyzer.AnalyzeWorkload(ctx, wc)

		dangerousCount := 0
		for _, f := range analysis.Findings {
			if f.Type == "dangerous_capability" {
				dangerousCount++
			}
		}
		if dangerousCount != 2 {
			t.Errorf("expected 2 dangerous_capability findings, got %d", dangerousCount)
		}
	})

	t.Run("no network policy", func(t *testing.T) {
		wc := &WorkloadContext{
			PodID:           "pod-5",
			PodName:         "no-netpol-pod",
			Namespace:       "default",
			NetworkPolicies: []string{},
		}

		analysis := analyzer.AnalyzeWorkload(ctx, wc)

		found := false
		for _, f := range analysis.Findings {
			if f.Type == "no_network_policy" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected no_network_policy finding")
		}
	})

	t.Run("auto-mounted token with secrets access", func(t *testing.T) {
		wc := &WorkloadContext{
			PodID:           "pod-6",
			PodName:         "token-pod",
			Namespace:       "default",
			AutoMountToken:  true,
			RBACPermissions: []string{"get secrets", "list secrets"},
		}

		analysis := analyzer.AnalyzeWorkload(ctx, wc)

		found := false
		for _, f := range analysis.Findings {
			if f.Type == "token_with_secrets_access" {
				found = true
				if f.Severity != "high" {
					t.Errorf("expected high severity, got %s", f.Severity)
				}
				break
			}
		}
		if !found {
			t.Error("expected token_with_secrets_access finding")
		}
	})

	t.Run("critical vulnerabilities", func(t *testing.T) {
		wc := &WorkloadContext{
			PodID:             "pod-7",
			PodName:           "vuln-pod",
			Namespace:         "default",
			CriticalVulnCount: 5,
			ImageVulnCount:    20,
		}

		analysis := analyzer.AnalyzeWorkload(ctx, wc)

		foundCritical := false
		foundMany := false
		for _, f := range analysis.Findings {
			if f.Type == "critical_vulnerabilities" {
				foundCritical = true
			}
			if f.Type == "many_vulnerabilities" {
				foundMany = true
			}
		}
		if !foundCritical {
			t.Error("expected critical_vulnerabilities finding")
		}
		if !foundMany {
			t.Error("expected many_vulnerabilities finding")
		}
	})

	t.Run("runs as root", func(t *testing.T) {
		wc := &WorkloadContext{
			PodID:        "pod-8",
			PodName:      "root-pod",
			Namespace:    "default",
			RunAsNonRoot: false,
		}

		analysis := analyzer.AnalyzeWorkload(ctx, wc)

		found := false
		for _, f := range analysis.Findings {
			if f.Type == "runs_as_root" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected runs_as_root finding")
		}
	})

	t.Run("overprivileged cloud role", func(t *testing.T) {
		wc := &WorkloadContext{
			PodID:             "pod-9",
			PodName:           "cloud-admin-pod",
			Namespace:         "default",
			CloudRole:         "arn:aws:iam::123456789012:role/admin-role",
			CloudRoleProvider: "aws",
		}

		analysis := analyzer.AnalyzeWorkload(ctx, wc)

		found := false
		for _, f := range analysis.Findings {
			if f.Type == "overprivileged_cloud_role" {
				found = true
				if f.Severity != "critical" {
					t.Errorf("expected critical severity, got %s", f.Severity)
				}
				break
			}
		}
		if !found {
			t.Error("expected overprivileged_cloud_role finding")
		}
	})

	t.Run("secure workload", func(t *testing.T) {
		wc := &WorkloadContext{
			PodID:             "pod-10",
			PodName:           "secure-pod",
			Namespace:         "app",
			ServiceAccount:    "app-sa",
			NetworkPolicies:   []string{"allow-app-traffic"},
			EgressRestricted:  true,
			IngressRestricted: true,
			RunAsNonRoot:      true,
			ReadOnlyRootFS:    true,
			Capabilities: SecurityCapabilities{
				Dropped: []string{"ALL"},
			},
		}

		analysis := analyzer.AnalyzeWorkload(ctx, wc)

		if analysis.RiskScore > 10 {
			t.Errorf("expected low risk score for secure workload, got %f", analysis.RiskScore)
		}
		if analysis.OverallRisk != "low" {
			t.Errorf("expected low overall risk, got %s", analysis.OverallRisk)
		}
	})
}

func TestWorkloadSecurityAnalyzer_AnalyzeNetworkPolicyGaps(t *testing.T) {
	analyzer := NewWorkloadSecurityAnalyzer(DefaultAnalyzerConfig())

	workloads := []*WorkloadContext{
		{PodName: "pod-1", Namespace: "default", IngressRestricted: false, EgressRestricted: false},
		{PodName: "pod-2", Namespace: "default", IngressRestricted: true, EgressRestricted: false},
		{PodName: "pod-3", Namespace: "app", IngressRestricted: true, EgressRestricted: true},
		{PodName: "pod-4", Namespace: "app", IngressRestricted: false, EgressRestricted: true},
	}

	gaps := analyzer.AnalyzeNetworkPolicyGaps(workloads)

	ingressGaps := 0
	egressGaps := 0
	for _, gap := range gaps {
		if gap.MissingPolicy == "ingress" {
			ingressGaps++
		}
		if gap.MissingPolicy == "egress" {
			egressGaps++
		}
	}

	if ingressGaps != 2 {
		t.Errorf("expected 2 namespaces with ingress gaps, got %d", ingressGaps)
	}
	if egressGaps != 1 {
		t.Errorf("expected 1 namespace with egress gap, got %d", egressGaps)
	}
}

func TestWorkloadSecurityAnalyzer_AnalyzeRBAC(t *testing.T) {
	analyzer := NewWorkloadSecurityAnalyzer(DefaultAnalyzerConfig())

	roles := []RBACRole{
		{
			Name: "secret-admin",
			Kind: "ClusterRole",
			Rules: []RBACRule{
				{Verbs: []string{"*"}, Resources: []string{"secrets"}},
			},
		},
		{
			Name: "cluster-admin-custom",
			Kind: "ClusterRole",
			Rules: []RBACRule{
				{Verbs: []string{"*"}, Resources: []string{"*"}},
			},
		},
		{
			Name: "exec-role",
			Kind: "Role",
			Rules: []RBACRule{
				{Verbs: []string{"create"}, Resources: []string{"pods/exec"}},
			},
		},
		{
			Name: "reader",
			Kind: "Role",
			Rules: []RBACRule{
				{Verbs: []string{"get", "list"}, Resources: []string{"pods"}},
			},
		},
	}

	bindings := []RBACBinding{
		{Name: "bind-1", RoleName: "secret-admin", Subject: "developer", SubjectKind: "User"},
		{Name: "bind-2", RoleName: "cluster-admin-custom", Subject: "app-sa", SubjectKind: "ServiceAccount"},
		{Name: "bind-3", RoleName: "exec-role", Subject: "debugger", SubjectKind: "User"},
		{Name: "bind-4", RoleName: "reader", Subject: "viewer", SubjectKind: "User"},
	}

	findings := analyzer.AnalyzeRBAC(roles, bindings)

	findingTypes := make(map[string]int)
	for _, f := range findings {
		findingTypes[f.Type]++
	}

	if findingTypes["wildcard_secrets"] < 1 {
		t.Errorf("expected at least 1 wildcard_secrets finding, got %d", findingTypes["wildcard_secrets"])
	}
	if findingTypes["cluster_admin_equivalent"] != 1 {
		t.Errorf("expected 1 cluster_admin_equivalent finding, got %d", findingTypes["cluster_admin_equivalent"])
	}
	if findingTypes["exec_access"] != 1 {
		t.Errorf("expected 1 exec_access finding, got %d", findingTypes["exec_access"])
	}

	// reader role should not generate findings
	for _, f := range findings {
		if f.Role == "reader" {
			t.Errorf("unexpected finding for reader role: %s", f.Type)
		}
	}
}

func TestScoreToRisk(t *testing.T) {
	testCases := []struct {
		score    float64
		expected string
	}{
		{0, "low"},
		{10, "low"},
		{24, "low"},
		{25, "medium"},
		{49, "medium"},
		{50, "high"},
		{69, "high"},
		{70, "critical"},
		{100, "critical"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := scoreToRisk(tc.score)
			if result != tc.expected {
				t.Errorf("scoreToRisk(%f) = %s, expected %s", tc.score, result, tc.expected)
			}
		})
	}
}

func TestContainsWildcard(t *testing.T) {
	testCases := []struct {
		items    []string
		expected bool
	}{
		{[]string{"get", "list"}, false},
		{[]string{"*"}, true},
		{[]string{"get", "*", "list"}, true},
		{[]string{}, false},
	}

	for _, tc := range testCases {
		result := containsWildcard(tc.items)
		if result != tc.expected {
			t.Errorf("containsWildcard(%v) = %v, expected %v", tc.items, result, tc.expected)
		}
	}
}

func TestContainsAny(t *testing.T) {
	testCases := []struct {
		items    []string
		targets  []string
		expected bool
	}{
		{[]string{"pods", "deployments"}, []string{"secrets"}, false},
		{[]string{"pods", "secrets"}, []string{"secrets"}, true},
		{[]string{"*"}, []string{"*"}, true},
		{[]string{}, []string{"secrets"}, false},
	}

	for _, tc := range testCases {
		result := containsAny(tc.items, tc.targets)
		if result != tc.expected {
			t.Errorf("containsAny(%v, %v) = %v, expected %v", tc.items, tc.targets, result, tc.expected)
		}
	}
}

func TestDefaultAnalyzerConfig(t *testing.T) {
	config := DefaultAnalyzerConfig()

	if len(config.DangerousCapabilities) == 0 {
		t.Error("expected dangerous capabilities to be set")
	}
	if len(config.SensitiveHostPaths) == 0 {
		t.Error("expected sensitive host paths to be set")
	}
	if len(config.HighRiskNamespaces) == 0 {
		t.Error("expected high risk namespaces to be set")
	}

	// Check specific capabilities
	found := false
	for _, cap := range config.DangerousCapabilities {
		if cap == "SYS_ADMIN" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SYS_ADMIN in dangerous capabilities")
	}
}
