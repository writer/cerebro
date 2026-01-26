package k8s

import (
	"context"
	"fmt"
	"strings"
)

// WorkloadContext represents security context for a K8s workload
type WorkloadContext struct {
	PodID             string               `json:"pod_id"`
	PodName           string               `json:"pod_name"`
	Namespace         string               `json:"namespace"`
	ServiceAccount    string               `json:"service_account"`
	CloudRole         string               `json:"cloud_role,omitempty"`
	CloudRoleProvider string               `json:"cloud_role_provider,omitempty"`
	NetworkPolicies   []string             `json:"network_policies,omitempty"`
	EgressRestricted  bool                 `json:"egress_restricted"`
	IngressRestricted bool                 `json:"ingress_restricted"`
	RBACPermissions   []string             `json:"rbac_permissions,omitempty"`
	ImageVulnCount    int                  `json:"image_vuln_count"`
	CriticalVulnCount int                  `json:"critical_vuln_count"`
	IsPrivileged      bool                 `json:"is_privileged"`
	HasHostNetwork    bool                 `json:"has_host_network"`
	HasHostPID        bool                 `json:"has_host_pid"`
	HasHostIPC        bool                 `json:"has_host_ipc"`
	HostPathMounts    []string             `json:"host_path_mounts,omitempty"`
	SecretMounts      []string             `json:"secret_mounts,omitempty"`
	AutoMountToken    bool                 `json:"auto_mount_token"`
	ReadOnlyRootFS    bool                 `json:"read_only_root_fs"`
	RunAsNonRoot      bool                 `json:"run_as_non_root"`
	Capabilities      SecurityCapabilities `json:"capabilities"`
	Labels            map[string]string    `json:"labels,omitempty"`
	RiskScore         float64              `json:"risk_score"`
	RiskFactors       []RiskFactor         `json:"risk_factors,omitempty"`
}

// SecurityCapabilities tracks Linux capabilities
type SecurityCapabilities struct {
	Added   []string `json:"added,omitempty"`
	Dropped []string `json:"dropped,omitempty"`
}

// RiskFactor represents a security risk factor
type RiskFactor struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Score       float64 `json:"score"`
}

// NetworkPolicyGap represents a gap in network policy coverage
type NetworkPolicyGap struct {
	PodSelector   string   `json:"pod_selector"`
	Namespace     string   `json:"namespace"`
	MissingPolicy string   `json:"missing_policy"`
	Risk          string   `json:"risk"`
	AffectedPods  []string `json:"affected_pods"`
	Description   string   `json:"description"`
}

// RBACFinding represents an RBAC security finding
type RBACFinding struct {
	Type              string   `json:"type"`
	Severity          string   `json:"severity"`
	Subject           string   `json:"subject"`
	SubjectKind       string   `json:"subject_kind"`
	Role              string   `json:"role"`
	RoleKind          string   `json:"role_kind"`
	Namespace         string   `json:"namespace,omitempty"`
	Verbs             []string `json:"verbs,omitempty"`
	Resources         []string `json:"resources,omitempty"`
	Description       string   `json:"description"`
	Recommendation    string   `json:"recommendation"`
	AffectedWorkloads []string `json:"affected_workloads,omitempty"`
}

// WorkloadSecurityAnalyzer analyzes K8s workload security
type WorkloadSecurityAnalyzer struct {
	config AnalyzerConfig
}

// AnalyzerConfig configures the analyzer
type AnalyzerConfig struct {
	DangerousCapabilities []string
	SensitiveHostPaths    []string
	HighRiskNamespaces    []string
	RequireNetworkPolicy  bool
}

// DefaultAnalyzerConfig returns sensible defaults
func DefaultAnalyzerConfig() AnalyzerConfig {
	return AnalyzerConfig{
		DangerousCapabilities: []string{
			"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN",
			"NET_RAW", "SYS_RAWIO", "DAC_OVERRIDE", "SETUID", "SETGID",
		},
		SensitiveHostPaths: []string{
			"/", "/etc", "/var/run/docker.sock", "/var/lib/kubelet",
			"/etc/kubernetes", "/var/lib/etcd", "/root", "/home",
		},
		HighRiskNamespaces: []string{
			"kube-system", "kube-public", "default",
		},
		RequireNetworkPolicy: true,
	}
}

// NewWorkloadSecurityAnalyzer creates a new analyzer
func NewWorkloadSecurityAnalyzer(config AnalyzerConfig) *WorkloadSecurityAnalyzer {
	return &WorkloadSecurityAnalyzer{
		config: config,
	}
}

// AnalyzeWorkload analyzes a workload for security issues
func (a *WorkloadSecurityAnalyzer) AnalyzeWorkload(ctx context.Context, wc *WorkloadContext) *WorkloadAnalysis {
	analysis := &WorkloadAnalysis{
		WorkloadID: wc.PodID,
		RiskScore:  0,
		Findings:   make([]SecurityFinding, 0),
	}

	checks := []func(*WorkloadContext, *WorkloadAnalysis){
		a.checkPrivilegedAccess,
		a.checkHostAccess,
		a.checkCapabilities,
		a.checkNetworkPolicy,
		a.checkServiceAccountRisk,
		a.checkImageVulnerabilities,
		a.checkSecurityContext,
		a.checkCloudRoleRisk,
	}

	for _, check := range checks {
		select {
		case <-ctx.Done():
			return analysis
		default:
			check(wc, analysis)
		}
	}

	if analysis.RiskScore > 100 {
		analysis.RiskScore = 100
	}
	wc.RiskScore = analysis.RiskScore

	analysis.OverallRisk = scoreToRisk(analysis.RiskScore)
	return analysis
}

// WorkloadAnalysis is the result of analyzing a workload
type WorkloadAnalysis struct {
	WorkloadID  string            `json:"workload_id"`
	RiskScore   float64           `json:"risk_score"`
	OverallRisk string            `json:"overall_risk"`
	Findings    []SecurityFinding `json:"findings"`
}

// SecurityFinding represents a security finding
type SecurityFinding struct {
	Type           string  `json:"type"`
	Severity       string  `json:"severity"`
	Title          string  `json:"title"`
	Description    string  `json:"description"`
	Resource       string  `json:"resource,omitempty"`
	Recommendation string  `json:"recommendation"`
	Score          float64 `json:"score"`
}

func (a *WorkloadSecurityAnalyzer) checkPrivilegedAccess(wc *WorkloadContext, analysis *WorkloadAnalysis) {
	if wc.IsPrivileged {
		finding := SecurityFinding{
			Type:           "privileged_container",
			Severity:       "critical",
			Title:          "Privileged Container",
			Description:    fmt.Sprintf("Pod %s runs in privileged mode with full host access", wc.PodName),
			Recommendation: "Remove privileged: true and use specific capabilities instead",
			Score:          40,
		}
		analysis.Findings = append(analysis.Findings, finding)
		analysis.RiskScore += finding.Score
		wc.RiskFactors = append(wc.RiskFactors, RiskFactor{
			Type:        "privileged",
			Description: "Container runs in privileged mode",
			Severity:    "critical",
			Score:       40,
		})
	}
}

func (a *WorkloadSecurityAnalyzer) checkHostAccess(wc *WorkloadContext, analysis *WorkloadAnalysis) {
	if wc.HasHostNetwork {
		finding := SecurityFinding{
			Type:           "host_network",
			Severity:       "high",
			Title:          "Host Network Access",
			Description:    "Pod uses host network namespace",
			Recommendation: "Use CNI networking instead of hostNetwork",
			Score:          25,
		}
		analysis.Findings = append(analysis.Findings, finding)
		analysis.RiskScore += finding.Score
	}

	if wc.HasHostPID {
		finding := SecurityFinding{
			Type:           "host_pid",
			Severity:       "high",
			Title:          "Host PID Namespace",
			Description:    "Pod shares host PID namespace",
			Recommendation: "Remove hostPID: true unless absolutely required",
			Score:          25,
		}
		analysis.Findings = append(analysis.Findings, finding)
		analysis.RiskScore += finding.Score
	}

	if wc.HasHostIPC {
		finding := SecurityFinding{
			Type:           "host_ipc",
			Severity:       "medium",
			Title:          "Host IPC Namespace",
			Description:    "Pod shares host IPC namespace",
			Recommendation: "Remove hostIPC: true unless absolutely required",
			Score:          15,
		}
		analysis.Findings = append(analysis.Findings, finding)
		analysis.RiskScore += finding.Score
	}

	for _, hostPath := range wc.HostPathMounts {
		for _, sensitive := range a.config.SensitiveHostPaths {
			if strings.HasPrefix(hostPath, sensitive) || hostPath == sensitive {
				finding := SecurityFinding{
					Type:           "sensitive_host_path",
					Severity:       "critical",
					Title:          "Sensitive Host Path Mount",
					Description:    fmt.Sprintf("Pod mounts sensitive host path: %s", hostPath),
					Resource:       hostPath,
					Recommendation: "Use ConfigMaps, Secrets, or PersistentVolumes instead of hostPath",
					Score:          35,
				}
				analysis.Findings = append(analysis.Findings, finding)
				analysis.RiskScore += finding.Score
				break
			}
		}
	}
}

func (a *WorkloadSecurityAnalyzer) checkCapabilities(wc *WorkloadContext, analysis *WorkloadAnalysis) {
	for _, cap := range wc.Capabilities.Added {
		for _, dangerous := range a.config.DangerousCapabilities {
			if cap == dangerous {
				finding := SecurityFinding{
					Type:           "dangerous_capability",
					Severity:       "high",
					Title:          "Dangerous Capability Added",
					Description:    fmt.Sprintf("Container adds dangerous capability: %s", cap),
					Resource:       cap,
					Recommendation: "Drop all capabilities and add only those specifically needed",
					Score:          20,
				}
				analysis.Findings = append(analysis.Findings, finding)
				analysis.RiskScore += finding.Score
				break
			}
		}
	}

	allDropped := false
	for _, cap := range wc.Capabilities.Dropped {
		if cap == "ALL" {
			allDropped = true
			break
		}
	}
	if !allDropped && len(wc.Capabilities.Dropped) == 0 {
		finding := SecurityFinding{
			Type:           "no_cap_drop",
			Severity:       "medium",
			Title:          "Capabilities Not Dropped",
			Description:    "Container does not drop default capabilities",
			Recommendation: "Add securityContext.capabilities.drop: ['ALL'] and add back only needed capabilities",
			Score:          10,
		}
		analysis.Findings = append(analysis.Findings, finding)
		analysis.RiskScore += finding.Score
	}
}

func (a *WorkloadSecurityAnalyzer) checkNetworkPolicy(wc *WorkloadContext, analysis *WorkloadAnalysis) {
	if !a.config.RequireNetworkPolicy {
		return
	}

	if len(wc.NetworkPolicies) == 0 {
		finding := SecurityFinding{
			Type:           "no_network_policy",
			Severity:       "high",
			Title:          "No Network Policy",
			Description:    fmt.Sprintf("Pod %s has no network policy applied", wc.PodName),
			Recommendation: "Create NetworkPolicy to restrict ingress and egress traffic",
			Score:          25,
		}
		analysis.Findings = append(analysis.Findings, finding)
		analysis.RiskScore += finding.Score
	}

	if !wc.EgressRestricted {
		finding := SecurityFinding{
			Type:           "unrestricted_egress",
			Severity:       "medium",
			Title:          "Unrestricted Egress",
			Description:    "Pod has unrestricted egress access to external networks",
			Recommendation: "Add NetworkPolicy to restrict egress to required destinations only",
			Score:          15,
		}
		analysis.Findings = append(analysis.Findings, finding)
		analysis.RiskScore += finding.Score
	}
}

func (a *WorkloadSecurityAnalyzer) checkServiceAccountRisk(wc *WorkloadContext, analysis *WorkloadAnalysis) {
	if wc.AutoMountToken && len(wc.RBACPermissions) > 0 {
		hasSecretsAccess := false
		for _, perm := range wc.RBACPermissions {
			if strings.Contains(perm, "secrets") {
				hasSecretsAccess = true
				break
			}
		}

		if hasSecretsAccess {
			finding := SecurityFinding{
				Type:           "token_with_secrets_access",
				Severity:       "high",
				Title:          "Auto-Mounted Token with Secrets Access",
				Description:    fmt.Sprintf("Pod %s auto-mounts SA token with secrets access", wc.PodName),
				Recommendation: "Set automountServiceAccountToken: false or use bounded service account tokens",
				Score:          25,
			}
			analysis.Findings = append(analysis.Findings, finding)
			analysis.RiskScore += finding.Score
		}
	}

	if wc.ServiceAccount == "default" {
		finding := SecurityFinding{
			Type:           "default_service_account",
			Severity:       "low",
			Title:          "Using Default Service Account",
			Description:    "Pod uses the default service account",
			Recommendation: "Create a dedicated service account with minimal permissions",
			Score:          5,
		}
		analysis.Findings = append(analysis.Findings, finding)
		analysis.RiskScore += finding.Score
	}
}

func (a *WorkloadSecurityAnalyzer) checkImageVulnerabilities(wc *WorkloadContext, analysis *WorkloadAnalysis) {
	if wc.CriticalVulnCount > 0 {
		finding := SecurityFinding{
			Type:           "critical_vulnerabilities",
			Severity:       "critical",
			Title:          "Critical Image Vulnerabilities",
			Description:    fmt.Sprintf("Container image has %d critical vulnerabilities", wc.CriticalVulnCount),
			Recommendation: "Update base image or patch vulnerable packages",
			Score:          float64(wc.CriticalVulnCount) * 10,
		}
		if finding.Score > 40 {
			finding.Score = 40
		}
		analysis.Findings = append(analysis.Findings, finding)
		analysis.RiskScore += finding.Score
	}

	if wc.ImageVulnCount > 10 {
		finding := SecurityFinding{
			Type:           "many_vulnerabilities",
			Severity:       "high",
			Title:          "Many Image Vulnerabilities",
			Description:    fmt.Sprintf("Container image has %d total vulnerabilities", wc.ImageVulnCount),
			Recommendation: "Review and remediate vulnerabilities, consider using distroless images",
			Score:          15,
		}
		analysis.Findings = append(analysis.Findings, finding)
		analysis.RiskScore += finding.Score
	}
}

func (a *WorkloadSecurityAnalyzer) checkSecurityContext(wc *WorkloadContext, analysis *WorkloadAnalysis) {
	if !wc.RunAsNonRoot {
		finding := SecurityFinding{
			Type:           "runs_as_root",
			Severity:       "medium",
			Title:          "Container Runs as Root",
			Description:    "Container may run as root user",
			Recommendation: "Set runAsNonRoot: true and specify a non-root runAsUser",
			Score:          15,
		}
		analysis.Findings = append(analysis.Findings, finding)
		analysis.RiskScore += finding.Score
	}

	if !wc.ReadOnlyRootFS {
		finding := SecurityFinding{
			Type:           "writable_root_fs",
			Severity:       "low",
			Title:          "Writable Root Filesystem",
			Description:    "Container has a writable root filesystem",
			Recommendation: "Set readOnlyRootFilesystem: true and use emptyDir for writable paths",
			Score:          5,
		}
		analysis.Findings = append(analysis.Findings, finding)
		analysis.RiskScore += finding.Score
	}
}

func (a *WorkloadSecurityAnalyzer) checkCloudRoleRisk(wc *WorkloadContext, analysis *WorkloadAnalysis) {
	if wc.CloudRole == "" {
		return
	}

	roleLower := strings.ToLower(wc.CloudRole)
	if strings.Contains(roleLower, "admin") || strings.Contains(roleLower, "poweruser") ||
		strings.Contains(roleLower, "fullaccess") {
		finding := SecurityFinding{
			Type:           "overprivileged_cloud_role",
			Severity:       "critical",
			Title:          "Overprivileged Cloud IAM Role",
			Description:    fmt.Sprintf("Pod assumes overprivileged cloud role: %s", wc.CloudRole),
			Resource:       wc.CloudRole,
			Recommendation: "Use least privilege IAM role specific to workload needs",
			Score:          35,
		}
		analysis.Findings = append(analysis.Findings, finding)
		analysis.RiskScore += finding.Score
	}
}

func scoreToRisk(score float64) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

// AnalyzeNetworkPolicyGaps finds pods without proper network policies
func (a *WorkloadSecurityAnalyzer) AnalyzeNetworkPolicyGaps(workloads []*WorkloadContext) []NetworkPolicyGap {
	var gaps []NetworkPolicyGap

	byNamespace := make(map[string][]*WorkloadContext)
	for _, wc := range workloads {
		byNamespace[wc.Namespace] = append(byNamespace[wc.Namespace], wc)
	}

	for ns, pods := range byNamespace {
		var noIngressPolicy []string
		var noEgressPolicy []string

		for _, pod := range pods {
			if !pod.IngressRestricted {
				noIngressPolicy = append(noIngressPolicy, pod.PodName)
			}
			if !pod.EgressRestricted {
				noEgressPolicy = append(noEgressPolicy, pod.PodName)
			}
		}

		if len(noIngressPolicy) > 0 {
			gaps = append(gaps, NetworkPolicyGap{
				Namespace:     ns,
				MissingPolicy: "ingress",
				Risk:          "high",
				AffectedPods:  noIngressPolicy,
				Description:   fmt.Sprintf("%d pods in namespace %s have no ingress restrictions", len(noIngressPolicy), ns),
			})
		}

		if len(noEgressPolicy) > 0 {
			gaps = append(gaps, NetworkPolicyGap{
				Namespace:     ns,
				MissingPolicy: "egress",
				Risk:          "medium",
				AffectedPods:  noEgressPolicy,
				Description:   fmt.Sprintf("%d pods in namespace %s have unrestricted egress", len(noEgressPolicy), ns),
			})
		}
	}

	return gaps
}

// AnalyzeRBAC analyzes RBAC configurations for security issues
func (a *WorkloadSecurityAnalyzer) AnalyzeRBAC(roles []RBACRole, bindings []RBACBinding) []RBACFinding {
	var findings []RBACFinding

	roleMap := make(map[string]RBACRole)
	for _, role := range roles {
		roleMap[role.Name] = role
	}

	for _, binding := range bindings {
		role, ok := roleMap[binding.RoleName]
		if !ok {
			continue
		}

		for _, rule := range role.Rules {
			if containsWildcard(rule.Verbs) && containsAny(rule.Resources, []string{"secrets", "*"}) {
				findings = append(findings, RBACFinding{
					Type:           "wildcard_secrets",
					Severity:       "critical",
					Subject:        binding.Subject,
					SubjectKind:    binding.SubjectKind,
					Role:           role.Name,
					RoleKind:       role.Kind,
					Namespace:      binding.Namespace,
					Verbs:          rule.Verbs,
					Resources:      rule.Resources,
					Description:    "Wildcard verbs on secrets enables credential theft",
					Recommendation: "Replace wildcard with specific verbs: get, list, watch",
				})
			}

			if containsWildcard(rule.Verbs) && containsWildcard(rule.Resources) {
				findings = append(findings, RBACFinding{
					Type:           "cluster_admin_equivalent",
					Severity:       "critical",
					Subject:        binding.Subject,
					SubjectKind:    binding.SubjectKind,
					Role:           role.Name,
					RoleKind:       role.Kind,
					Namespace:      binding.Namespace,
					Description:    "Role grants cluster-admin equivalent permissions",
					Recommendation: "Use more restrictive RBAC rules with specific resources and verbs",
				})
			}

			if containsAny(rule.Verbs, []string{"create", "update", "patch", "*"}) &&
				containsAny(rule.Resources, []string{"pods/exec", "pods/attach"}) {
				findings = append(findings, RBACFinding{
					Type:           "exec_access",
					Severity:       "high",
					Subject:        binding.Subject,
					SubjectKind:    binding.SubjectKind,
					Role:           role.Name,
					RoleKind:       role.Kind,
					Namespace:      binding.Namespace,
					Description:    "Role allows exec into pods, enabling code execution",
					Recommendation: "Restrict exec access to specific namespaces and require auditing",
				})
			}
		}
	}

	return findings
}

// RBACRole represents a K8s Role or ClusterRole
type RBACRole struct {
	Name      string     `json:"name"`
	Kind      string     `json:"kind"`
	Namespace string     `json:"namespace,omitempty"`
	Rules     []RBACRule `json:"rules"`
}

// RBACRule represents a rule in an RBAC role
type RBACRule struct {
	Verbs     []string `json:"verbs"`
	Resources []string `json:"resources"`
	APIGroups []string `json:"api_groups,omitempty"`
}

// RBACBinding represents a RoleBinding or ClusterRoleBinding
type RBACBinding struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Namespace   string `json:"namespace,omitempty"`
	RoleName    string `json:"role_name"`
	RoleKind    string `json:"role_kind"`
	Subject     string `json:"subject"`
	SubjectKind string `json:"subject_kind"`
}

func containsWildcard(items []string) bool {
	for _, item := range items {
		if item == "*" {
			return true
		}
	}
	return false
}

func containsAny(items, targets []string) bool {
	targetMap := make(map[string]bool)
	for _, t := range targets {
		targetMap[t] = true
	}
	for _, item := range items {
		if targetMap[item] {
			return true
		}
	}
	return false
}
