package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	defaultRuntimeRemoteActionTimeout = 30 * time.Second
	runtimeSourceSystem               = "runtime_response"
	runtimeSourceActor                = "cerebro"
	maxRuntimeScaleReplicas           = 1<<31 - 1
)

const (
	runtimeToolKillProcess       = "security.runtime.kill_process"
	runtimeToolIsolateContainer  = "security.runtime.isolate_container"
	runtimeToolIsolateHost       = "security.runtime.isolate_host"
	runtimeToolQuarantineFile    = "security.runtime.quarantine_file"
	runtimeToolBlockIP           = "security.runtime.block_ip"
	runtimeToolBlockDomain       = "security.runtime.block_domain"
	runtimeToolRevokeCredentials = "security.runtime.revoke_credentials"
	runtimeToolScaleDown         = "security.runtime.scale_down"
)

type RemoteActionCaller interface {
	CallTool(ctx context.Context, toolName string, args json.RawMessage, timeout time.Duration) (string, error)
}

type WorkloadScaler interface {
	ScaleDown(ctx context.Context, target WorkloadTarget, replicas int32) error
}

type WorkloadTarget struct {
	Kind      string
	Namespace string
	Name      string
}

func (t WorkloadTarget) String() string {
	if t.Namespace == "" {
		return fmt.Sprintf("%s:%s", t.Kind, t.Name)
	}
	return fmt.Sprintf("%s:%s/%s", t.Kind, t.Namespace, t.Name)
}

type ActionCapabilityError struct {
	Action  ResponseActionType
	Code    string
	Message string
}

type TrustedActuationScope struct {
	AllowedResourceIDs      []string
	AllowedContainerIDs     []string
	AllowedNamespaces       []string
	AllowedWorkloadTargets  []string
	AllowedPrincipalIDs     []string
	AllowNetworkContainment bool
}

type trustedActuationScopeContextKey struct{}

func (e *ActionCapabilityError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message == "" {
		return fmt.Sprintf("runtime action %s unavailable (%s)", e.Action, e.Code)
	}
	return e.Message
}

func WithTrustedActuationScope(ctx context.Context, scope TrustedActuationScope) context.Context {
	return context.WithValue(ctx, trustedActuationScopeContextKey{}, TrustedActuationScope{
		AllowedResourceIDs:      append([]string(nil), scope.AllowedResourceIDs...),
		AllowedContainerIDs:     append([]string(nil), scope.AllowedContainerIDs...),
		AllowedNamespaces:       append([]string(nil), scope.AllowedNamespaces...),
		AllowedWorkloadTargets:  append([]string(nil), scope.AllowedWorkloadTargets...),
		AllowedPrincipalIDs:     append([]string(nil), scope.AllowedPrincipalIDs...),
		AllowNetworkContainment: scope.AllowNetworkContainment,
	})
}

func TrustedActuationScopeFromContext(ctx context.Context) (TrustedActuationScope, bool) {
	if ctx == nil {
		return TrustedActuationScope{}, false
	}
	scope, ok := ctx.Value(trustedActuationScopeContextKey{}).(TrustedActuationScope)
	return scope, ok
}

type DefaultActionHandlerOptions struct {
	Blocklist      *Blocklist
	RemoteCaller   RemoteActionCaller
	WorkloadScaler WorkloadScaler
	RemoteTimeout  time.Duration
}

type DefaultActionHandler struct {
	blocklist      *Blocklist
	remoteCaller   RemoteActionCaller
	workloadScaler WorkloadScaler
	remoteTimeout  time.Duration
	mu             sync.RWMutex
}

func NewDefaultActionHandler(opts DefaultActionHandlerOptions) *DefaultActionHandler {
	timeout := opts.RemoteTimeout
	if timeout <= 0 {
		timeout = defaultRuntimeRemoteActionTimeout
	}
	scaler := opts.WorkloadScaler
	if scaler == nil {
		scaler = NewKubernetesWorkloadScaler("", "")
	}
	return &DefaultActionHandler{
		blocklist:      opts.Blocklist,
		remoteCaller:   opts.RemoteCaller,
		workloadScaler: scaler,
		remoteTimeout:  timeout,
	}
}

func (h *DefaultActionHandler) SetRemoteCaller(caller RemoteActionCaller) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.remoteCaller = caller
}

func (h *DefaultActionHandler) KillProcess(ctx context.Context, resourceID string, pid int) error {
	return h.callRemoteRequired(ctx, ActionKillProcess, runtimeToolKillProcess, map[string]any{
		"resource_id": resourceID,
		"pid":         pid,
	})
}

func (h *DefaultActionHandler) IsolateContainer(ctx context.Context, containerID, namespace string) error {
	return h.callRemoteRequired(ctx, ActionIsolateContainer, runtimeToolIsolateContainer, map[string]any{
		"container_id": containerID,
		"namespace":    namespace,
	})
}

func (h *DefaultActionHandler) IsolateHost(ctx context.Context, instanceID, provider string) error {
	return h.callRemoteRequired(ctx, ActionIsolateHost, runtimeToolIsolateHost, map[string]any{
		"resource_id": instanceID,
		"provider":    provider,
	})
}

func (h *DefaultActionHandler) QuarantineFile(ctx context.Context, resourceID, path string) error {
	return h.callRemoteRequired(ctx, ActionQuarantineFile, runtimeToolQuarantineFile, map[string]any{
		"resource_id": resourceID,
		"path":        path,
	})
}

func (h *DefaultActionHandler) BlockIP(ctx context.Context, ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("ip is required")
	}
	if err := authorizeActuation(ctx, ActionBlockIP, map[string]any{"ip": ip}); err != nil {
		return err
	}
	if h.blocklist != nil {
		h.blocklist.AddIP(ip, "runtime response containment", runtimeSourceSystem, runtimeSourceActor, nil)
	}
	_ = h.callRemoteBestEffort(ctx, ActionBlockIP, runtimeToolBlockIP, map[string]any{"ip": ip})
	return nil
}

func (h *DefaultActionHandler) BlockDomain(ctx context.Context, domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	if err := authorizeActuation(ctx, ActionBlockDomain, map[string]any{"domain": domain}); err != nil {
		return err
	}
	if h.blocklist != nil {
		h.blocklist.AddDomain(domain, "runtime response containment", runtimeSourceSystem, runtimeSourceActor, nil)
	}
	_ = h.callRemoteBestEffort(ctx, ActionBlockDomain, runtimeToolBlockDomain, map[string]any{"domain": domain})
	return nil
}

func (h *DefaultActionHandler) RevokeCredentials(ctx context.Context, principalID, provider string) error {
	return h.callRemoteRequired(ctx, ActionRevokeCredentials, runtimeToolRevokeCredentials, map[string]any{
		"principal_id": principalID,
		"provider":     provider,
	})
}

func (h *DefaultActionHandler) ScaleDown(ctx context.Context, resourceID string, replicas int) error {
	resourceID = strings.TrimSpace(resourceID)
	if replicas < 0 {
		return fmt.Errorf("replicas must be non-negative")
	}
	if err := authorizeActuation(ctx, ActionScaleDown, map[string]any{
		"resource_id": resourceID,
		"replicas":    replicas,
	}); err != nil {
		return err
	}
	replicas32, err := runtimeScaleReplicas32(replicas)
	if err != nil {
		return err
	}
	target, err := ParseWorkloadTarget(resourceID)
	if err == nil && h.workloadScaler != nil {
		if scaleErr := h.workloadScaler.ScaleDown(ctx, target, replicas32); scaleErr == nil {
			return nil
		} else {
			err = scaleErr
		}
	}
	if remoteErr := h.callRemoteBestEffort(ctx, ActionScaleDown, runtimeToolScaleDown, map[string]any{
		"resource_id": resourceID,
		"replicas":    replicas,
	}); remoteErr == nil {
		return nil
	}
	if err != nil {
		return err
	}
	return &ActionCapabilityError{
		Action:  ActionScaleDown,
		Code:    "direct_target_unresolved",
		Message: fmt.Sprintf("runtime action %s requires an explicit workload target", ActionScaleDown),
	}
}

func (h *DefaultActionHandler) callRemoteRequired(ctx context.Context, action ResponseActionType, tool string, payload map[string]any) error {
	caller := h.currentRemoteCaller()
	if caller == nil {
		return &ActionCapabilityError{
			Action:  action,
			Code:    "requires_ensemble",
			Message: fmt.Sprintf("runtime action %s requires an Ensemble remote tool", action),
		}
	}
	if err := authorizeActuation(ctx, action, payload); err != nil {
		return err
	}
	args, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal runtime remote payload: %w", err)
	}
	_, err = caller.CallTool(ctx, tool, args, remainingRuntimeTimeout(ctx, h.remoteTimeout))
	return err
}

func (h *DefaultActionHandler) callRemoteBestEffort(ctx context.Context, action ResponseActionType, tool string, payload map[string]any) error {
	caller := h.currentRemoteCaller()
	if caller == nil {
		return fmt.Errorf("remote tool caller not configured")
	}
	if err := authorizeActuation(ctx, action, payload); err != nil {
		return err
	}
	args, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = caller.CallTool(ctx, tool, args, remainingRuntimeTimeout(ctx, h.remoteTimeout))
	return err
}

func (h *DefaultActionHandler) currentRemoteCaller() RemoteActionCaller {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.remoteCaller
}

func authorizeActuation(ctx context.Context, action ResponseActionType, payload map[string]any) error {
	scope, ok := TrustedActuationScopeFromContext(ctx)
	if !ok {
		return &ActionCapabilityError{
			Action:  action,
			Code:    "trusted_scope_required",
			Message: fmt.Sprintf("runtime action %s requires a trusted actuation scope", action),
		}
	}

	switch action {
	case ActionKillProcess, ActionIsolateHost, ActionQuarantineFile:
		if !scopeAllows(scope.AllowedResourceIDs, runtimeMapValueToString(payload, "resource_id")) {
			return unauthorizedRuntimeTargetError(action)
		}
	case ActionIsolateContainer:
		containerID := runtimeMapValueToString(payload, "container_id")
		namespace := runtimeMapValueToString(payload, "namespace")
		if !scopeAllows(scope.AllowedContainerIDs, containerID) || !scopeAllows(scope.AllowedNamespaces, namespace) {
			return unauthorizedRuntimeTargetError(action)
		}
	case ActionRevokeCredentials:
		if !scopeAllows(scope.AllowedPrincipalIDs, runtimeMapValueToString(payload, "principal_id")) {
			return unauthorizedRuntimeTargetError(action)
		}
	case ActionScaleDown:
		if !scopeAllows(scope.AllowedWorkloadTargets, runtimeMapValueToString(payload, "resource_id")) {
			return unauthorizedRuntimeTargetError(action)
		}
	case ActionBlockIP, ActionBlockDomain:
		if !scope.AllowNetworkContainment {
			return unauthorizedRuntimeTargetError(action)
		}
	}
	return nil
}

func unauthorizedRuntimeTargetError(action ResponseActionType) error {
	return &ActionCapabilityError{
		Action:  action,
		Code:    "target_not_authorized",
		Message: fmt.Sprintf("runtime action %s target is outside the trusted actuation scope", action),
	}
}

func scopeAllows(values []string, candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return false
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), candidate) {
			return true
		}
	}
	return false
}

func withDerivedTrustedActuationScope(ctx context.Context, finding *RuntimeFinding) context.Context {
	if _, ok := TrustedActuationScopeFromContext(ctx); ok {
		return ctx
	}
	scope := trustedActuationScopeForFinding(finding)
	if trustedActuationScopeEmpty(scope) {
		return ctx
	}
	return WithTrustedActuationScope(ctx, scope)
}

func trustedActuationScopeForFinding(finding *RuntimeFinding) TrustedActuationScope {
	if finding == nil {
		return TrustedActuationScope{}
	}
	scope := TrustedActuationScope{}
	appendUnique := func(values []string, candidate string) []string {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return values
		}
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), candidate) {
				return values
			}
		}
		return append(values, candidate)
	}

	scope.AllowedResourceIDs = appendUnique(scope.AllowedResourceIDs, finding.ResourceID)
	if target, err := ParseWorkloadTarget(finding.ResourceID); err == nil {
		scope.AllowedWorkloadTargets = appendUnique(scope.AllowedWorkloadTargets, target.String())
	}
	if finding.Event != nil {
		if finding.Event.Network != nil {
			scope.AllowNetworkContainment = true
		}
		if finding.Event.Container != nil {
			scope.AllowedContainerIDs = appendUnique(scope.AllowedContainerIDs, finding.Event.Container.ContainerID)
			scope.AllowedNamespaces = appendUnique(scope.AllowedNamespaces, finding.Event.Container.Namespace)
		}
		scope.AllowedNamespaces = appendUnique(scope.AllowedNamespaces, runtimeMapValueToString(finding.Event.Metadata, "namespace"))
		scope.AllowedNamespaces = appendUnique(scope.AllowedNamespaces, runtimeMapValueToString(finding.Event.Metadata, "kubernetes_namespace"))
	}
	scope.AllowedPrincipalIDs = appendUnique(scope.AllowedPrincipalIDs, runtimePrincipalIDFromFinding(finding))
	scope.AllowedWorkloadTargets = appendUnique(scope.AllowedWorkloadTargets, runtimeScaleDownTargetFromFinding(finding))
	return scope
}

func trustedActuationScopeEmpty(scope TrustedActuationScope) bool {
	return len(scope.AllowedResourceIDs) == 0 &&
		len(scope.AllowedContainerIDs) == 0 &&
		len(scope.AllowedNamespaces) == 0 &&
		len(scope.AllowedWorkloadTargets) == 0 &&
		len(scope.AllowedPrincipalIDs) == 0 &&
		!scope.AllowNetworkContainment
}

func runtimeScaleReplicas32(replicas int) (int32, error) {
	if replicas < 0 {
		return 0, fmt.Errorf("replicas must be non-negative")
	}
	if replicas > maxRuntimeScaleReplicas {
		return 0, fmt.Errorf("replicas must be <= %d", maxRuntimeScaleReplicas)
	}
	return int32(replicas), nil
}

func remainingRuntimeTimeout(ctx context.Context, fallback time.Duration) time.Duration {
	if fallback <= 0 {
		fallback = defaultRuntimeRemoteActionTimeout
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return fallback
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return time.Millisecond
	}
	if remaining < fallback {
		return remaining
	}
	return fallback
}

func ParseWorkloadTarget(resourceID string) (WorkloadTarget, error) {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" {
		return WorkloadTarget{}, fmt.Errorf("workload target is required")
	}
	parts := strings.SplitN(resourceID, ":", 2)
	if len(parts) != 2 {
		return WorkloadTarget{}, fmt.Errorf("unsupported workload target %q", resourceID)
	}
	kind := normalizeWorkloadKind(parts[0])
	location := strings.TrimSpace(parts[1])
	locationParts := strings.SplitN(location, "/", 2)
	if kind == "" || len(locationParts) != 2 {
		return WorkloadTarget{}, fmt.Errorf("unsupported workload target %q", resourceID)
	}
	namespace := strings.TrimSpace(locationParts[0])
	name := strings.TrimSpace(locationParts[1])
	if namespace == "" || name == "" {
		return WorkloadTarget{}, fmt.Errorf("unsupported workload target %q", resourceID)
	}
	return WorkloadTarget{
		Kind:      kind,
		Namespace: namespace,
		Name:      name,
	}, nil
}

func normalizeWorkloadKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "deployment", "deploy":
		return "deployment"
	case "statefulset", "sts":
		return "statefulset"
	default:
		return ""
	}
}

type KubernetesWorkloadScaler struct {
	kubeconfig  string
	kubeContext string
}

func NewKubernetesWorkloadScaler(kubeconfig, kubeContext string) *KubernetesWorkloadScaler {
	return &KubernetesWorkloadScaler{
		kubeconfig:  strings.TrimSpace(kubeconfig),
		kubeContext: strings.TrimSpace(kubeContext),
	}
}

func (s *KubernetesWorkloadScaler) ScaleDown(ctx context.Context, target WorkloadTarget, replicas int32) error {
	config, err := s.loadConfig()
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("create kubernetes client: %w", err)
	}
	switch target.Kind {
	case "deployment":
		scale, getErr := client.AppsV1().Deployments(target.Namespace).GetScale(ctx, target.Name, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("get deployment scale: %w", getErr)
		}
		scale.Spec.Replicas = replicas
		_, updateErr := client.AppsV1().Deployments(target.Namespace).UpdateScale(ctx, target.Name, scale, metav1.UpdateOptions{})
		return updateErr
	case "statefulset":
		scale, getErr := client.AppsV1().StatefulSets(target.Namespace).GetScale(ctx, target.Name, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("get statefulset scale: %w", getErr)
		}
		scale.Spec.Replicas = replicas
		_, updateErr := client.AppsV1().StatefulSets(target.Namespace).UpdateScale(ctx, target.Name, scale, metav1.UpdateOptions{})
		return updateErr
	default:
		return fmt.Errorf("unsupported workload kind %q", target.Kind)
	}
}

func (s *KubernetesWorkloadScaler) loadConfig() (*rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if s.kubeconfig != "" {
		rules.ExplicitPath = s.kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if s.kubeContext != "" {
		overrides.CurrentContext = s.kubeContext
	}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	cfg, err := clientConfig.ClientConfig()
	if err == nil {
		return cfg, nil
	}
	if s.kubeconfig != "" {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	inClusterCfg, inClusterErr := rest.InClusterConfig()
	if inClusterErr != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	return inClusterCfg, nil
}

func runtimeScaleDownTargetFromFinding(finding *RuntimeFinding) string {
	if finding == nil {
		return ""
	}
	metadata := map[string]any(nil)
	if finding.Event != nil {
		metadata = finding.Event.Metadata
	}
	kind := firstNonEmptyRuntime(
		runtimeMapValueToString(metadata, "workload_kind"),
		runtimeMapValueToString(metadata, "controller_kind"),
		finding.ResourceType,
	)
	name := firstNonEmptyRuntime(
		runtimeMapValueToString(metadata, "workload_name"),
		runtimeMapValueToString(metadata, "controller_name"),
		runtimeMapValueToString(metadata, "deployment"),
		runtimeMapValueToString(metadata, "statefulset"),
	)
	namespace := firstNonEmptyRuntime(
		runtimeMapValueToString(metadata, "namespace"),
		runtimeMapValueToString(metadata, "kubernetes_namespace"),
	)
	if finding.Event != nil && finding.Event.Container != nil {
		namespace = firstNonEmptyRuntime(namespace, finding.Event.Container.Namespace)
	}
	if name == "" {
		switch normalizeWorkloadKind(finding.ResourceType) {
		case "deployment", "statefulset":
			name = extractRuntimeResourceName(finding.ResourceID)
		}
	}
	kind = normalizeWorkloadKind(kind)
	if kind == "" || name == "" || namespace == "" {
		return ""
	}
	return WorkloadTarget{Kind: kind, Namespace: namespace, Name: name}.String()
}

func runtimeScaleDownReplicas(action PolicyAction) (int, error) {
	if action.Parameters == nil {
		return 0, fmt.Errorf("scale_down requires replicas parameter")
	}
	value := strings.TrimSpace(action.Parameters["replicas"])
	if value == "" {
		return 0, fmt.Errorf("scale_down requires replicas parameter")
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid replicas value %q: %w", value, err)
	}
	if _, err := runtimeScaleReplicas32(parsed); err != nil {
		return 0, err
	}
	return parsed, nil
}

func runtimeProviderFromFinding(finding *RuntimeFinding) string {
	if finding == nil || finding.Event == nil {
		return ""
	}
	return firstNonEmptyRuntime(
		runtimeMapValueToString(finding.Event.Metadata, "provider"),
		runtimeMapValueToString(finding.Event.Metadata, "cloud_provider"),
		runtimeMapValueToString(finding.Event.Metadata, "identity_provider"),
	)
}

func runtimePrincipalIDFromFinding(finding *RuntimeFinding) string {
	if finding == nil || finding.Event == nil {
		return ""
	}
	return firstNonEmptyRuntime(
		runtimeMapValueToString(finding.Event.Metadata, "principal_id"),
		runtimeMapValueToString(finding.Event.Metadata, "credential_id"),
		runtimeMapValueToString(finding.Event.Metadata, "access_key_id"),
	)
}

func extractRuntimeResourceName(resourceID string) string {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" {
		return ""
	}
	if idx := strings.LastIndex(resourceID, "/"); idx >= 0 && idx+1 < len(resourceID) {
		return strings.TrimSpace(resourceID[idx+1:])
	}
	return resourceID
}
