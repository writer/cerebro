package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/evalops/cerebro/internal/actionengine"
)

// ResponseEngine handles automated threat response actions
type ResponseEngine struct {
	policies      map[string]*ResponsePolicy
	executions    []*ResponseExecution
	blocklist     *Blocklist
	actionHandler ActionHandler
	shared        *actionengine.Executor
	mu            sync.RWMutex
}

// ResponsePolicy defines automated response rules
type ResponsePolicy struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Enabled         bool            `json:"enabled"`
	Priority        int             `json:"priority"`
	Triggers        []PolicyTrigger `json:"triggers"`
	Actions         []PolicyAction  `json:"actions"`
	RequireApproval bool            `json:"require_approval"`
	Scope           PolicyScope     `json:"scope"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// PolicyTrigger defines when a policy should activate
type PolicyTrigger struct {
	Type       string            `json:"type"` // finding, detection, threshold
	Category   DetectionCategory `json:"category,omitempty"`
	Severity   string            `json:"severity,omitempty"`
	RuleID     string            `json:"rule_id,omitempty"`
	Conditions map[string]string `json:"conditions,omitempty"`
}

// PolicyAction defines what action to take
type PolicyAction struct {
	Type       ResponseActionType `json:"type"`
	Parameters map[string]string  `json:"parameters,omitempty"`
	Timeout    int                `json:"timeout_seconds,omitempty"`
	OnFailure  string             `json:"on_failure,omitempty"` // continue, abort
}

type ResponseActionType string

const (
	ActionKillProcess       ResponseActionType = "kill_process"
	ActionIsolateContainer  ResponseActionType = "isolate_container"
	ActionIsolateHost       ResponseActionType = "isolate_host"
	ActionQuarantineFile    ResponseActionType = "quarantine_file"
	ActionBlockIP           ResponseActionType = "block_ip"
	ActionBlockDomain       ResponseActionType = "block_domain"
	ActionRevokeCredentials ResponseActionType = "revoke_credentials" //nolint:gosec // G101 false positive - this is an action type name, not a credential
	ActionScaleDown         ResponseActionType = "scale_down"
	ActionAlert             ResponseActionType = "alert"
	ActionCreateTicket      ResponseActionType = "create_ticket"
	ActionWebhook           ResponseActionType = "webhook"
)

var supportedResponseActions = []ResponseActionType{
	ActionKillProcess,
	ActionIsolateContainer,
	ActionIsolateHost,
	ActionBlockIP,
	ActionBlockDomain,
	ActionAlert,
	ActionCreateTicket,
}

// PolicyScope limits where policy applies
type PolicyScope struct {
	Clusters   []string          `json:"clusters,omitempty"`
	Namespaces []string          `json:"namespaces,omitempty"`
	Accounts   []string          `json:"accounts,omitempty"`
	Regions    []string          `json:"regions,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
}

// ResponseExecution tracks a response action execution
type ResponseExecution struct {
	ID           string            `json:"id"`
	PolicyID     string            `json:"policy_id"`
	PolicyName   string            `json:"policy_name"`
	TriggerEvent string            `json:"trigger_event"`
	TriggerData  map[string]any    `json:"trigger_data,omitempty"`
	Actions      []ActionExecution `json:"actions"`
	Status       ExecutionStatus   `json:"status"`
	ResourceID   string            `json:"resource_id"`
	ResourceType string            `json:"resource_type"`
	ApprovedBy   string            `json:"approved_by,omitempty"`
	ApprovedAt   *time.Time        `json:"approved_at,omitempty"`
	StartTime    time.Time         `json:"start_time"`
	EndTime      *time.Time        `json:"end_time,omitempty"`
	Error        string            `json:"error,omitempty"`
}

type ActionExecution struct {
	Type      ResponseActionType `json:"type"`
	Status    ExecutionStatus    `json:"status"`
	StartTime time.Time          `json:"start_time"`
	EndTime   *time.Time         `json:"end_time,omitempty"`
	Output    string             `json:"output,omitempty"`
	Error     string             `json:"error,omitempty"`
}

type ExecutionStatus string

const (
	StatusPending   ExecutionStatus = "pending"
	StatusApproval  ExecutionStatus = "awaiting_approval"
	StatusRunning   ExecutionStatus = "running"
	StatusCompleted ExecutionStatus = "completed"
	StatusFailed    ExecutionStatus = "failed"
	StatusCanceled  ExecutionStatus = "canceled"
)

// Blocklist maintains runtime blocklists
type Blocklist struct {
	IPs       map[string]*BlockEntry `json:"ips"`
	Domains   map[string]*BlockEntry `json:"domains"`
	Hashes    map[string]*BlockEntry `json:"hashes"`
	Processes map[string]*BlockEntry `json:"processes"`
	mu        sync.RWMutex
}

type BlockEntry struct {
	Value     string     `json:"value"`
	Type      string     `json:"type"`
	Reason    string     `json:"reason"`
	Source    string     `json:"source"` // manual, policy, threat_intel
	AddedAt   time.Time  `json:"added_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	AddedBy   string     `json:"added_by"`
}

// ActionHandler interface for executing response actions
type ActionHandler interface {
	KillProcess(ctx context.Context, resourceID string, pid int) error
	IsolateContainer(ctx context.Context, containerID, namespace string) error
	IsolateHost(ctx context.Context, instanceID, provider string) error
	QuarantineFile(ctx context.Context, resourceID, path string) error
	BlockIP(ctx context.Context, ip string) error
	BlockDomain(ctx context.Context, domain string) error
	RevokeCredentials(ctx context.Context, principalID, provider string) error
	ScaleDown(ctx context.Context, resourceID string, replicas int) error
}

func NewResponseEngine() *ResponseEngine {
	engine := &ResponseEngine{
		policies:   make(map[string]*ResponsePolicy),
		executions: make([]*ResponseExecution, 0),
		blocklist:  NewBlocklist(),
		shared:     actionengine.NewExecutor(nil),
	}
	engine.loadDefaultPolicies()
	return engine
}

func NewBlocklist() *Blocklist {
	return &Blocklist{
		IPs:       make(map[string]*BlockEntry),
		Domains:   make(map[string]*BlockEntry),
		Hashes:    make(map[string]*BlockEntry),
		Processes: make(map[string]*BlockEntry),
	}
}

func (e *ResponseEngine) SetActionHandler(handler ActionHandler) {
	e.actionHandler = handler
}

func (e *ResponseEngine) SetSharedExecutor(shared *actionengine.Executor) {
	if shared == nil {
		return
	}
	e.shared = shared
}

func (e *ResponseEngine) loadDefaultPolicies() {
	policies := []*ResponsePolicy{
		{
			ID:          "auto-kill-crypto-miner",
			Name:        "Kill Cryptocurrency Miner",
			Description: "Automatically terminate cryptocurrency mining processes",
			Enabled:     true,
			Priority:    1,
			Triggers: []PolicyTrigger{
				{Type: "detection", Category: CategoryCryptoMining, Severity: "high"},
			},
			Actions: []PolicyAction{
				{Type: ActionKillProcess, Timeout: 30},
				{Type: ActionAlert, Parameters: map[string]string{"channel": "security"}},
			},
			RequireApproval: false,
		},
		{
			ID:          "auto-isolate-container-escape",
			Name:        "Isolate Container on Escape Attempt",
			Description: "Automatically isolate containers attempting escape",
			Enabled:     true,
			Priority:    1,
			Triggers: []PolicyTrigger{
				{Type: "detection", Category: CategoryContainerEscape, Severity: "critical"},
			},
			Actions: []PolicyAction{
				{Type: ActionIsolateContainer, Timeout: 30},
				{Type: ActionAlert, Parameters: map[string]string{"channel": "security", "severity": "critical"}},
				{Type: ActionCreateTicket, Parameters: map[string]string{"priority": "critical"}},
			},
			RequireApproval: false,
		},
		{
			ID:          "auto-kill-reverse-shell",
			Name:        "Kill Reverse Shell",
			Description: "Automatically terminate reverse shell processes",
			Enabled:     true,
			Priority:    1,
			Triggers: []PolicyTrigger{
				{Type: "detection", Category: CategoryReverseShell, Severity: "critical"},
			},
			Actions: []PolicyAction{
				{Type: ActionKillProcess, Timeout: 10},
				{Type: ActionBlockIP, Parameters: map[string]string{"target": "destination"}},
				{Type: ActionAlert, Parameters: map[string]string{"channel": "security", "severity": "critical"}},
			},
			RequireApproval: false,
		},
		{
			ID:          "block-c2-communication",
			Name:        "Block C2 Communication",
			Description: "Block communication to known C2 servers",
			Enabled:     true,
			Priority:    1,
			Triggers: []PolicyTrigger{
				{Type: "threat_intel", Category: CategoryMalware},
			},
			Actions: []PolicyAction{
				{Type: ActionBlockIP},
				{Type: ActionBlockDomain},
				{Type: ActionAlert},
			},
			RequireApproval: false,
		},
		{
			ID:          "isolate-compromised-host",
			Name:        "Isolate Compromised Host",
			Description: "Isolate host showing signs of compromise (requires approval)",
			Enabled:     true,
			Priority:    2,
			Triggers: []PolicyTrigger{
				{Type: "detection", Category: CategoryLateralMovement, Severity: "high"},
				{Type: "detection", Category: CategoryCredentialAccess, Severity: "critical"},
			},
			Actions: []PolicyAction{
				{Type: ActionIsolateHost, Timeout: 300},
				{Type: ActionRevokeCredentials},
				{Type: ActionAlert, Parameters: map[string]string{"channel": "incident-response"}},
			},
			RequireApproval: true,
		},
		{
			ID:          "scale-down-drift",
			Name:        "Scale Down on Critical Drift",
			Description: "Scale down workloads with critical configuration drift",
			Enabled:     false, // Disabled by default
			Priority:    3,
			Triggers: []PolicyTrigger{
				{Type: "detection", Category: CategoryContainerDrift, Severity: "critical"},
			},
			Actions: []PolicyAction{
				{Type: ActionScaleDown, Parameters: map[string]string{"replicas": "0"}},
				{Type: ActionCreateTicket},
			},
			RequireApproval: true,
		},
	}

	for _, p := range policies {
		p.CreatedAt = time.Now()
		p.UpdatedAt = time.Now()
		e.policies[p.ID] = p
	}
}

// ProcessFinding evaluates a runtime finding against policies
func (e *ResponseEngine) ProcessFinding(ctx context.Context, finding *RuntimeFinding) (*ResponseExecution, error) {
	e.mu.RLock()
	var matched *ResponsePolicy
	for _, policy := range e.policies {
		if !policy.Enabled {
			continue
		}

		if e.matchesTriggers(finding, policy.Triggers) {
			matched = cloneResponsePolicy(policy)
			break
		}
	}
	e.mu.RUnlock()

	if matched == nil {
		return nil, nil
	}
	return e.createExecution(ctx, matched, finding), nil
}

func (e *ResponseEngine) matchesTriggers(finding *RuntimeFinding, triggers []PolicyTrigger) bool {
	for _, trigger := range triggers {
		if trigger.Type != "detection" && trigger.Type != "finding" {
			continue
		}

		if trigger.Category != "" && trigger.Category != finding.Category {
			continue
		}

		if trigger.Severity != "" {
			if !severityMatches(finding.Severity, trigger.Severity) {
				continue
			}
		}

		if trigger.RuleID != "" && trigger.RuleID != finding.RuleID {
			continue
		}

		return true
	}
	return false
}

func severityMatches(actual, required string) bool {
	severityRank := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
	}

	return severityRank[actual] >= severityRank[required]
}

func (e *ResponseEngine) createExecution(ctx context.Context, policy *ResponsePolicy, finding *RuntimeFinding) *ResponseExecution {
	playbook := runtimePlaybookFromPolicy(policy)
	signal := runtimeSignalFromFinding(finding)
	sharedExecution := e.shared.NewExecution(playbook, signal)
	_ = e.shared.Execute(ctx, sharedExecution, playbook, signal, runtimeStepRunner{engine: e})

	execution := responseExecutionFromShared(sharedExecution, policy)
	e.mu.Lock()
	e.executions = append(e.executions, execution)
	e.mu.Unlock()
	return execution
}

func (e *ResponseEngine) executeAction(ctx context.Context, action PolicyAction, finding *RuntimeFinding) error {
	if e.actionHandler == nil {
		return fmt.Errorf("no action handler configured")
	}

	switch action.Type {
	case ActionKillProcess:
		if finding.Event != nil && finding.Event.Process != nil {
			return e.actionHandler.KillProcess(ctx, finding.ResourceID, finding.Event.Process.PID)
		}

	case ActionIsolateContainer:
		if finding.Event != nil && finding.Event.Container != nil {
			return e.actionHandler.IsolateContainer(ctx,
				finding.Event.Container.ContainerID,
				finding.Event.Container.Namespace)
		}

	case ActionIsolateHost:
		return e.actionHandler.IsolateHost(ctx, finding.ResourceID, "")

	case ActionBlockIP:
		if finding.Event != nil && finding.Event.Network != nil {
			ip := finding.Event.Network.DstIP
			if action.Parameters["target"] == "source" {
				ip = finding.Event.Network.SrcIP
			}
			return e.actionHandler.BlockIP(ctx, ip)
		}

	case ActionBlockDomain:
		if finding.Event != nil && finding.Event.Network != nil {
			return e.actionHandler.BlockDomain(ctx, finding.Event.Network.Domain)
		}

	case ActionAlert:
		// Alert is handled separately by notification system
		return nil

	case ActionCreateTicket:
		// Ticket creation handled separately
		return nil

	default:
		return unsupportedResponseActionError(action.Type, supportedResponseActions)
	}

	return nil
}

type runtimeStepRunner struct {
	engine *ResponseEngine
}

func (r runtimeStepRunner) RunStep(ctx context.Context, step actionengine.Step, signal actionengine.Signal, execution *actionengine.Execution) (string, error) {
	if r.engine == nil {
		return "", fmt.Errorf("response engine is nil")
	}
	action := PolicyAction{
		Type:       ResponseActionType(step.Type),
		Parameters: cloneRuntimeStringMap(step.Parameters),
		Timeout:    step.TimeoutSeconds,
	}
	finding := runtimeFindingFromSignal(signal)
	if err := r.engine.executeAction(ctx, action, finding); err != nil {
		return "", err
	}
	return step.Type + " executed", nil
}

func runtimePlaybookFromPolicy(policy *ResponsePolicy) actionengine.Playbook {
	if policy == nil {
		return actionengine.Playbook{}
	}
	steps := make([]actionengine.Step, 0, len(policy.Actions))
	for idx, action := range policy.Actions {
		failurePolicy := actionengine.FailurePolicyContinue
		if action.OnFailure == "abort" {
			failurePolicy = actionengine.FailurePolicyAbort
		}
		steps = append(steps, actionengine.Step{
			ID:             fmt.Sprintf("%s-step-%d", policy.ID, idx+1),
			Type:           string(action.Type),
			Parameters:     cloneRuntimeStringMap(action.Parameters),
			TimeoutSeconds: action.Timeout,
			OnFailure:      failurePolicy,
		})
	}
	triggers := make([]actionengine.Trigger, 0, len(policy.Triggers))
	for _, trigger := range policy.Triggers {
		triggers = append(triggers, actionengine.Trigger{
			Kind:              trigger.Type,
			Severity:          trigger.Severity,
			SeverityMatchMode: actionengine.SeverityMatchMinimum,
			Category:          string(trigger.Category),
			RuleID:            trigger.RuleID,
			Conditions:        cloneRuntimeStringMap(trigger.Conditions),
		})
	}
	return actionengine.Playbook{
		ID:              policy.ID,
		Name:            policy.Name,
		Description:     policy.Description,
		Enabled:         policy.Enabled,
		Priority:        policy.Priority,
		Triggers:        triggers,
		Steps:           steps,
		RequireApproval: policy.RequireApproval,
		CreatedAt:       policy.CreatedAt,
		UpdatedAt:       policy.UpdatedAt,
	}
}

func runtimeSignalFromFinding(finding *RuntimeFinding) actionengine.Signal {
	signal := actionengine.Signal{
		ID:           findingID(finding),
		Kind:         "finding",
		Severity:     findingSeverity(finding),
		Category:     string(findingCategory(finding)),
		RuleID:       findingRuleID(finding),
		ResourceID:   findingResourceID(finding),
		ResourceType: findingResourceType(finding),
		Data:         map[string]any{},
		CreatedAt:    time.Now().UTC(),
	}
	if finding == nil {
		return signal
	}
	var payload map[string]any
	if bytes, err := json.Marshal(finding); err == nil {
		_ = json.Unmarshal(bytes, &payload)
	}
	if payload != nil {
		signal.Data["finding"] = payload
	}
	if signal.RuleID != "" {
		signal.Data["rule_id"] = signal.RuleID
	}
	if signal.ResourceID != "" {
		signal.Data["resource_id"] = signal.ResourceID
	}
	if signal.ResourceType != "" {
		signal.Data["resource_type"] = signal.ResourceType
	}
	return signal
}

func runtimeSignalFromTriggerData(data map[string]any) actionengine.Signal {
	signal := actionengine.Signal{
		ID:           runtimeMapValueToString(data, "finding_id"),
		Kind:         firstNonEmptyRuntime(runtimeMapValueToString(data, "signal_kind"), runtimeMapValueToString(data, "type"), "finding"),
		Severity:     runtimeMapValueToString(data, "severity"),
		Category:     runtimeMapValueToString(data, "category"),
		RuleID:       runtimeMapValueToString(data, "rule_id"),
		ResourceID:   runtimeMapValueToString(data, "resource_id"),
		ResourceType: runtimeMapValueToString(data, "resource_type"),
		Data:         cloneRuntimeAnyMap(data),
		CreatedAt:    time.Now().UTC(),
	}
	return signal
}

func runtimeFindingFromSignal(signal actionengine.Signal) *RuntimeFinding {
	if signal.Data != nil {
		if raw, ok := signal.Data["finding"]; ok {
			bytes, err := json.Marshal(raw)
			if err == nil {
				var finding RuntimeFinding
				if err := json.Unmarshal(bytes, &finding); err == nil {
					if finding.ID == "" {
						finding.ID = signal.ID
					}
					if finding.ResourceID == "" {
						finding.ResourceID = signal.ResourceID
					}
					if finding.ResourceType == "" {
						finding.ResourceType = signal.ResourceType
					}
					if finding.Severity == "" {
						finding.Severity = signal.Severity
					}
					if finding.Category == "" {
						finding.Category = DetectionCategory(signal.Category)
					}
					return &finding
				}
			}
		}
	}
	return &RuntimeFinding{
		ID:           signal.ID,
		Severity:     signal.Severity,
		Category:     DetectionCategory(signal.Category),
		RuleID:       signal.RuleID,
		ResourceID:   signal.ResourceID,
		ResourceType: signal.ResourceType,
	}
}

func responseExecutionFromShared(shared *actionengine.Execution, policy *ResponsePolicy) *ResponseExecution {
	execution := &ResponseExecution{
		ID:           shared.ID,
		PolicyID:     shared.PlaybookID,
		PolicyName:   shared.PlaybookName,
		TriggerEvent: shared.SignalID,
		TriggerData:  cloneRuntimeAnyMap(shared.TriggerData),
		Status:       sharedStatusToRuntime(shared.Status),
		ResourceID:   shared.ResourceID,
		ResourceType: shared.ResourceType,
		ApprovedBy:   shared.ApprovedBy,
		ApprovedAt:   shared.ApprovedAt,
		StartTime:    shared.StartedAt,
		EndTime:      shared.CompletedAt,
		Error:        shared.Error,
		Actions:      make([]ActionExecution, 0, len(shared.Results)),
	}
	if policy != nil && execution.PolicyName == "" {
		execution.PolicyName = policy.Name
	}
	for _, result := range shared.Results {
		execution.Actions = append(execution.Actions, ActionExecution{
			Type:      ResponseActionType(result.Type),
			Status:    sharedStatusToRuntime(result.Status),
			StartTime: result.StartedAt,
			EndTime:   result.CompletedAt,
			Output:    result.Output,
			Error:     result.Error,
		})
	}
	return execution
}

func runtimeExecutionToShared(execution *ResponseExecution) *actionengine.Execution {
	shared := &actionengine.Execution{
		ID:           execution.ID,
		PlaybookID:   execution.PolicyID,
		PlaybookName: execution.PolicyName,
		SignalID:     execution.TriggerEvent,
		Status:       runtimeStatusToShared(execution.Status),
		ResourceID:   execution.ResourceID,
		ResourceType: execution.ResourceType,
		TriggerData:  cloneRuntimeAnyMap(execution.TriggerData),
		Results:      make([]actionengine.ActionResult, 0, len(execution.Actions)),
		ApprovedBy:   execution.ApprovedBy,
		ApprovedAt:   execution.ApprovedAt,
		StartedAt:    execution.StartTime,
		CompletedAt:  execution.EndTime,
		Error:        execution.Error,
	}
	for _, action := range execution.Actions {
		shared.Results = append(shared.Results, actionengine.ActionResult{
			Type:        string(action.Type),
			Status:      runtimeStatusToShared(action.Status),
			Output:      action.Output,
			Error:       action.Error,
			StartedAt:   action.StartTime,
			CompletedAt: action.EndTime,
		})
	}
	return shared
}

func applySharedResponseExecution(target *ResponseExecution, shared *actionengine.Execution) {
	if target == nil || shared == nil {
		return
	}
	target.Status = sharedStatusToRuntime(shared.Status)
	target.TriggerData = cloneRuntimeAnyMap(shared.TriggerData)
	target.ResourceID = shared.ResourceID
	target.ResourceType = shared.ResourceType
	target.ApprovedBy = shared.ApprovedBy
	target.ApprovedAt = shared.ApprovedAt
	target.StartTime = shared.StartedAt
	target.EndTime = shared.CompletedAt
	target.Error = shared.Error
	target.Actions = make([]ActionExecution, 0, len(shared.Results))
	for _, result := range shared.Results {
		target.Actions = append(target.Actions, ActionExecution{
			Type:      ResponseActionType(result.Type),
			Status:    sharedStatusToRuntime(result.Status),
			StartTime: result.StartedAt,
			EndTime:   result.CompletedAt,
			Output:    result.Output,
			Error:     result.Error,
		})
	}
}

func runtimeStatusToShared(status ExecutionStatus) actionengine.Status {
	switch status {
	case StatusApproval:
		return actionengine.StatusAwaitingApproval
	case StatusRunning:
		return actionengine.StatusRunning
	case StatusCompleted:
		return actionengine.StatusCompleted
	case StatusFailed:
		return actionengine.StatusFailed
	case StatusCanceled:
		return actionengine.StatusCanceled
	default:
		return actionengine.StatusPending
	}
}

func sharedStatusToRuntime(status actionengine.Status) ExecutionStatus {
	switch status {
	case actionengine.StatusAwaitingApproval:
		return StatusApproval
	case actionengine.StatusRunning:
		return StatusRunning
	case actionengine.StatusCompleted:
		return StatusCompleted
	case actionengine.StatusFailed:
		return StatusFailed
	case actionengine.StatusCanceled:
		return StatusCanceled
	default:
		return StatusPending
	}
}

func findingID(finding *RuntimeFinding) string {
	if finding == nil {
		return ""
	}
	return finding.ID
}

func findingSeverity(finding *RuntimeFinding) string {
	if finding == nil {
		return ""
	}
	return finding.Severity
}

func findingCategory(finding *RuntimeFinding) DetectionCategory {
	if finding == nil {
		return ""
	}
	return finding.Category
}

func findingRuleID(finding *RuntimeFinding) string {
	if finding == nil {
		return ""
	}
	return finding.RuleID
}

func findingResourceID(finding *RuntimeFinding) string {
	if finding == nil {
		return ""
	}
	return finding.ResourceID
}

func findingResourceType(finding *RuntimeFinding) string {
	if finding == nil {
		return ""
	}
	return finding.ResourceType
}

func cloneRuntimeStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func cloneResponsePolicy(policy *ResponsePolicy) *ResponsePolicy {
	if policy == nil {
		return nil
	}
	cloned := *policy
	if len(policy.Triggers) > 0 {
		cloned.Triggers = make([]PolicyTrigger, 0, len(policy.Triggers))
		for _, trigger := range policy.Triggers {
			triggerCopy := trigger
			triggerCopy.Conditions = cloneRuntimeStringMap(trigger.Conditions)
			cloned.Triggers = append(cloned.Triggers, triggerCopy)
		}
	}
	if len(policy.Actions) > 0 {
		cloned.Actions = make([]PolicyAction, 0, len(policy.Actions))
		for _, action := range policy.Actions {
			actionCopy := action
			actionCopy.Parameters = cloneRuntimeStringMap(action.Parameters)
			cloned.Actions = append(cloned.Actions, actionCopy)
		}
	}
	cloned.Scope = PolicyScope{
		Clusters:   append([]string(nil), policy.Scope.Clusters...),
		Namespaces: append([]string(nil), policy.Scope.Namespaces...),
		Accounts:   append([]string(nil), policy.Scope.Accounts...),
		Regions:    append([]string(nil), policy.Scope.Regions...),
		Tags:       cloneRuntimeStringMap(policy.Scope.Tags),
	}
	return &cloned
}

func cloneRuntimeAnyMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func runtimeMapValueToString(values map[string]any, key string) string {
	if len(values) == 0 {
		return ""
	}
	value, ok := values[key]
	if !ok {
		return ""
	}
	return fmt.Sprintf("%v", value)
}

func firstNonEmptyRuntime(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// ApproveExecution approves a pending execution
func (e *ResponseEngine) ApproveExecution(ctx context.Context, executionID, approver string) error {
	e.mu.Lock()
	var target *ResponseExecution
	var policyCopy *ResponsePolicy
	var sharedExecution *actionengine.Execution
	var signal actionengine.Signal
	for _, exec := range e.executions {
		if exec.ID == executionID {
			if exec.Status != StatusApproval {
				e.mu.Unlock()
				return fmt.Errorf("execution not awaiting approval")
			}

			policy, ok := e.policies[exec.PolicyID]
			if !ok {
				e.mu.Unlock()
				return fmt.Errorf("policy not found")
			}
			target = exec
			policyCopy = cloneResponsePolicy(policy)
			now := time.Now().UTC()
			target.Status = StatusRunning
			target.ApprovedBy = approver
			target.ApprovedAt = &now
			target.Error = ""
			sharedExecution = runtimeExecutionToShared(target)
			signal = runtimeSignalFromTriggerData(target.TriggerData)
			break
		}
	}
	e.mu.Unlock()

	if target == nil || policyCopy == nil || sharedExecution == nil {
		return fmt.Errorf("execution not found")
	}
	err := e.shared.Approve(ctx, sharedExecution, approver, runtimePlaybookFromPolicy(policyCopy), signal, runtimeStepRunner{engine: e})
	e.mu.Lock()
	defer e.mu.Unlock()
	applySharedResponseExecution(target, sharedExecution)
	if err != nil {
		return err
	}
	return nil
}

// RejectExecution rejects a pending execution
func (e *ResponseEngine) RejectExecution(executionID, rejecter, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, exec := range e.executions {
		if exec.ID == executionID {
			if exec.Status != StatusApproval {
				return fmt.Errorf("execution not awaiting approval")
			}

			sharedExecution := runtimeExecutionToShared(exec)
			_ = e.shared.Reject(context.Background(), sharedExecution, rejecter, reason)
			applySharedResponseExecution(exec, sharedExecution)
			return nil
		}
	}

	return fmt.Errorf("execution not found")
}

// AddToBlocklist adds an entry to the blocklist
func (b *Blocklist) AddIP(ip, reason, source, addedBy string, expiration *time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.IPs[ip] = &BlockEntry{
		Value:     ip,
		Type:      "ip",
		Reason:    reason,
		Source:    source,
		AddedAt:   time.Now(),
		ExpiresAt: expiration,
		AddedBy:   addedBy,
	}
}

func (b *Blocklist) AddDomain(domain, reason, source, addedBy string, expiration *time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.Domains[domain] = &BlockEntry{
		Value:     domain,
		Type:      "domain",
		Reason:    reason,
		Source:    source,
		AddedAt:   time.Now(),
		ExpiresAt: expiration,
		AddedBy:   addedBy,
	}
}

func (b *Blocklist) IsBlocked(value, blockType string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var list map[string]*BlockEntry
	switch blockType {
	case "ip":
		list = b.IPs
	case "domain":
		list = b.Domains
	case "hash":
		list = b.Hashes
	default:
		return false
	}

	entry, exists := list[value]
	if !exists {
		return false
	}

	// Check expiration
	if entry.ExpiresAt != nil && time.Now().After(*entry.ExpiresAt) {
		return false
	}

	return true
}

// ListPolicies returns all response policies
func (e *ResponseEngine) ListPolicies() []*ResponsePolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	policies := make([]*ResponsePolicy, 0, len(e.policies))
	for _, p := range e.policies {
		policies = append(policies, p)
	}
	return policies
}

// ListExecutions returns recent executions
func (e *ResponseEngine) ListExecutions(limit int) []*ResponseExecution {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if limit <= 0 || limit > len(e.executions) {
		limit = len(e.executions)
	}

	// Return most recent
	start := len(e.executions) - limit
	if start < 0 {
		start = 0
	}

	result := make([]*ResponseExecution, limit)
	copy(result, e.executions[start:])
	return result
}

// CreatePolicy creates a new response policy
func (e *ResponseEngine) CreatePolicy(policy *ResponsePolicy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if policy.ID == "" {
		return fmt.Errorf("policy ID required")
	}

	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	e.policies[policy.ID] = policy
	return nil
}

// EnablePolicy enables a policy
func (e *ResponseEngine) EnablePolicy(policyID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	policy, ok := e.policies[policyID]
	if !ok {
		return fmt.Errorf("policy not found")
	}

	policy.Enabled = true
	policy.UpdatedAt = time.Now()
	return nil
}

// DisablePolicy disables a policy
func (e *ResponseEngine) DisablePolicy(policyID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	policy, ok := e.policies[policyID]
	if !ok {
		return fmt.Errorf("policy not found")
	}

	policy.Enabled = false
	policy.UpdatedAt = time.Now()
	return nil
}
