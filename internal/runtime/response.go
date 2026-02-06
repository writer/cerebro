package runtime

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ResponseEngine handles automated threat response actions
type ResponseEngine struct {
	policies      map[string]*ResponsePolicy
	executions    []*ResponseExecution
	blocklist     *Blocklist
	actionHandler ActionHandler
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
	defer e.mu.RUnlock()

	for _, policy := range e.policies {
		if !policy.Enabled {
			continue
		}

		if e.matchesTriggers(finding, policy.Triggers) {
			return e.createExecution(ctx, policy, finding), nil
		}
	}

	return nil, nil
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
	execution := &ResponseExecution{
		ID:           fmt.Sprintf("exec-%s-%d", policy.ID, time.Now().UnixNano()),
		PolicyID:     policy.ID,
		PolicyName:   policy.Name,
		TriggerEvent: finding.ID,
		Status:       StatusPending,
		ResourceID:   finding.ResourceID,
		ResourceType: finding.ResourceType,
		StartTime:    time.Now(),
	}

	if policy.RequireApproval {
		execution.Status = StatusApproval
		e.mu.Lock()
		e.executions = append(e.executions, execution)
		e.mu.Unlock()
		return execution
	}

	// Execute immediately
	execution.Status = StatusRunning
	err := e.executeActions(ctx, execution, policy.Actions, finding)
	if err != nil {
		execution.Status = StatusFailed
		execution.Error = err.Error()
	} else {
		execution.Status = StatusCompleted
	}

	now := time.Now()
	execution.EndTime = &now

	e.mu.Lock()
	e.executions = append(e.executions, execution)
	e.mu.Unlock()

	return execution
}

func (e *ResponseEngine) executeActions(ctx context.Context, execution *ResponseExecution, actions []PolicyAction, finding *RuntimeFinding) error {
	for _, action := range actions {
		actionExec := ActionExecution{
			Type:      action.Type,
			Status:    StatusRunning,
			StartTime: time.Now(),
		}

		err := e.executeAction(ctx, action, finding)

		now := time.Now()
		actionExec.EndTime = &now

		if err != nil {
			actionExec.Status = StatusFailed
			actionExec.Error = err.Error()

			if action.OnFailure == "abort" {
				execution.Actions = append(execution.Actions, actionExec)
				return err
			}
		} else {
			actionExec.Status = StatusCompleted
		}

		execution.Actions = append(execution.Actions, actionExec)
	}

	return nil
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

// ApproveExecution approves a pending execution
func (e *ResponseEngine) ApproveExecution(ctx context.Context, executionID, approver string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, exec := range e.executions {
		if exec.ID == executionID {
			if exec.Status != StatusApproval {
				return fmt.Errorf("execution not awaiting approval")
			}

			now := time.Now()
			exec.ApprovedBy = approver
			exec.ApprovedAt = &now
			exec.Status = StatusRunning

			// Get policy and execute
			policy, ok := e.policies[exec.PolicyID]
			if !ok {
				return fmt.Errorf("policy not found")
			}

			// Create dummy finding for execution
			finding := &RuntimeFinding{
				ID:         exec.TriggerEvent,
				ResourceID: exec.ResourceID,
			}

			go func() {
				err := e.executeActions(ctx, exec, policy.Actions, finding)
				if err != nil {
					exec.Status = StatusFailed
					exec.Error = err.Error()
				} else {
					exec.Status = StatusCompleted
				}
				end := time.Now()
				exec.EndTime = &end
			}()

			return nil
		}
	}

	return fmt.Errorf("execution not found")
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

			exec.Status = StatusCanceled
			exec.Error = fmt.Sprintf("Rejected by %s: %s", rejecter, reason)
			now := time.Now()
			exec.EndTime = &now
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
