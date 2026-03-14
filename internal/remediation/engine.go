// Package remediation provides automated response and remediation capabilities
// for security findings. It implements a rule-based engine that triggers actions
// based on finding severity, policy violations, or scheduled events.
//
// The package supports:
//   - Event-driven triggers (finding created, finding open, scheduled, manual)
//   - Multiple action types (create ticket, notify Slack/PagerDuty, webhooks)
//   - Approval workflows for sensitive actions
//   - Execution tracking and audit logging
//
// Default rules include:
//   - Auto-create Jira tickets for critical findings
//   - Page on-call via PagerDuty for critical security events
//   - Create tickets for high-severity findings
//   - Notify on S3 public access violations
//
// Example usage:
//
//	engine := remediation.NewEngine(logger)
//	executions, _ := engine.Evaluate(ctx, Event{
//	    Type:     TriggerFindingCreated,
//	    Severity: "critical",
//	    FindingID: "finding-123",
//	})
//	// Executions are created for each matching rule
package remediation

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Engine is the auto-remediation orchestrator. It maintains a set of rules
// that define when and how to respond to security events. When an event
// matches a rule's trigger conditions, the engine creates an execution
// and runs the configured actions.
//
// The engine supports approval workflows for sensitive actions and maintains
// a complete audit trail of all executions.
type Engine struct {
	rules      []Rule                // Active remediation rules
	executions map[string]*Execution // Execution history indexed by ID
	logger     *slog.Logger          // Structured logger
	mu         sync.RWMutex          // Protects rules and executions
}

// Rule defines when and how to auto-remediate
type Rule struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Enabled     bool              `json:"enabled"`
	Trigger     Trigger           `json:"trigger"`
	Actions     []Action          `json:"actions"`
	Conditions  map[string]string `json:"conditions,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}

// Trigger defines what causes a rule to fire
type Trigger struct {
	Type     TriggerType `json:"type"`
	Severity string      `json:"severity,omitempty"` // critical, high, medium, low
	PolicyID string      `json:"policy_id,omitempty"`
	Tags     []string    `json:"tags,omitempty"`
}

type TriggerType string

const (
	TriggerFindingCreated TriggerType = "finding.created"
	TriggerFindingOpen    TriggerType = "finding.open"
	TriggerSignalCreated  TriggerType = "signal.created"
	TriggerSchedule       TriggerType = "schedule"
	TriggerManual         TriggerType = "manual"
)

// Action defines what to do when rule triggers
type Action struct {
	Type             ActionType        `json:"type"`
	Config           map[string]string `json:"config"`
	RequiresApproval bool              `json:"requires_approval"`
	TimeoutSeconds   int               `json:"timeout_seconds,omitempty"`
}

type ActionType string

const (
	ActionCreateTicket    ActionType = "create_ticket"
	ActionNotifySlack     ActionType = "notify_slack"
	ActionNotifyPagerDuty ActionType = "notify_pagerduty"
	ActionResolveFinding  ActionType = "resolve_finding"
	ActionRunWebhook      ActionType = "run_webhook"
	ActionTagResource     ActionType = "tag_resource"

	ActionUpdateCRMField    ActionType = "update_crm_field"
	ActionTriggerWorkflow   ActionType = "trigger_workflow"
	ActionCreateReview      ActionType = "create_review"
	ActionEscalateToOwner   ActionType = "escalate_to_owner"
	ActionPauseSubscription ActionType = "pause_subscription"
	ActionSendCustomerComm  ActionType = "send_customer_comm"

	ActionRestrictPublicStorageAccess ActionType = "restrict_public_storage_access"
	ActionDisableStaleAccessKey       ActionType = "disable_stale_access_key"
)

// Execution tracks a rule execution
type Execution struct {
	ID          string          `json:"id"`
	RuleID      string          `json:"rule_id"`
	RuleName    string          `json:"rule_name"`
	Status      ExecutionStatus `json:"status"`
	TriggerData map[string]any  `json:"trigger_data"`
	Actions     []ActionResult  `json:"actions"`
	StartedAt   time.Time       `json:"started_at"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	Error       string          `json:"error,omitempty"`
	ApprovalID  string          `json:"approval_id,omitempty"`
}

type ExecutionStatus string

const (
	ExecutionPending   ExecutionStatus = "pending"
	ExecutionRunning   ExecutionStatus = "running"
	ExecutionApproval  ExecutionStatus = "awaiting_approval"
	ExecutionCompleted ExecutionStatus = "completed"
	ExecutionFailed    ExecutionStatus = "failed"
	ExecutionCancelled ExecutionStatus = "canceled"
)

type ActionResult struct {
	ActionType ActionType     `json:"action_type"`
	Status     string         `json:"status"`
	Output     string         `json:"output,omitempty"`
	Error      string         `json:"error,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	StartedAt  time.Time      `json:"started_at"`
	Duration   string         `json:"duration,omitempty"`
}

func NewEngine(logger *slog.Logger) *Engine {
	e := &Engine{
		rules:      make([]Rule, 0),
		executions: make(map[string]*Execution),
		logger:     logger,
	}
	e.loadDefaultRules()
	return e
}

func (e *Engine) loadDefaultRules() {
	e.rules = []Rule{
		{
			ID:          "auto-ticket-critical",
			Name:        "Auto-create ticket for critical findings",
			Description: "Automatically creates a Jira ticket when a critical finding is detected",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerFindingCreated,
				Severity: "critical",
			},
			Actions: []Action{
				{
					Type: ActionCreateTicket,
					Config: map[string]string{
						"priority": "highest",
						"labels":   "security,critical,auto-generated",
					},
					RequiresApproval: false,
				},
				{
					Type: ActionNotifySlack,
					Config: map[string]string{
						"channel": "#security-alerts",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "pagerduty-critical",
			Name:        "Page on-call for critical findings",
			Description: "Creates PagerDuty incident for critical security findings",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerFindingCreated,
				Severity: "critical",
			},
			Actions: []Action{
				{
					Type: ActionNotifyPagerDuty,
					Config: map[string]string{
						"urgency": "high",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "auto-ticket-high",
			Name:        "Auto-create ticket for high findings",
			Description: "Automatically creates a ticket for high severity findings",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerFindingCreated,
				Severity: "high",
			},
			Actions: []Action{
				{
					Type: ActionCreateTicket,
					Config: map[string]string{
						"priority": "high",
						"labels":   "security,high,auto-generated",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "s3-public-notify",
			Name:        "Alert on public S3 bucket",
			Description: "Immediately notify when a public S3 bucket is detected",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerFindingCreated,
				PolicyID: "aws-s3-bucket-no-public-access",
			},
			Actions: []Action{
				{
					Type: ActionNotifySlack,
					Config: map[string]string{
						"channel": "#security-alerts",
						"message": "PUBLIC S3 BUCKET DETECTED - Immediate review required",
					},
					RequiresApproval: false,
				},
				{
					Type: ActionCreateTicket,
					Config: map[string]string{
						"priority": "highest",
						"labels":   "s3,public-access,data-exposure",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "s3-public-restrict",
			Name:        "Restrict public S3 bucket",
			Description: "Approval-gated automatic public access restriction for S3 buckets",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerFindingCreated,
				PolicyID: "aws-s3-bucket-no-public-access",
			},
			Actions: []Action{
				{
					Type: ActionRestrictPublicStorageAccess,
					Config: map[string]string{
						"approval_mode": "required",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "gcs-public-notify",
			Name:        "Alert on public GCS bucket",
			Description: "Create tracking for public GCS bucket findings",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerFindingCreated,
				PolicyID: "gcp-storage-bucket-no-public",
			},
			Actions: []Action{
				{
					Type: ActionNotifySlack,
					Config: map[string]string{
						"channel": "#security-alerts",
						"message": "PUBLIC GCS BUCKET DETECTED - Approval required for access restriction",
					},
					RequiresApproval: false,
				},
				{
					Type: ActionCreateTicket,
					Config: map[string]string{
						"priority": "highest",
						"labels":   "gcs,public-access,data-exposure",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "gcs-public-restrict",
			Name:        "Restrict public GCS bucket",
			Description: "Approval-gated automatic public access restriction for GCS buckets",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerFindingCreated,
				PolicyID: "gcp-storage-bucket-no-public",
			},
			Actions: []Action{
				{
					Type: ActionRestrictPublicStorageAccess,
					Config: map[string]string{
						"approval_mode": "required",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "gcs-public-principal-notify",
			Name:        "Alert on GCS bucket with public principals",
			Description: "Create tracking when GCS bucket IAM exposes public principals",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerFindingCreated,
				PolicyID: "gcp-storage-no-public-allusers",
			},
			Actions: []Action{
				{
					Type: ActionCreateTicket,
					Config: map[string]string{
						"priority": "highest",
						"labels":   "gcs,public-principal,data-exposure",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "gcs-public-principal-restrict",
			Name:        "Restrict GCS bucket with public principals",
			Description: "Approval-gated automatic public principal removal for GCS bucket IAM",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerFindingCreated,
				PolicyID: "gcp-storage-no-public-allusers",
			},
			Actions: []Action{
				{
					Type: ActionRestrictPublicStorageAccess,
					Config: map[string]string{
						"approval_mode": "required",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "identity-stale-user-remediation",
			Name:        "Stale User Access Remediation",
			Description: "Create and notify on stale inactive user findings for identity hygiene follow-up",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerFindingCreated,
				PolicyID: "identity-stale-inactive-user",
			},
			Actions: []Action{
				{
					Type: ActionCreateTicket,
					Config: map[string]string{
						"priority": "high",
						"labels":   "identity,stale-access,auto-generated",
					},
					RequiresApproval: false,
				},
				{
					Type: ActionNotifySlack,
					Config: map[string]string{
						"channel": "#identity-security",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "aws-unused-access-key-notify",
			Name:        "Track stale AWS access keys",
			Description: "Create tracking for unused AWS IAM access key findings",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerFindingCreated,
				PolicyID: "aws-iam-user-unused-credentials",
			},
			Actions: []Action{
				{
					Type: ActionCreateTicket,
					Config: map[string]string{
						"priority": "high",
						"labels":   "identity,access-key,stale,auto-generated",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "aws-unused-access-key-disable",
			Name:        "Disable stale AWS access keys",
			Description: "Disable unused AWS IAM access keys after approval once they cross the inactivity threshold",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerFindingCreated,
				PolicyID: "aws-iam-user-unused-credentials",
			},
			Actions: []Action{
				{
					Type: ActionDisableStaleAccessKey,
					Config: map[string]string{
						"inactive_days": "90",
						"approval_mode": "required",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "gcp-user-managed-key-notify",
			Name:        "Track stale GCP user-managed service account keys",
			Description: "Create tracking for stale GCP service account key findings",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerFindingCreated,
				PolicyID: "gcp-iam-minimize-user-managed-keys",
			},
			Actions: []Action{
				{
					Type: ActionCreateTicket,
					Config: map[string]string{
						"priority": "high",
						"labels":   "gcp,service-account-key,stale,auto-generated",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "gcp-user-managed-key-disable",
			Name:        "Disable stale GCP user-managed service account keys",
			Description: "Disable stale GCP service account keys once they cross the inactivity threshold and are approved",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerFindingCreated,
				PolicyID: "gcp-iam-minimize-user-managed-keys",
			},
			Actions: []Action{
				{
					Type: ActionDisableStaleAccessKey,
					Config: map[string]string{
						"inactive_days": "90",
						"approval_mode": "required",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "identity-excessive-privilege-remediation",
			Name:        "Identity Excessive Privilege Escalation",
			Description: "Escalate excessive identity privilege findings with high-priority response",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerFindingCreated,
				PolicyID: "identity-excessive-privilege",
			},
			Actions: []Action{
				{
					Type: ActionCreateTicket,
					Config: map[string]string{
						"priority": "highest",
						"labels":   "identity,privilege,critical,auto-generated",
					},
					RequiresApproval: false,
				},
				{
					Type: ActionNotifySlack,
					Config: map[string]string{
						"channel": "#security-alerts",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "dspm-restricted-data-unencrypted-remediation",
			Name:        "DSPM Restricted Data Encryption Enforcement",
			Description: "Escalate and track restricted data stores detected without encryption at rest",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerFindingCreated,
				PolicyID: "dspm-restricted-data-unencrypted",
			},
			Actions: []Action{
				{
					Type: ActionCreateTicket,
					Config: map[string]string{
						"priority": "highest",
						"labels":   "dspm,data-encryption,restricted,auto-generated",
					},
					RequiresApproval: false,
				},
				{
					Type: ActionNotifySlack,
					Config: map[string]string{
						"channel": "#security-alerts",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "dspm-confidential-data-public-remediation",
			Name:        "DSPM Public Sensitive Data Access Restriction",
			Description: "Trigger response playbooks when confidential or restricted data is publicly exposed",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerFindingCreated,
				PolicyID: "dspm-confidential-data-public",
			},
			Actions: []Action{
				{
					Type: ActionCreateTicket,
					Config: map[string]string{
						"priority": "highest",
						"labels":   "dspm,public-exposure,data-security,auto-generated",
					},
					RequiresApproval: false,
				},
				{
					Type: ActionNotifySlack,
					Config: map[string]string{
						"channel": "#security-alerts",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "signal-escalate-customer-health-critical",
			Name:        "Escalate Critical Customer Health Signals",
			Description: "Escalate critical customer-health signals to account owner and create a tracking ticket",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerSignalCreated,
				Severity: "critical",
			},
			Conditions: map[string]string{
				"domain": "customer_health",
			},
			Actions: []Action{
				{
					Type: ActionEscalateToOwner,
					Config: map[string]string{
						"tool":      "slack.send_message",
						"task_tool": "hubspot.create_task",
					},
					RequiresApproval: false,
				},
				{
					Type: ActionCreateTicket,
					Config: map[string]string{
						"priority": "high",
						"labels":   "signal,customer-health,critical",
					},
					RequiresApproval: false,
				},
			},
		},
		{
			ID:          "signal-finance-refund-approval",
			Name:        "Finance Approval Guardrail for Large Refund",
			Description: "Route large refund signals through finance approvals with CRM flag update",
			Enabled:     true,
			Trigger: Trigger{
				Type:     TriggerSignalCreated,
				PolicyID: "stripe-large-refund",
			},
			Actions: []Action{
				{
					Type: ActionNotifySlack,
					Config: map[string]string{
						"channel": "#finance-approvals",
					},
					RequiresApproval: false,
				},
				{
					Type: ActionUpdateCRMField,
					Config: map[string]string{
						"tool":          "hubspot.update_contact",
						"fallback_tool": "salesforce.update_record",
					},
					RequiresApproval: true,
				},
			},
		},
	}
}

// AddRule adds a new rule
func (e *Engine) AddRule(rule Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}
	rule.CreatedAt = time.Now().UTC()

	e.rules = append(e.rules, rule)
	return nil
}

// UpdateRule updates an existing rule by ID.
func (e *Engine) UpdateRule(id string, rule Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i := range e.rules {
		if e.rules[i].ID == id {
			createdAt := e.rules[i].CreatedAt
			rule.ID = id
			if createdAt.IsZero() {
				createdAt = time.Now().UTC()
			}
			rule.CreatedAt = createdAt
			e.rules[i] = rule
			return nil
		}
	}
	return fmt.Errorf("rule not found: %s", id)
}

// DeleteRule removes a rule by ID.
func (e *Engine) DeleteRule(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i := range e.rules {
		if e.rules[i].ID == id {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("rule not found: %s", id)
}

// GetRule gets a rule by ID
func (e *Engine) GetRule(id string) (*Rule, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for i := range e.rules {
		if e.rules[i].ID == id {
			return &e.rules[i], true
		}
	}
	return nil, false
}

// ListRules returns all rules
func (e *Engine) ListRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Rule{}, e.rules...)
}

// EnableRule enables a rule
func (e *Engine) EnableRule(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i := range e.rules {
		if e.rules[i].ID == id {
			e.rules[i].Enabled = true
			return nil
		}
	}
	return fmt.Errorf("rule not found: %s", id)
}

// DisableRule disables a rule
func (e *Engine) DisableRule(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i := range e.rules {
		if e.rules[i].ID == id {
			e.rules[i].Enabled = false
			return nil
		}
	}
	return fmt.Errorf("rule not found: %s", id)
}

// Evaluate checks if any rules match the given event
func (e *Engine) Evaluate(ctx context.Context, event Event) ([]*Execution, error) {
	e.mu.RLock()
	rules := append([]Rule{}, e.rules...)
	e.mu.RUnlock()

	var executions []*Execution

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		if e.matchesTrigger(rule.Trigger, event) && e.matchesConditions(rule.Conditions, event) {
			exec := e.createExecution(rule, event)
			executions = append(executions, exec)

			e.mu.Lock()
			e.executions[exec.ID] = exec
			e.mu.Unlock()

			e.logger.Info("rule triggered",
				"rule_id", rule.ID,
				"rule_name", rule.Name,
				"execution_id", exec.ID,
			)
		}
	}

	return executions, nil
}

// Event represents something that can trigger rules
type Event struct {
	Type       TriggerType    `json:"type"`
	FindingID  string         `json:"finding_id,omitempty"`
	Severity   string         `json:"severity,omitempty"`
	PolicyID   string         `json:"policy_id,omitempty"`
	SignalType string         `json:"signal_type,omitempty"`
	Domain     string         `json:"domain,omitempty"`
	EntityID   string         `json:"entity_id,omitempty"`
	Tags       []string       `json:"tags,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
}

func (e *Engine) matchesTrigger(trigger Trigger, event Event) bool {
	if trigger.Type != event.Type {
		return false
	}

	if trigger.Severity != "" && trigger.Severity != event.Severity {
		return false
	}

	if trigger.PolicyID != "" && trigger.PolicyID != event.PolicyID {
		return false
	}

	// Check tag matching
	if len(trigger.Tags) > 0 {
		matched := false
		for _, tt := range trigger.Tags {
			for _, et := range event.Tags {
				if tt == et {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

func (e *Engine) matchesConditions(conditions map[string]string, event Event) bool {
	if len(conditions) == 0 {
		return true
	}

	for key, expected := range conditions {
		actual, ok := eventFieldValue(event, key)
		if !ok {
			return false
		}
		if strings.TrimSpace(strings.ToLower(actual)) != strings.TrimSpace(strings.ToLower(expected)) {
			return false
		}
	}
	return true
}

func eventFieldValue(event Event, key string) (string, bool) {
	normalized := strings.TrimSpace(strings.ToLower(key))
	switch normalized {
	case "type":
		return string(event.Type), true
	case "finding_id":
		return event.FindingID, event.FindingID != ""
	case "severity":
		return event.Severity, event.Severity != ""
	case "policy_id":
		return event.PolicyID, event.PolicyID != ""
	case "signal_type":
		return event.SignalType, event.SignalType != ""
	case "domain":
		return event.Domain, event.Domain != ""
	case "entity_id":
		return event.EntityID, event.EntityID != ""
	}

	if event.Data == nil {
		return "", false
	}
	raw, ok := event.Data[key]
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%v", raw), true
}

func (e *Engine) createExecution(rule Rule, event Event) *Execution {
	triggerData := map[string]any{
		"event_type":  event.Type,
		"finding_id":  event.FindingID,
		"severity":    event.Severity,
		"policy_id":   event.PolicyID,
		"signal_type": event.SignalType,
		"domain":      event.Domain,
		"entity_id":   event.EntityID,
	}
	for key, value := range event.Data {
		if _, exists := triggerData[key]; !exists {
			triggerData[key] = value
		}
	}

	return &Execution{
		ID:          uuid.New().String(),
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		Status:      ExecutionPending,
		TriggerData: triggerData,
		Actions:     make([]ActionResult, 0),
		StartedAt:   time.Now().UTC(),
	}
}

// GetExecution gets an execution by ID
func (e *Engine) GetExecution(id string) (*Execution, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	exec, ok := e.executions[id]
	return exec, ok
}

// ListExecutions returns recent executions
func (e *Engine) ListExecutions(limit int) []*Execution {
	e.mu.RLock()
	defer e.mu.RUnlock()

	execs := make([]*Execution, 0, len(e.executions))
	for _, ex := range e.executions {
		execs = append(execs, ex)
	}

	// Sort by started time descending (most recent first)
	for i := 0; i < len(execs)-1; i++ {
		for j := i + 1; j < len(execs); j++ {
			if execs[j].StartedAt.After(execs[i].StartedAt) {
				execs[i], execs[j] = execs[j], execs[i]
			}
		}
	}

	if len(execs) > limit {
		execs = execs[:limit]
	}

	return execs
}
