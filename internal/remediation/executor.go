package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/notifications"
	"github.com/writer/cerebro/internal/ticketing"
)

// Executor runs remediation actions
type Executor struct {
	engine        *Engine
	ticketing     *ticketing.Service
	notifications *notifications.Manager
	findings      findings.FindingStore
}

func NewExecutor(
	engine *Engine,
	ticketing *ticketing.Service,
	notifications *notifications.Manager,
	findings findings.FindingStore,
) *Executor {
	return &Executor{
		engine:        engine,
		ticketing:     ticketing,
		notifications: notifications,
		findings:      findings,
	}
}

// Execute runs an execution
func (ex *Executor) Execute(ctx context.Context, execution *Execution) error {
	execution.Status = ExecutionRunning

	rule, ok := ex.engine.GetRule(execution.RuleID)
	if !ok {
		execution.Status = ExecutionFailed
		execution.Error = "rule not found"
		return fmt.Errorf("rule not found: %s", execution.RuleID)
	}

	// Check if any action requires approval
	for _, action := range rule.Actions {
		if action.RequiresApproval {
			execution.Status = ExecutionApproval
			execution.ApprovalID = fmt.Sprintf("approval-%s", execution.ID)
			return nil
		}
	}

	// Execute all actions
	for _, action := range rule.Actions {
		result := ex.executeAction(ctx, action, execution)
		execution.Actions = append(execution.Actions, result)

		if result.Error != "" {
			execution.Status = ExecutionFailed
			execution.Error = result.Error
			now := time.Now().UTC()
			execution.CompletedAt = &now
			return fmt.Errorf("action failed: %s", result.Error)
		}
	}

	execution.Status = ExecutionCompleted
	now := time.Now().UTC()
	execution.CompletedAt = &now

	return nil
}

func (ex *Executor) executeAction(ctx context.Context, action Action, execution *Execution) ActionResult {
	result := ActionResult{
		ActionType: action.Type,
		Status:     "running",
		StartedAt:  time.Now().UTC(),
	}

	var err error

	switch action.Type {
	case ActionCreateTicket:
		err = ex.createTicket(ctx, action, execution)
		if err == nil {
			result.Output = "Ticket created"
		}

	case ActionNotifySlack:
		err = ex.notifySlack(ctx, action, execution)
		if err == nil {
			result.Output = "Slack notification sent"
		}

	case ActionNotifyPagerDuty:
		err = ex.notifyPagerDuty(ctx, action, execution)
		if err == nil {
			result.Output = "PagerDuty alert sent"
		}

	case ActionResolveFinding:
		err = ex.resolveFinding(ctx, action, execution)
		if err == nil {
			result.Output = "Finding resolved"
		}

	case ActionRunWebhook:
		err = ex.runWebhook(ctx, action, execution)
		if err == nil {
			result.Output = "Webhook executed"
		}

	default:
		err = fmt.Errorf("unknown action type: %s", action.Type)
	}

	duration := time.Since(result.StartedAt)
	result.Duration = duration.String()

	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
	} else {
		result.Status = "completed"
	}

	return result
}

func (ex *Executor) createTicket(ctx context.Context, action Action, execution *Execution) error {
	if ex.ticketing == nil || ex.ticketing.Primary() == nil {
		return fmt.Errorf("ticketing not configured")
	}

	findingID, _ := execution.TriggerData["finding_id"].(string)
	severity, _ := execution.TriggerData["severity"].(string)

	priority := action.Config["priority"]
	if priority == "" {
		priority = severityToPriority(severity)
	}

	_, err := ex.ticketing.Primary().CreateTicket(ctx, &ticketing.Ticket{
		Title:       fmt.Sprintf("[Cerebro] Security finding: %s", findingID),
		Description: fmt.Sprintf("Auto-generated ticket for security finding.\n\nFinding ID: %s\nSeverity: %s\nRule: %s", findingID, severity, execution.RuleName),
		Priority:    priority,
		Labels:      []string{"security", "auto-remediation", severity},
		Type:        "finding",
		FindingIDs:  []string{findingID},
	})

	return err
}

func (ex *Executor) notifySlack(ctx context.Context, action Action, execution *Execution) error {
	if ex.notifications == nil {
		return fmt.Errorf("notifications not configured")
	}

	findingID, _ := execution.TriggerData["finding_id"].(string)
	severity, _ := execution.TriggerData["severity"].(string)

	message := action.Config["message"]
	if message == "" {
		message = fmt.Sprintf("Security finding detected: %s (severity: %s)", findingID, severity)
	}

	return ex.notifications.Send(ctx, notifications.Event{
		Type:     notifications.EventFindingCreated,
		Title:    fmt.Sprintf("Auto-remediation: %s", execution.RuleName),
		Message:  message,
		Severity: severity,
		Data: map[string]interface{}{
			"finding_id":   findingID,
			"rule_id":      execution.RuleID,
			"execution_id": execution.ID,
		},
	})
}

func (ex *Executor) notifyPagerDuty(ctx context.Context, _ Action, execution *Execution) error {
	if ex.notifications == nil {
		return fmt.Errorf("notifications not configured")
	}

	findingID, _ := execution.TriggerData["finding_id"].(string)
	severity, _ := execution.TriggerData["severity"].(string)

	// PagerDuty only for critical/high
	if severity != "critical" && severity != "high" {
		return nil
	}

	return ex.notifications.Send(ctx, notifications.Event{
		Type:     notifications.EventFindingCreated,
		Title:    fmt.Sprintf("Security Alert: %s", findingID),
		Message:  fmt.Sprintf("Critical security finding requires immediate attention. Rule: %s", execution.RuleName),
		Severity: severity,
		Data: map[string]interface{}{
			"finding_id":   findingID,
			"rule_id":      execution.RuleID,
			"execution_id": execution.ID,
		},
	})
}

func (ex *Executor) resolveFinding(_ context.Context, _ Action, execution *Execution) error {
	if ex.findings == nil {
		return fmt.Errorf("findings store not configured")
	}

	findingID, _ := execution.TriggerData["finding_id"].(string)
	if findingID == "" {
		return fmt.Errorf("no finding_id in trigger data")
	}

	if !ex.findings.Resolve(findingID) {
		return fmt.Errorf("finding not found: %s", findingID)
	}

	return nil
}

// WebhookPayload is the payload sent to webhook endpoints
type WebhookPayload struct {
	Event     string                 `json:"event"`
	Timestamp time.Time              `json:"timestamp"`
	Action    string                 `json:"action"`
	Finding   map[string]interface{} `json:"finding,omitempty"`
	Execution map[string]interface{} `json:"execution,omitempty"`
	RuleID    string                 `json:"rule_id,omitempty"`
	Metadata  map[string]string      `json:"metadata,omitempty"`
}

func (ex *Executor) runWebhook(ctx context.Context, action Action, execution *Execution) error {
	urlStr := action.Config["url"]
	if urlStr == "" {
		return fmt.Errorf("webhook url not configured")
	}

	// Build webhook payload
	payload := WebhookPayload{
		Event:     "remediation.action",
		Timestamp: time.Now().UTC(),
		Action:    string(action.Type),
		RuleID:    execution.RuleID,
		Execution: map[string]interface{}{
			"id":         execution.ID,
			"rule_id":    execution.RuleID,
			"rule_name":  execution.RuleName,
			"status":     string(execution.Status),
			"started_at": execution.StartedAt,
		},
		Metadata: action.Config,
	}

	// Add finding info from trigger data if available
	if execution.TriggerData != nil {
		if findingID, ok := execution.TriggerData["finding_id"].(string); ok {
			payload.Finding = map[string]interface{}{
				"id": findingID,
			}
			if title, ok := execution.TriggerData["title"].(string); ok {
				payload.Finding["title"] = title
			}
			if severity, ok := execution.TriggerData["severity"].(string); ok {
				payload.Finding["severity"] = severity
			}
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	// Determine HTTP method (default POST)
	method := "POST"
	if m := action.Config["method"]; m != "" {
		method = m
	}

	req, err := http.NewRequestWithContext(ctx, method, urlStr, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cerebro-Event", "remediation.action")
	req.Header.Set("X-Cerebro-Execution-ID", execution.ID)

	// Add secret header if configured
	if secret := action.Config["secret"]; secret != "" {
		req.Header.Set("X-Cerebro-Secret", secret)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func severityToPriority(severity string) string {
	switch severity {
	case "critical":
		return "highest"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

// Approve approves a pending execution
func (ex *Executor) Approve(ctx context.Context, executionID, approverID string) error {
	execution, ok := ex.engine.GetExecution(executionID)
	if !ok {
		return fmt.Errorf("execution not found: %s", executionID)
	}

	if execution.Status != ExecutionApproval {
		return fmt.Errorf("execution is not awaiting approval")
	}

	return ex.Execute(ctx, execution)
}

// Reject rejects a pending execution
func (ex *Executor) Reject(ctx context.Context, executionID, rejecterID, reason string) error {
	execution, ok := ex.engine.GetExecution(executionID)
	if !ok {
		return fmt.Errorf("execution not found: %s", executionID)
	}

	if execution.Status != ExecutionApproval {
		return fmt.Errorf("execution is not awaiting approval")
	}

	execution.Status = ExecutionCancelled
	execution.Error = fmt.Sprintf("Rejected by %s: %s", rejecterID, reason)
	now := time.Now().UTC()
	execution.CompletedAt = &now

	return nil
}
