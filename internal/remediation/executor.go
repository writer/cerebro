package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/actionengine"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/notifications"
	"github.com/writer/cerebro/internal/ticketing"
	"github.com/writer/cerebro/internal/webhooks"
)

// Executor runs remediation actions
type RemoteActionCaller interface {
	CallTool(ctx context.Context, toolName string, args json.RawMessage, timeout time.Duration) (string, error)
}

type TicketService interface {
	Primary() ticketing.Provider
}

type NotificationSender interface {
	Send(ctx context.Context, event notifications.Event) error
}

type FindingsWriter interface {
	Resolve(id string) bool
}

type EventPublisher interface {
	EmitWithErrors(ctx context.Context, eventType webhooks.EventType, data map[string]interface{}) error
}

var (
	_ TicketService      = (*ticketing.Service)(nil)
	_ NotificationSender = (*notifications.Manager)(nil)
	_ FindingsWriter     = (*findings.Store)(nil)
	_ FindingsWriter     = (*findings.SQLiteStore)(nil)
	_ FindingsWriter     = (*findings.SnowflakeStore)(nil)
	_ EventPublisher     = (*webhooks.Service)(nil)
)

type Executor struct {
	engine        *Engine
	ticketing     TicketService
	notifications NotificationSender
	findings      FindingsWriter
	webhooks      EventPublisher
	remoteCaller  RemoteActionCaller
	ensemble      *EnsembleExecutor
	shared        *actionengine.Executor
}

func NewExecutor(
	engine *Engine,
	ticketing TicketService,
	notifications NotificationSender,
	findings FindingsWriter,
	webhookService EventPublisher,
) *Executor {
	return &Executor{
		engine:        engine,
		ticketing:     ticketing,
		notifications: notifications,
		findings:      findings,
		webhooks:      webhookService,
		ensemble:      NewEnsembleExecutor(nil, webhookService),
		shared:        actionengine.NewExecutor(nil),
	}
}

func (ex *Executor) SetRemoteCaller(caller RemoteActionCaller) {
	ex.remoteCaller = caller
	if ex.ensemble != nil {
		ex.ensemble.SetRemoteCaller(caller)
	}
}

func (ex *Executor) SetSharedExecutor(shared *actionengine.Executor) {
	if shared == nil {
		return
	}
	ex.shared = shared
}

// Execute runs an execution
func (ex *Executor) Execute(ctx context.Context, execution *Execution) error {
	rule, ok := ex.engine.GetRule(execution.RuleID)
	if !ok {
		execution.Status = ExecutionFailed
		execution.Error = "rule not found"
		return fmt.Errorf("rule not found: %s", execution.RuleID)
	}
	playbook := remediationPlaybookFromRule(*rule, ex, execution)
	signal := remediationSignalFromTriggerData(execution.TriggerData)
	sharedExecution := remediationExecutionToShared(execution)
	err := ex.shared.Execute(ctx, sharedExecution, playbook, signal, remediationStepRunner{executor: ex})
	applySharedExecution(execution, sharedExecution)
	if execution.Status == ExecutionApproval {
		execution.ApprovalID = fmt.Sprintf("approval-%s", execution.ID)
		ex.emitApprovalRequested(ctx, execution, rule)
		return nil
	}
	delete(execution.TriggerData, "_approval_granted")
	if err != nil {
		return fmt.Errorf("action failed: %w", err)
	}
	return nil
}

func (ex *Executor) actionRequiresApproval(action Action, execution *Execution) bool {
	switch strings.ToLower(strings.TrimSpace(action.Config["approval_mode"])) {
	case "auto", "none", "disabled", "not_required":
		return false
	case "required", "manual":
		return true
	}
	entry, _ := CatalogEntryByAction(action.Type)
	mode := actionDeliveryMode(action, execution, entry)
	if catalogSupportsDeliveryMode(entry, mode) && mode == DeliveryModeTerraform {
		return false
	}
	if action.RequiresApproval || entry.RequiresApproval {
		return true
	}
	if ex != nil && ex.ensemble != nil {
		return ex.ensemble.ActionRequiresApproval(action.Type)
	}
	return false
}

type remediationStepRunner struct {
	executor *Executor
}

func (r remediationStepRunner) RunStep(ctx context.Context, step actionengine.Step, signal actionengine.Signal, execution *actionengine.Execution) (string, error) {
	if r.executor == nil {
		return "", fmt.Errorf("remediation executor is nil")
	}
	action := remediationActionFromStep(step)
	nativeExecution := &Execution{
		ID:          execution.ID,
		RuleID:      execution.PlaybookID,
		RuleName:    execution.PlaybookName,
		TriggerData: remediationTriggerDataFromSignal(signal),
		StartedAt:   execution.StartedAt,
	}
	if nativeExecution.TriggerData == nil {
		nativeExecution.TriggerData = map[string]any{}
	}
	nativeExecution.TriggerData["_approval_granted"] = true
	result := r.executor.executeAction(ctx, action, nativeExecution)
	if execution.TriggerData == nil {
		execution.TriggerData = map[string]any{}
	}
	for key, value := range nativeExecution.TriggerData {
		if key == "_approval_granted" {
			continue
		}
		execution.TriggerData[key] = value
	}
	if len(result.Metadata) > 0 {
		actionengine.SetStepMetadata(execution, step.ID, result.Metadata)
	}
	if result.Error != "" {
		return "", errors.New(result.Error)
	}
	return result.Output, nil
}

func remediationPlaybookFromRule(rule Rule, executor *Executor, execution *Execution) actionengine.Playbook {
	steps := make([]actionengine.Step, 0, len(rule.Actions))
	for idx, action := range rule.Actions {
		failurePolicy := actionengine.FailurePolicyAbort
		steps = append(steps, actionengine.Step{
			ID:               fmt.Sprintf("%s-step-%d", firstNonEmpty(rule.ID, "rule"), idx+1),
			Type:             string(action.Type),
			Parameters:       cloneStringMap(action.Config),
			RequiresApproval: executor != nil && executor.actionRequiresApproval(action, execution),
			TimeoutSeconds:   action.TimeoutSeconds,
			OnFailure:        failurePolicy,
		})
	}
	trigger := actionengine.Trigger{
		Kind:              string(rule.Trigger.Type),
		Severity:          rule.Trigger.Severity,
		SeverityMatchMode: actionengine.SeverityMatchExact,
		PolicyID:          rule.Trigger.PolicyID,
		Tags:              append([]string(nil), rule.Trigger.Tags...),
		Conditions:        cloneStringMap(rule.Conditions),
	}
	return actionengine.Playbook{
		ID:          rule.ID,
		Name:        rule.Name,
		Description: rule.Description,
		Enabled:     rule.Enabled,
		Triggers:    []actionengine.Trigger{trigger},
		Steps:       steps,
		CreatedAt:   rule.CreatedAt,
	}
}

func remediationSignalFromTriggerData(data map[string]any) actionengine.Signal {
	signal := actionengine.Signal{
		Kind:         remediationMapValueToString(data, "event_type"),
		Severity:     remediationMapValueToString(data, "severity"),
		PolicyID:     remediationMapValueToString(data, "policy_id"),
		ResourceID:   firstNonEmpty(remediationMapValueToString(data, "entity_id"), remediationMapValueToString(data, "resource_id")),
		ResourceType: remediationMapValueToString(data, "resource_type"),
		Data:         cloneAnyMap(data),
		Attributes: map[string]string{
			"signal_type": remediationMapValueToString(data, "signal_type"),
			"domain":      remediationMapValueToString(data, "domain"),
			"entity_id":   remediationMapValueToString(data, "entity_id"),
			"finding_id":  remediationMapValueToString(data, "finding_id"),
		},
		CreatedAt: time.Now().UTC(),
	}
	if rawTags, ok := data["tags"]; ok {
		signal.Tags = remediationAnyToStringSlice(rawTags)
	}
	return signal
}

func remediationExecutionToShared(execution *Execution) *actionengine.Execution {
	shared := &actionengine.Execution{
		ID:           execution.ID,
		PlaybookID:   execution.RuleID,
		PlaybookName: execution.RuleName,
		Status:       remediationStatusToShared(execution.Status),
		ResourceID:   firstNonEmpty(remediationMapValueToString(execution.TriggerData, "entity_id"), remediationMapValueToString(execution.TriggerData, "resource_id")),
		ResourceType: remediationMapValueToString(execution.TriggerData, "resource_type"),
		TriggerData:  cloneAnyMap(execution.TriggerData),
		Results:      make([]actionengine.ActionResult, 0, len(execution.Actions)),
		StartedAt:    execution.StartedAt,
		CompletedAt:  execution.CompletedAt,
		Error:        execution.Error,
	}
	for _, action := range execution.Actions {
		shared.Results = append(shared.Results, actionengine.ActionResult{
			Type:      string(action.ActionType),
			Status:    remediationResultStatusToShared(action.Status),
			Output:    action.Output,
			Error:     action.Error,
			Metadata:  cloneAnyMap(action.Metadata),
			StartedAt: action.StartedAt,
			Duration:  action.Duration,
		})
	}
	if approvedBy := remediationMapValueToString(execution.TriggerData, "approved_by"); approvedBy != "" {
		shared.ApprovedBy = approvedBy
	}
	return shared
}

func applySharedExecution(target *Execution, shared *actionengine.Execution) {
	if target == nil || shared == nil {
		return
	}
	target.Status = sharedStatusToRemediation(shared.Status)
	target.Error = shared.Error
	target.StartedAt = shared.StartedAt
	target.CompletedAt = shared.CompletedAt
	if target.TriggerData == nil {
		target.TriggerData = map[string]any{}
	}
	for key, value := range shared.TriggerData {
		target.TriggerData[key] = value
	}
	if shared.ApprovedBy != "" {
		target.TriggerData["approved_by"] = shared.ApprovedBy
	}
	if shared.ApprovedAt != nil && !shared.ApprovedAt.IsZero() {
		target.TriggerData["approved_at"] = shared.ApprovedAt.UTC().Format(time.RFC3339Nano)
	}
	target.Actions = make([]ActionResult, 0, len(shared.Results))
	for _, result := range shared.Results {
		target.Actions = append(target.Actions, ActionResult{
			ActionType: ActionType(result.Type),
			Status:     sharedActionResultStatus(result.Status),
			Output:     result.Output,
			Error:      result.Error,
			Metadata:   cloneAnyMap(result.Metadata),
			StartedAt:  result.StartedAt,
			Duration:   result.Duration,
		})
	}
}

func remediationActionFromStep(step actionengine.Step) Action {
	return Action{
		Type:             ActionType(step.Type),
		Config:           cloneStringMap(step.Parameters),
		RequiresApproval: step.RequiresApproval,
		TimeoutSeconds:   step.TimeoutSeconds,
	}
}

func remediationTriggerDataFromSignal(signal actionengine.Signal) map[string]any {
	data := cloneAnyMap(signal.Data)
	if data == nil {
		data = map[string]any{}
	}
	for key, value := range signal.Attributes {
		if _, exists := data[key]; !exists {
			data[key] = value
		}
	}
	data["event_type"] = signal.Kind
	if signal.Severity != "" {
		data["severity"] = signal.Severity
	}
	if signal.PolicyID != "" {
		data["policy_id"] = signal.PolicyID
	}
	if signal.ResourceID != "" {
		data["entity_id"] = signal.ResourceID
	}
	if signal.ResourceType != "" {
		data["resource_type"] = signal.ResourceType
	}
	if len(signal.Tags) > 0 {
		data["tags"] = append([]string(nil), signal.Tags...)
	}
	return data
}

func remediationStatusToShared(status ExecutionStatus) actionengine.Status {
	switch status {
	case ExecutionApproval:
		return actionengine.StatusAwaitingApproval
	case ExecutionRunning:
		return actionengine.StatusRunning
	case ExecutionCompleted:
		return actionengine.StatusCompleted
	case ExecutionFailed:
		return actionengine.StatusFailed
	case ExecutionCancelled:
		return actionengine.StatusCanceled
	default:
		return actionengine.StatusPending
	}
}

func sharedStatusToRemediation(status actionengine.Status) ExecutionStatus {
	switch status {
	case actionengine.StatusAwaitingApproval:
		return ExecutionApproval
	case actionengine.StatusRunning:
		return ExecutionRunning
	case actionengine.StatusCompleted:
		return ExecutionCompleted
	case actionengine.StatusFailed:
		return ExecutionFailed
	case actionengine.StatusCanceled:
		return ExecutionCancelled
	default:
		return ExecutionPending
	}
}

func remediationResultStatusToShared(status string) actionengine.Status {
	switch strings.TrimSpace(strings.ToLower(status)) {
	case "running":
		return actionengine.StatusRunning
	case "completed":
		return actionengine.StatusCompleted
	case "failed":
		return actionengine.StatusFailed
	default:
		return actionengine.StatusPending
	}
}

func sharedActionResultStatus(status actionengine.Status) string {
	switch status {
	case actionengine.StatusRunning:
		return "running"
	case actionengine.StatusCompleted:
		return "completed"
	case actionengine.StatusFailed:
		return "failed"
	default:
		return "pending"
	}
}

func remediationMapValueToString(values map[string]any, key string) string {
	if len(values) == 0 {
		return ""
	}
	value, ok := values[key]
	if !ok {
		return ""
	}
	return fmt.Sprintf("%v", value)
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func cloneAnyMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func remediationAnyToStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(fmt.Sprintf("%v", item))
			if text != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		text := strings.TrimSpace(fmt.Sprintf("%v", value))
		if text == "" || text == "<nil>" {
			return nil
		}
		return []string{text}
	}
}

func (ex *Executor) executeAction(ctx context.Context, action Action, execution *Execution) ActionResult {
	result := ActionResult{
		ActionType: action.Type,
		Status:     "running",
		StartedAt:  time.Now().UTC(),
	}

	var err error
	approvalGranted, _ := execution.TriggerData["_approval_granted"].(bool)
	if ex.actionRequiresApproval(action, execution) && !approvalGranted {
		err = fmt.Errorf("%s action requires approval", action.Type)
	}

	if err == nil {
		if output, metadata, catalogErr, handled := ex.executeCatalogAction(ctx, action, execution); handled {
			result.Output = output
			result.Metadata = metadata
			err = catalogErr
		} else {
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

			case ActionUpdateCRMField:
				err = ex.updateCRMField(ctx, action, execution)
				if err == nil {
					result.Output = "CRM field updated"
				}

			case ActionTriggerWorkflow:
				err = ex.triggerWorkflow(ctx, action, execution)
				if err == nil {
					result.Output = "Workflow triggered"
				}

			case ActionCreateReview:
				err = ex.createReview(ctx, action, execution)
				if err == nil {
					result.Output = "Review created"
				}

			case ActionEscalateToOwner:
				err = ex.escalateToOwner(ctx, action, execution)
				if err == nil {
					result.Output = "Escalated to owner"
				}

			case ActionPauseSubscription:
				err = ex.pauseSubscription(ctx, action, execution)
				if err == nil {
					result.Output = "Subscription paused"
				}
			case ActionSendCustomerComm:
				err = ex.sendCustomerCommunication(ctx, action, execution)
				if err == nil {
					result.Output = "Customer communication sent"
				}

			default:
				err = fmt.Errorf("unknown action type: %s", action.Type)
			}
		}
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
	if ex.ensemble != nil && ex.ensemble.HasRemoteCaller() {
		if err := ex.ensemble.Execute(ctx, action, execution); err == nil {
			return nil
		} else if ex.ticketing == nil || ex.ticketing.Primary() == nil {
			return err
		} else if ex.engine != nil && ex.engine.logger != nil {
			ex.engine.logger.Warn("ensemble create_ticket failed; falling back to local ticketing",
				"execution_id", execution.ID,
				"rule_id", execution.RuleID,
				"error", err,
			)
		}
	}

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
	if ex.ensemble != nil && ex.ensemble.HasRemoteCaller() {
		if err := ex.ensemble.Execute(ctx, action, execution); err == nil {
			return nil
		} else if ex.notifications == nil {
			return err
		} else if ex.engine != nil && ex.engine.logger != nil {
			ex.engine.logger.Warn("ensemble notify_slack failed; falling back to local notifications",
				"execution_id", execution.ID,
				"rule_id", execution.RuleID,
				"error", err,
			)
		}
	}

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

func (ex *Executor) updateCRMField(ctx context.Context, action Action, execution *Execution) error {
	return ex.executeEnsembleAction(ctx, action, execution)
}

func (ex *Executor) triggerWorkflow(ctx context.Context, action Action, execution *Execution) error {
	tool := firstNonEmpty(action.Config["tool"], "ensemble_trigger_workflow")
	return ex.invokeRemoteTool(ctx, tool, action, execution)
}

func (ex *Executor) createReview(ctx context.Context, action Action, execution *Execution) error {
	tool := firstNonEmpty(action.Config["tool"], "create_review")
	return ex.invokeRemoteTool(ctx, tool, action, execution)
}

func (ex *Executor) escalateToOwner(ctx context.Context, action Action, execution *Execution) error {
	return ex.executeEnsembleAction(ctx, action, execution)
}

func (ex *Executor) pauseSubscription(ctx context.Context, action Action, execution *Execution) error {
	return ex.executeEnsembleAction(ctx, action, execution)
}

func (ex *Executor) sendCustomerCommunication(ctx context.Context, action Action, execution *Execution) error {
	return ex.executeEnsembleAction(ctx, action, execution)
}

func (ex *Executor) executeEnsembleAction(ctx context.Context, action Action, execution *Execution) error {
	if ex.ensemble == nil || !ex.ensemble.HasRemoteCaller() {
		return fmt.Errorf("remote tool caller not configured")
	}
	return ex.ensemble.Execute(ctx, action, execution)
}

func (ex *Executor) invokeRemoteTool(ctx context.Context, tool string, action Action, execution *Execution) error {
	if ex.remoteCaller == nil {
		return fmt.Errorf("remote tool caller not configured")
	}

	timeout := 30 * time.Second
	if action.TimeoutSeconds > 0 {
		timeout = time.Duration(action.TimeoutSeconds) * time.Second
	}

	payload := map[string]interface{}{
		"execution_id": execution.ID,
		"rule_id":      execution.RuleID,
		"rule_name":    execution.RuleName,
		"trigger_data": execution.TriggerData,
		"config":       action.Config,
	}
	if entityID, ok := execution.TriggerData["entity_id"].(string); ok && strings.TrimSpace(entityID) != "" {
		payload["entity_id"] = entityID
	}
	if findingID, ok := execution.TriggerData["finding_id"].(string); ok && strings.TrimSpace(findingID) != "" {
		payload["finding_id"] = findingID
	}
	if policyID, ok := execution.TriggerData["policy_id"].(string); ok && strings.TrimSpace(policyID) != "" {
		payload["policy_id"] = policyID
	}

	args, _ := json.Marshal(payload)
	_, err := ex.remoteCaller.CallTool(ctx, tool, args, timeout)
	return err
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (ex *Executor) emitApprovalRequested(ctx context.Context, execution *Execution, rule *Rule) {
	if ex.webhooks == nil {
		return
	}
	actions := make([]string, 0, len(rule.Actions))
	for _, action := range rule.Actions {
		if ex.actionRequiresApproval(action, execution) {
			actions = append(actions, string(action.Type))
		}
	}

	_ = ex.webhooks.EmitWithErrors(ctx, webhooks.EventApprovalRequested, map[string]interface{}{
		"approval_id":      execution.ApprovalID,
		"execution_id":     execution.ID,
		"rule_id":          execution.RuleID,
		"rule_name":        execution.RuleName,
		"approval_actions": actions,
		"trigger_data":     execution.TriggerData,
	})
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

	if execution.TriggerData == nil {
		execution.TriggerData = make(map[string]any)
	}
	execution.TriggerData["_approval_granted"] = true
	execution.TriggerData["approved_by"] = approverID
	execution.TriggerData["approved_at"] = time.Now().UTC().Format(time.RFC3339Nano)

	if rule, ok := ex.engine.GetRule(execution.RuleID); ok {
		sharedExecution := remediationExecutionToShared(execution)
		sharedExecution.ApprovedBy = approverID
		if approvedAt, _ := time.Parse(time.RFC3339Nano, remediationMapValueToString(execution.TriggerData, "approved_at")); !approvedAt.IsZero() {
			sharedExecution.ApprovedAt = &approvedAt
		}
		playbook := remediationPlaybookFromRule(*rule, ex, execution)
		signal := remediationSignalFromTriggerData(execution.TriggerData)
		err := ex.shared.Approve(ctx, sharedExecution, approverID, playbook, signal, remediationStepRunner{executor: ex})
		applySharedExecution(execution, sharedExecution)
		delete(execution.TriggerData, "_approval_granted")
		return err
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
	if sharedExecution := remediationExecutionToShared(execution); sharedExecution != nil {
		_ = ex.shared.Reject(ctx, sharedExecution, rejecterID, reason)
		applySharedExecution(execution, sharedExecution)
	}

	return nil
}
