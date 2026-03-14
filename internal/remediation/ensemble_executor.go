package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/webhooks"
)

const (
	defaultEnsembleActionTimeout = 30 * time.Second
	defaultEnsembleMaxAttempts   = 3
	defaultEnsembleBaseBackoff   = 250 * time.Millisecond
	defaultEnsembleMaxBackoff    = 2 * time.Second
)

// EnsembleExecutor maps remediation business actions to Ensemble remote tools.
type EnsembleExecutor struct {
	caller      RemoteActionCaller
	webhooks    EventPublisher
	maxAttempts int
	baseBackoff time.Duration
	maxBackoff  time.Duration
	sleep       func(context.Context, time.Duration) error
}

func NewEnsembleExecutor(caller RemoteActionCaller, hooks EventPublisher) *EnsembleExecutor {
	return &EnsembleExecutor{
		caller:      caller,
		webhooks:    hooks,
		maxAttempts: defaultEnsembleMaxAttempts,
		baseBackoff: defaultEnsembleBaseBackoff,
		maxBackoff:  defaultEnsembleMaxBackoff,
		sleep:       sleepWithContext,
	}
}

func (e *EnsembleExecutor) SetRemoteCaller(caller RemoteActionCaller) {
	e.caller = caller
}

func (e *EnsembleExecutor) HasRemoteCaller() bool {
	return e != nil && e.caller != nil
}

func (e *EnsembleExecutor) ActionRequiresApproval(actionType ActionType) bool {
	switch actionType {
	case ActionPauseSubscription, ActionSendCustomerComm, ActionRestrictPublicStorageAccess, ActionDisableStaleAccessKey, ActionRestrictPublicSecurityGroupIngress:
		return true
	default:
		return false
	}
}

// Execute runs one remediation action through Ensemble remote tools.
func (e *EnsembleExecutor) Execute(ctx context.Context, action Action, execution *Execution) error {
	_, err := e.ExecuteWithOutput(ctx, action, execution)
	return err
}

// ExecuteWithOutput runs one remediation action through Ensemble remote tools and returns the tool output.
func (e *EnsembleExecutor) ExecuteWithOutput(ctx context.Context, action Action, execution *Execution) (string, error) {
	if e == nil || e.caller == nil {
		return "", fmt.Errorf("remote tool caller not configured")
	}

	timeout := defaultEnsembleActionTimeout
	if action.TimeoutSeconds > 0 {
		timeout = time.Duration(action.TimeoutSeconds) * time.Second
	}
	args, err := marshalEnsembleActionArgs(action, execution)
	if err != nil {
		return "", err
	}

	switch action.Type {
	case ActionEscalateToOwner:
		ownerMsgTool := firstNonEmpty(action.Config["tool"], action.Config["owner_message_tool"], "slack.send_message")
		if _, err := e.callWithRetry(ctx, ownerMsgTool, action, execution, args, timeout); err != nil {
			return "", err
		}
		ownerTaskTool := firstNonEmpty(action.Config["task_tool"], action.Config["owner_task_tool"], "hubspot.create_task")
		return e.callWithRetry(ctx, ownerTaskTool, action, execution, args, timeout)

	case ActionSendCustomerComm:
		return e.callFirstSuccess(ctx, []string{
			firstNonEmpty(action.Config["tool"], "slack.send_message"),
			firstNonEmpty(action.Config["fallback_tool"], "gmail.send"),
		}, action, execution, args, timeout)

	case ActionUpdateCRMField:
		return e.callFirstSuccess(ctx, []string{
			firstNonEmpty(action.Config["tool"], "hubspot.update_contact"),
			firstNonEmpty(action.Config["fallback_tool"], "salesforce.update_record"),
		}, action, execution, args, timeout)

	case ActionCreateTicket:
		return e.callFirstSuccess(ctx, []string{
			firstNonEmpty(action.Config["tool"], "jira.create_issue"),
			firstNonEmpty(action.Config["fallback_tool"], "zendesk.create_ticket"),
		}, action, execution, args, timeout)

	case ActionPauseSubscription:
		tool := firstNonEmpty(action.Config["tool"], "stripe.pause_subscription")
		return e.callWithRetry(ctx, tool, action, execution, args, timeout)

	case ActionNotifySlack:
		tool := firstNonEmpty(action.Config["tool"], "slack.send_message")
		return e.callWithRetry(ctx, tool, action, execution, args, timeout)

	case ActionRestrictPublicStorageAccess, ActionDisableStaleAccessKey, ActionRestrictPublicSecurityGroupIngress:
		tool := strings.TrimSpace(action.Config["tool"])
		if tool == "" {
			return "", fmt.Errorf("ensemble tool name is required")
		}
		return e.callWithRetry(ctx, tool, action, execution, args, timeout)

	default:
		// Keep unsupported actions on the existing executor path.
		return "", fmt.Errorf("unsupported ensemble action type: %s", action.Type)
	}
}

func (e *EnsembleExecutor) callFirstSuccess(ctx context.Context, tools []string, action Action, execution *Execution, args json.RawMessage, timeout time.Duration) (string, error) {
	errorsByTool := make([]string, 0)
	seen := make(map[string]struct{})
	for _, tool := range tools {
		tool = strings.TrimSpace(tool)
		if tool == "" {
			continue
		}
		if _, ok := seen[tool]; ok {
			continue
		}
		seen[tool] = struct{}{}

		if result, err := e.callWithRetry(ctx, tool, action, execution, args, timeout); err == nil {
			return result, nil
		} else {
			errorsByTool = append(errorsByTool, err.Error())
		}
	}
	if len(errorsByTool) == 0 {
		return "", fmt.Errorf("no ensemble tool configured for action %s", action.Type)
	}
	return "", fmt.Errorf("ensemble action %s failed: %s", action.Type, strings.Join(errorsByTool, "; "))
}

func (e *EnsembleExecutor) callWithRetry(ctx context.Context, tool string, action Action, execution *Execution, args json.RawMessage, timeout time.Duration) (string, error) {
	tool = strings.TrimSpace(tool)
	if tool == "" {
		return "", fmt.Errorf("ensemble tool name is required")
	}

	attempts := e.maxAttempts
	if attempts <= 0 {
		attempts = defaultEnsembleMaxAttempts
	}

	var lastErr error
	started := time.Now().UTC()
	for attempt := 1; attempt <= attempts; attempt++ {
		result, err := e.caller.CallTool(ctx, tool, args, timeout)
		if err == nil {
			e.emitActionEvent(ctx, webhooks.EventRemediationActionCompleted, action, execution, tool, attempt, started, result, "")
			return result, nil
		}
		lastErr = err
		if attempt >= attempts {
			break
		}
		backoff := e.retryBackoff(attempt)
		if sleepErr := e.sleep(ctx, backoff); sleepErr != nil {
			lastErr = sleepErr
			break
		}
	}

	e.emitActionEvent(ctx, webhooks.EventRemediationActionFailed, action, execution, tool, attempts, started, "", firstNonEmpty(lastErrString(lastErr), "unknown error"))
	return "", fmt.Errorf("ensemble tool %s failed after %d attempts: %w", tool, attempts, lastErr)
}

func (e *EnsembleExecutor) retryBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		attempt = 1
	}
	base := e.baseBackoff
	if base <= 0 {
		base = defaultEnsembleBaseBackoff
	}
	maxBackoff := e.maxBackoff
	if maxBackoff <= 0 {
		maxBackoff = defaultEnsembleMaxBackoff
	}

	backoff := base
	for i := 1; i < attempt; i++ {
		backoff *= 2
		if backoff >= maxBackoff {
			return maxBackoff
		}
	}
	if backoff > maxBackoff {
		return maxBackoff
	}
	return backoff
}

func marshalEnsembleActionArgs(action Action, execution *Execution) (json.RawMessage, error) {
	payload := map[string]interface{}{
		"execution_id": execution.ID,
		"rule_id":      execution.RuleID,
		"rule_name":    execution.RuleName,
		"action_type":  string(action.Type),
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
	if provider, ok := execution.TriggerData["provider"].(string); ok && strings.TrimSpace(provider) != "" {
		payload["provider"] = provider
	}
	if resourceName, ok := execution.TriggerData["resource_name"].(string); ok && strings.TrimSpace(resourceName) != "" {
		payload["resource_name"] = resourceName
	}
	if resourceType, ok := execution.TriggerData["resource_type"].(string); ok && strings.TrimSpace(resourceType) != "" {
		payload["resource_type"] = resourceType
	}

	args, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal ensemble action args: %w", err)
	}
	return args, nil
}

func (e *EnsembleExecutor) emitActionEvent(
	ctx context.Context,
	eventType webhooks.EventType,
	action Action,
	execution *Execution,
	tool string,
	attempts int,
	startedAt time.Time,
	output string,
	errMsg string,
) {
	if e == nil || e.webhooks == nil {
		return
	}
	data := map[string]interface{}{
		"execution_id": execution.ID,
		"rule_id":      execution.RuleID,
		"rule_name":    execution.RuleName,
		"action_type":  string(action.Type),
		"tool":         tool,
		"attempts":     attempts,
		"duration_ms":  time.Since(startedAt).Milliseconds(),
		"trigger_data": execution.TriggerData,
	}
	if strings.TrimSpace(output) != "" {
		data["output"] = output
	}
	if strings.TrimSpace(errMsg) != "" {
		data["error"] = errMsg
	}
	_ = e.webhooks.EmitWithErrors(ctx, eventType, data)
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func lastErrString(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}
