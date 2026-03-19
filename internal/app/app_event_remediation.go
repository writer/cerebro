package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/notifications"
	"github.com/evalops/cerebro/internal/remediation"
	"github.com/evalops/cerebro/internal/webhooks"
)

func (a *App) startEventRemediation(_ context.Context) {
	if a == nil || a.Webhooks == nil || a.Remediation == nil || a.RemediationExecutor == nil {
		return
	}

	a.Webhooks.Subscribe(func(eventCtx context.Context, event webhooks.Event) error {
		return a.handleRemediationEvent(eventCtx, event)
	})
	a.Logger.Info("event remediation pipeline enabled")
}

func (a *App) handleRemediationEvent(ctx context.Context, event webhooks.Event) error {
	remediationEvent, ok := remediationEventFromWebhook(event)
	if !ok {
		return nil
	}

	executions, err := a.Remediation.Evaluate(ctx, remediationEvent)
	if err != nil {
		return err
	}

	for _, execution := range executions {
		allowed := true
		if proposal := a.executionChangeProposal(execution, remediationEvent); proposal != nil {
			engine := a.propagationEngine()
			if engine != nil {
				result, evalErr := engine.Evaluate(proposal)
				if evalErr != nil {
					a.Logger.Warn("failed to evaluate propagation for remediation", "execution_id", execution.ID, "error", evalErr)
				} else {
					switch result.Decision {
					case graph.DecisionBlocked:
						allowed = false
						a.sendPropagationDecisionNotification(ctx, execution, result)
					case graph.DecisionNeedsApproval:
						allowed = false
						a.sendPropagationDecisionNotification(ctx, execution, result)
					}
				}
			}
		}

		if !allowed {
			continue
		}

		if err := a.RemediationExecutor.Execute(ctx, execution); err != nil {
			a.Logger.Warn("failed to execute remediation from event pipeline", "execution_id", execution.ID, "rule_id", execution.RuleID, "error", err)
		}
	}

	return nil
}

func remediationEventFromWebhook(event webhooks.Event) (remediation.Event, bool) {
	var trigger remediation.TriggerType
	signalType := ""

	switch event.Type {
	case webhooks.EventFindingCreated:
		trigger = remediation.TriggerFindingCreated
	case webhooks.EventSignalCreated, webhooks.EventRiskScoreChanged, webhooks.EventToxicCombinationDetected, webhooks.EventGraphMutated:
		trigger = remediation.TriggerSignalCreated
		signalType = string(event.Type)
	default:
		return remediation.Event{}, false
	}

	data := make(map[string]any, len(event.Data))
	for key, value := range event.Data {
		data[key] = value
	}

	severity := strings.ToLower(strings.TrimSpace(remediationAnyToString(event.Data["severity"])))
	findingID := strings.TrimSpace(remediationAnyToString(event.Data["finding_id"]))
	policyID := strings.TrimSpace(remediationAnyToString(event.Data["policy_id"]))
	domain := strings.TrimSpace(remediationAnyToString(event.Data["domain"]))
	entityID := strings.TrimSpace(remediationAnyToString(event.Data["entity_id"]))
	if entityID == "" {
		entityID = strings.TrimSpace(remediationAnyToString(event.Data["resource_id"]))
	}
	if signalType == "" {
		signalType = strings.TrimSpace(remediationAnyToString(event.Data["signal_type"]))
	}
	if signalType == "" {
		signalType = string(event.Type)
	}

	return remediation.Event{
		Type:       trigger,
		FindingID:  findingID,
		Severity:   severity,
		PolicyID:   policyID,
		SignalType: signalType,
		Domain:     domain,
		EntityID:   entityID,
		Tags:       remediationAnyToStringSlice(event.Data["tags"]),
		Data:       data,
	}, true
}

func (a *App) propagationEngine() *graph.PropagationEngine {
	if a == nil {
		return nil
	}

	a.securityGraphInitMu.RLock()
	if a.Propagation != nil {
		engine := a.Propagation
		a.securityGraphInitMu.RUnlock()
		return engine
	}
	securityGraph := a.SecurityGraph
	a.securityGraphInitMu.RUnlock()
	if securityGraph == nil {
		return a.currentOrStoredPassivePropagationEngine()
	}

	engine := graph.NewPropagationEngine(securityGraph)

	a.securityGraphInitMu.Lock()
	if a.SecurityGraph == nil {
		a.securityGraphInitMu.Unlock()
		return a.currentOrStoredPassivePropagationEngine()
	}
	if a.Propagation == nil {
		if a.SecurityGraph != securityGraph {
			engine = graph.NewPropagationEngine(a.SecurityGraph)
		}
		a.Propagation = engine
	} else {
		engine = a.Propagation
	}
	a.securityGraphInitMu.Unlock()
	return engine
}

func (a *App) currentOrStoredPassivePropagationEngine() *graph.PropagationEngine {
	view, err := a.currentOrStoredPassiveSecurityGraphView()
	if err != nil {
		if a.Logger != nil {
			a.Logger.Warn("failed to resolve propagation graph", "error", err)
		}
		return nil
	}
	if view == nil {
		return nil
	}
	return graph.NewPropagationEngine(view)
}

func (a *App) executionChangeProposal(execution *remediation.Execution, event remediation.Event) *graph.ChangeProposal {
	if execution == nil || a.Remediation == nil {
		return nil
	}
	rule, ok := a.Remediation.GetRule(execution.RuleID)
	if !ok || rule == nil {
		return nil
	}

	nodeID := strings.TrimSpace(event.EntityID)
	if nodeID == "" {
		nodeID = strings.TrimSpace(remediationAnyToString(event.Data["resource_id"]))
	}
	if nodeID == "" {
		return nil
	}

	delta := graph.GraphDelta{}
	for _, action := range rule.Actions {
		if !actionAffectsGraph(action.Type) {
			continue
		}
		properties := actionPropertiesForProposal(action)
		if len(properties) == 0 {
			continue
		}
		delta.Nodes = append(delta.Nodes, graph.NodeMutation{
			Action:     "modify",
			ID:         nodeID,
			Properties: properties,
		})
	}

	if len(delta.Nodes) == 0 && len(delta.Edges) == 0 {
		return nil
	}

	source := "remediation"
	if rule.ID != "" {
		source = "remediation:" + rule.ID
	}
	reason := strings.TrimSpace(event.SignalType)
	if reason == "" {
		reason = fmt.Sprintf("remediation execution %s", execution.ID)
	}
	return &graph.ChangeProposal{
		ID:     execution.ID,
		Source: source,
		Reason: reason,
		Delta:  delta,
	}
}

func actionAffectsGraph(action remediation.ActionType) bool {
	switch action {
	case remediation.ActionTagResource,
		remediation.ActionPauseSubscription,
		remediation.ActionUpdateCRMField,
		remediation.ActionEscalateToOwner,
		remediation.ActionCreateReview,
		remediation.ActionSendCustomerComm:
		return true
	default:
		return false
	}
}

func actionPropertiesForProposal(action remediation.Action) map[string]any {
	properties := map[string]any{}
	switch action.Type {
	case remediation.ActionPauseSubscription:
		properties["subscription_status"] = "paused"
	case remediation.ActionUpdateCRMField:
		field := strings.TrimSpace(action.Config["field"])
		if field == "" {
			field = "crm_updated"
		}
		value := strings.TrimSpace(action.Config["value"])
		if value == "" {
			properties[field] = true
		} else {
			properties[field] = value
		}
	case remediation.ActionEscalateToOwner:
		properties["escalated_to_owner"] = true
	case remediation.ActionCreateReview:
		properties["review_required"] = true
	case remediation.ActionSendCustomerComm:
		properties["customer_comm_sent"] = true
	case remediation.ActionTagResource:
		key := strings.TrimSpace(action.Config["tag_key"])
		if key == "" {
			key = "tag"
		}
		value := strings.TrimSpace(action.Config["tag_value"])
		if value == "" {
			value = "true"
		}
		properties[key] = value
	}
	return properties
}

func (a *App) sendPropagationDecisionNotification(ctx context.Context, execution *remediation.Execution, result *graph.PropagationResult) {
	if a == nil || a.Notifications == nil || execution == nil || result == nil {
		return
	}

	severity := "medium"
	message := "remediation action requires approval before execution"
	reasons := result.ApprovalReasons
	if result.Decision == graph.DecisionBlocked {
		severity = "high"
		message = "remediation action blocked by propagation policy"
		reasons = result.BlockReasons
	}

	if err := a.Notifications.Send(ctx, notifications.Event{
		Type:     notifications.EventReviewRequired,
		Severity: severity,
		Title:    "Remediation Propagation Review",
		Message:  message,
		Data: map[string]any{
			"execution_id":       execution.ID,
			"rule_id":            execution.RuleID,
			"decision":           result.Decision,
			"reasons":            reasons,
			"affected_arr":       result.AffectedARR,
			"affected_customers": len(result.AffectedCustomers),
			"risk_score_delta":   result.RiskScoreDelta,
		},
	}); err != nil {
		a.Logger.Warn("failed to send propagation decision notification", "execution_id", execution.ID, "error", err)
	}
}

func remediationAnyToString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		if value == nil {
			return ""
		}
		return fmt.Sprintf("%v", value)
	}
}

func remediationAnyToStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		result := make([]string, 0, len(typed))
		for _, entry := range typed {
			if s := strings.TrimSpace(remediationAnyToString(entry)); s != "" {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}
