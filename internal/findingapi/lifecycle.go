package findingapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type MCPArguments map[string]any
type MCPSchemaProperties map[string]any
type MCPActionProposalPayload map[string]any

// StatusUpdateOptions converts API lifecycle preconditions into the domain request.
func StatusUpdateOptions(expectedStatus string, lastObservedBefore time.Time, statusSource string) (findings.FindingStatusUpdateOptions, error) {
	options := findings.FindingStatusUpdateOptions{
		LastObservedBefore: lastObservedBefore.UTC(),
		Source:             strings.TrimSpace(statusSource),
	}
	if expected := strings.TrimSpace(expectedStatus); expected != "" {
		normalized, err := NormalizeStatus(expected)
		if err != nil {
			return options, err
		}
		options.ExpectedStatus = normalized
	}
	return options, nil
}

// NormalizeStatus validates a finding status string and returns the domain value.
func NormalizeStatus(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "open", "finding_status_open":
		return "open", nil
	case "resolved", "finding_status_resolved":
		return "resolved", nil
	case "suppressed", "finding_status_suppressed":
		return "suppressed", nil
	default:
		return "", fmt.Errorf("%w: unsupported finding status %q", findings.ErrInvalidRequest, raw)
	}
}

// ValidateOptionalStatus validates raw when present.
func ValidateOptionalStatus(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	_, err := NormalizeStatus(raw)
	return err
}

// ExternalRefFromLinkRequest converts the proto request to a persisted reference.
func ExternalRefFromLinkRequest(request *cerebrov1.LinkFindingExternalRefRequest) ports.FindingExternalRef {
	if request == nil {
		return ports.FindingExternalRef{}
	}
	return ports.FindingExternalRef{
		System:               request.GetSystem(),
		Kind:                 request.GetKind(),
		ExternalID:           request.GetExternalId(),
		URL:                  request.GetUrl(),
		ExternalStatus:       request.GetExternalStatus(),
		ExternalStatusReason: request.GetExternalStatusReason(),
		LifecycleOwner:       request.GetLifecycleOwner(),
		ObservedAt:           timestampValue(request.GetObservedAt()),
	}
}

// ExternalRefMessages converts persisted lifecycle references into proto messages.
func ExternalRefMessages(values []ports.FindingExternalRef) []*cerebrov1.FindingExternalRef {
	if len(values) == 0 {
		return nil
	}
	messages := make([]*cerebrov1.FindingExternalRef, 0, len(values))
	for _, value := range values {
		system := strings.TrimSpace(value.System)
		kind := strings.TrimSpace(value.Kind)
		externalID := strings.TrimSpace(value.ExternalID)
		if system == "" || kind == "" || externalID == "" {
			continue
		}
		message := &cerebrov1.FindingExternalRef{
			System:               system,
			Kind:                 kind,
			ExternalId:           externalID,
			Url:                  strings.TrimSpace(value.URL),
			ExternalStatus:       strings.TrimSpace(value.ExternalStatus),
			ExternalStatusReason: strings.TrimSpace(value.ExternalStatusReason),
			LifecycleOwner:       strings.TrimSpace(value.LifecycleOwner),
		}
		if !value.ObservedAt.IsZero() {
			message.ObservedAt = timestamppb.New(value.ObservedAt.UTC())
		}
		messages = append(messages, message)
	}
	return messages
}

func timestampValue(value *timestamppb.Timestamp) time.Time {
	if value == nil {
		return time.Time{}
	}
	return value.AsTime()
}

// NewMCPActionProposal returns the dry-run structured proposal payload for finding actions.
func NewMCPActionProposal(args MCPArguments, findingID string, action string) MCPActionProposalPayload {
	return MCPActionProposalPayload{
		"dry_run":                true,
		"would_mutate":           false,
		"finding_id":             findingID,
		"action":                 action,
		"status":                 mcpStringArg(args, "status"),
		"reason":                 mcpStringArg(args, "reason"),
		"expected_status":        mcpStringArg(args, "expected_status"),
		"last_observed_before":   mcpStringArg(args, "last_observed_before"),
		"status_source":          mcpStringArg(args, "status_source"),
		"lifecycle_owner":        mcpStringArg(args, "lifecycle_owner"),
		"external_system":        mcpStringArg(args, "external_system"),
		"external_id":            mcpStringArg(args, "external_id"),
		"ticket_url":             mcpStringArg(args, "ticket_url"),
		"ticket_id":              mcpStringArg(args, "ticket_id"),
		"external_ref_kind":      mcpStringArg(args, "external_ref_kind"),
		"external_status":        mcpStringArg(args, "external_status"),
		"external_status_reason": mcpStringArg(args, "external_status_reason"),
		"external_url":           mcpStringArg(args, "external_url"),
		"graph_action":           mcpStringArg(args, "graph_action"),
		"target":                 mcpStringArg(args, "target"),
		"email_or_user_id":       mcpStringArg(args, "email_or_user_id"),
		"idempotency_key":        mcpStringArg(args, "idempotency_key"),
		"endpoint":               mcpStringArg(args, "endpoint"),
		"recommended_action":     mcpStringArg(args, "recommended_action"),
		"handoff_required":       false,
		"proposal_note":          mcpStringArg(args, "proposal_note"),
		"required_scope":         "write",
		"approval_required":      true,
	}
}

func MCPGraphActionTarget(args MCPArguments, finding *ports.FindingRecord) (string, error) {
	graphAction := strings.TrimSpace(mcpStringArg(args, "graph_action"))
	target := strings.TrimSpace(mcpStringArg(args, "target"))
	if target == "" {
		target = mcpStringArg(args, "email_or_user_id")
	}
	return graphactions.TargetForAction(graphAction, finding, target)
}

func ApplyMCPGraphActionProposal(proposal MCPActionProposalPayload, finding *ports.FindingRecord, action string, args MCPArguments, requiredScope string) error {
	if action != "execute_graph_action" {
		return nil
	}
	graphAction := strings.TrimSpace(mcpStringArg(args, "graph_action"))
	if err := graphactions.ValidateActionForFinding(graphAction, finding); err != nil {
		return err
	}
	spec, err := graphactions.DefaultRegistry().Lookup(graphAction)
	if err != nil {
		return err
	}
	target, err := MCPGraphActionTarget(args, finding)
	if err != nil {
		return err
	}
	findingID, _ := proposal["finding_id"].(string)
	endpoint := "/platform/graph/actions"
	clearMCPGraphActionExternalRefProposal(proposal)
	proposal["graph_action"] = graphAction
	proposal["target"] = target
	proposal["endpoint"] = endpoint
	proposal["idempotency_key"] = graphactions.IdempotencyKey(graphAction, strings.TrimSpace(findingID), target)
	proposal["recommended_action"] = "POST " + endpoint
	proposal["required_scope"] = requiredScope
	proposal["approval_required"] = true
	proposal["handoff_required"] = true
	proposal["external_system"] = spec.Provider
	proposal["external_ref_kind"] = graphactions.RefKind
	proposal["proposal_note"] = "Use the graph action endpoint to queue " + graphAction + " through " + spec.Provider + "; this dry run does not mutate the provider or Cerebro."
	return nil
}

func clearMCPGraphActionExternalRefProposal(proposal MCPActionProposalPayload) {
	for _, key := range []string{
		"lifecycle_owner",
		"external_id",
		"external_url",
		"external_status",
		"external_status_reason",
	} {
		proposal[key] = ""
	}
}

// MCPActionInputProperties returns the finding action proposal input schema pieces.
func MCPActionInputProperties() MCPSchemaProperties {
	return MCPSchemaProperties{
		"dry_run":                map[string]any{"type": "boolean", "const": true},
		"finding_id":             map[string]any{"type": "string"},
		"action":                 map[string]any{"type": "string", "enum": []string{"add_note", "update_status", "create_exception", "link_ticket", "execute_graph_action"}},
		"note":                   map[string]any{"type": "string"},
		"status":                 map[string]any{"type": "string", "enum": []string{"open", "resolved", "suppressed"}},
		"reason":                 map[string]any{"type": "string"},
		"expected_status":        map[string]any{"type": "string", "enum": []string{"open", "resolved", "suppressed"}},
		"last_observed_before":   map[string]any{"type": "string", "format": "date-time"},
		"status_source":          map[string]any{"type": "string"},
		"lifecycle_owner":        map[string]any{"type": "string", "enum": []string{"cerebro_owned", "external_owned", "proposal_only"}},
		"external_system":        map[string]any{"type": "string"},
		"external_id":            map[string]any{"type": "string"},
		"ticket_url":             map[string]any{"type": "string"},
		"ticket_id":              map[string]any{"type": "string"},
		"external_ref_kind":      map[string]any{"type": "string"},
		"external_status":        map[string]any{"type": "string"},
		"external_status_reason": map[string]any{"type": "string"},
		"external_url":           map[string]any{"type": "string"},
		"graph_action":           map[string]any{"type": "string", "enum": graphActionEnum()},
		"target":                 map[string]any{"type": "string"},
		"email_or_user_id":       map[string]any{"type": "string"},
		"idempotency_key":        map[string]any{"type": "string"},
		"endpoint":               map[string]any{"type": "string"},
		"recommended_action":     map[string]any{"type": "string"},
		"handoff_required":       map[string]any{"type": "boolean"},
		"proposal_note":          map[string]any{"type": "string"},
	}
}

func graphActionEnum() []string {
	specs := graphactions.KnownActionSpecs()
	out := make([]string, 0, len(specs))
	for _, spec := range specs {
		out = append(out, spec.ID)
	}
	return out
}

// MCPActionOutputProperties returns the finding action proposal output schema fields.
func MCPActionOutputProperties() MCPSchemaProperties {
	return MCPSchemaProperties{
		"dry_run":                map[string]any{"type": "boolean", "const": true},
		"would_mutate":           map[string]any{"type": "boolean", "const": false},
		"finding_id":             map[string]any{"type": "string"},
		"action":                 map[string]any{"type": "string"},
		"status":                 map[string]any{"type": "string"},
		"reason":                 map[string]any{"type": "string"},
		"expected_status":        map[string]any{"type": "string"},
		"last_observed_before":   map[string]any{"type": "string"},
		"status_source":          map[string]any{"type": "string"},
		"lifecycle_owner":        map[string]any{"type": "string"},
		"external_system":        map[string]any{"type": "string"},
		"external_id":            map[string]any{"type": "string"},
		"ticket_url":             map[string]any{"type": "string"},
		"ticket_id":              map[string]any{"type": "string"},
		"external_ref_kind":      map[string]any{"type": "string"},
		"external_status":        map[string]any{"type": "string"},
		"external_status_reason": map[string]any{"type": "string"},
		"external_url":           map[string]any{"type": "string"},
		"graph_action":           map[string]any{"type": "string"},
		"target":                 map[string]any{"type": "string"},
		"email_or_user_id":       map[string]any{"type": "string"},
		"idempotency_key":        map[string]any{"type": "string"},
		"endpoint":               map[string]any{"type": "string"},
		"recommended_action":     map[string]any{"type": "string"},
		"handoff_required":       map[string]any{"type": "boolean"},
		"proposal_note":          map[string]any{"type": "string"},
		"required_scope":         map[string]any{"type": "string"},
		"approval_required":      map[string]any{"type": "boolean"},
	}
}

func mcpStringArg(args MCPArguments, key string) string {
	value, ok := args[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}
