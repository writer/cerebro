package graphactions

import (
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

type TargetResolver func(*ports.FindingRecord, string) (string, error)
type EligibilityChecker func(string, *ports.FindingRecord) error

type ActionSpec struct {
	ID               string
	Provider         string
	ProviderAction   string
	TargetKind       string
	Effect           string
	Destructive      bool
	ReversibleBy     string
	ResolveTarget    TargetResolver
	CheckEligibility EligibilityChecker
}

type Registry struct {
	actions map[string]ActionSpec
}

func (r Registry) Lookup(action string) (ActionSpec, error) {
	action = strings.TrimSpace(action)
	if len(r.actions) == 0 {
		r = DefaultRegistry()
	}
	spec, ok := r.actions[action]
	if !ok {
		return ActionSpec{}, fmt.Errorf("%w: unsupported action %q", ErrInvalidRequest, action)
	}
	return spec, nil
}

func TargetForAction(action string, finding *ports.FindingRecord, explicit string) (string, error) {
	spec, err := DefaultRegistry().Lookup(action)
	if err != nil {
		return "", err
	}
	if spec.ResolveTarget == nil {
		return "", fmt.Errorf("%w: action %q has no target resolver", ErrInvalidRequest, action)
	}
	return spec.ResolveTarget(finding, explicit)
}

func ValidateActionForFinding(action string, finding *ports.FindingRecord) error {
	spec, err := DefaultRegistry().Lookup(action)
	if err != nil {
		return err
	}
	if spec.CheckEligibility == nil {
		return nil
	}
	return spec.CheckEligibility(spec.ID, finding)
}

func FindingAllowsAction(action string, finding *ports.FindingRecord) error {
	action = strings.TrimSpace(action)
	if action == "" {
		return fmt.Errorf("%w: action is required", ErrInvalidRequest)
	}
	if finding == nil || strings.TrimSpace(finding.ID) == "" {
		return fmt.Errorf("%w: finding is required", ErrInvalidRequest)
	}
	if !findingStatusAllowsAction(finding.Status) {
		return fmt.Errorf("%w: finding is not open for graph action execution", ErrInvalidRequest)
	}
	if !findingActionAllowedByAttributes(action, finding.Attributes) {
		return fmt.Errorf("%w: action %q is not allowed by finding policy", ErrInvalidRequest, action)
	}
	return nil
}

func findingStatusAllowsAction(status string) bool {
	status = strings.ToLower(strings.TrimSpace(status))
	return status == "open" || status == "finding_status_open"
}

func findingActionAllowedByAttributes(action string, attrs map[string]string) bool {
	for _, key := range []string{"graph_actions_allowed", "allowed_graph_actions", "graph_action_allowed"} {
		if delimitedContainsAction(attrs[key], action) {
			return true
		}
	}
	return false
}

func delimitedContainsAction(raw string, action string) bool {
	action = strings.TrimSpace(action)
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\t' || r == ';' || r == ' '
	}) {
		if strings.EqualFold(strings.TrimSpace(part), action) {
			return true
		}
	}
	return false
}
