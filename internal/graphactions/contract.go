package graphactions

import "strings"

const (
	ActionStatusPending        = "pending"
	ActionStatusQueued         = "queued"
	ActionStatusRunning        = "running"
	ActionStatusSucceeded      = "succeeded"
	ActionStatusFailed         = "failed"
	ActionStatusCancelled      = "cancelled"
	ActionStatusNeedsAttention = "needs_attention"
)

// ActionMetadata is the serializable, behavior-free description of an action.
// DefinitionDigest binds callers to the exact generated catalog definition.
type ActionMetadata struct {
	ID               string `json:"id"`
	Provider         string `json:"provider"`
	ProviderAction   string `json:"provider_action"`
	TargetKind       string `json:"target_kind"`
	Effect           string `json:"effect"`
	Destructive      bool   `json:"destructive"`
	ReversibleBy     string `json:"reversible_by,omitempty"`
	DefinitionDigest string `json:"definition_digest"`
}

// Metadata returns the normalized public metadata for an action specification.
func (s ActionSpec) Metadata() ActionMetadata {
	return ActionMetadata{
		ID:               strings.TrimSpace(s.ID),
		Provider:         strings.TrimSpace(s.Provider),
		ProviderAction:   strings.TrimSpace(s.ProviderAction),
		TargetKind:       strings.TrimSpace(s.TargetKind),
		Effect:           strings.TrimSpace(s.Effect),
		Destructive:      s.Destructive,
		ReversibleBy:     strings.TrimSpace(s.ReversibleBy),
		DefinitionDigest: strings.TrimSpace(s.DefinitionDigest),
	}
}

// NormalizeActionStatus converts provider status text to Cerebro's comparison
// form without deciding whether the result is supported.
func NormalizeActionStatus(status string) string {
	return strings.ToLower(strings.TrimSpace(status))
}

// KnownActionStatuses returns a new slice containing every asynchronous status
// accepted from providers. Dry-run is local planning state and is not included.
func KnownActionStatuses() []string {
	return []string{
		ActionStatusPending,
		ActionStatusQueued,
		ActionStatusRunning,
		ActionStatusSucceeded,
		ActionStatusFailed,
		ActionStatusCancelled,
		ActionStatusNeedsAttention,
	}
}

// ActionStatusKnown reports whether status is in the provider lifecycle.
func ActionStatusKnown(status string) bool {
	switch NormalizeActionStatus(status) {
	case ActionStatusPending,
		ActionStatusQueued,
		ActionStatusRunning,
		ActionStatusSucceeded,
		ActionStatusFailed,
		ActionStatusCancelled,
		ActionStatusNeedsAttention:
		return true
	default:
		return false
	}
}

// ActionStatusTerminal reports whether provider polling can stop. The
// needs_attention state is terminal for automation even though a human may
// perform follow-up work.
func ActionStatusTerminal(status string) bool {
	switch NormalizeActionStatus(status) {
	case ActionStatusSucceeded, ActionStatusFailed, ActionStatusCancelled, ActionStatusNeedsAttention:
		return true
	default:
		return false
	}
}
