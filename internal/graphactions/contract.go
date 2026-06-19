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

type ActionMetadata struct {
	ID             string `json:"id"`
	Provider       string `json:"provider"`
	ProviderAction string `json:"provider_action"`
	TargetKind     string `json:"target_kind"`
	Effect         string `json:"effect"`
	Destructive    bool   `json:"destructive"`
	ReversibleBy   string `json:"reversible_by,omitempty"`
}

func (s ActionSpec) Metadata() ActionMetadata {
	return ActionMetadata{
		ID:             strings.TrimSpace(s.ID),
		Provider:       strings.TrimSpace(s.Provider),
		ProviderAction: strings.TrimSpace(s.ProviderAction),
		TargetKind:     strings.TrimSpace(s.TargetKind),
		Effect:         strings.TrimSpace(s.Effect),
		Destructive:    s.Destructive,
		ReversibleBy:   strings.TrimSpace(s.ReversibleBy),
	}
}

func NormalizeActionStatus(status string) string {
	return strings.ToLower(strings.TrimSpace(status))
}

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

func ActionStatusTerminal(status string) bool {
	switch NormalizeActionStatus(status) {
	case ActionStatusSucceeded, ActionStatusFailed, ActionStatusCancelled, ActionStatusNeedsAttention:
		return true
	default:
		return false
	}
}
