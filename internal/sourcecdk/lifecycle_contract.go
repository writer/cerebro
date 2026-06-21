package sourcecdk

import (
	"fmt"
	"sort"
	"strings"
)

// LifecycleStatus describes the rollout state for one source-emitted event kind.
type LifecycleStatus string

const (
	LifecycleStatusActive     LifecycleStatus = "active"
	LifecycleStatusPlanned    LifecycleStatus = "planned"
	LifecycleStatusDeprecated LifecycleStatus = "deprecated"
	LifecycleStatusRetired    LifecycleStatus = "retired"
)

// KindLifecycle describes whether a source event kind is actively emitted or
// intentionally planned/deprecated/retired.
type KindLifecycle struct {
	Kind        string          `json:"kind" yaml:"kind"`
	Status      LifecycleStatus `json:"status" yaml:"status"`
	Replacement string          `json:"replacement,omitempty" yaml:"replacement,omitempty"`
}

// LifecycleContract is the catalog-backed lifecycle contract for a source.
type LifecycleContract struct {
	SourceID string          `json:"source_id" yaml:"source_id"`
	Kinds    []KindLifecycle `json:"kinds" yaml:"kinds"`
}

// LifecycleContractProvider exposes catalog-level source kind lifecycle data.
type LifecycleContractProvider interface {
	LifecycleContract() LifecycleContract
}

func normalizeLifecycleContract(sourceID string, emittedKinds []string, entries []KindLifecycle) (LifecycleContract, error) {
	sourceID = strings.TrimSpace(sourceID)
	emitted := map[string]struct{}{}
	for _, kind := range emittedKinds {
		kind = strings.TrimSpace(kind)
		if kind != "" {
			emitted[kind] = struct{}{}
		}
	}
	known := map[string]struct{}{}
	normalized := make([]KindLifecycle, 0, len(entries)+len(emittedKinds))
	for _, entry := range entries {
		kind := strings.TrimSpace(entry.Kind)
		status := LifecycleStatus(strings.ToLower(strings.TrimSpace(string(entry.Status))))
		replacement := strings.TrimSpace(entry.Replacement)
		if kind == "" {
			return LifecycleContract{}, fmt.Errorf("kind_lifecycle kind is required")
		}
		if !validEventKind(kind) {
			return LifecycleContract{}, fmt.Errorf("kind_lifecycle kind %q must use dot-separated lowercase identifiers", kind)
		}
		if _, ok := known[kind]; ok {
			return LifecycleContract{}, fmt.Errorf("duplicate kind_lifecycle kind %q", kind)
		}
		known[kind] = struct{}{}
		switch status {
		case LifecycleStatusActive, LifecycleStatusPlanned, LifecycleStatusDeprecated, LifecycleStatusRetired:
		default:
			return LifecycleContract{}, fmt.Errorf("kind_lifecycle kind %q has invalid status %q", kind, entry.Status)
		}
		if replacement != "" && !validEventKind(replacement) {
			return LifecycleContract{}, fmt.Errorf("kind_lifecycle kind %q has invalid replacement %q", kind, replacement)
		}
		if _, emittedKind := emitted[kind]; !emittedKind && status == LifecycleStatusActive {
			return LifecycleContract{}, fmt.Errorf("kind_lifecycle kind %q is active but not listed in emitted_kinds", kind)
		}
		normalized = append(normalized, KindLifecycle{Kind: kind, Status: status, Replacement: replacement})
	}
	for kind := range emitted {
		if _, ok := known[kind]; ok {
			continue
		}
		normalized = append(normalized, KindLifecycle{Kind: kind, Status: LifecycleStatusActive})
		known[kind] = struct{}{}
	}
	for _, entry := range normalized {
		if entry.Replacement == "" {
			continue
		}
		if _, ok := known[entry.Replacement]; !ok {
			return LifecycleContract{}, fmt.Errorf("kind_lifecycle kind %q replacement %q is not declared", entry.Kind, entry.Replacement)
		}
	}
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].Kind < normalized[j].Kind
	})
	if len(normalized) == 0 {
		return LifecycleContract{}, nil
	}
	return LifecycleContract{SourceID: sourceID, Kinds: normalized}, nil
}

func cloneLifecycleContract(contract LifecycleContract) LifecycleContract {
	contract.SourceID = strings.TrimSpace(contract.SourceID)
	if len(contract.Kinds) == 0 {
		contract.Kinds = nil
		return contract
	}
	contract.Kinds = append([]KindLifecycle(nil), contract.Kinds...)
	return contract
}
