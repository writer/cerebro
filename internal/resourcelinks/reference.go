package resourcelinks

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/writer/cerebro/internal/fabriccontract"
)

var (
	// ErrInvalidReference indicates that a resource reference cannot round-trip
	// through its declared locations.
	ErrInvalidReference = errors.New("invalid resource reference")
	// ErrInvalidLink indicates that a link violates the registered relation or
	// endpoint-kind contract.
	ErrInvalidLink = errors.New("invalid resource link")
)

// State distinguishes mutable current views from immutable revisions.
type State string

const (
	StateCurrent     State = "current"
	StateImmutable   State = "immutable"
	StateUnavailable State = "unavailable"
)

// Authority describes where the relationship is asserted.
type Authority string

const (
	AuthorityCanonicalRecord Authority = "canonical_record"
	AuthorityDerivedRecord   Authority = "derived_record"
)

// Completeness states whether the source record enumerates the full relation.
type Completeness string

const (
	CompletenessComplete Completeness = "complete"
	CompletenessPartial  Completeness = "partial"
)

// ResourceRef is a transport-neutral pointer to a canonical current or
// immutable resource. APIPath is always relative so request Host values never
// participate in link construction.
type ResourceRef struct {
	Kind     Kind   `json:"kind"`
	ID       string `json:"id"`
	Revision string `json:"revision,omitempty"`
	APIPath  string `json:"api_path,omitempty"`
	MCPURI   string `json:"mcp_uri,omitempty"`
	State    State  `json:"state"`
}

// ResourceLink connects one authorized source resource to one target without
// expanding or authorizing the target on the caller's behalf.
type ResourceLink struct {
	Relation     string       `json:"rel"`
	Target       ResourceRef  `json:"target"`
	Authority    Authority    `json:"authority"`
	Completeness Completeness `json:"completeness"`
}

// NewReference validates and normalizes one resource reference.
func NewReference(reference ResourceRef) (ResourceRef, error) {
	reference.Kind = Kind(strings.TrimSpace(string(reference.Kind)))
	reference.ID = strings.TrimSpace(reference.ID)
	reference.Revision = strings.TrimSpace(reference.Revision)
	reference.APIPath = strings.TrimSpace(reference.APIPath)
	reference.MCPURI = strings.TrimSpace(reference.MCPURI)
	reference.State = State(strings.TrimSpace(string(reference.State)))
	if !IsKind(reference.Kind) || reference.ID == "" {
		return ResourceRef{}, ErrInvalidReference
	}
	if reference.State != StateCurrent && reference.State != StateImmutable && reference.State != StateUnavailable {
		return ResourceRef{}, ErrInvalidReference
	}
	if reference.State == StateImmutable && reference.Revision == "" {
		return ResourceRef{}, ErrInvalidReference
	}
	if reference.APIPath == "" && reference.MCPURI == "" {
		return ResourceRef{}, ErrInvalidReference
	}
	if reference.APIPath != "" {
		parsed, err := url.Parse(reference.APIPath)
		if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" || !strings.HasPrefix(parsed.Path, "/") {
			return ResourceRef{}, ErrInvalidReference
		}
	}
	if reference.MCPURI != "" {
		parsed, err := url.Parse(reference.MCPURI)
		if err != nil || parsed.Scheme != "cerebro" || strings.TrimSpace(parsed.Host) == "" || parsed.User != nil || parsed.Fragment != "" {
			return ResourceRef{}, ErrInvalidReference
		}
	}
	return reference, nil
}

// NewLink validates one link against the shared relation registry.
func NewLink(sourceKind Kind, relation string, target ResourceRef, authority Authority, completeness Completeness) (ResourceLink, error) {
	sourceKind = Kind(strings.TrimSpace(string(sourceKind)))
	relation = strings.TrimSpace(relation)
	authority = Authority(strings.TrimSpace(string(authority)))
	completeness = Completeness(strings.TrimSpace(string(completeness)))
	if !IsKind(sourceKind) {
		return ResourceLink{}, ErrInvalidLink
	}
	validatedTarget, err := NewReference(target)
	if err != nil {
		return ResourceLink{}, fmt.Errorf("%w: %w", ErrInvalidLink, err)
	}
	definition, ok := fabriccontract.LookupRelation(relation)
	if !ok || !kindAllowed(string(sourceKind), definition.SourceKinds) || !kindAllowed(string(validatedTarget.Kind), definition.TargetKinds) {
		return ResourceLink{}, ErrInvalidLink
	}
	if authority != AuthorityCanonicalRecord && authority != AuthorityDerivedRecord {
		return ResourceLink{}, ErrInvalidLink
	}
	if completeness != CompletenessComplete && completeness != CompletenessPartial {
		return ResourceLink{}, ErrInvalidLink
	}
	return ResourceLink{
		Relation:     relation,
		Target:       validatedTarget,
		Authority:    authority,
		Completeness: completeness,
	}, nil
}

func kindAllowed(kind string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if candidate == kind {
			return true
		}
	}
	return false
}

// CanonicalReferenceBytes returns deterministic JSON for digesting and golden
// contract fixtures.
func CanonicalReferenceBytes(reference ResourceRef) ([]byte, error) {
	validated, err := NewReference(reference)
	if err != nil {
		return nil, err
	}
	return json.Marshal(validated)
}
