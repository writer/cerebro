package resourcelinks

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/writer/cerebro/internal/fabriccontract"
	"github.com/writer/cerebro/internal/urn"
)

const (
	apiResourcePrefix  = "/platform/resources"
	mcpResourcePrefix  = "cerebro://resource"
	maxIdentifierBytes = 4096
)

var ErrInvalidResourceRef = errors.New("invalid resource reference")

// ResourceState describes whether a reference resolves to current or historical state.
type ResourceState string

const (
	ResourceStateCurrent     ResourceState = "current"
	ResourceStateImmutable   ResourceState = "immutable"
	ResourceStateSuperseded  ResourceState = "superseded"
	ResourceStateArchived    ResourceState = "archived"
	ResourceStateUnavailable ResourceState = "unavailable"
	ResourceStateRedacted    ResourceState = "redacted"
)

// ResourceRef identifies one record without changing which domain owns it.
// APIPath is always relative, and MCPURI always uses the cerebro URI scheme.
type ResourceRef struct {
	Kind     fabriccontract.ResourceKind `json:"kind"`
	ID       string                      `json:"id,omitempty"`
	URN      string                      `json:"urn,omitempty"`
	Revision string                      `json:"revision,omitempty"`
	Digest   string                      `json:"digest,omitempty"`
	Label    string                      `json:"label,omitempty"`
	State    ResourceState               `json:"state"`
	APIPath  string                      `json:"api_path"`
	MCPURI   string                      `json:"mcp_uri"`
}

// NewID builds a canonical reference for an ID-addressed resource kind.
func NewID(kind fabriccontract.ResourceKind, id string) (ResourceRef, error) {
	return Normalize(ResourceRef{Kind: kind, ID: id})
}

// NewURN builds a canonical reference for a URN-addressed resource kind.
func NewURN(kind fabriccontract.ResourceKind, resourceURN string) (ResourceRef, error) {
	return Normalize(ResourceRef{Kind: kind, URN: resourceURN})
}

// Normalize validates a reference and derives its canonical paths.
func Normalize(reference ResourceRef) (ResourceRef, error) {
	normalized := ResourceRef{
		Kind:     fabriccontract.ResourceKind(strings.TrimSpace(string(reference.Kind))),
		ID:       strings.TrimSpace(reference.ID),
		URN:      strings.TrimSpace(reference.URN),
		Revision: strings.TrimSpace(reference.Revision),
		Digest:   strings.TrimSpace(reference.Digest),
		Label:    strings.TrimSpace(reference.Label),
		State:    ResourceState(strings.TrimSpace(string(reference.State))),
	}

	definition, ok := fabriccontract.ResourceKindDefinitionFor(string(normalized.Kind))
	if !ok {
		return ResourceRef{}, fmt.Errorf("%w: unsupported kind %q", ErrInvalidResourceRef, normalized.Kind)
	}

	identifier, err := normalizeIdentifier(definition, normalized.ID, normalized.URN)
	if err != nil {
		return ResourceRef{}, err
	}
	if err := validateMetadata("revision", normalized.Revision); err != nil {
		return ResourceRef{}, err
	}
	if err := validateMetadata("digest", normalized.Digest); err != nil {
		return ResourceRef{}, err
	}
	if err := validateMetadata("label", normalized.Label); err != nil {
		return ResourceRef{}, err
	}

	if normalized.State == "" {
		normalized.State = ResourceStateCurrent
		if normalized.Revision != "" || normalized.Digest != "" {
			normalized.State = ResourceStateImmutable
		}
	}
	if !isResourceState(normalized.State) {
		return ResourceRef{}, fmt.Errorf("%w: unsupported state %q", ErrInvalidResourceRef, normalized.State)
	}
	if normalized.State == ResourceStateImmutable && normalized.Revision == "" && normalized.Digest == "" {
		return ResourceRef{}, fmt.Errorf("%w: immutable reference requires revision or digest", ErrInvalidResourceRef)
	}
	if normalized.State == ResourceStateCurrent && (normalized.Revision != "" || normalized.Digest != "") {
		return ResourceRef{}, fmt.Errorf("%w: current reference cannot include revision or digest", ErrInvalidResourceRef)
	}

	normalized.APIPath = buildAPIPath(normalized.Kind, identifier)
	normalized.MCPURI = buildMCPURI(normalized.Kind, identifier)
	if provided := strings.TrimSpace(reference.APIPath); provided != "" && provided != normalized.APIPath {
		return ResourceRef{}, fmt.Errorf("%w: api_path is not canonical", ErrInvalidResourceRef)
	}
	if provided := strings.TrimSpace(reference.MCPURI); provided != "" && provided != normalized.MCPURI {
		return ResourceRef{}, fmt.Errorf("%w: mcp_uri is not canonical", ErrInvalidResourceRef)
	}
	return normalized, nil
}

// Identifier returns the canonical ID or URN for the reference kind.
func (reference ResourceRef) Identifier() string {
	if reference.URN != "" {
		return reference.URN
	}
	return reference.ID
}

// CanonicalJSON returns stable JSON after applying reference normalization.
func (reference ResourceRef) CanonicalJSON() ([]byte, error) {
	return json.Marshal(reference)
}

// MarshalJSON prevents invalid or non-canonical references from being serialized.
func (reference ResourceRef) MarshalJSON() ([]byte, error) {
	normalized, err := Normalize(reference)
	if err != nil {
		return nil, err
	}
	type resourceRefJSON struct {
		Kind     fabriccontract.ResourceKind `json:"kind"`
		ID       string                      `json:"id,omitempty"`
		URN      string                      `json:"urn,omitempty"`
		Revision string                      `json:"revision,omitempty"`
		Digest   string                      `json:"digest,omitempty"`
		Label    string                      `json:"label,omitempty"`
		State    ResourceState               `json:"state"`
		APIPath  string                      `json:"api_path"`
		MCPURI   string                      `json:"mcp_uri"`
	}
	return json.Marshal(resourceRefJSON(normalized))
}

// UnmarshalJSON rejects references whose paths do not match their identifiers.
func (reference *ResourceRef) UnmarshalJSON(data []byte) error {
	if reference == nil {
		return fmt.Errorf("%w: nil destination", ErrInvalidResourceRef)
	}
	type resourceRefWire ResourceRef
	var decoded resourceRefWire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("%w: decode json: %w", ErrInvalidResourceRef, err)
	}
	normalized, err := Normalize(ResourceRef(decoded))
	if err != nil {
		return err
	}
	*reference = normalized
	return nil
}

func normalizeIdentifier(definition fabriccontract.ResourceKindDefinition, id string, resourceURN string) (string, error) {
	switch definition.Identifier {
	case fabriccontract.ResourceIdentifierID:
		if id == "" || resourceURN != "" {
			return "", fmt.Errorf("%w: kind %q requires id and forbids urn", ErrInvalidResourceRef, definition.Kind)
		}
		if err := validateIdentifier(id); err != nil {
			return "", err
		}
		return id, nil
	case fabriccontract.ResourceIdentifierURN:
		if resourceURN == "" || id != "" {
			return "", fmt.Errorf("%w: kind %q requires urn and forbids id", ErrInvalidResourceRef, definition.Kind)
		}
		if err := validateIdentifier(resourceURN); err != nil {
			return "", err
		}
		if _, err := urn.Parse(resourceURN); err != nil {
			return "", fmt.Errorf("%w: invalid urn for kind %q", ErrInvalidResourceRef, definition.Kind)
		}
		return resourceURN, nil
	default:
		return "", fmt.Errorf("%w: kind %q has unsupported identifier contract", ErrInvalidResourceRef, definition.Kind)
	}
}

func validateIdentifier(value string) error {
	if value == "" {
		return fmt.Errorf("%w: identifier is required", ErrInvalidResourceRef)
	}
	if len(value) > maxIdentifierBytes {
		return fmt.Errorf("%w: identifier exceeds %d bytes", ErrInvalidResourceRef, maxIdentifierBytes)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: identifier is not valid utf-8", ErrInvalidResourceRef)
	}
	if strings.ContainsRune(value, '\\') {
		return fmt.Errorf("%w: identifier contains a path separator", ErrInvalidResourceRef)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: identifier contains a control character", ErrInvalidResourceRef)
		}
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("%w: identifier contains a traversal segment", ErrInvalidResourceRef)
		}
	}
	return nil
}

func validateMetadata(name string, value string) error {
	if len(value) > maxIdentifierBytes {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalidResourceRef, name, maxIdentifierBytes)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s is not valid utf-8", ErrInvalidResourceRef, name)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s contains a control character", ErrInvalidResourceRef, name)
		}
	}
	return nil
}

func isResourceState(state ResourceState) bool {
	switch state {
	case ResourceStateCurrent, ResourceStateImmutable, ResourceStateSuperseded, ResourceStateArchived, ResourceStateUnavailable, ResourceStateRedacted:
		return true
	default:
		return false
	}
}

func buildAPIPath(kind fabriccontract.ResourceKind, identifier string) string {
	return apiResourcePrefix + "/" + url.PathEscape(string(kind)) + "/" + url.PathEscape(identifier)
}

func buildMCPURI(kind fabriccontract.ResourceKind, identifier string) string {
	return mcpResourcePrefix + "/" + url.PathEscape(string(kind)) + "/" + url.PathEscape(identifier)
}
