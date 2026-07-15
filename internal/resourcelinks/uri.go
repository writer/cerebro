package resourcelinks

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/writer/cerebro/internal/fabriccontract"
)

// ParseAPIPath parses only canonical, relative resource paths.
func ParseAPIPath(raw string) (ResourceRef, error) {
	value := strings.TrimSpace(raw)
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return ResourceRef{}, fmt.Errorf("%w: invalid api path", ErrInvalidResourceRef)
	}
	escapedPath := parsed.EscapedPath()
	if !strings.HasPrefix(escapedPath, apiResourcePrefix+"/") {
		return ResourceRef{}, fmt.Errorf("%w: invalid api path", ErrInvalidResourceRef)
	}
	kind, identifier, err := parseEscapedResourcePath(strings.TrimPrefix(escapedPath, apiResourcePrefix))
	if err != nil {
		return ResourceRef{}, err
	}
	reference, err := newReferenceForIdentifier(kind, identifier)
	if err != nil {
		return ResourceRef{}, err
	}
	if reference.APIPath != value {
		return ResourceRef{}, fmt.Errorf("%w: api path is not canonical", ErrInvalidResourceRef)
	}
	return reference, nil
}

// ParseMCPURI parses only canonical cerebro://resource URIs.
func ParseMCPURI(raw string) (ResourceRef, error) {
	value := strings.TrimSpace(raw)
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "cerebro" || parsed.Host != "resource" || parsed.User != nil || parsed.Port() != "" || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return ResourceRef{}, fmt.Errorf("%w: invalid mcp uri", ErrInvalidResourceRef)
	}
	kind, identifier, err := parseEscapedResourcePath(parsed.EscapedPath())
	if err != nil {
		return ResourceRef{}, err
	}
	reference, err := newReferenceForIdentifier(kind, identifier)
	if err != nil {
		return ResourceRef{}, err
	}
	if reference.MCPURI != value {
		return ResourceRef{}, fmt.Errorf("%w: mcp uri is not canonical", ErrInvalidResourceRef)
	}
	return reference, nil
}

func parseEscapedResourcePath(escapedPath string) (fabriccontract.ResourceKind, string, error) {
	segments := strings.Split(strings.TrimPrefix(escapedPath, "/"), "/")
	if len(segments) != 2 || segments[0] == "" || segments[1] == "" {
		return "", "", fmt.Errorf("%w: resource path requires kind and identifier", ErrInvalidResourceRef)
	}
	kindValue, err := url.PathUnescape(segments[0])
	if err != nil {
		return "", "", fmt.Errorf("%w: invalid escaped kind", ErrInvalidResourceRef)
	}
	identifier, err := url.PathUnescape(segments[1])
	if err != nil {
		return "", "", fmt.Errorf("%w: invalid escaped identifier", ErrInvalidResourceRef)
	}
	return fabriccontract.ResourceKind(kindValue), identifier, nil
}

func newReferenceForIdentifier(kind fabriccontract.ResourceKind, identifier string) (ResourceRef, error) {
	definition, ok := fabriccontract.ResourceKindDefinitionFor(string(kind))
	if !ok {
		return ResourceRef{}, fmt.Errorf("%w: unsupported kind %q", ErrInvalidResourceRef, kind)
	}
	switch definition.Identifier {
	case fabriccontract.ResourceIdentifierID:
		return NewID(kind, identifier)
	case fabriccontract.ResourceIdentifierURN:
		return NewURN(kind, identifier)
	default:
		return ResourceRef{}, fmt.Errorf("%w: kind %q has unsupported identifier contract", ErrInvalidResourceRef, kind)
	}
}
