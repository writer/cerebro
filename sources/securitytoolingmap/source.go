package securitytoolingmap

import (
	"context"
	"embed"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/securitytooling"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID       = "security_tooling_map"
	defaultFamily  = familyTool
	defaultBaseURL = ""

	familyTool           = "tool"
	familyControlMapping = "control_mapping"
)

// Source reads the security tooling inventory.
type Source struct {
	inner *jsonapi.Source
}

// New constructs the Security Tooling Map source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  defaultBaseURL,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		TokenScheme:     "Bearer",
		Families: []jsonapi.Family{
			{
				Name:    familyTool,
				Path:    "/tools",
				URNKind: "security_tool",
				IDKeys:  []string{"id", "name"},
				TimestampKeys: []string{
					"last_pushed", "updated_at", "created_at",
				},
				Attributes: map[string]string{
					"tool_id":          "id",
					"name":             "name",
					"org":              "org",
					"repo":             "repo",
					"repository":       "repository",
					"url":              "url",
					"status":           "status",
					"lifecycle_owner":  "lifecycle_owner",
					"owners":           "owners",
					"primary_language": "primary_language",
					"categories":       "categories",
					"capabilities":     "capabilities",
					"surfaces":         "surfaces",
					"depends_on":       "depends_on",
					"consumed_by":      "consumed_by",
					"overlaps_with":    "overlaps_with",
					"agent_role":       "agent_role",
					"last_pushed":      "last_pushed",
				},
				StaticAttributes: map[string]string{"source_product": "security_tooling_map"},
			},
			{
				Name:    familyControlMapping,
				Path:    "/control-mappings",
				URNKind: "security_tool_control_mapping",
				IDKeys:  []string{"id"},
				TimestampKeys: []string{
					"updated_at", "observed_at",
				},
				Attributes: map[string]string{
					"mapping_id":       "id",
					"tool_id":          "tool_id",
					"tool_name":        "tool_name",
					"control_id":       "control_id",
					"control_name":     "control_name",
					"framework":        "framework",
					"coverage":         "coverage",
					"control_status":   "control_status",
					"evidence_surface": "evidence_surface",
					"gap_reason":       "gap_reason",
					"owner":            "owner",
					"last_assessed_at": "last_assessed_at",
				},
				StaticAttributes: map[string]string{"source_product": "security_tooling_map"},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

// Spec returns static Security Tooling Map source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Spec()
}

// Check validates that the configured inventory family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.inner.Check(ctx, cfg)
}

// Discover returns Security Tooling Map URNs for the configured family.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.inner.Discover(ctx, cfg)
}

// Read pages inventory records, drops malformed tooling/control records, and
// emits normalized security_tooling_map.* events with a deterministic
// coverage-status posture attribute on control mappings.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	pull, err := s.inner.Read(ctx, cfg, cursor)
	if err != nil {
		return pull, err
	}
	pull.Events = normalizeEvents(pull.Events)
	return pull, nil
}

func normalizeEvents(events []*cerebrov1.EventEnvelope) []*cerebrov1.EventEnvelope {
	if len(events) == 0 {
		return events
	}
	out := make([]*cerebrov1.EventEnvelope, 0, len(events))
	for _, event := range events {
		if event == nil {
			continue
		}
		switch event.GetKind() {
		case sourceID + "." + familyTool:
			if !normalizeToolEvent(event) {
				continue
			}
		case sourceID + "." + familyControlMapping:
			if !normalizeControlMappingEvent(event) {
				continue
			}
		}
		out = append(out, event)
	}
	return out
}

func normalizeToolEvent(event *cerebrov1.EventEnvelope) bool {
	attrs := event.GetAttributes()
	if attrs == nil {
		return false
	}
	toolID := firstNonEmptyAttr(attrs, "tool_id", "name")
	if toolID == "" {
		return false
	}
	attrs["tool_id"] = toolID
	return true
}

func normalizeControlMappingEvent(event *cerebrov1.EventEnvelope) bool {
	attrs := event.GetAttributes()
	if attrs == nil {
		return false
	}
	toolID := firstNonEmptyAttr(attrs, "tool_id", "tool_name")
	controlID := strings.TrimSpace(attrs["control_id"])
	if toolID == "" || controlID == "" {
		return false
	}
	attrs["tool_id"] = toolID
	if status := securitytooling.CoverageStatus(attrs["coverage"]); status != "" {
		attrs["coverage_status"] = status
	}
	return true
}

func firstNonEmptyAttr(attrs map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(attrs[key]); value != "" {
			return value
		}
	}
	return ""
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
	}
}
