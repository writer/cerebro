package stream

import (
	"strings"
	"time"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
)

func (r *Runtime) resolveTapMappingIdentity(raw string, evt events.CloudEvent) string {
	if securityGraph := r.currentTapResolveGraph(); securityGraph != nil {
		return r.resolveTapMappingIdentityOnGraph(securityGraph, raw, evt)
	}
	if securityGraph := r.currentSecurityGraph(); securityGraph != nil {
		return r.resolveTapMappingIdentityOnGraph(securityGraph, raw, evt)
	}
	return r.resolveTapMappingIdentityOnGraph(nil, raw, evt)
}

func tapIdentityPersonNodeID(email string) string {
	return "person:" + strings.ToLower(strings.TrimSpace(email))
}

func (r *Runtime) resolveTapMappingIdentityOnGraph(securityGraph *graph.Graph, raw string, evt events.CloudEvent) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, ":") {
		return raw
	}

	email := strings.ToLower(strings.TrimSpace(raw))
	if strings.Contains(email, "@") {
		canonicalNodeID := tapIdentityPersonNodeID(email)
		if securityGraph != nil {
			if _, ok := securityGraph.GetNode(canonicalNodeID); !ok {
				securityGraph.AddNode(&graph.Node{
					ID:       canonicalNodeID,
					Kind:     graph.NodeKindPerson,
					Name:     email,
					Provider: "org",
					Properties: map[string]any{
						"email":           email,
						"source_system":   firstNonEmpty(SourceSystemFromTapType(evt.Type), "tap"),
						"source_event_id": evt.ID,
						"observed_at":     evt.Time.UTC().Format(time.RFC3339),
						"valid_from":      evt.Time.UTC().Format(time.RFC3339),
						"confidence":      0.80,
					},
				})
			}
			if _, err := graph.ResolveIdentityAlias(securityGraph, graph.IdentityAliasAssertion{
				SourceSystem:  firstNonEmpty(SourceSystemFromTapType(evt.Type), "tap"),
				SourceEventID: strings.TrimSpace(evt.ID),
				ExternalID:    email,
				Email:         email,
				CanonicalHint: canonicalNodeID,
				ObservedAt:    evt.Time.UTC(),
				Confidence:    0.95,
			}, graph.IdentityResolutionOptions{}); err != nil && r != nil && r.logger() != nil {
				r.logger().Warn("resolve tap identity alias failed", "identity", email, "event_id", strings.TrimSpace(evt.ID), "error", err)
			}
		}
		return canonicalNodeID
	}
	return raw
}

func (r *Runtime) withTapResolveGraph(securityGraph *graph.Graph, fn func() error) error {
	if r == nil {
		if fn == nil {
			return nil
		}
		return fn()
	}
	r.resolveGraphMu.Lock()
	r.resolveGraph = securityGraph
	r.resolveGraphMu.Unlock()
	defer func() {
		r.resolveGraphMu.Lock()
		r.resolveGraph = nil
		r.resolveGraphMu.Unlock()
	}()
	if fn == nil {
		return nil
	}
	return fn()
}

func (r *Runtime) currentTapResolveGraph() *graph.Graph {
	if r == nil {
		return nil
	}
	r.resolveGraphMu.RLock()
	defer r.resolveGraphMu.RUnlock()
	return r.resolveGraph
}

func (r *Runtime) ResolveTapMappingIdentity(raw string, evt events.CloudEvent) string {
	return r.resolveTapMappingIdentity(raw, evt)
}

func (r *Runtime) WithTapResolveGraph(securityGraph *graph.Graph, fn func() error) error {
	return r.withTapResolveGraph(securityGraph, fn)
}

func (r *Runtime) CurrentTapResolveGraph() *graph.Graph {
	return r.currentTapResolveGraph()
}
