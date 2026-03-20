package app

import (
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/graph"
)

func (a *App) resolveTapMappingIdentity(raw string, evt events.CloudEvent) string {
	if securityGraph := a.currentTapResolveGraph(); securityGraph != nil {
		return a.resolveTapMappingIdentityOnGraph(securityGraph, raw, evt)
	}
	if securityGraph := a.CurrentSecurityGraph(); securityGraph != nil {
		return a.resolveTapMappingIdentityOnGraph(securityGraph, raw, evt)
	}
	return a.resolveTapMappingIdentityOnGraph(nil, raw, evt)
}

func (a *App) resolveTapMappingIdentityOnGraph(securityGraph *graph.Graph, raw string, evt events.CloudEvent) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, ":") {
		return raw
	}

	email := strings.ToLower(strings.TrimSpace(raw))
	if strings.Contains(email, "@") {
		canonicalID := "person:" + email
		if securityGraph != nil {
			if _, ok := securityGraph.GetNode(canonicalID); !ok {
				securityGraph.AddNode(&graph.Node{
					ID:       canonicalID,
					Kind:     graph.NodeKindPerson,
					Name:     email,
					Provider: "org",
					Properties: map[string]any{
						"email":           email,
						"source_system":   firstNonEmpty(sourceSystemFromTapType(evt.Type), "tap"),
						"source_event_id": evt.ID,
						"observed_at":     evt.Time.UTC().Format(time.RFC3339),
						"valid_from":      evt.Time.UTC().Format(time.RFC3339),
						"confidence":      0.80,
					},
				})
			}
			_, _ = graph.ResolveIdentityAlias(securityGraph, graph.IdentityAliasAssertion{
				SourceSystem:  firstNonEmpty(sourceSystemFromTapType(evt.Type), "tap"),
				SourceEventID: strings.TrimSpace(evt.ID),
				ExternalID:    email,
				Email:         email,
				CanonicalHint: canonicalID,
				ObservedAt:    evt.Time.UTC(),
				Confidence:    0.95,
			}, graph.IdentityResolutionOptions{})
		}
		return canonicalID
	}
	return raw
}

func (a *App) withTapResolveGraph(securityGraph *graph.Graph, fn func() error) error {
	if a == nil {
		if fn == nil {
			return nil
		}
		return fn()
	}
	a.tapResolveGraphMu.Lock()
	a.tapResolveGraph = securityGraph
	a.tapResolveGraphMu.Unlock()
	defer func() {
		a.tapResolveGraphMu.Lock()
		a.tapResolveGraph = nil
		a.tapResolveGraphMu.Unlock()
	}()
	if fn == nil {
		return nil
	}
	return fn()
}

func (a *App) currentTapResolveGraph() *graph.Graph {
	if a == nil {
		return nil
	}
	a.tapResolveGraphMu.RLock()
	defer a.tapResolveGraphMu.RUnlock()
	return a.tapResolveGraph
}
