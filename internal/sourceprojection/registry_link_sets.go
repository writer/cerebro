package sourceprojection

import (
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

// LinkSetProjectFunc converts one source event into guarded link sets a
// projector wants applied atomically instead of through the plain link
// upsert path (Contract C9). Most event kinds never emit link sets and
// leave this unregistered.
type LinkSetProjectFunc func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error)

// registerLinkSetProjector records the optional link-set projector for a
// kind that NewRegistry has already registered a base projector for, so
// Kinds never needs a separate entry for link sets.
func (r *Registry) registerLinkSetProjector(kind string, project LinkSetProjectFunc) {
	if project == nil {
		return
	}
	if r.linkSetProjectors == nil {
		r.linkSetProjectors = make(map[string]LinkSetProjectFunc)
	}
	r.linkSetProjectors[kind] = project
}

// ProjectLinkSets returns the guarded link sets (Contract C9) the
// registered projector emits for this event, validating their tenant scope
// the same way Project and ProjectContext validate entities and links.
// Event kinds without a registered link-set projector return (nil, nil).
func (r *Registry) ProjectLinkSets(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
	if event == nil {
		return nil, fmt.Errorf("event is required")
	}
	if r == nil {
		return nil, nil
	}
	kind := strings.TrimSpace(event.GetKind())
	if sourceID := rustAuthoritativeEventSource(event); r.enforceRustAuthority && sourceID != "" {
		// Rust owns this source's organizational projection; fail closed the
		// same way project() does ahead of every dispatch path.
		return nil, fmt.Errorf("projector %q: %w", kind, rustProjectionRequiredError(sourceID))
	}
	r.mu.RLock()
	project := r.linkSetProjectors[kind]
	r.mu.RUnlock()
	if project == nil {
		return nil, nil
	}
	sets, err := project(event)
	if err != nil {
		return nil, err
	}
	if err := ports.ValidateProjectedLinkSetsTenantScopes(sets); err != nil {
		return nil, err
	}
	return sets, nil
}
