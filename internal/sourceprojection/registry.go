package sourceprojection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/ports"
)

// ProjectionHandler processes events for a specific source type or event kind.
type ProjectionHandler interface {
	// Handles reports which event kind prefixes this handler processes.
	Handles() []string
}

// ProjectFunc converts one source event into graph projection records.
type ProjectFunc func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error)

// ContextProjectFunc converts one source event using caller cancellation and deadlines.
type ContextProjectFunc func(context.Context, *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error)

// ErrProjectionContextRequired indicates that a context-free projection API cannot run the
// registered projector. Call the corresponding Context method with a caller-owned context.
var ErrProjectionContextRequired = errors.New("source projection requires caller context")

type projectionCall struct {
	ctx context.Context
}

// EventProjector binds one event kind to one projector.
type EventProjector struct {
	Kind    string
	Project ProjectFunc
}

// Registry indexes projectors by event kind.
type Registry struct {
	mu                              sync.RWMutex
	projectors                      map[string]ProjectFunc
	contextProjectors               map[string]ContextProjectFunc
	handlers                        map[string]ProjectionHandler
	connectorDefinitionFingerprints map[string]string
	connectorDefinitionKinds        map[string]map[string]struct{}
	connectorDefinitionBases        map[string]ProjectFunc
	connectorDefinitionProjectors   map[string]map[string]ProjectFunc
}

// NewRegistry constructs an event projection registry.
func NewRegistry(projectors ...EventProjector) (*Registry, error) {
	registry := &Registry{
		projectors:                      make(map[string]ProjectFunc, len(projectors)),
		contextProjectors:               make(map[string]ContextProjectFunc),
		handlers:                        make(map[string]ProjectionHandler),
		connectorDefinitionFingerprints: map[string]string{},
		connectorDefinitionKinds:        map[string]map[string]struct{}{},
		connectorDefinitionBases:        map[string]ProjectFunc{},
		connectorDefinitionProjectors:   map[string]map[string]ProjectFunc{},
	}
	for _, projector := range projectors {
		kind := strings.TrimSpace(projector.Kind)
		if kind == "" {
			return nil, fmt.Errorf("projector kind is required")
		}
		if projector.Project == nil {
			return nil, fmt.Errorf("projector %q function is required", kind)
		}
		if _, ok := registry.projectors[kind]; ok {
			return nil, fmt.Errorf("duplicate projector kind %q", kind)
		}
		registry.projectors[kind] = projector.Project
	}
	return registry, nil
}

// RegisterConnectorDefinitions adds declarative runtime connector projectors to the registry.
func (r *Registry) RegisterConnectorDefinitions(definitions ...connectordefinitions.Definition) {
	if r == nil || len(definitions) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensureConnectorDefinitionState()
	for _, definition := range definitions {
		normalized, err := connectordefinitions.Normalize(definition)
		if err != nil {
			continue
		}
		definition = normalized
		sourceID := strings.TrimSpace(definition.SourceID)
		if sourceID == "" || definition.Validation.Status == connectordefinitions.ValidationBlocked {
			continue
		}
		fingerprint := connectorDefinitionProjectorFingerprint(definition)
		if r.connectorDefinitionFingerprints[sourceID] == fingerprint {
			continue
		}
		r.unregisterConnectorDefinitionProjectors(sourceID)
		sourceProjectors := catalogRuntimeDefinitionProjectors(definition)
		if len(sourceProjectors) == 0 {
			continue
		}
		kinds := make([]string, 0, len(sourceProjectors))
		for kind, projector := range sourceProjectors {
			if _, ok := r.connectorDefinitionProjectors[kind]; !ok {
				r.connectorDefinitionBases[kind] = r.projectors[kind]
				r.connectorDefinitionProjectors[kind] = map[string]ProjectFunc{}
			}
			r.connectorDefinitionProjectors[kind][sourceID] = projector
			r.projectors[kind] = connectorDefinitionDispatchProjector(r.connectorDefinitionBases[kind], r.connectorDefinitionProjectors[kind])
			kinds = append(kinds, kind)
		}
		r.connectorDefinitionFingerprints[sourceID] = fingerprint
		r.connectorDefinitionKinds[sourceID] = kindSet(kinds)
	}
}

func (r *Registry) ensureConnectorDefinitionState() {
	if r.connectorDefinitionFingerprints == nil {
		r.connectorDefinitionFingerprints = map[string]string{}
	}
	if r.connectorDefinitionKinds == nil {
		r.connectorDefinitionKinds = map[string]map[string]struct{}{}
	}
	if r.connectorDefinitionBases == nil {
		r.connectorDefinitionBases = map[string]ProjectFunc{}
	}
	if r.connectorDefinitionProjectors == nil {
		r.connectorDefinitionProjectors = map[string]map[string]ProjectFunc{}
	}
}

func (r *Registry) unregisterConnectorDefinitionProjectors(sourceID string) {
	kinds := r.connectorDefinitionKinds[sourceID]
	for kind := range kinds {
		sourceProjectors := r.connectorDefinitionProjectors[kind]
		if sourceProjectors != nil {
			delete(sourceProjectors, sourceID)
			if len(sourceProjectors) > 0 {
				r.projectors[kind] = connectorDefinitionDispatchProjector(r.connectorDefinitionBases[kind], sourceProjectors)
				continue
			}
		}
		base, ok := r.connectorDefinitionBases[kind]
		if ok && base != nil {
			r.projectors[kind] = base
		} else {
			delete(r.projectors, kind)
		}
		delete(r.connectorDefinitionBases, kind)
		delete(r.connectorDefinitionProjectors, kind)
	}
	delete(r.connectorDefinitionKinds, sourceID)
	delete(r.connectorDefinitionFingerprints, sourceID)
}

func connectorDefinitionDispatchProjector(base ProjectFunc, sourceProjectors map[string]ProjectFunc) ProjectFunc {
	projectors := make(map[string]ProjectFunc, len(sourceProjectors))
	for sourceID, projector := range sourceProjectors {
		if projector != nil {
			projectors[sourceID] = projector
		}
	}
	return func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		if event != nil {
			if projector := projectors[strings.TrimSpace(event.GetSourceId())]; projector != nil {
				return projector(event)
			}
		}
		if base != nil {
			return base(event)
		}
		return nil, nil, nil
	}
}

func connectorDefinitionProjectorFingerprint(definition connectordefinitions.Definition) string {
	body, err := json.Marshal(struct {
		SourceID         string                                `json:"source_id"`
		ResourceFamilies []connectordefinitions.ResourceFamily `json:"resource_families"`
	}{SourceID: strings.TrimSpace(definition.SourceID), ResourceFamilies: definition.ResourceFamilies})
	if err != nil {
		return strings.TrimSpace(definition.SourceID)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func kindSet(kinds []string) map[string]struct{} {
	out := make(map[string]struct{}, len(kinds))
	for _, kind := range kinds {
		out[kind] = struct{}{}
	}
	return out
}

// BuiltinRegistry returns the default source event projector registry.
func BuiltinRegistry() *Registry {
	return builtinRegistry
}

// Register adds a handler for the kind prefixes it declares via Handles.
func (r *Registry) Register(h ProjectionHandler) {
	if r == nil || h == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handlers == nil {
		r.handlers = make(map[string]ProjectionHandler)
	}
	for _, prefix := range h.Handles() {
		r.handlers[prefix] = h
	}
}

// Lookup finds the handler for a given event kind by trying progressively
// shorter prefixes until a match is found.
func (r *Registry) Lookup(kind string) (ProjectionHandler, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.handlers == nil {
		return nil, false
	}
	for i := len(kind); i > 0; i-- {
		if h, ok := r.handlers[kind[:i]]; ok {
			return h, true
		}
	}
	return nil, false
}

// Kinds returns sorted registered event kinds.
func (r *Registry) Kinds() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	kindSet := make(map[string]struct{}, len(r.projectors)+len(r.contextProjectors))
	for kind := range r.projectors {
		kindSet[kind] = struct{}{}
	}
	for kind := range r.contextProjectors {
		kindSet[kind] = struct{}{}
	}
	kinds := make([]string, 0, len(kindSet))
	for kind := range kindSet {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}

// Project applies the registered base projector for an event. Projectors that require caller
// cancellation return ErrProjectionContextRequired; use ProjectContext for those event kinds.
func (r *Registry) Project(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := r.project(projectionCall{}, event)
	if err != nil {
		return nil, nil, err
	}
	if err := ports.ValidateProjectedTenantScopes(entities, links); err != nil {
		return nil, nil, err
	}
	return entities, links, nil
}

// ProjectContext applies the registered projector and context-aware enrichments.
func (r *Registry) ProjectContext(ctx context.Context, event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	if ctx == nil {
		return nil, nil, fmt.Errorf("context is required")
	}
	entities, links, err := r.project(projectionCall{ctx: ctx}, event)
	if err != nil {
		return nil, nil, err
	}
	entities, links, err = addMITREProjectionContext(ctx, event, entities, links)
	if err != nil {
		return nil, nil, err
	}
	if err := ports.ValidateProjectedTenantScopes(entities, links); err != nil {
		return nil, nil, err
	}
	return entities, links, nil
}

func (r *Registry) project(call projectionCall, event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	if event == nil {
		return nil, nil, fmt.Errorf("event is required")
	}
	if r == nil {
		return nil, nil, nil
	}
	r.mu.RLock()
	kind := strings.TrimSpace(event.GetKind())
	project := r.projectors[kind]
	contextProject := r.contextProjectors[kind]
	connectorProject := r.connectorDefinitionProjectors[kind][strings.TrimSpace(event.GetSourceId())]
	r.mu.RUnlock()
	switch {
	case connectorProject != nil:
		return connectorProject(event)
	case call.ctx != nil && contextProject != nil:
		return contextProject(call.ctx, event)
	case project != nil:
		return project(event)
	case contextProject != nil:
		return nil, nil, fmt.Errorf("projector %q: %w", kind, ErrProjectionContextRequired)
	default:
		return nil, nil, nil
	}
}

// ProjectEvent projects one event through the built-in base registry without stores. Projectors
// that require caller cancellation return ErrProjectionContextRequired; use ProjectEventContext.
func ProjectEvent(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return BuiltinRegistry().Project(event)
}

// ProjectEventContext projects one event through the built-in registry with caller cancellation and context-aware enrichments.
func ProjectEventContext(ctx context.Context, event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return BuiltinRegistry().ProjectContext(ctx, event)
}
