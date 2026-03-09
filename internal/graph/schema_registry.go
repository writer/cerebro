package graph

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// NodeKindCategory groups node kinds by behavioral category.
type NodeKindCategory string

const (
	NodeCategoryIdentity   NodeKindCategory = "identity"
	NodeCategoryResource   NodeKindCategory = "resource"
	NodeCategoryBusiness   NodeKindCategory = "business"
	NodeCategoryKubernetes NodeKindCategory = "kubernetes"
)

// NodeKindDefinition describes one node kind schema registration.
type NodeKindDefinition struct {
	Kind          NodeKind           `json:"kind"`
	Categories    []NodeKindCategory `json:"categories,omitempty"`
	Properties    map[string]string  `json:"properties,omitempty"`
	Relationships []EdgeKind         `json:"relationships,omitempty"`
	Description   string             `json:"description,omitempty"`
}

// EdgeKindDefinition describes one edge kind schema registration.
type EdgeKindDefinition struct {
	Kind        EdgeKind `json:"kind"`
	Description string   `json:"description,omitempty"`
}

// SchemaRegistry stores runtime node/edge schema declarations.
type SchemaRegistry struct {
	mu            sync.RWMutex
	nodeKinds     map[NodeKind]NodeKindDefinition
	edgeKinds     map[EdgeKind]EdgeKindDefinition
	categoryIndex map[NodeKindCategory]map[NodeKind]struct{}
}

var (
	globalSchemaRegistry     *SchemaRegistry
	globalSchemaRegistryOnce sync.Once
)

// GlobalSchemaRegistry returns the singleton schema registry.
func GlobalSchemaRegistry() *SchemaRegistry {
	globalSchemaRegistryOnce.Do(func() {
		globalSchemaRegistry = NewSchemaRegistry()
	})
	return globalSchemaRegistry
}

// NewSchemaRegistry creates a schema registry with all built-in kinds pre-registered.
func NewSchemaRegistry() *SchemaRegistry {
	reg := &SchemaRegistry{
		nodeKinds:     make(map[NodeKind]NodeKindDefinition),
		edgeKinds:     make(map[EdgeKind]EdgeKindDefinition),
		categoryIndex: make(map[NodeKindCategory]map[NodeKind]struct{}),
	}
	reg.registerBuiltins()
	return reg
}

// RegisterNodeKindDefinition registers or updates one node kind definition.
func RegisterNodeKindDefinition(def NodeKindDefinition) (NodeKindDefinition, error) {
	return GlobalSchemaRegistry().RegisterNodeKindDefinition(def)
}

// RegisterEdgeKindDefinition registers or updates one edge kind definition.
func RegisterEdgeKindDefinition(def EdgeKindDefinition) (EdgeKindDefinition, error) {
	return GlobalSchemaRegistry().RegisterEdgeKindDefinition(def)
}

// RegisteredNodeKinds returns all registered node kinds sorted by kind name.
func RegisteredNodeKinds() []NodeKindDefinition {
	return GlobalSchemaRegistry().ListNodeKinds()
}

// RegisteredEdgeKinds returns all registered edge kinds sorted by kind name.
func RegisteredEdgeKinds() []EdgeKindDefinition {
	return GlobalSchemaRegistry().ListEdgeKinds()
}

// IsNodeKindInCategory returns true when a node kind belongs to a category.
func IsNodeKindInCategory(kind NodeKind, category NodeKindCategory) bool {
	return GlobalSchemaRegistry().NodeKindInCategory(kind, category)
}

// RegisterNodeKindDefinition registers or updates one node kind definition in this registry.
func (r *SchemaRegistry) RegisterNodeKindDefinition(def NodeKindDefinition) (NodeKindDefinition, error) {
	normalized, err := normalizeNodeKindDefinition(def)
	if err != nil {
		return NodeKindDefinition{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.nodeKinds[normalized.Kind]; ok {
		merged := mergeNodeKindDefinitions(existing, normalized)
		r.nodeKinds[merged.Kind] = merged
		r.reindexNodeKindLocked(merged.Kind, merged.Categories)
		return cloneNodeKindDefinition(merged), nil
	}

	r.nodeKinds[normalized.Kind] = normalized
	r.reindexNodeKindLocked(normalized.Kind, normalized.Categories)
	return cloneNodeKindDefinition(normalized), nil
}

// RegisterEdgeKindDefinition registers or updates one edge kind definition in this registry.
func (r *SchemaRegistry) RegisterEdgeKindDefinition(def EdgeKindDefinition) (EdgeKindDefinition, error) {
	normalized, err := normalizeEdgeKindDefinition(def)
	if err != nil {
		return EdgeKindDefinition{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.edgeKinds[normalized.Kind]; ok {
		merged := existing
		if strings.TrimSpace(merged.Description) == "" {
			merged.Description = normalized.Description
		}
		r.edgeKinds[merged.Kind] = merged
		return merged, nil
	}

	r.edgeKinds[normalized.Kind] = normalized
	return normalized, nil
}

// ListNodeKinds returns all node kinds sorted by kind.
func (r *SchemaRegistry) ListNodeKinds() []NodeKindDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]NodeKindDefinition, 0, len(r.nodeKinds))
	for _, def := range r.nodeKinds {
		out = append(out, cloneNodeKindDefinition(def))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Kind < out[j].Kind
	})
	return out
}

// ListEdgeKinds returns all edge kinds sorted by kind.
func (r *SchemaRegistry) ListEdgeKinds() []EdgeKindDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]EdgeKindDefinition, 0, len(r.edgeKinds))
	for _, def := range r.edgeKinds {
		out = append(out, def)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Kind < out[j].Kind
	})
	return out
}

// NodeKindInCategory returns true when kind belongs to category.
func (r *SchemaRegistry) NodeKindInCategory(kind NodeKind, category NodeKindCategory) bool {
	kind = NodeKind(strings.TrimSpace(string(kind)))
	category, ok := normalizeNodeCategory(category)
	if !ok || kind == "" {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if kinds, ok := r.categoryIndex[category]; ok {
		_, exists := kinds[kind]
		return exists
	}
	return false
}

// IsNodeKindRegistered returns true when kind exists in registry.
func (r *SchemaRegistry) IsNodeKindRegistered(kind NodeKind) bool {
	kind = NodeKind(strings.TrimSpace(string(kind)))
	if kind == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.nodeKinds[kind]
	return ok
}

// IsEdgeKindRegistered returns true when edge kind exists in registry.
func (r *SchemaRegistry) IsEdgeKindRegistered(kind EdgeKind) bool {
	kind = EdgeKind(strings.TrimSpace(string(kind)))
	if kind == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.edgeKinds[kind]
	return ok
}

func (r *SchemaRegistry) registerBuiltins() {
	for _, def := range builtInNodeKinds {
		_, _ = r.RegisterNodeKindDefinition(def)
	}
	for _, def := range builtInEdgeKinds {
		_, _ = r.RegisterEdgeKindDefinition(def)
	}
}

func (r *SchemaRegistry) reindexNodeKindLocked(kind NodeKind, categories []NodeKindCategory) {
	for category, kinds := range r.categoryIndex {
		delete(kinds, kind)
		if len(kinds) == 0 {
			delete(r.categoryIndex, category)
		}
	}
	for _, category := range categories {
		if r.categoryIndex[category] == nil {
			r.categoryIndex[category] = make(map[NodeKind]struct{})
		}
		r.categoryIndex[category][kind] = struct{}{}
	}
}

func normalizeNodeKindDefinition(def NodeKindDefinition) (NodeKindDefinition, error) {
	kind := NodeKind(strings.TrimSpace(string(def.Kind)))
	if kind == "" {
		return NodeKindDefinition{}, fmt.Errorf("node kind is required")
	}

	categories := make([]NodeKindCategory, 0, len(def.Categories))
	for _, category := range def.Categories {
		normalizedCategory, ok := normalizeNodeCategory(category)
		if !ok {
			return NodeKindDefinition{}, fmt.Errorf("unknown node category %q", category)
		}
		categories = append(categories, normalizedCategory)
	}

	props := make(map[string]string)
	for key, value := range def.Properties {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		props[trimmedKey] = strings.TrimSpace(value)
	}

	relationships := make([]EdgeKind, 0, len(def.Relationships))
	for _, relationship := range def.Relationships {
		trimmed := EdgeKind(strings.TrimSpace(string(relationship)))
		if trimmed == "" {
			continue
		}
		relationships = append(relationships, trimmed)
	}

	return NodeKindDefinition{
		Kind:          kind,
		Categories:    uniqueSortedNodeCategories(categories),
		Properties:    props,
		Relationships: uniqueSortedEdgeKinds(relationships),
		Description:   strings.TrimSpace(def.Description),
	}, nil
}

func normalizeEdgeKindDefinition(def EdgeKindDefinition) (EdgeKindDefinition, error) {
	kind := EdgeKind(strings.TrimSpace(string(def.Kind)))
	if kind == "" {
		return EdgeKindDefinition{}, fmt.Errorf("edge kind is required")
	}
	return EdgeKindDefinition{
		Kind:        kind,
		Description: strings.TrimSpace(def.Description),
	}, nil
}

func normalizeNodeCategory(category NodeKindCategory) (NodeKindCategory, bool) {
	normalized := NodeKindCategory(strings.ToLower(strings.TrimSpace(string(category))))
	switch normalized {
	case NodeCategoryIdentity, NodeCategoryResource, NodeCategoryBusiness, NodeCategoryKubernetes:
		return normalized, true
	default:
		return "", false
	}
}

func mergeNodeKindDefinitions(existing NodeKindDefinition, incoming NodeKindDefinition) NodeKindDefinition {
	merged := cloneNodeKindDefinition(existing)
	merged.Categories = uniqueSortedNodeCategories(append(merged.Categories, incoming.Categories...))
	merged.Relationships = uniqueSortedEdgeKinds(append(merged.Relationships, incoming.Relationships...))
	if merged.Properties == nil {
		merged.Properties = make(map[string]string)
	}
	for key, value := range incoming.Properties {
		merged.Properties[key] = value
	}
	if strings.TrimSpace(incoming.Description) != "" {
		merged.Description = incoming.Description
	}
	return merged
}

func cloneNodeKindDefinition(def NodeKindDefinition) NodeKindDefinition {
	cloned := NodeKindDefinition{
		Kind:          def.Kind,
		Categories:    append([]NodeKindCategory(nil), def.Categories...),
		Relationships: append([]EdgeKind(nil), def.Relationships...),
		Description:   def.Description,
	}
	if def.Properties != nil {
		cloned.Properties = make(map[string]string, len(def.Properties))
		for key, value := range def.Properties {
			cloned.Properties[key] = value
		}
	}
	return cloned
}

func uniqueSortedNodeCategories(values []NodeKindCategory) []NodeKindCategory {
	if len(values) == 0 {
		return nil
	}
	set := make(map[NodeKindCategory]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	out := make([]NodeKindCategory, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func uniqueSortedEdgeKinds(values []EdgeKind) []EdgeKind {
	if len(values) == 0 {
		return nil
	}
	set := make(map[EdgeKind]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	out := make([]EdgeKind, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

var builtInNodeKinds = []NodeKindDefinition{
	{Kind: NodeKindAny},
	{Kind: NodeKindUser, Categories: []NodeKindCategory{NodeCategoryIdentity}},
	{Kind: NodeKindPerson, Categories: []NodeKindCategory{NodeCategoryIdentity}},
	{Kind: NodeKindRole, Categories: []NodeKindCategory{NodeCategoryIdentity}},
	{Kind: NodeKindGroup, Categories: []NodeKindCategory{NodeCategoryIdentity}},
	{Kind: NodeKindServiceAccount, Categories: []NodeKindCategory{NodeCategoryIdentity}},
	{Kind: NodeKindBucket, Categories: []NodeKindCategory{NodeCategoryResource}},
	{Kind: NodeKindInstance, Categories: []NodeKindCategory{NodeCategoryResource}},
	{Kind: NodeKindDatabase, Categories: []NodeKindCategory{NodeCategoryResource}},
	{Kind: NodeKindSecret, Categories: []NodeKindCategory{NodeCategoryResource}},
	{Kind: NodeKindFunction, Categories: []NodeKindCategory{NodeCategoryResource}},
	{Kind: NodeKindNetwork, Categories: []NodeKindCategory{NodeCategoryResource}},
	{Kind: NodeKindApplication, Categories: []NodeKindCategory{NodeCategoryResource}},
	{Kind: NodeKindPod, Categories: []NodeKindCategory{NodeCategoryResource, NodeCategoryKubernetes}},
	{Kind: NodeKindDeployment, Categories: []NodeKindCategory{NodeCategoryResource, NodeCategoryKubernetes}},
	{Kind: NodeKindNamespace, Categories: []NodeKindCategory{NodeCategoryKubernetes}},
	{Kind: NodeKindClusterRole, Categories: []NodeKindCategory{NodeCategoryKubernetes}},
	{Kind: NodeKindClusterRoleBinding, Categories: []NodeKindCategory{NodeCategoryKubernetes}},
	{Kind: NodeKindConfigMap, Categories: []NodeKindCategory{NodeCategoryResource, NodeCategoryKubernetes}},
	{Kind: NodeKindPersistentVolume, Categories: []NodeKindCategory{NodeCategoryResource, NodeCategoryKubernetes}},
	{Kind: NodeKindRepository},
	{Kind: NodeKindCIWorkflow},
	{Kind: NodeKindInternet},
	{Kind: NodeKindSCP},
	{Kind: NodeKindPermissionBoundary},
	{Kind: NodeKindCustomer, Categories: []NodeKindCategory{NodeCategoryBusiness}},
	{Kind: NodeKindContact, Categories: []NodeKindCategory{NodeCategoryBusiness}},
	{Kind: NodeKindCompany, Categories: []NodeKindCategory{NodeCategoryBusiness}},
	{Kind: NodeKindDeal, Categories: []NodeKindCategory{NodeCategoryBusiness}},
	{Kind: NodeKindOpportunity, Categories: []NodeKindCategory{NodeCategoryBusiness}},
	{Kind: NodeKindSubscription, Categories: []NodeKindCategory{NodeCategoryBusiness}},
	{Kind: NodeKindInvoice, Categories: []NodeKindCategory{NodeCategoryBusiness}},
	{Kind: NodeKindTicket, Categories: []NodeKindCategory{NodeCategoryBusiness}},
	{Kind: NodeKindLead, Categories: []NodeKindCategory{NodeCategoryBusiness}},
	{Kind: NodeKindActivity, Categories: []NodeKindCategory{NodeCategoryBusiness}},
	{Kind: NodeKindDepartment, Categories: []NodeKindCategory{NodeCategoryBusiness}},
	{Kind: NodeKindLocation, Categories: []NodeKindCategory{NodeCategoryBusiness}},
}

var builtInEdgeKinds = []EdgeKindDefinition{
	{Kind: EdgeKindCanAssume},
	{Kind: EdgeKindMemberOf},
	{Kind: EdgeKindResolvesTo},
	{Kind: EdgeKindReportsTo},
	{Kind: EdgeKindCanRead},
	{Kind: EdgeKindCanWrite},
	{Kind: EdgeKindCanDelete},
	{Kind: EdgeKindCanAdmin},
	{Kind: EdgeKindConnectsTo},
	{Kind: EdgeKindExposedTo},
	{Kind: EdgeKindDeployedFrom},
	{Kind: EdgeKindOriginatedFrom},
	{Kind: EdgeKindProvisionedAs},
	{Kind: EdgeKindOwns},
	{Kind: EdgeKindSubscribedTo},
	{Kind: EdgeKindBilledBy},
	{Kind: EdgeKindWorksAt},
	{Kind: EdgeKindManagedBy},
	{Kind: EdgeKindAssignedTo},
	{Kind: EdgeKindRenews},
	{Kind: EdgeKindEscalatedTo},
	{Kind: EdgeKindRefers},
	{Kind: EdgeKindInteractedWith},
	{Kind: EdgeKindLocatedIn},
}
