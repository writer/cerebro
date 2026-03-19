package graph

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

// NodeKindCategory groups node kinds by behavioral category.
type NodeKindCategory string

const (
	NodeCategoryIdentity   NodeKindCategory = "identity"
	NodeCategoryResource   NodeKindCategory = "resource"
	NodeCategoryBusiness   NodeKindCategory = "business"
	NodeCategoryKubernetes NodeKindCategory = "kubernetes"
)

// NodeKindCapability captures behavior that runtime engines can reason about.
type NodeKindCapability string

const (
	NodeCapabilityInternetExposable  NodeKindCapability = "internet_exposable"
	NodeCapabilitySensitiveData      NodeKindCapability = "stores_sensitive_data"
	NodeCapabilityPrivilegedIdentity NodeKindCapability = "privileged_identity"
	NodeCapabilityCredentialStore    NodeKindCapability = "stores_credentials"
)

// SchemaValidationIssueCode identifies one ontology conformance issue.
type SchemaValidationIssueCode string

const (
	SchemaIssueUnknownNodeKind         SchemaValidationIssueCode = "unknown_node_kind"
	SchemaIssueMissingRequiredProperty SchemaValidationIssueCode = "missing_required_property"
	SchemaIssueInvalidPropertyType     SchemaValidationIssueCode = "invalid_property_type"
	SchemaIssueInvalidEventContract    SchemaValidationIssueCode = "invalid_event_contract"
	SchemaIssueInvalidProvenance       SchemaValidationIssueCode = "invalid_provenance"
	SchemaIssueMissingMetadataKey      SchemaValidationIssueCode = "missing_metadata_key"
	SchemaIssueInvalidMetadataEnum     SchemaValidationIssueCode = "invalid_metadata_enum"
	SchemaIssueInvalidMetadataTS       SchemaValidationIssueCode = "invalid_metadata_timestamp"
	SchemaIssueUnknownEdgeKind         SchemaValidationIssueCode = "unknown_edge_kind"
	SchemaIssueMissingSourceNode       SchemaValidationIssueCode = "missing_source_node"
	SchemaIssueMissingTargetNode       SchemaValidationIssueCode = "missing_target_node"
	SchemaIssueUnknownSourceKind       SchemaValidationIssueCode = "unknown_source_kind"
	SchemaIssueUnknownTargetKind       SchemaValidationIssueCode = "unknown_target_kind"
	SchemaIssueRelationshipNotAllowed  SchemaValidationIssueCode = "relationship_not_allowed"
)

// NodeMetadataProfile defines per-kind metadata requirements and validation hints.
type NodeMetadataProfile struct {
	RequiredKeys  []string            `json:"required_keys,omitempty"`
	OptionalKeys  []string            `json:"optional_keys,omitempty"`
	TimestampKeys []string            `json:"timestamp_keys,omitempty"`
	EnumValues    map[string][]string `json:"enum_values,omitempty"`
}

// IsZero allows json omitempty to elide empty metadata profiles.
func (p NodeMetadataProfile) IsZero() bool {
	return !hasNodeMetadataProfile(p)
}

// NodeKindDefinition describes one node kind schema registration.
type NodeKindDefinition struct {
	Kind               NodeKind             `json:"kind"`
	Categories         []NodeKindCategory   `json:"categories,omitempty"`
	Properties         map[string]string    `json:"properties,omitempty"`
	RequiredProperties []string             `json:"required_properties,omitempty"`
	Relationships      []EdgeKind           `json:"relationships,omitempty"`
	Capabilities       []NodeKindCapability `json:"capabilities,omitempty"`
	MetadataProfile    NodeMetadataProfile  `json:"metadata_profile,omitempty"`
	Description        string               `json:"description,omitempty"`
}

// EdgeKindDefinition describes one edge kind schema registration.
type EdgeKindDefinition struct {
	Kind        EdgeKind `json:"kind"`
	Description string   `json:"description,omitempty"`
}

// SchemaValidationIssue represents one node/edge validation issue.
type SchemaValidationIssue struct {
	Code     SchemaValidationIssueCode `json:"code"`
	EntityID string                    `json:"entity_id,omitempty"`
	Kind     string                    `json:"kind,omitempty"`
	Property string                    `json:"property,omitempty"`
	Message  string                    `json:"message"`
}

func (i SchemaValidationIssue) Error() string { return i.Message }

// SchemaChange captures one schema version change.
type SchemaChange struct {
	Version               int64      `json:"version"`
	ChangedAt             time.Time  `json:"changed_at"`
	AddedNodeKinds        []NodeKind `json:"added_node_kinds,omitempty"`
	UpdatedNodeKinds      []NodeKind `json:"updated_node_kinds,omitempty"`
	AddedEdgeKinds        []EdgeKind `json:"added_edge_kinds,omitempty"`
	UpdatedEdgeKinds      []EdgeKind `json:"updated_edge_kinds,omitempty"`
	CompatibilityWarnings []string   `json:"compatibility_warnings,omitempty"`
}

// SchemaDriftReport aggregates schema changes between versions.
type SchemaDriftReport struct {
	FromVersion           int64      `json:"from_version"`
	ToVersion             int64      `json:"to_version"`
	AddedNodeKinds        []NodeKind `json:"added_node_kinds,omitempty"`
	UpdatedNodeKinds      []NodeKind `json:"updated_node_kinds,omitempty"`
	AddedEdgeKinds        []EdgeKind `json:"added_edge_kinds,omitempty"`
	UpdatedEdgeKinds      []EdgeKind `json:"updated_edge_kinds,omitempty"`
	CompatibilityWarnings []string   `json:"compatibility_warnings,omitempty"`
}

// SchemaSnapshot captures a full registry snapshot for persistence/export.
type SchemaSnapshot struct {
	Version   int64                `json:"version"`
	NodeKinds []NodeKindDefinition `json:"node_kinds"`
	EdgeKinds []EdgeKindDefinition `json:"edge_kinds"`
	History   []SchemaChange       `json:"history,omitempty"`
}

const schemaHistoryLimit = 128

// SchemaRegistry stores runtime node/edge schema declarations.
type SchemaRegistry struct {
	mu            sync.RWMutex
	nodeKinds     map[NodeKind]NodeKindDefinition
	edgeKinds     map[EdgeKind]EdgeKindDefinition
	categoryIndex map[NodeKindCategory]map[NodeKind]struct{}
	version       int64
	history       []SchemaChange
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
		version:       1,
	}
	reg.registerBuiltins()
	reg.history = []SchemaChange{
		{
			Version:        1,
			ChangedAt:      time.Now().UTC(),
			AddedNodeKinds: sortedNodeKindsFromMap(reg.nodeKinds),
			AddedEdgeKinds: sortedEdgeKindsFromMap(reg.edgeKinds),
		},
	}
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

// SchemaVersion returns the current schema version.
func SchemaVersion() int64 {
	return GlobalSchemaRegistry().Version()
}

// SchemaHistory returns recent schema changes (all when limit <= 0).
func SchemaHistory(limit int) []SchemaChange {
	return GlobalSchemaRegistry().History(limit)
}

// SchemaDriftSince returns drift summary since one version.
func SchemaDriftSince(version int64) SchemaDriftReport {
	return GlobalSchemaRegistry().DriftSince(version)
}

// CurrentSchemaSnapshot returns the current full schema snapshot.
func CurrentSchemaSnapshot() SchemaSnapshot {
	return GlobalSchemaRegistry().Snapshot()
}

// IsNodeKindInCategory returns true when a node kind belongs to a category.
func IsNodeKindInCategory(kind NodeKind, category NodeKindCategory) bool {
	return GlobalSchemaRegistry().NodeKindInCategory(kind, category)
}

// NodeKindHasCapability returns true when a kind advertises one capability.
func NodeKindHasCapability(kind NodeKind, capability NodeKindCapability) bool {
	return GlobalSchemaRegistry().NodeKindHasCapability(kind, capability)
}

// ValidateNodeAgainstSchema validates one node against the current schema.
func ValidateNodeAgainstSchema(node *Node) []SchemaValidationIssue {
	return GlobalSchemaRegistry().ValidateNode(node)
}

// ValidateEdgeAgainstSchema validates one edge against the current schema.
func ValidateEdgeAgainstSchema(edge *Edge, source *Node, target *Node) []SchemaValidationIssue {
	return GlobalSchemaRegistry().ValidateEdge(edge, source, target)
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
		if reflect.DeepEqual(existing, merged) {
			return cloneNodeKindDefinition(existing), nil
		}
		r.nodeKinds[merged.Kind] = merged
		r.reindexNodeKindLocked(merged.Kind, merged.Categories)
		r.recordSchemaChangeLocked(SchemaChange{
			UpdatedNodeKinds:      []NodeKind{merged.Kind},
			CompatibilityWarnings: compatibilityWarningsForNodeUpdate(existing, normalized),
		})
		return cloneNodeKindDefinition(merged), nil
	}

	r.nodeKinds[normalized.Kind] = normalized
	r.reindexNodeKindLocked(normalized.Kind, normalized.Categories)
	r.recordSchemaChangeLocked(SchemaChange{
		AddedNodeKinds: []NodeKind{normalized.Kind},
	})
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
		if strings.TrimSpace(merged.Description) == "" && strings.TrimSpace(normalized.Description) != "" {
			merged.Description = normalized.Description
		}
		if reflect.DeepEqual(existing, merged) {
			return existing, nil
		}
		r.edgeKinds[merged.Kind] = merged
		r.recordSchemaChangeLocked(SchemaChange{
			UpdatedEdgeKinds: []EdgeKind{merged.Kind},
		})
		return merged, nil
	}

	r.edgeKinds[normalized.Kind] = normalized
	r.recordSchemaChangeLocked(SchemaChange{
		AddedEdgeKinds: []EdgeKind{normalized.Kind},
	})
	return normalized, nil
}

// Version returns the current schema version.
func (r *SchemaRegistry) Version() int64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.version
}

// History returns recent changes (all when limit <= 0).
func (r *SchemaRegistry) History(limit int) []SchemaChange {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if limit <= 0 || limit >= len(r.history) {
		return cloneSchemaChanges(r.history)
	}
	start := len(r.history) - limit
	return cloneSchemaChanges(r.history[start:])
}

// DriftSince summarizes changes since one version.
func (r *SchemaRegistry) DriftSince(version int64) SchemaDriftReport {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if version < 1 {
		version = 1
	}
	drift := SchemaDriftReport{
		FromVersion: version,
		ToVersion:   r.version,
	}
	if version >= r.version {
		return drift
	}

	addedNodeKinds := make(map[NodeKind]struct{})
	updatedNodeKinds := make(map[NodeKind]struct{})
	addedEdgeKinds := make(map[EdgeKind]struct{})
	updatedEdgeKinds := make(map[EdgeKind]struct{})
	warnings := make([]string, 0)

	for _, change := range r.history {
		if change.Version <= version {
			continue
		}
		for _, kind := range change.AddedNodeKinds {
			addedNodeKinds[kind] = struct{}{}
		}
		for _, kind := range change.UpdatedNodeKinds {
			updatedNodeKinds[kind] = struct{}{}
		}
		for _, kind := range change.AddedEdgeKinds {
			addedEdgeKinds[kind] = struct{}{}
		}
		for _, kind := range change.UpdatedEdgeKinds {
			updatedEdgeKinds[kind] = struct{}{}
		}
		warnings = append(warnings, change.CompatibilityWarnings...)
	}

	drift.AddedNodeKinds = sortedNodeKinds(addedNodeKinds)
	drift.UpdatedNodeKinds = sortedNodeKinds(updatedNodeKinds)
	drift.AddedEdgeKinds = sortedEdgeKinds(addedEdgeKinds)
	drift.UpdatedEdgeKinds = sortedEdgeKinds(updatedEdgeKinds)
	drift.CompatibilityWarnings = uniqueSortedStrings(warnings)
	return drift
}

// Snapshot returns a full registry snapshot for persistence/export.
func (r *SchemaRegistry) Snapshot() SchemaSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	nodeKinds := make([]NodeKindDefinition, 0, len(r.nodeKinds))
	for _, def := range r.nodeKinds {
		nodeKinds = append(nodeKinds, cloneNodeKindDefinition(def))
	}
	sort.Slice(nodeKinds, func(i, j int) bool {
		return nodeKinds[i].Kind < nodeKinds[j].Kind
	})

	edgeKinds := make([]EdgeKindDefinition, 0, len(r.edgeKinds))
	for _, def := range r.edgeKinds {
		edgeKinds = append(edgeKinds, def)
	}
	sort.Slice(edgeKinds, func(i, j int) bool {
		return edgeKinds[i].Kind < edgeKinds[j].Kind
	})

	return SchemaSnapshot{
		Version:   r.version,
		NodeKinds: nodeKinds,
		EdgeKinds: edgeKinds,
		History:   cloneSchemaChanges(r.history),
	}
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

// NodeKindHasCapability returns true when a kind advertises capability.
func (r *SchemaRegistry) NodeKindHasCapability(kind NodeKind, capability NodeKindCapability) bool {
	kind = NodeKind(strings.TrimSpace(string(kind)))
	capability, ok := normalizeNodeCapability(capability)
	if !ok || kind == "" {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	def, exists := r.nodeKinds[kind]
	if !exists {
		return false
	}
	for _, c := range def.Capabilities {
		if c == capability {
			return true
		}
	}
	return false
}

// NodeKindDefinition returns one definition by kind.
func (r *SchemaRegistry) NodeKindDefinition(kind NodeKind) (NodeKindDefinition, bool) {
	kind = NodeKind(strings.TrimSpace(string(kind)))
	if kind == "" {
		return NodeKindDefinition{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	def, ok := r.nodeKinds[kind]
	if !ok {
		return NodeKindDefinition{}, false
	}
	return cloneNodeKindDefinition(def), true
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

// ValidateNode validates one node against registered schema.
func (r *SchemaRegistry) ValidateNode(node *Node) []SchemaValidationIssue {
	if node == nil {
		return nil
	}

	kind := NodeKind(strings.TrimSpace(string(node.Kind)))
	if kind == "" {
		return []SchemaValidationIssue{
			{
				Code:     SchemaIssueUnknownNodeKind,
				EntityID: node.ID,
				Message:  "node kind is empty",
			},
		}
	}

	r.mu.RLock()
	def, ok := r.nodeKinds[kind]
	r.mu.RUnlock()
	if !ok {
		return []SchemaValidationIssue{
			{
				Code:     SchemaIssueUnknownNodeKind,
				EntityID: node.ID,
				Kind:     string(kind),
				Message:  fmt.Sprintf("node kind %q is not registered", kind),
			},
		}
	}

	issues := make([]SchemaValidationIssue, 0)
	required := make(map[string]struct{})
	for _, property := range def.RequiredProperties {
		property = strings.TrimSpace(property)
		if property != "" {
			required[property] = struct{}{}
		}
	}
	for property, spec := range def.Properties {
		_, mustExist := parsePropertyTypeSpec(spec)
		if mustExist {
			required[property] = struct{}{}
		}
	}

	for property := range required {
		if node.Properties == nil {
			issues = append(issues, SchemaValidationIssue{
				Code:     SchemaIssueMissingRequiredProperty,
				EntityID: node.ID,
				Kind:     string(kind),
				Property: property,
				Message:  fmt.Sprintf("node kind %q requires property %q", kind, property),
			})
			continue
		}
		value, exists := node.Properties[property]
		if !exists || value == nil {
			issues = append(issues, SchemaValidationIssue{
				Code:     SchemaIssueMissingRequiredProperty,
				EntityID: node.ID,
				Kind:     string(kind),
				Property: property,
				Message:  fmt.Sprintf("node kind %q requires property %q", kind, property),
			})
		}
	}

	for property, spec := range def.Properties {
		if node.Properties == nil {
			continue
		}
		value, exists := node.Properties[property]
		if !exists || value == nil {
			continue
		}
		expectedTypes, _ := parsePropertyTypeSpec(spec)
		if !matchesAnyPropertyType(value, expectedTypes) {
			issues = append(issues, SchemaValidationIssue{
				Code:     SchemaIssueInvalidPropertyType,
				EntityID: node.ID,
				Kind:     string(kind),
				Property: property,
				Message:  fmt.Sprintf("property %q on node kind %q should be %s", property, kind, strings.Join(expectedTypes, "|")),
			})
		}
	}

	issues = append(issues, validateNodeMetadataProfile(node, kind, def.MetadataProfile, required)...)

	return issues
}

func validateNodeMetadataProfile(node *Node, kind NodeKind, profile NodeMetadataProfile, alreadyRequired map[string]struct{}) []SchemaValidationIssue {
	profile = normalizeNodeMetadataProfile(profile)
	if !hasNodeMetadataProfile(profile) || node == nil {
		return nil
	}

	issues := make([]SchemaValidationIssue, 0)
	properties := node.Properties

	for _, key := range profile.RequiredKeys {
		if _, coveredByPropertyRequirement := alreadyRequired[key]; coveredByPropertyRequirement {
			continue
		}
		if properties == nil {
			issues = append(issues, SchemaValidationIssue{
				Code:     SchemaIssueMissingMetadataKey,
				EntityID: node.ID,
				Kind:     string(kind),
				Property: key,
				Message:  fmt.Sprintf("node kind %q requires metadata key %q", kind, key),
			})
			continue
		}
		value, ok := properties[key]
		if !ok || value == nil {
			issues = append(issues, SchemaValidationIssue{
				Code:     SchemaIssueMissingMetadataKey,
				EntityID: node.ID,
				Kind:     string(kind),
				Property: key,
				Message:  fmt.Sprintf("node kind %q requires metadata key %q", kind, key),
			})
		}
	}

	for _, key := range profile.TimestampKeys {
		if properties == nil {
			continue
		}
		value, ok := properties[key]
		if !ok || value == nil {
			continue
		}
		if matchesPropertyType(value, "timestamp") {
			continue
		}
		issues = append(issues, SchemaValidationIssue{
			Code:     SchemaIssueInvalidMetadataTS,
			EntityID: node.ID,
			Kind:     string(kind),
			Property: key,
			Message:  fmt.Sprintf("metadata key %q on node kind %q should be RFC3339 timestamp", key, kind),
		})
	}

	for key, allowedValues := range profile.EnumValues {
		if properties == nil {
			continue
		}
		value, ok := properties[key]
		if !ok || value == nil {
			continue
		}
		stringValue, ok := value.(string)
		if !ok {
			issues = append(issues, SchemaValidationIssue{
				Code:     SchemaIssueInvalidMetadataEnum,
				EntityID: node.ID,
				Kind:     string(kind),
				Property: key,
				Message:  fmt.Sprintf("metadata key %q on node kind %q should be one of %s", key, kind, strings.Join(allowedValues, "|")),
			})
			continue
		}
		normalized := strings.ToLower(strings.TrimSpace(stringValue))
		if normalized == "" || !sliceContainsString(allowedValues, normalized) {
			issues = append(issues, SchemaValidationIssue{
				Code:     SchemaIssueInvalidMetadataEnum,
				EntityID: node.ID,
				Kind:     string(kind),
				Property: key,
				Message:  fmt.Sprintf("metadata key %q on node kind %q should be one of %s", key, kind, strings.Join(allowedValues, "|")),
			})
		}
	}

	return issues
}

// ValidateEdge validates one edge against registered schema.
func (r *SchemaRegistry) ValidateEdge(edge *Edge, source *Node, target *Node) []SchemaValidationIssue {
	if edge == nil {
		return nil
	}

	kind := EdgeKind(strings.TrimSpace(string(edge.Kind)))
	issues := make([]SchemaValidationIssue, 0)

	r.mu.RLock()
	defer r.mu.RUnlock()

	if kind == "" {
		issues = append(issues, SchemaValidationIssue{
			Code:     SchemaIssueUnknownEdgeKind,
			EntityID: edge.ID,
			Message:  "edge kind is empty",
		})
	} else if _, ok := r.edgeKinds[kind]; !ok {
		issues = append(issues, SchemaValidationIssue{
			Code:     SchemaIssueUnknownEdgeKind,
			EntityID: edge.ID,
			Kind:     string(kind),
			Message:  fmt.Sprintf("edge kind %q is not registered", kind),
		})
	}

	var sourceDef NodeKindDefinition
	sourceKindKnown := false
	if source == nil {
		issues = append(issues, SchemaValidationIssue{
			Code:     SchemaIssueMissingSourceNode,
			EntityID: edge.ID,
			Kind:     string(kind),
			Message:  fmt.Sprintf("edge %q source node %q not found", edge.ID, edge.Source),
		})
	} else if def, ok := r.nodeKinds[source.Kind]; ok {
		sourceDef = def
		sourceKindKnown = true
	} else {
		issues = append(issues, SchemaValidationIssue{
			Code:     SchemaIssueUnknownSourceKind,
			EntityID: edge.ID,
			Kind:     string(source.Kind),
			Message:  fmt.Sprintf("source node kind %q is not registered", source.Kind),
		})
	}

	if target == nil {
		issues = append(issues, SchemaValidationIssue{
			Code:     SchemaIssueMissingTargetNode,
			EntityID: edge.ID,
			Kind:     string(kind),
			Message:  fmt.Sprintf("edge %q target node %q not found", edge.ID, edge.Target),
		})
	} else if _, ok := r.nodeKinds[target.Kind]; !ok {
		issues = append(issues, SchemaValidationIssue{
			Code:     SchemaIssueUnknownTargetKind,
			EntityID: edge.ID,
			Kind:     string(target.Kind),
			Message:  fmt.Sprintf("target node kind %q is not registered", target.Kind),
		})
	}

	if sourceKindKnown && kind != "" && len(sourceDef.Relationships) > 0 && !sliceContainsEdgeKind(sourceDef.Relationships, kind) {
		issues = append(issues, SchemaValidationIssue{
			Code:     SchemaIssueRelationshipNotAllowed,
			EntityID: edge.ID,
			Kind:     string(kind),
			Message:  fmt.Sprintf("edge kind %q is not allowed from source kind %q", kind, source.Kind),
		})
	}

	return issues
}

func (r *SchemaRegistry) registerBuiltins() {
	for _, def := range builtInNodeKinds {
		normalized, err := normalizeNodeKindDefinition(def)
		if err != nil {
			continue
		}
		r.nodeKinds[normalized.Kind] = normalized
		r.reindexNodeKindLocked(normalized.Kind, normalized.Categories)
	}
	for _, def := range builtInEdgeKinds {
		normalized, err := normalizeEdgeKindDefinition(def)
		if err != nil {
			continue
		}
		r.edgeKinds[normalized.Kind] = normalized
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

func (r *SchemaRegistry) recordSchemaChangeLocked(change SchemaChange) {
	if len(change.AddedNodeKinds) == 0 &&
		len(change.UpdatedNodeKinds) == 0 &&
		len(change.AddedEdgeKinds) == 0 &&
		len(change.UpdatedEdgeKinds) == 0 &&
		len(change.CompatibilityWarnings) == 0 {
		return
	}

	r.version++
	change.Version = r.version
	change.ChangedAt = time.Now().UTC()
	change.AddedNodeKinds = uniqueSortedNodeKinds(change.AddedNodeKinds)
	change.UpdatedNodeKinds = uniqueSortedNodeKinds(change.UpdatedNodeKinds)
	change.AddedEdgeKinds = uniqueSortedEdgeKinds(change.AddedEdgeKinds)
	change.UpdatedEdgeKinds = uniqueSortedEdgeKinds(change.UpdatedEdgeKinds)
	change.CompatibilityWarnings = uniqueSortedStrings(change.CompatibilityWarnings)

	r.history = append(r.history, change)
	if len(r.history) > schemaHistoryLimit {
		r.history = append([]SchemaChange(nil), r.history[len(r.history)-schemaHistoryLimit:]...)
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
		spec := strings.ToLower(strings.TrimSpace(value))
		if spec == "" {
			spec = "any"
		}
		props[trimmedKey] = spec
	}
	if len(props) == 0 {
		props = nil
	}

	required := make([]string, 0, len(def.RequiredProperties))
	for _, property := range def.RequiredProperties {
		property = strings.TrimSpace(property)
		if property == "" {
			continue
		}
		required = append(required, property)
	}

	relationships := make([]EdgeKind, 0, len(def.Relationships))
	for _, relationship := range def.Relationships {
		trimmed := EdgeKind(strings.TrimSpace(string(relationship)))
		if trimmed == "" {
			continue
		}
		relationships = append(relationships, trimmed)
	}

	capabilities := make([]NodeKindCapability, 0, len(def.Capabilities))
	for _, capability := range def.Capabilities {
		normalizedCapability, ok := normalizeNodeCapability(capability)
		if !ok {
			return NodeKindDefinition{}, fmt.Errorf("unknown node capability %q", capability)
		}
		capabilities = append(capabilities, normalizedCapability)
	}
	metadataProfile := normalizeNodeMetadataProfile(def.MetadataProfile)

	return NodeKindDefinition{
		Kind:               kind,
		Categories:         uniqueSortedNodeCategories(categories),
		Properties:         props,
		RequiredProperties: uniqueSortedStrings(required),
		Relationships:      uniqueSortedEdgeKinds(relationships),
		Capabilities:       uniqueSortedNodeCapabilities(capabilities),
		MetadataProfile:    metadataProfile,
		Description:        strings.TrimSpace(def.Description),
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

func normalizeNodeCapability(capability NodeKindCapability) (NodeKindCapability, bool) {
	normalized := NodeKindCapability(strings.ToLower(strings.TrimSpace(string(capability))))
	switch normalized {
	case NodeCapabilityInternetExposable,
		NodeCapabilitySensitiveData,
		NodeCapabilityPrivilegedIdentity,
		NodeCapabilityCredentialStore:
		return normalized, true
	default:
		return "", false
	}
}

func normalizeNodeMetadataProfile(profile NodeMetadataProfile) NodeMetadataProfile {
	required := uniqueSortedStrings(profile.RequiredKeys)
	requiredSet := make(map[string]struct{}, len(required))
	for _, key := range required {
		requiredSet[key] = struct{}{}
	}

	optionalRaw := uniqueSortedStrings(profile.OptionalKeys)
	optional := make([]string, 0, len(optionalRaw))
	for _, key := range optionalRaw {
		if _, required := requiredSet[key]; required {
			continue
		}
		optional = append(optional, key)
	}
	optional = uniqueSortedStrings(optional)

	timestamps := uniqueSortedStrings(profile.TimestampKeys)
	enumValues := make(map[string][]string)
	for key, values := range profile.EnumValues {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		normalizedValues := make([]string, 0, len(values))
		for _, value := range values {
			value = strings.ToLower(strings.TrimSpace(value))
			if value == "" {
				continue
			}
			normalizedValues = append(normalizedValues, value)
		}
		normalizedValues = uniqueSortedStrings(normalizedValues)
		if len(normalizedValues) == 0 {
			continue
		}
		enumValues[key] = normalizedValues
	}
	if len(enumValues) == 0 {
		enumValues = nil
	}

	profile = NodeMetadataProfile{
		RequiredKeys:  required,
		OptionalKeys:  optional,
		TimestampKeys: timestamps,
		EnumValues:    enumValues,
	}
	if !hasNodeMetadataProfile(profile) {
		return NodeMetadataProfile{}
	}
	return profile
}

func mergeNodeKindDefinitions(existing NodeKindDefinition, incoming NodeKindDefinition) NodeKindDefinition {
	merged := cloneNodeKindDefinition(existing)
	merged.Categories = uniqueSortedNodeCategories(append(merged.Categories, incoming.Categories...))
	merged.RequiredProperties = uniqueSortedStrings(append(merged.RequiredProperties, incoming.RequiredProperties...))
	merged.Relationships = uniqueSortedEdgeKinds(append(merged.Relationships, incoming.Relationships...))
	merged.Capabilities = uniqueSortedNodeCapabilities(append(merged.Capabilities, incoming.Capabilities...))
	merged.MetadataProfile = mergeNodeMetadataProfiles(merged.MetadataProfile, incoming.MetadataProfile)

	if merged.Properties == nil && len(incoming.Properties) > 0 {
		merged.Properties = make(map[string]string, len(incoming.Properties))
	}
	for key, value := range incoming.Properties {
		merged.Properties[key] = value
	}
	if len(merged.Properties) == 0 {
		merged.Properties = nil
	}
	if strings.TrimSpace(incoming.Description) != "" {
		merged.Description = incoming.Description
	}
	return merged
}

func mergeNodeMetadataProfiles(existing NodeMetadataProfile, incoming NodeMetadataProfile) NodeMetadataProfile {
	if !hasNodeMetadataProfile(existing) {
		return normalizeNodeMetadataProfile(incoming)
	}
	if !hasNodeMetadataProfile(incoming) {
		return normalizeNodeMetadataProfile(existing)
	}

	merged := NodeMetadataProfile{
		RequiredKeys:  append([]string(nil), existing.RequiredKeys...),
		OptionalKeys:  append([]string(nil), existing.OptionalKeys...),
		TimestampKeys: append([]string(nil), existing.TimestampKeys...),
		EnumValues:    cloneStringSliceMap(existing.EnumValues),
	}
	merged.RequiredKeys = uniqueSortedStrings(append(merged.RequiredKeys, incoming.RequiredKeys...))
	merged.OptionalKeys = uniqueSortedStrings(append(merged.OptionalKeys, incoming.OptionalKeys...))
	merged.TimestampKeys = uniqueSortedStrings(append(merged.TimestampKeys, incoming.TimestampKeys...))

	if merged.EnumValues == nil && len(incoming.EnumValues) > 0 {
		merged.EnumValues = make(map[string][]string, len(incoming.EnumValues))
	}
	for key, values := range incoming.EnumValues {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		merged.EnumValues[key] = uniqueSortedStrings(append(merged.EnumValues[key], values...))
	}

	return normalizeNodeMetadataProfile(merged)
}

func cloneNodeKindDefinition(def NodeKindDefinition) NodeKindDefinition {
	cloned := NodeKindDefinition{
		Kind:               def.Kind,
		Categories:         append([]NodeKindCategory(nil), def.Categories...),
		RequiredProperties: append([]string(nil), def.RequiredProperties...),
		Relationships:      append([]EdgeKind(nil), def.Relationships...),
		Capabilities:       append([]NodeKindCapability(nil), def.Capabilities...),
		MetadataProfile:    cloneNodeMetadataProfile(def.MetadataProfile),
		Description:        def.Description,
	}
	if def.Properties != nil {
		cloned.Properties = make(map[string]string, len(def.Properties))
		for key, value := range def.Properties {
			cloned.Properties[key] = value
		}
	}
	return cloned
}

func cloneNodeMetadataProfile(profile NodeMetadataProfile) NodeMetadataProfile {
	if !hasNodeMetadataProfile(profile) {
		return NodeMetadataProfile{}
	}
	return NodeMetadataProfile{
		RequiredKeys:  append([]string(nil), profile.RequiredKeys...),
		OptionalKeys:  append([]string(nil), profile.OptionalKeys...),
		TimestampKeys: append([]string(nil), profile.TimestampKeys...),
		EnumValues:    cloneStringSliceMap(profile.EnumValues),
	}
}

func hasNodeMetadataProfile(profile NodeMetadataProfile) bool {
	return len(profile.RequiredKeys) > 0 ||
		len(profile.OptionalKeys) > 0 ||
		len(profile.TimestampKeys) > 0 ||
		len(profile.EnumValues) > 0
}

func compatibilityWarningsForNodeUpdate(existing NodeKindDefinition, incoming NodeKindDefinition) []string {
	warnings := make([]string, 0)

	existingRequired := make(map[string]struct{}, len(existing.RequiredProperties))
	for _, property := range existing.RequiredProperties {
		existingRequired[property] = struct{}{}
	}
	for _, property := range incoming.RequiredProperties {
		if _, ok := existingRequired[property]; ok {
			continue
		}
		warnings = append(warnings, fmt.Sprintf("node kind %q added required property %q", existing.Kind, property))
	}

	for key, newSpec := range incoming.Properties {
		oldSpec, ok := existing.Properties[key]
		if !ok {
			continue
		}
		oldTypes, _ := parsePropertyTypeSpec(oldSpec)
		newTypes, _ := parsePropertyTypeSpec(newSpec)
		if reflect.DeepEqual(oldTypes, newTypes) {
			continue
		}
		warnings = append(warnings, fmt.Sprintf("node kind %q changed property %q type from %s to %s", existing.Kind, key, strings.Join(oldTypes, "|"), strings.Join(newTypes, "|")))
	}

	existingRequiredMetadata := make(map[string]struct{}, len(existing.MetadataProfile.RequiredKeys))
	for _, key := range existing.MetadataProfile.RequiredKeys {
		existingRequiredMetadata[key] = struct{}{}
	}
	for _, key := range incoming.MetadataProfile.RequiredKeys {
		if _, ok := existingRequiredMetadata[key]; ok {
			continue
		}
		warnings = append(warnings, fmt.Sprintf("node kind %q added required metadata key %q", existing.Kind, key))
	}

	for key, incomingValues := range incoming.MetadataProfile.EnumValues {
		existingValues, ok := existing.MetadataProfile.EnumValues[key]
		if !ok {
			continue
		}
		if reflect.DeepEqual(existingValues, incomingValues) {
			continue
		}
		warnings = append(warnings, fmt.Sprintf("node kind %q changed metadata enum %q from %s to %s", existing.Kind, key, strings.Join(existingValues, "|"), strings.Join(incomingValues, "|")))
	}

	return uniqueSortedStrings(warnings)
}

func parsePropertyTypeSpec(spec string) ([]string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(spec))
	required := false

	if strings.HasPrefix(normalized, "required:") {
		required = true
		normalized = strings.TrimSpace(strings.TrimPrefix(normalized, "required:"))
	}
	if strings.HasSuffix(normalized, "!") {
		required = true
		normalized = strings.TrimSpace(strings.TrimSuffix(normalized, "!"))
	}
	if normalized == "" {
		return []string{"any"}, required
	}

	parts := strings.FieldsFunc(normalized, func(r rune) bool {
		return r == '|' || r == ','
	})

	typeSet := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		canonical := normalizePropertyTypeToken(part)
		if canonical == "" {
			continue
		}
		typeSet[canonical] = struct{}{}
	}
	if len(typeSet) == 0 {
		return []string{"any"}, required
	}

	types := make([]string, 0, len(typeSet))
	for value := range typeSet {
		types = append(types, value)
	}
	sort.Strings(types)
	return types, required
}

func normalizePropertyTypeToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", "*", "any":
		return "any"
	case "string", "text", "uuid", "email", "url", "uri":
		return "string"
	case "bool", "boolean":
		return "boolean"
	case "int", "integer", "long", "short", "uint", "uint64", "uint32", "int64", "int32", "int16", "uint16":
		return "integer"
	case "float", "double", "decimal", "number":
		return "number"
	case "object", "map", "json", "record":
		return "object"
	case "array", "list", "slice", "set":
		return "array"
	case "time", "timestamp", "datetime", "date":
		return "timestamp"
	case "duration":
		return "duration"
	default:
		if strings.HasSuffix(value, "[]") {
			return "array"
		}
		return "any"
	}
}

func matchesAnyPropertyType(value any, expectedTypes []string) bool {
	for _, expected := range expectedTypes {
		if expected == "any" || matchesPropertyType(value, expected) {
			return true
		}
	}
	return false
}

func matchesPropertyType(value any, expectedType string) bool {
	switch expectedType {
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "integer":
		switch value.(type) {
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
			return true
		default:
			return false
		}
	case "number":
		switch value.(type) {
		case float32, float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, json.Number:
			return true
		default:
			return false
		}
	case "object":
		if value == nil {
			return false
		}
		kind := reflect.TypeOf(value).Kind()
		return kind == reflect.Map || kind == reflect.Struct
	case "array":
		if value == nil {
			return false
		}
		kind := reflect.TypeOf(value).Kind()
		return kind == reflect.Slice || kind == reflect.Array
	case "timestamp":
		switch typed := value.(type) {
		case time.Time:
			return true
		case string:
			_, err := time.Parse(time.RFC3339, strings.TrimSpace(typed))
			return err == nil
		default:
			return false
		}
	case "duration":
		switch typed := value.(type) {
		case time.Duration:
			return true
		case string:
			_, err := time.ParseDuration(strings.TrimSpace(typed))
			return err == nil
		default:
			return false
		}
	default:
		return true
	}
}

func sliceContainsEdgeKind(values []EdgeKind, target EdgeKind) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sliceContainsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func cloneStringSliceMap(values map[string][]string) map[string][]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string][]string, len(values))
	for key, entries := range values {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		cloned[key] = append([]string(nil), entries...)
	}
	if len(cloned) == 0 {
		return nil
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

func uniqueSortedNodeCapabilities(values []NodeKindCapability) []NodeKindCapability {
	if len(values) == 0 {
		return nil
	}
	set := make(map[NodeKindCapability]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	out := make([]NodeKindCapability, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func uniqueSortedNodeKinds(values []NodeKind) []NodeKind {
	if len(values) == 0 {
		return nil
	}
	set := make(map[NodeKind]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return sortedNodeKinds(set)
}

func sortedNodeKinds(set map[NodeKind]struct{}) []NodeKind {
	if len(set) == 0 {
		return nil
	}
	out := make([]NodeKind, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedNodeKindsFromMap(values map[NodeKind]NodeKindDefinition) []NodeKind {
	out := make([]NodeKind, 0, len(values))
	for kind := range values {
		out = append(out, kind)
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
	return sortedEdgeKinds(set)
}

func sortedEdgeKinds(set map[EdgeKind]struct{}) []EdgeKind {
	if len(set) == 0 {
		return nil
	}
	out := make([]EdgeKind, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedEdgeKindsFromMap(values map[EdgeKind]EdgeKindDefinition) []EdgeKind {
	out := make([]EdgeKind, 0, len(values))
	for kind := range values {
		out = append(out, kind)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func cloneSchemaChanges(changes []SchemaChange) []SchemaChange {
	if len(changes) == 0 {
		return nil
	}
	out := make([]SchemaChange, 0, len(changes))
	for _, change := range changes {
		out = append(out, SchemaChange{
			Version:               change.Version,
			ChangedAt:             change.ChangedAt,
			AddedNodeKinds:        append([]NodeKind(nil), change.AddedNodeKinds...),
			UpdatedNodeKinds:      append([]NodeKind(nil), change.UpdatedNodeKinds...),
			AddedEdgeKinds:        append([]EdgeKind(nil), change.AddedEdgeKinds...),
			UpdatedEdgeKinds:      append([]EdgeKind(nil), change.UpdatedEdgeKinds...),
			CompatibilityWarnings: append([]string(nil), change.CompatibilityWarnings...),
		})
	}
	return out
}

var defaultWriteMetadataKeys = []string{
	"source_system",
	"source_event_id",
	"observed_at",
	"valid_from",
	"valid_to",
	"recorded_at",
	"transaction_from",
	"transaction_to",
	"confidence",
}

var defaultWriteTimestampKeys = []string{
	"observed_at",
	"valid_from",
	"valid_to",
	"recorded_at",
	"transaction_from",
	"transaction_to",
}

func writeMetadataProfile(requiredKeys []string, enumValues map[string][]string) NodeMetadataProfile {
	return normalizeNodeMetadataProfile(NodeMetadataProfile{
		RequiredKeys:  append([]string(nil), requiredKeys...),
		OptionalKeys:  append([]string(nil), defaultWriteMetadataKeys...),
		TimestampKeys: append([]string(nil), defaultWriteTimestampKeys...),
		EnumValues:    cloneStringSliceMap(enumValues),
	})
}

var builtInNodeKinds = []NodeKindDefinition{
	{Kind: NodeKindAny},
	{Kind: NodeKindUser, Categories: []NodeKindCategory{NodeCategoryIdentity}, MetadataProfile: writeMetadataProfile(nil, nil)},
	{Kind: NodeKindPerson, Categories: []NodeKindCategory{NodeCategoryIdentity}, MetadataProfile: writeMetadataProfile(nil, nil)},
	{
		Kind:       NodeKindIdentityAlias,
		Categories: []NodeKindCategory{NodeCategoryIdentity},
		Properties: map[string]string{
			"source_system":   "string",
			"source_event_id": "string",
			"external_id":     "string",
			"alias_type":      "string",
			"canonical_hint":  "string",
			"confidence":      "number",
			"observed_at":     "string",
			"valid_from":      "string",
			"valid_to":        "string",
		},
		RequiredProperties: []string{"source_system", "external_id", "observed_at", "valid_from"},
		Relationships:      []EdgeKind{EdgeKindAliasOf},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from"},
			map[string][]string{
				"alias_type": {"email", "username", "uid", "upn", "employee_id", "github", "slack"},
			},
		),
	},
	{
		Kind:            NodeKindRole,
		Categories:      []NodeKindCategory{NodeCategoryIdentity},
		Capabilities:    []NodeKindCapability{NodeCapabilityPrivilegedIdentity},
		MetadataProfile: writeMetadataProfile(nil, nil),
	},
	{Kind: NodeKindGroup, Categories: []NodeKindCategory{NodeCategoryIdentity}, MetadataProfile: writeMetadataProfile(nil, nil)},
	{
		Kind:            NodeKindServiceAccount,
		Categories:      []NodeKindCategory{NodeCategoryIdentity},
		Capabilities:    []NodeKindCapability{NodeCapabilityPrivilegedIdentity},
		MetadataProfile: writeMetadataProfile(nil, nil),
	},
	{
		Kind:       NodeKindPolicy,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
		Properties: map[string]string{
			"policy_id":          "string",
			"policy_version":     "string",
			"title":              "string",
			"summary":            "string",
			"content":            "string",
			"content_digest":     "string",
			"owner_id":           "string",
			"review_cycle_days":  "number",
			"framework_mappings": "array",
			"version_history":    "array",
			"observed_at":        "string",
			"valid_from":         "string",
			"valid_to":           "string",
			"recorded_at":        "string",
			"transaction_from":   "string",
			"transaction_to":     "string",
			"source_system":      "string",
			"source_event_id":    "string",
			"confidence":         "number",
		},
		RequiredProperties: []string{"policy_id", "policy_version", "title", "observed_at", "valid_from"},
		Relationships:      []EdgeKind{EdgeKindAssignedTo},
		MetadataProfile:    writeMetadataProfile([]string{"source_system", "observed_at", "valid_from"}, nil),
	},
	{
		Kind:       NodeKindService,
		Categories: []NodeKindCategory{NodeCategoryResource, NodeCategoryBusiness},
		Properties: map[string]string{
			"service_id":      "string",
			"criticality":     "string",
			"owner_team_id":   "string",
			"source_system":   "string",
			"source_event_id": "string",
			"observed_at":     "string",
			"valid_from":      "string",
			"valid_to":        "string",
			"confidence":      "number",
		},
		RequiredProperties: []string{"service_id", "observed_at", "valid_from"},
		Relationships:      []EdgeKind{EdgeKindOwns, EdgeKindRuns, EdgeKindDependsOn, EdgeKindTargets},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from"},
			map[string][]string{
				"criticality": {"critical", "high", "medium", "low", "tier0", "tier1", "tier2", "tier3"},
			},
		),
	},
	{
		Kind:       NodeKindOrganization,
		Categories: []NodeKindCategory{NodeCategoryResource},
		Properties: map[string]string{
			"organization_id": "string",
			"resource_name":   "string",
			"state":           "string",
			"display_name":    "string",
		},
		RequiredProperties: []string{"organization_id", "resource_name"},
		MetadataProfile:    writeMetadataProfile(nil, nil),
	},
	{
		Kind:       NodeKindFolder,
		Categories: []NodeKindCategory{NodeCategoryResource},
		Properties: map[string]string{
			"folder_id":       "string",
			"resource_name":   "string",
			"parent":          "string",
			"organization_id": "string",
			"depth":           "number",
			"state":           "string",
			"display_name":    "string",
		},
		RequiredProperties: []string{"folder_id", "resource_name"},
		Relationships:      []EdgeKind{EdgeKindLocatedIn},
		MetadataProfile:    writeMetadataProfile(nil, nil),
	},
	{
		Kind:       NodeKindProject,
		Categories: []NodeKindCategory{NodeCategoryResource},
		Properties: map[string]string{
			"project_id":      "string",
			"project_number":  "string",
			"resource_name":   "string",
			"parent":          "string",
			"organization_id": "string",
			"folder_ids":      "array",
			"labels":          "object",
			"state":           "string",
			"display_name":    "string",
		},
		RequiredProperties: []string{"project_id", "resource_name"},
		Relationships:      []EdgeKind{EdgeKindLocatedIn},
		MetadataProfile:    writeMetadataProfile(nil, nil),
	},
	{
		Kind:       NodeKindWorkload,
		Categories: []NodeKindCategory{NodeCategoryResource},
		Properties: map[string]string{
			"workload_id":     "string",
			"runtime":         "string",
			"environment":     "string",
			"service_id":      "string",
			"source_system":   "string",
			"source_event_id": "string",
			"observed_at":     "string",
			"valid_from":      "string",
			"valid_to":        "string",
			"confidence":      "number",
		},
		RequiredProperties: []string{"workload_id", "runtime", "observed_at", "valid_from"},
		Relationships:      []EdgeKind{EdgeKindConnectsTo, EdgeKindDependsOn, EdgeKindTargets},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from"},
			map[string][]string{
				"environment": {"prod", "production", "staging", "qa", "dev", "test", "sandbox"},
			},
		),
	},
	{
		Kind:         NodeKindBucket,
		Categories:   []NodeKindCategory{NodeCategoryResource},
		Capabilities: []NodeKindCapability{NodeCapabilityInternetExposable, NodeCapabilitySensitiveData},
		Relationships: []EdgeKind{
			EdgeKindExposedTo,
			EdgeKindDependsOn,
			EdgeKindConfigures,
			EdgeKindOwns,
			EdgeKindManagedBy,
			EdgeKindTargets,
		},
	},
	{
		Kind:       NodeKindBucketPolicyStatement,
		Categories: []NodeKindCategory{NodeCategoryResource},
		Properties: map[string]string{
			"bucket_id":        "string",
			"statement_id":     "string",
			"effect":           "string",
			"principal":        "string",
			"principal_type":   "string",
			"public_access":    "boolean",
			"action_count":     "integer|number",
			"source_system":    "string",
			"source_event_id":  "string",
			"observed_at":      "string",
			"valid_from":       "string",
			"valid_to":         "string",
			"recorded_at":      "string",
			"transaction_from": "string",
			"transaction_to":   "string",
			"confidence":       "number",
		},
		RequiredProperties: []string{"bucket_id", "statement_id", "effect", "observed_at", "valid_from", "recorded_at", "transaction_from"},
		Relationships:      []EdgeKind{EdgeKindConfigures, EdgeKindTargets, EdgeKindBasedOn, EdgeKindAssertedBy},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from", "recorded_at", "transaction_from"},
			map[string][]string{
				"effect":         {"allow", "deny"},
				"principal_type": {"public", "anonymous", "all_users", "all_authenticated_users", "account", "user", "service"},
			},
		),
	},
	{
		Kind:       NodeKindBucketPublicAccessBlock,
		Categories: []NodeKindCategory{NodeCategoryResource},
		Properties: map[string]string{
			"bucket_id":                "string",
			"public_access_block_id":   "string",
			"block_public_acls":        "boolean",
			"ignore_public_acls":       "boolean",
			"block_public_policy":      "boolean",
			"restrict_public_buckets":  "boolean",
			"public_access_prevention": "string",
			"source_system":            "string",
			"source_event_id":          "string",
			"observed_at":              "string",
			"valid_from":               "string",
			"valid_to":                 "string",
			"recorded_at":              "string",
			"transaction_from":         "string",
			"transaction_to":           "string",
			"confidence":               "number",
		},
		RequiredProperties: []string{"bucket_id", "public_access_block_id", "observed_at", "valid_from", "recorded_at", "transaction_from"},
		Relationships:      []EdgeKind{EdgeKindConfigures, EdgeKindTargets, EdgeKindBasedOn, EdgeKindAssertedBy},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from", "recorded_at", "transaction_from"},
			map[string][]string{
				"public_access_prevention": {"enforced", "inherited", "unspecified", "disabled", "enabled"},
			},
		),
	},
	{
		Kind:       NodeKindBucketEncryptionConfig,
		Categories: []NodeKindCategory{NodeCategoryResource},
		Properties: map[string]string{
			"bucket_id":            "string",
			"encryption_config_id": "string",
			"encrypted":            "boolean",
			"encryption_algorithm": "string",
			"encryption_key_id":    "string",
			"bucket_key_enabled":   "boolean",
			"source_system":        "string",
			"source_event_id":      "string",
			"observed_at":          "string",
			"valid_from":           "string",
			"valid_to":             "string",
			"recorded_at":          "string",
			"transaction_from":     "string",
			"transaction_to":       "string",
			"confidence":           "number",
		},
		RequiredProperties: []string{"bucket_id", "encryption_config_id", "observed_at", "valid_from", "recorded_at", "transaction_from"},
		Relationships:      []EdgeKind{EdgeKindConfigures, EdgeKindRefers, EdgeKindBasedOn, EdgeKindAssertedBy},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from", "recorded_at", "transaction_from"},
			nil,
		),
	},
	{
		Kind:       NodeKindBucketLoggingConfig,
		Categories: []NodeKindCategory{NodeCategoryResource},
		Properties: map[string]string{
			"bucket_id":             "string",
			"logging_config_id":     "string",
			"logging_enabled":       "boolean",
			"logging_target_bucket": "string",
			"target_prefix":         "string",
			"source_system":         "string",
			"source_event_id":       "string",
			"observed_at":           "string",
			"valid_from":            "string",
			"valid_to":              "string",
			"recorded_at":           "string",
			"transaction_from":      "string",
			"transaction_to":        "string",
			"confidence":            "number",
		},
		RequiredProperties: []string{"bucket_id", "logging_config_id", "observed_at", "valid_from", "recorded_at", "transaction_from"},
		Relationships:      []EdgeKind{EdgeKindConfigures, EdgeKindTargets, EdgeKindBasedOn, EdgeKindAssertedBy},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from", "recorded_at", "transaction_from"},
			nil,
		),
	},
	{
		Kind:       NodeKindBucketVersioningConfig,
		Categories: []NodeKindCategory{NodeCategoryResource},
		Properties: map[string]string{
			"bucket_id":            "string",
			"versioning_config_id": "string",
			"versioning_status":    "string",
			"mfa_delete":           "boolean",
			"source_system":        "string",
			"source_event_id":      "string",
			"observed_at":          "string",
			"valid_from":           "string",
			"valid_to":             "string",
			"recorded_at":          "string",
			"transaction_from":     "string",
			"transaction_to":       "string",
			"confidence":           "number",
		},
		RequiredProperties: []string{"bucket_id", "versioning_config_id", "observed_at", "valid_from", "recorded_at", "transaction_from"},
		Relationships:      []EdgeKind{EdgeKindConfigures, EdgeKindBasedOn, EdgeKindAssertedBy},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from", "recorded_at", "transaction_from"},
			map[string][]string{
				"versioning_status": {"enabled", "suspended", "disabled", "on", "off"},
			},
		),
	},
	{Kind: NodeKindInstance, Categories: []NodeKindCategory{NodeCategoryResource}, Capabilities: []NodeKindCapability{NodeCapabilityInternetExposable}},
	{Kind: NodeKindDatabase, Categories: []NodeKindCategory{NodeCategoryResource}, Capabilities: []NodeKindCapability{NodeCapabilitySensitiveData}},
	{Kind: NodeKindSecret, Categories: []NodeKindCategory{NodeCategoryResource}, Capabilities: []NodeKindCapability{NodeCapabilitySensitiveData, NodeCapabilityCredentialStore}},
	{Kind: NodeKindFunction, Categories: []NodeKindCategory{NodeCategoryResource}, Capabilities: []NodeKindCapability{NodeCapabilityInternetExposable}},
	{
		Kind:       NodeKindWorkloadScan,
		Categories: []NodeKindCategory{NodeCategoryResource},
		Properties: map[string]string{
			"scan_id":                         "string",
			"target_id":                       "string",
			"target_kind":                     "string",
			"provider":                        "string",
			"status":                          "string",
			"stage":                           "string",
			"submitted_at":                    "string",
			"started_at":                      "string",
			"completed_at":                    "string",
			"os_name":                         "string",
			"os_version":                      "string",
			"os_architecture":                 "string",
			"package_count":                   "integer|number",
			"vulnerability_count":             "integer|number",
			"critical_vulnerability_count":    "integer|number",
			"high_vulnerability_count":        "integer|number",
			"medium_vulnerability_count":      "integer|number",
			"low_vulnerability_count":         "integer|number",
			"unknown_vulnerability_count":     "integer|number",
			"known_exploited_count":           "integer|number",
			"exploitable_vulnerability_count": "integer|number",
			"fixable_vulnerability_count":     "integer|number",
			"secret_count":                    "integer|number",
			"misconfiguration_count":          "integer|number",
			"malware_count":                   "integer|number",
			"finding_count":                   "integer|number",
			"sbom_ref":                        "string",
			"source_system":                   "string",
			"source_event_id":                 "string",
			"observed_at":                     "string",
			"valid_from":                      "string",
			"valid_to":                        "string",
			"recorded_at":                     "string",
			"transaction_from":                "string",
			"transaction_to":                  "string",
			"confidence":                      "number",
		},
		RequiredProperties: []string{"scan_id", "target_id", "target_kind", "status", "observed_at", "valid_from", "recorded_at", "transaction_from"},
		Relationships:      []EdgeKind{EdgeKindTargets, EdgeKindHasScan, EdgeKindContainsPkg, EdgeKindFoundVuln, EdgeKindBasedOn},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from", "recorded_at", "transaction_from"},
			map[string][]string{
				"status": {"queued", "running", "succeeded", "failed"},
			},
		),
	},
	{
		Kind:       NodeKindPackage,
		Categories: []NodeKindCategory{NodeCategoryResource},
		Properties: map[string]string{
			"package_name":     "string",
			"version":          "string",
			"ecosystem":        "string",
			"manager":          "string",
			"purl":             "string",
			"source_system":    "string",
			"source_event_id":  "string",
			"observed_at":      "string",
			"valid_from":       "string",
			"valid_to":         "string",
			"recorded_at":      "string",
			"transaction_from": "string",
			"transaction_to":   "string",
			"confidence":       "number",
		},
		RequiredProperties: []string{"package_name", "version", "ecosystem", "observed_at", "valid_from", "recorded_at", "transaction_from"},
		Relationships:      []EdgeKind{EdgeKindAffectedBy, EdgeKindBasedOn},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from", "recorded_at", "transaction_from"},
			nil,
		),
	},
	{
		Kind:       NodeKindVulnerability,
		Categories: []NodeKindCategory{NodeCategoryResource},
		Properties: map[string]string{
			"vulnerability_id": "string",
			"cve_id":           "string",
			"severity":         "string",
			"cvss":             "number",
			"epss":             "number",
			"known_exploited":  "boolean",
			"exploitable":      "boolean",
			"fixed_version":    "string",
			"published_at":     "string",
			"source_system":    "string",
			"source_event_id":  "string",
			"observed_at":      "string",
			"valid_from":       "string",
			"valid_to":         "string",
			"recorded_at":      "string",
			"transaction_from": "string",
			"transaction_to":   "string",
			"confidence":       "number",
		},
		RequiredProperties: []string{"vulnerability_id", "severity", "observed_at", "valid_from", "recorded_at", "transaction_from"},
		Relationships:      []EdgeKind{EdgeKindBasedOn},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from", "recorded_at", "transaction_from"},
			map[string][]string{
				"severity": {"critical", "high", "medium", "low", "unknown"},
			},
		),
	},
	{Kind: NodeKindNetwork, Categories: []NodeKindCategory{NodeCategoryResource}, Capabilities: []NodeKindCapability{NodeCapabilityInternetExposable}},
	{Kind: NodeKindApplication, Categories: []NodeKindCategory{NodeCategoryResource}},
	{Kind: NodeKindPod, Categories: []NodeKindCategory{NodeCategoryResource, NodeCategoryKubernetes}},
	{Kind: NodeKindDeployment, Categories: []NodeKindCategory{NodeCategoryResource, NodeCategoryKubernetes}},
	{Kind: NodeKindNamespace, Categories: []NodeKindCategory{NodeCategoryKubernetes}},
	{Kind: NodeKindClusterRole, Categories: []NodeKindCategory{NodeCategoryKubernetes}},
	{Kind: NodeKindClusterRoleBinding, Categories: []NodeKindCategory{NodeCategoryKubernetes}},
	{Kind: NodeKindRoleBinding, Categories: []NodeKindCategory{NodeCategoryKubernetes}},
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
	{
		Kind:       NodeKindPullRequest,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
		Properties: map[string]string{
			"repository":      "string",
			"number":          "integer|number|string",
			"state":           "string",
			"author_email":    "string",
			"source_system":   "string",
			"source_event_id": "string",
			"observed_at":     "string",
			"valid_from":      "string",
			"valid_to":        "string",
			"confidence":      "number",
		},
		RequiredProperties: []string{"repository", "number", "state", "observed_at", "valid_from"},
		Relationships:      []EdgeKind{EdgeKindTargets, EdgeKindBasedOn},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from"},
			map[string][]string{
				"state": {"open", "opened", "closed", "merged", "draft", "review_submitted"},
			},
		),
	},
	{
		Kind:       NodeKindDeploymentRun,
		Categories: []NodeKindCategory{NodeCategoryResource, NodeCategoryBusiness},
		Properties: map[string]string{
			"deploy_id":       "string",
			"service_id":      "string",
			"environment":     "string",
			"status":          "string",
			"source_system":   "string",
			"source_event_id": "string",
			"observed_at":     "string",
			"valid_from":      "string",
			"valid_to":        "string",
			"confidence":      "number",
		},
		RequiredProperties: []string{"deploy_id", "service_id", "environment", "status", "observed_at", "valid_from"},
		Relationships:      []EdgeKind{EdgeKindTargets, EdgeKindBasedOn, EdgeKindDependsOn, EdgeKindTriggeredBy},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from"},
			map[string][]string{
				"status":      {"queued", "pending", "in_progress", "running", "completed", "success", "successful", "succeeded", "failure", "failed", "cancelled", "error"},
				"environment": {"prod", "production", "staging", "qa", "dev", "test", "sandbox"},
			},
		),
	},
	{
		Kind:       NodeKindPipelineRun,
		Categories: []NodeKindCategory{NodeCategoryResource, NodeCategoryBusiness},
		Properties: map[string]string{
			"pipeline_id":     "string",
			"run_id":          "string",
			"status":          "string",
			"branch":          "string",
			"commit_sha":      "string",
			"started_at":      "string",
			"completed_at":    "string",
			"service_id":      "string",
			"source_system":   "string",
			"source_event_id": "string",
			"observed_at":     "string",
			"valid_from":      "string",
			"valid_to":        "string",
			"confidence":      "number",
		},
		RequiredProperties: []string{"pipeline_id", "run_id", "status", "service_id", "observed_at", "valid_from"},
		Relationships:      []EdgeKind{EdgeKindTargets, EdgeKindBasedOn, EdgeKindExecutedBy},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from"},
			map[string][]string{
				"status": {"queued", "pending", "in_progress", "running", "completed", "success", "successful", "succeeded", "failure", "failed", "passed", "cancelled", "neutral", "timed_out", "action_required", "skipped"},
			},
		),
	},
	{
		Kind:       NodeKindCheckRun,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
		Properties: map[string]string{
			"check_run_id":    "string",
			"repository":      "string",
			"check_name":      "string",
			"status":          "string",
			"conclusion":      "string",
			"commit_sha":      "string",
			"url":             "string",
			"source_system":   "string",
			"source_event_id": "string",
			"observed_at":     "string",
			"valid_from":      "string",
			"valid_to":        "string",
			"confidence":      "number",
		},
		RequiredProperties: []string{"check_run_id", "repository", "check_name", "status", "observed_at", "valid_from"},
		Relationships:      []EdgeKind{EdgeKindTargets, EdgeKindBasedOn, EdgeKindEvaluates, EdgeKindCausedBy},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from"},
			map[string][]string{
				"status":     {"queued", "in_progress", "completed"},
				"conclusion": {"success", "failure", "neutral", "cancelled", "timed_out", "action_required", "stale", "skipped", "startup_failure"},
			},
		),
	},
	{
		Kind:       NodeKindMeeting,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
		Properties: map[string]string{
			"meeting_id":      "string",
			"starts_at":       "string",
			"ends_at":         "string",
			"organizer_email": "string",
			"source_system":   "string",
			"source_event_id": "string",
			"observed_at":     "string",
			"valid_from":      "string",
			"valid_to":        "string",
			"confidence":      "number",
		},
		RequiredProperties: []string{"meeting_id", "starts_at", "ends_at", "observed_at", "valid_from"},
		Relationships:      []EdgeKind{EdgeKindTargets, EdgeKindAssignedTo, EdgeKindBasedOn},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from"},
			nil,
		),
	},
	{
		Kind:       NodeKindDocument,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
		Properties: map[string]string{
			"document_id":     "string",
			"url":             "string",
			"title":           "string",
			"source_system":   "string",
			"source_event_id": "string",
			"observed_at":     "string",
			"valid_from":      "string",
			"valid_to":        "string",
			"confidence":      "number",
		},
		RequiredProperties: []string{"document_id", "title", "observed_at", "valid_from"},
		Relationships:      []EdgeKind{EdgeKindTargets, EdgeKindBasedOn},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from"},
			nil,
		),
	},
	{
		Kind:       NodeKindThread,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
		Properties: map[string]string{
			"thread_id":       "string",
			"channel_id":      "string",
			"channel_name":    "string",
			"source_system":   "string",
			"source_event_id": "string",
			"observed_at":     "string",
			"valid_from":      "string",
			"valid_to":        "string",
			"confidence":      "number",
		},
		RequiredProperties: []string{"thread_id", "channel_id", "observed_at", "valid_from"},
		Relationships:      []EdgeKind{EdgeKindTargets, EdgeKindInteractedWith, EdgeKindBasedOn},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from"},
			nil,
		),
	},
	{
		Kind:       NodeKindIncident,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
		Properties: map[string]string{
			"incident_id":     "string",
			"status":          "string",
			"severity":        "string",
			"service_id":      "string",
			"source_system":   "string",
			"source_event_id": "string",
			"observed_at":     "string",
			"valid_from":      "string",
			"valid_to":        "string",
			"confidence":      "number",
		},
		RequiredProperties: []string{"incident_id", "status", "observed_at", "valid_from"},
		Relationships:      []EdgeKind{EdgeKindTargets, EdgeKindBasedOn, EdgeKindEvaluates, EdgeKindCausedBy},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from"},
			map[string][]string{
				"status":   {"triggered", "acknowledged", "investigating", "monitoring", "open", "resolved", "closed", "postmortem"},
				"severity": {"critical", "high", "medium", "low", "sev1", "sev2", "sev3", "sev4"},
			},
		),
	},
	{
		Kind:       NodeKindDecision,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
		Properties: map[string]string{
			"decision_type":   "string",
			"status":          "string",
			"made_at":         "string",
			"made_by":         "string",
			"rationale":       "string",
			"source_system":   "string",
			"source_event_id": "string",
			"observed_at":     "string",
			"valid_from":      "string",
			"valid_to":        "string",
			"confidence":      "number",
		},
		RequiredProperties: []string{"decision_type", "status", "made_at", "observed_at", "valid_from"},
		Relationships:      []EdgeKind{EdgeKindTargets, EdgeKindBasedOn, EdgeKindExecutedBy},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from"},
			map[string][]string{
				"status": {"proposed", "approved", "rejected", "deferred", "cancelled", "in_progress", "completed"},
			},
		),
	},
	{
		Kind:       NodeKindOutcome,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
		Properties: map[string]string{
			"outcome_type":    "string",
			"verdict":         "string",
			"impact_score":    "number",
			"source_system":   "string",
			"source_event_id": "string",
			"observed_at":     "string",
			"valid_from":      "string",
			"valid_to":        "string",
			"confidence":      "number",
		},
		RequiredProperties: []string{"outcome_type", "verdict", "observed_at", "valid_from"},
		Relationships:      []EdgeKind{EdgeKindEvaluates, EdgeKindTargets},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from"},
			map[string][]string{
				"verdict": {"positive", "negative", "neutral", "mixed", "unknown"},
			},
		),
	},
	{
		Kind:       NodeKindEvidence,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
		Properties: map[string]string{
			"evidence_type":   "string",
			"detail":          "string",
			"source_system":   "string",
			"source_event_id": "string",
			"observed_at":     "string",
			"valid_from":      "string",
			"valid_to":        "string",
			"confidence":      "number",
		},
		RequiredProperties: []string{"evidence_type", "source_system", "observed_at", "valid_from"},
		Relationships:      []EdgeKind{EdgeKindTargets, EdgeKindBasedOn},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from"},
			nil,
		),
	},
	{
		Kind:       NodeKindObservation,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
		Properties: map[string]string{
			"observation_type": "string",
			"subject_id":       "string",
			"detail":           "string",
			"source_system":    "string",
			"source_event_id":  "string",
			"observed_at":      "string",
			"valid_from":       "string",
			"valid_to":         "string",
			"recorded_at":      "string",
			"transaction_from": "string",
			"transaction_to":   "string",
			"confidence":       "number",
		},
		RequiredProperties: []string{"observation_type", "subject_id", "observed_at", "valid_from", "recorded_at", "transaction_from"},
		Relationships:      []EdgeKind{EdgeKindTargets, EdgeKindBasedOn, EdgeKindAssertedBy},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from", "recorded_at", "transaction_from"},
			nil,
		),
	},
	{
		Kind:       NodeKindSource,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
		Properties: map[string]string{
			"source_type":       "string",
			"canonical_name":    "string",
			"url":               "string",
			"trust_tier":        "string",
			"reliability_score": "number",
			"source_system":     "string",
			"source_event_id":   "string",
			"observed_at":       "string",
			"valid_from":        "string",
			"valid_to":          "string",
			"recorded_at":       "string",
			"transaction_from":  "string",
			"transaction_to":    "string",
			"confidence":        "number",
		},
		RequiredProperties: []string{"source_type", "canonical_name", "observed_at", "valid_from", "recorded_at", "transaction_from"},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from", "recorded_at", "transaction_from"},
			map[string][]string{
				"source_type": {"system", "human", "document", "sensor", "model", "pipeline", "external_api"},
				"trust_tier":  {"authoritative", "verified", "derived", "unverified"},
			},
		),
	},
	{
		Kind:       NodeKindClaim,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
		Properties: map[string]string{
			"claim_type":       "string",
			"subject_id":       "string",
			"predicate":        "string",
			"object_id":        "string",
			"object_value":     "string",
			"status":           "string",
			"summary":          "string",
			"source_system":    "string",
			"source_event_id":  "string",
			"observed_at":      "string",
			"valid_from":       "string",
			"valid_to":         "string",
			"recorded_at":      "string",
			"transaction_from": "string",
			"transaction_to":   "string",
			"confidence":       "number",
		},
		RequiredProperties: []string{"claim_type", "subject_id", "predicate", "status", "observed_at", "valid_from", "recorded_at", "transaction_from"},
		Relationships: []EdgeKind{
			EdgeKindTargets,
			EdgeKindRefers,
			EdgeKindBasedOn,
			EdgeKindAssertedBy,
			EdgeKindSupports,
			EdgeKindRefutes,
			EdgeKindSupersedes,
			EdgeKindContradicts,
		},
		MetadataProfile: writeMetadataProfile(
			[]string{"source_system", "observed_at", "valid_from", "recorded_at", "transaction_from"},
			map[string][]string{
				"claim_type": {"relation", "attribute", "classification", "existence"},
				"status":     {"asserted", "disputed", "corrected", "retracted", "superseded", "refuted"},
			},
		),
	},
	{
		Kind:       NodeKindAction,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
		Properties: map[string]string{
			"action_type":     "string",
			"status":          "string",
			"performed_at":    "string",
			"actor_id":        "string",
			"source_system":   "string",
			"source_event_id": "string",
			"observed_at":     "string",
			"valid_from":      "string",
			"valid_to":        "string",
			"confidence":      "number",
		},
		RequiredProperties: []string{"action_type", "status", "observed_at", "valid_from"},
		Relationships:      []EdgeKind{EdgeKindTargets, EdgeKindEvaluates, EdgeKindBasedOn, EdgeKindInteractedWith},
		MetadataProfile:    writeMetadataProfile([]string{"source_system", "observed_at", "valid_from"}, nil),
	},
	{Kind: NodeKindDepartment, Categories: []NodeKindCategory{NodeCategoryBusiness}},
	{Kind: NodeKindLocation, Categories: []NodeKindCategory{NodeCategoryBusiness}},
}

var builtInEdgeKinds = []EdgeKindDefinition{
	{Kind: EdgeKindCanAssume},
	{Kind: EdgeKindMemberOf},
	{Kind: EdgeKindResolvesTo},
	{Kind: EdgeKindAliasOf},
	{Kind: EdgeKindReportsTo},
	{Kind: EdgeKindAcknowledged},
	{Kind: EdgeKindCanRead},
	{Kind: EdgeKindCanWrite},
	{Kind: EdgeKindCanDelete},
	{Kind: EdgeKindCanAdmin},
	{Kind: EdgeKindConnectsTo},
	{Kind: EdgeKindRuns},
	{Kind: EdgeKindDependsOn},
	{Kind: EdgeKindConfigures},
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
	{Kind: EdgeKindTargets},
	{Kind: EdgeKindBasedOn},
	{Kind: EdgeKindExecutedBy},
	{Kind: EdgeKindEvaluates},
	{Kind: EdgeKindHasScan},
	{Kind: EdgeKindFoundVuln},
	{Kind: EdgeKindContainsPkg},
	{Kind: EdgeKindAffectedBy},
	{Kind: EdgeKindAssertedBy},
	{Kind: EdgeKindSupports},
	{Kind: EdgeKindRefutes},
	{Kind: EdgeKindSupersedes},
	{Kind: EdgeKindContradicts},
	{Kind: EdgeKindTriggeredBy},
	{Kind: EdgeKindCausedBy},
	{Kind: EdgeKindHasCredentialFor},
}
