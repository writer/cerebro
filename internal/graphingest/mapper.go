package graphingest

import (
	_ "embed"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/graph"
)

//go:embed mappings.yaml
var defaultMappingsYAML []byte

var templatePattern = regexp.MustCompile(`{{\s*([^{}]+)\s*}}`)

type IdentityResolver func(raw string, evt events.CloudEvent) string

// MapperValidationMode controls mapper behavior when schema validation fails.
type MapperValidationMode string

const (
	// MapperValidationEnforce rejects invalid writes and dead-letters them.
	MapperValidationEnforce MapperValidationMode = "enforce"
	// MapperValidationWarn keeps historical behavior and allows invalid writes.
	MapperValidationWarn MapperValidationMode = "warn"
)

// MapperOptions controls declarative mapper runtime behavior.
type MapperOptions struct {
	ValidationMode MapperValidationMode `json:"validation_mode,omitempty"`
	DeadLetterPath string               `json:"dead_letter_path,omitempty"`
}

type MappingConfig struct {
	Mappings []EventMapping `json:"mappings" yaml:"mappings"`
}

type EventMapping struct {
	Name   string        `json:"name" yaml:"name"`
	Source string        `json:"source" yaml:"source"`
	Nodes  []NodeMapping `json:"nodes" yaml:"nodes"`
	Edges  []EdgeMapping `json:"edges" yaml:"edges"`
}

type NodeMapping struct {
	ID         string         `json:"id" yaml:"id"`
	Kind       string         `json:"kind" yaml:"kind"`
	Name       string         `json:"name" yaml:"name"`
	Provider   string         `json:"provider" yaml:"provider"`
	Risk       string         `json:"risk" yaml:"risk"`
	Properties map[string]any `json:"properties" yaml:"properties"`
}

type EdgeMapping struct {
	ID         string         `json:"id" yaml:"id"`
	Source     string         `json:"source" yaml:"source"`
	Target     string         `json:"target" yaml:"target"`
	Kind       string         `json:"kind" yaml:"kind"`
	Effect     string         `json:"effect" yaml:"effect"`
	Properties map[string]any `json:"properties" yaml:"properties"`
}

type ApplyResult struct {
	Matched       bool     `json:"matched"`
	MappingNames  []string `json:"mapping_names,omitempty"`
	NodesUpserted []string `json:"nodes_upserted,omitempty"`
	EdgesUpserted []string `json:"edges_upserted,omitempty"`
	NodesRejected int      `json:"nodes_rejected,omitempty"`
	EdgesRejected int      `json:"edges_rejected,omitempty"`
	DeadLettered  int      `json:"dead_lettered,omitempty"`
}

// MapperStats captures mapper counters since process start.
type MapperStats struct {
	EventsProcessed    int64                        `json:"events_processed"`
	EventsMatched      int64                        `json:"events_matched"`
	NodesUpserted      int64                        `json:"nodes_upserted"`
	EdgesUpserted      int64                        `json:"edges_upserted"`
	NodesRejected      int64                        `json:"nodes_rejected"`
	EdgesRejected      int64                        `json:"edges_rejected"`
	DeadLettered       int64                        `json:"dead_lettered"`
	DeadLetterFailures int64                        `json:"dead_letter_failures"`
	NodeRejectByCode   map[string]int               `json:"node_reject_by_code,omitempty"`
	EdgeRejectByCode   map[string]int               `json:"edge_reject_by_code,omitempty"`
	SourceStats        map[string]MapperSourceStats `json:"source_stats,omitempty"`
}

// MapperSourceStats captures source-domain counters for mapper SLO tracking.
type MapperSourceStats struct {
	EventsProcessed int64     `json:"events_processed"`
	EventsMatched   int64     `json:"events_matched"`
	EventsUnmatched int64     `json:"events_unmatched"`
	NodesUpserted   int64     `json:"nodes_upserted"`
	EdgesUpserted   int64     `json:"edges_upserted"`
	NodesRejected   int64     `json:"nodes_rejected"`
	EdgesRejected   int64     `json:"edges_rejected"`
	DeadLettered    int64     `json:"dead_lettered"`
	LastEventAt     time.Time `json:"last_event_at,omitempty"`
}

type Mapper struct {
	config     MappingConfig
	resolver   IdentityResolver
	options    MapperOptions
	deadLetter DeadLetterSink

	statsMu sync.Mutex
	stats   MapperStats
}

func LoadDefaultConfig() (MappingConfig, error) {
	return ParseConfig(defaultMappingsYAML)
}

func LoadConfigFile(path string) (MappingConfig, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return MappingConfig{}, fmt.Errorf("path is required")
	}
	payload, err := os.ReadFile(path) // #nosec G304 -- operator-configured mapping path
	if err != nil {
		return MappingConfig{}, fmt.Errorf("read mapping config %s: %w", path, err)
	}
	return ParseConfig(payload)
}

func ParseConfig(payload []byte) (MappingConfig, error) {
	var config MappingConfig
	if err := yaml.Unmarshal(payload, &config); err != nil {
		return MappingConfig{}, fmt.Errorf("decode mapping config: %w", err)
	}
	if len(config.Mappings) == 0 {
		return MappingConfig{}, fmt.Errorf("mapping config requires at least one mapping")
	}
	for idx := range config.Mappings {
		mapping := &config.Mappings[idx]
		mapping.Name = strings.TrimSpace(mapping.Name)
		mapping.Source = strings.TrimSpace(mapping.Source)
		if mapping.Name == "" {
			mapping.Name = fmt.Sprintf("mapping_%d", idx+1)
		}
		if mapping.Source == "" {
			return MappingConfig{}, fmt.Errorf("mapping %q requires source", mapping.Name)
		}
	}
	return config, nil
}

func NewMapper(config MappingConfig, resolver IdentityResolver) (*Mapper, error) {
	return NewMapperWithOptions(config, resolver, MapperOptions{
		ValidationMode: MapperValidationEnforce,
	})
}

func NewMapperWithOptions(config MappingConfig, resolver IdentityResolver, opts MapperOptions) (*Mapper, error) {
	if len(config.Mappings) == 0 {
		return nil, fmt.Errorf("mapper requires at least one mapping")
	}
	options := normalizeMapperOptions(opts)
	var deadLetter DeadLetterSink
	if options.DeadLetterPath != "" {
		sink, err := NewDeadLetterSink(options.DeadLetterPath)
		if err != nil {
			return nil, err
		}
		deadLetter = sink
	}
	return &Mapper{
		config:     config,
		resolver:   resolver,
		options:    options,
		deadLetter: deadLetter,
		stats: MapperStats{
			NodeRejectByCode: make(map[string]int),
			EdgeRejectByCode: make(map[string]int),
			SourceStats:      make(map[string]MapperSourceStats),
		},
	}, nil
}

// Stats returns a copy of mapper runtime counters.
func (m *Mapper) Stats() MapperStats {
	if m == nil {
		return MapperStats{}
	}
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	return MapperStats{
		EventsProcessed:    m.stats.EventsProcessed,
		EventsMatched:      m.stats.EventsMatched,
		NodesUpserted:      m.stats.NodesUpserted,
		EdgesUpserted:      m.stats.EdgesUpserted,
		NodesRejected:      m.stats.NodesRejected,
		EdgesRejected:      m.stats.EdgesRejected,
		DeadLettered:       m.stats.DeadLettered,
		DeadLetterFailures: m.stats.DeadLetterFailures,
		NodeRejectByCode:   cloneIntMap(m.stats.NodeRejectByCode),
		EdgeRejectByCode:   cloneIntMap(m.stats.EdgeRejectByCode),
		SourceStats:        cloneSourceStatsMap(m.stats.SourceStats),
	}
}

func (m *Mapper) Apply(g *graph.Graph, evt events.CloudEvent) (ApplyResult, error) {
	if m == nil {
		return ApplyResult{}, fmt.Errorf("mapper is required")
	}
	if g == nil {
		return ApplyResult{}, fmt.Errorf("graph is required")
	}
	eventSource := sourceSystemFromEvent(evt)
	m.incrementProcessed(eventSource, evt.Time)

	context := eventContext(evt)
	matchedNames := make([]string, 0)
	nodesUpserted := make([]string, 0)
	edgesUpserted := make([]string, 0)
	nodesRejected := 0
	edgesRejected := 0
	deadLettered := 0
	stagedNodes := make(map[string]*graph.Node)

	for _, mapping := range m.config.Mappings {
		if !mappingMatchesSource(mapping.Source, evt.Type) {
			continue
		}

		matchedNames = append(matchedNames, mapping.Name)
		for _, nodeDef := range mapping.Nodes {
			nodeID := strings.TrimSpace(m.renderTemplate(nodeDef.ID, context, evt))
			if nodeID == "" {
				continue
			}
			nodeKind := graph.NodeKind(strings.ToLower(strings.TrimSpace(m.renderTemplate(nodeDef.Kind, context, evt))))
			if nodeKind == "" {
				continue
			}
			nodeName := strings.TrimSpace(m.renderTemplate(nodeDef.Name, context, evt))
			if nodeName == "" {
				nodeName = nodeID
			}
			provider := strings.TrimSpace(m.renderTemplate(nodeDef.Provider, context, evt))
			if provider == "" {
				provider = sourceSystemFromEvent(evt)
			}
			properties := m.renderProperties(nodeDef.Properties, context, evt)
			ensureTemporalAndProvenance(properties, evt)
			node := &graph.Node{
				ID:         nodeID,
				Kind:       nodeKind,
				Name:       nodeName,
				Provider:   provider,
				Properties: properties,
				Risk:       parseRiskLevel(nodeDef.Risk),
			}
			nodeIssues := validateMapperWriteMetadata(node.Properties, "node", node.ID, string(node.Kind))
			nodeIssues = append(nodeIssues, graph.ValidateNodeAgainstSchema(node)...)
			if len(nodeIssues) > 0 && m.shouldEnforceValidation() {
				nodesRejected++
				m.incrementNodeRejected(nodeIssues, eventSource, evt.Time)
				if m.writeDeadLetter(buildDeadLetterRecord(evt, mapping.Name, "node", node.ID, string(node.Kind), map[string]any{
					"id":         node.ID,
					"kind":       node.Kind,
					"name":       node.Name,
					"provider":   node.Provider,
					"properties": node.Properties,
				}, nodeIssues), eventSource, evt.Time) {
					deadLettered++
				}
				continue
			}

			g.AddNode(node)
			stagedNodes[node.ID] = node
			nodesUpserted = append(nodesUpserted, nodeID)
			m.incrementNodeUpserted(eventSource, evt.Time)
		}

		for _, edgeDef := range mapping.Edges {
			source := strings.TrimSpace(m.renderTemplate(edgeDef.Source, context, evt))
			target := strings.TrimSpace(m.renderTemplate(edgeDef.Target, context, evt))
			if source == "" || target == "" {
				continue
			}
			kind := graph.EdgeKind(strings.ToLower(strings.TrimSpace(m.renderTemplate(edgeDef.Kind, context, evt))))
			if kind == "" {
				continue
			}
			effect := parseEdgeEffect(edgeDef.Effect)
			properties := m.renderProperties(edgeDef.Properties, context, evt)
			ensureTemporalAndProvenance(properties, evt)

			edgeID := strings.TrimSpace(m.renderTemplate(edgeDef.ID, context, evt))
			if edgeID == "" {
				edgeID = fmt.Sprintf("%s:%s->%s", kind, source, target)
			}
			edge := &graph.Edge{
				ID:         edgeID,
				Source:     source,
				Target:     target,
				Kind:       kind,
				Effect:     effect,
				Properties: properties,
				Risk:       graph.RiskNone,
			}
			edgeIssues := validateMapperWriteMetadata(edge.Properties, "edge", edge.ID, string(edge.Kind))
			edgeIssues = append(edgeIssues, graph.ValidateEdgeAgainstSchema(edge, lookupValidationNode(g, stagedNodes, source), lookupValidationNode(g, stagedNodes, target))...)
			if len(edgeIssues) > 0 && m.shouldEnforceValidation() {
				edgesRejected++
				m.incrementEdgeRejected(edgeIssues, eventSource, evt.Time)
				if m.writeDeadLetter(buildDeadLetterRecord(evt, mapping.Name, "edge", edge.ID, string(edge.Kind), map[string]any{
					"id":         edge.ID,
					"source":     edge.Source,
					"target":     edge.Target,
					"kind":       edge.Kind,
					"effect":     edge.Effect,
					"properties": edge.Properties,
				}, edgeIssues), eventSource, evt.Time) {
					deadLettered++
				}
				continue
			}

			g.AddEdge(edge)
			edgesUpserted = append(edgesUpserted, edgeID)
			m.incrementEdgeUpserted(eventSource, evt.Time)
		}
	}

	sort.Strings(matchedNames)
	sort.Strings(nodesUpserted)
	sort.Strings(edgesUpserted)
	m.incrementMatched(len(matchedNames) > 0, eventSource, evt.Time)
	return ApplyResult{
		Matched:       len(matchedNames) > 0,
		MappingNames:  matchedNames,
		NodesUpserted: nodesUpserted,
		EdgesUpserted: edgesUpserted,
		NodesRejected: nodesRejected,
		EdgesRejected: edgesRejected,
		DeadLettered:  deadLettered,
	}, nil
}

func lookupValidationNode(g *graph.Graph, staged map[string]*graph.Node, nodeID string) *graph.Node {
	if node := staged[nodeID]; node != nil {
		return node
	}
	if g == nil {
		return nil
	}
	node, _ := g.GetNode(nodeID)
	return node
}

func (m *Mapper) renderProperties(raw map[string]any, context map[string]any, evt events.CloudEvent) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(raw))
	for key, value := range raw {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		switch typed := value.(type) {
		case string:
			out[key] = m.renderTemplate(typed, context, evt)
		default:
			out[key] = typed
		}
	}
	return out
}

func (m *Mapper) renderTemplate(input string, context map[string]any, evt events.CloudEvent) string {
	input = strings.TrimSpace(input)
	if input == "" || !strings.Contains(input, "{{") {
		return input
	}

	return templatePattern.ReplaceAllStringFunc(input, func(segment string) string {
		matches := templatePattern.FindStringSubmatch(segment)
		if len(matches) != 2 {
			return ""
		}
		expression := strings.TrimSpace(matches[1])
		if expression == "" {
			return ""
		}
		if strings.HasPrefix(expression, "resolve(") && strings.HasSuffix(expression, ")") {
			argument := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(expression, "resolve("), ")"))
			raw := valueToString(contextValue(context, argument))
			if m.resolver == nil {
				return raw
			}
			resolved := strings.TrimSpace(m.resolver(raw, evt))
			if resolved == "" {
				return raw
			}
			return resolved
		}
		return valueToString(contextValue(context, expression))
	})
}

func eventContext(evt events.CloudEvent) map[string]any {
	return map[string]any{
		"id":        evt.ID,
		"source":    evt.Source,
		"type":      evt.Type,
		"subject":   evt.Subject,
		"time":      evt.Time.UTC().Format(time.RFC3339),
		"tenant_id": evt.TenantID,
		"data":      evt.Data,
	}
}

func contextValue(context map[string]any, pathExpr string) any {
	pathExpr = strings.TrimSpace(pathExpr)
	if pathExpr == "" {
		return ""
	}
	segments := strings.Split(pathExpr, ".")
	value := lookupPath(context, segments)
	if value != nil {
		return value
	}
	if _, hasData := context["data"]; hasData && len(segments) > 0 && segments[0] != "data" {
		withData := append([]string{"data"}, segments...)
		if value = lookupPath(context, withData); value != nil {
			return value
		}
	}
	return ""
}

func lookupPath(root map[string]any, segments []string) any {
	var current any = root
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return nil
		}
		switch typed := current.(type) {
		case map[string]any:
			next, ok := typed[segment]
			if !ok {
				return nil
			}
			current = next
		default:
			return nil
		}
	}
	return current
}

func mappingMatchesSource(pattern, eventType string) bool {
	pattern = strings.TrimSpace(pattern)
	eventType = strings.TrimSpace(eventType)
	if pattern == "" || eventType == "" {
		return false
	}
	if pattern == eventType {
		return true
	}
	matched, err := path.Match(pattern, eventType)
	if err != nil {
		return pattern == eventType
	}
	return matched
}

func ensureTemporalAndProvenance(properties map[string]any, evt events.CloudEvent) {
	if properties == nil {
		return
	}

	sourceSystem := firstNonEmptyString(
		valueToString(properties["source_system"]),
		sourceSystemFromEvent(evt),
		"tap",
	)
	sourceEventID := firstNonEmptyString(valueToString(properties["source_event_id"]), evt.ID)
	observedAt := firstNonEmptyString(valueToString(properties["observed_at"]), evt.Time.UTC().Format(time.RFC3339))
	validFrom := firstNonEmptyString(valueToString(properties["valid_from"]), observedAt)

	properties["source_system"] = sourceSystem
	properties["source_event_id"] = sourceEventID
	properties["observed_at"] = observedAt
	properties["valid_from"] = validFrom
	if _, ok := properties["confidence"]; !ok {
		properties["confidence"] = 0.80
	}
}

func sourceSystemFromEvent(evt events.CloudEvent) string {
	parts := strings.Split(strings.TrimSpace(evt.Type), ".")
	if len(parts) >= 3 {
		return strings.ToLower(strings.TrimSpace(parts[2]))
	}
	source := strings.ToLower(strings.TrimSpace(evt.Source))
	source = strings.TrimPrefix(source, "urn:")
	return firstNonEmptyString(source, "tap")
}

func validateMapperWriteMetadata(properties map[string]any, entityType, entityID, entityKind string) []graph.SchemaValidationIssue {
	issues := make([]graph.SchemaValidationIssue, 0, 6)
	appendIssue := func(property, message string) {
		issues = append(issues, graph.SchemaValidationIssue{
			Code:     graph.SchemaIssueInvalidProvenance,
			EntityID: strings.TrimSpace(entityID),
			Kind:     strings.TrimSpace(entityKind),
			Property: strings.TrimSpace(property),
			Message:  strings.TrimSpace(message),
		})
	}

	if properties == nil {
		appendIssue("properties", fmt.Sprintf("%s %q is missing metadata properties", entityType, strings.TrimSpace(entityID)))
		return issues
	}

	sourceSystem := strings.TrimSpace(valueToString(properties["source_system"]))
	if sourceSystem == "" {
		appendIssue("source_system", fmt.Sprintf("%s %q must include source_system", entityType, strings.TrimSpace(entityID)))
	}
	sourceEventID := strings.TrimSpace(valueToString(properties["source_event_id"]))
	if sourceEventID == "" {
		appendIssue("source_event_id", fmt.Sprintf("%s %q must include source_event_id", entityType, strings.TrimSpace(entityID)))
	}

	observedAtRaw := strings.TrimSpace(valueToString(properties["observed_at"]))
	observedAt, err := time.Parse(time.RFC3339, observedAtRaw)
	if observedAtRaw == "" || err != nil {
		appendIssue("observed_at", fmt.Sprintf("%s %q observed_at must be RFC3339", entityType, strings.TrimSpace(entityID)))
	}

	validFromRaw := strings.TrimSpace(valueToString(properties["valid_from"]))
	validFrom, err := time.Parse(time.RFC3339, validFromRaw)
	if validFromRaw == "" || err != nil {
		appendIssue("valid_from", fmt.Sprintf("%s %q valid_from must be RFC3339", entityType, strings.TrimSpace(entityID)))
	}

	if !observedAt.IsZero() && !validFrom.IsZero() && observedAt.Before(validFrom) {
		appendIssue("observed_at", fmt.Sprintf("%s %q observed_at must be >= valid_from", entityType, strings.TrimSpace(entityID)))
	}

	validToRaw := strings.TrimSpace(valueToString(properties["valid_to"]))
	if validToRaw != "" {
		validTo, err := time.Parse(time.RFC3339, validToRaw)
		if err != nil {
			appendIssue("valid_to", fmt.Sprintf("%s %q valid_to must be RFC3339 when provided", entityType, strings.TrimSpace(entityID)))
		} else if !validFrom.IsZero() && validTo.Before(validFrom) {
			appendIssue("valid_to", fmt.Sprintf("%s %q valid_to must be >= valid_from", entityType, strings.TrimSpace(entityID)))
		}
	}

	if _, ok := toFloat64(properties["confidence"]); !ok {
		appendIssue("confidence", fmt.Sprintf("%s %q confidence must be a number between 0 and 1", entityType, strings.TrimSpace(entityID)))
	} else if confidence, _ := toFloat64(properties["confidence"]); confidence < 0 || confidence > 1 {
		appendIssue("confidence", fmt.Sprintf("%s %q confidence must be between 0 and 1", entityType, strings.TrimSpace(entityID)))
	}

	return issues
}

func parseRiskLevel(raw string) graph.RiskLevel {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(graph.RiskCritical):
		return graph.RiskCritical
	case string(graph.RiskHigh):
		return graph.RiskHigh
	case string(graph.RiskMedium):
		return graph.RiskMedium
	case string(graph.RiskLow):
		return graph.RiskLow
	default:
		return graph.RiskNone
	}
}

func parseEdgeEffect(raw string) graph.EdgeEffect {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(graph.EdgeEffectDeny):
		return graph.EdgeEffectDeny
	default:
		return graph.EdgeEffectAllow
	}
}

func valueToString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	case fmt.Stringer:
		return typed.String()
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, bool:
		return fmt.Sprintf("%v", typed)
	default:
		return ""
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func normalizeMapperOptions(options MapperOptions) MapperOptions {
	mode := MapperValidationMode(strings.ToLower(strings.TrimSpace(string(options.ValidationMode))))
	switch mode {
	case MapperValidationWarn:
		options.ValidationMode = MapperValidationWarn
	default:
		options.ValidationMode = MapperValidationEnforce
	}
	options.DeadLetterPath = strings.TrimSpace(options.DeadLetterPath)
	return options
}

func (m *Mapper) shouldEnforceValidation() bool {
	if m == nil {
		return true
	}
	return m.options.ValidationMode == MapperValidationEnforce
}

func (m *Mapper) incrementProcessed(source string, eventTime time.Time) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	m.stats.EventsProcessed++
	stats := m.sourceStatsLocked(source)
	stats.EventsProcessed++
	stats.LastEventAt = latestEventTime(stats.LastEventAt, eventTime)
	m.stats.SourceStats[sourceKey(source)] = stats
}

func (m *Mapper) incrementMatched(matched bool, source string, eventTime time.Time) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	stats := m.sourceStatsLocked(source)
	if matched {
		m.stats.EventsMatched++
		stats.EventsMatched++
	} else {
		stats.EventsUnmatched++
	}
	stats.LastEventAt = latestEventTime(stats.LastEventAt, eventTime)
	m.stats.SourceStats[sourceKey(source)] = stats
}

func (m *Mapper) incrementNodeUpserted(source string, eventTime time.Time) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	m.stats.NodesUpserted++
	stats := m.sourceStatsLocked(source)
	stats.NodesUpserted++
	stats.LastEventAt = latestEventTime(stats.LastEventAt, eventTime)
	m.stats.SourceStats[sourceKey(source)] = stats
}

func (m *Mapper) incrementEdgeUpserted(source string, eventTime time.Time) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	m.stats.EdgesUpserted++
	stats := m.sourceStatsLocked(source)
	stats.EdgesUpserted++
	stats.LastEventAt = latestEventTime(stats.LastEventAt, eventTime)
	m.stats.SourceStats[sourceKey(source)] = stats
}

func (m *Mapper) incrementNodeRejected(issues []graph.SchemaValidationIssue, source string, eventTime time.Time) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	m.stats.NodesRejected++
	stats := m.sourceStatsLocked(source)
	stats.NodesRejected++
	stats.LastEventAt = latestEventTime(stats.LastEventAt, eventTime)
	m.stats.SourceStats[sourceKey(source)] = stats
	for _, issue := range issues {
		m.stats.NodeRejectByCode[string(issue.Code)]++
	}
}

func (m *Mapper) incrementEdgeRejected(issues []graph.SchemaValidationIssue, source string, eventTime time.Time) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	m.stats.EdgesRejected++
	stats := m.sourceStatsLocked(source)
	stats.EdgesRejected++
	stats.LastEventAt = latestEventTime(stats.LastEventAt, eventTime)
	m.stats.SourceStats[sourceKey(source)] = stats
	for _, issue := range issues {
		m.stats.EdgeRejectByCode[string(issue.Code)]++
	}
}

func (m *Mapper) writeDeadLetter(record DeadLetterRecord, source string, eventTime time.Time) bool {
	if m == nil || m.deadLetter == nil {
		return false
	}
	if err := m.deadLetter.WriteDeadLetter(record); err != nil {
		m.statsMu.Lock()
		m.stats.DeadLetterFailures++
		m.statsMu.Unlock()
		return false
	}
	m.statsMu.Lock()
	m.stats.DeadLettered++
	stats := m.sourceStatsLocked(source)
	stats.DeadLettered++
	stats.LastEventAt = latestEventTime(stats.LastEventAt, eventTime)
	m.stats.SourceStats[sourceKey(source)] = stats
	m.statsMu.Unlock()
	return true
}

func (m *Mapper) sourceStatsLocked(source string) MapperSourceStats {
	source = sourceKey(source)
	if m.stats.SourceStats == nil {
		m.stats.SourceStats = make(map[string]MapperSourceStats)
	}
	return m.stats.SourceStats[source]
}

func sourceKey(source string) string {
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "" {
		return "unknown"
	}
	return source
}

func latestEventTime(current, candidate time.Time) time.Time {
	candidate = candidate.UTC()
	if candidate.IsZero() {
		candidate = time.Now().UTC()
	}
	if current.IsZero() || candidate.After(current) {
		return candidate
	}
	return current
}

func cloneIntMap(values map[string]int) map[string]int {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]int, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func cloneSourceStatsMap(values map[string]MapperSourceStats) map[string]MapperSourceStats {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]MapperSourceStats, len(values))
	for source, stats := range values {
		out[source] = stats
	}
	return out
}

func toFloat64(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int8:
		return float64(typed), true
	case int16:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case uint:
		return float64(typed), true
	case uint8:
		return float64(typed), true
	case uint16:
		return float64(typed), true
	case uint32:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return 0, false
		}
		parsed, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}
