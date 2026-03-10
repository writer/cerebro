package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	ReportExecutionModeSync  = "sync"
	ReportExecutionModeAsync = "async"

	ReportRunStatusQueued    = "queued"
	ReportRunStatusRunning   = "running"
	ReportRunStatusSucceeded = "succeeded"
	ReportRunStatusFailed    = "failed"
	ReportRunStatusCanceled  = "canceled"
)

// ReportParameterValue holds one typed parameter binding for a report run.
type ReportParameterValue struct {
	Name           string     `json:"name"`
	StringValue    string     `json:"string_value,omitempty"`
	IntegerValue   *int64     `json:"integer_value,omitempty"`
	NumberValue    *float64   `json:"number_value,omitempty"`
	BooleanValue   *bool      `json:"boolean_value,omitempty"`
	TimestampValue *time.Time `json:"timestamp_value,omitempty"`
}

// ReportTimeSlice captures the most important temporal selectors used by report runs.
type ReportTimeSlice struct {
	AsOf       *time.Time `json:"as_of,omitempty"`
	From       *time.Time `json:"from,omitempty"`
	To         *time.Time `json:"to,omitempty"`
	ValidAt    *time.Time `json:"valid_at,omitempty"`
	RecordedAt *time.Time `json:"recorded_at,omitempty"`
}

// ReportRetryPolicy captures retry/backoff policy metadata for one report run.
type ReportRetryPolicy struct {
	MaxAttempts   int   `json:"max_attempts,omitempty"`
	BaseBackoffMS int64 `json:"base_backoff_ms,omitempty"`
	MaxBackoffMS  int64 `json:"max_backoff_ms,omitempty"`
}

// ReportSectionResult summarizes one rendered section within a report run.
type ReportSectionResult struct {
	Key             string                        `json:"key"`
	Title           string                        `json:"title"`
	Kind            string                        `json:"kind"`
	EnvelopeKind    string                        `json:"envelope_kind,omitempty"`
	Present         bool                          `json:"present"`
	ContentType     string                        `json:"content_type,omitempty"`
	ItemCount       int                           `json:"item_count,omitempty"`
	FieldCount      int                           `json:"field_count,omitempty"`
	FieldKeys       []string                      `json:"field_keys,omitempty"`
	MeasureIDs      []string                      `json:"measure_ids,omitempty"`
	Lineage         *ReportSectionLineage         `json:"lineage,omitempty"`
	Materialization *ReportSectionMaterialization `json:"materialization,omitempty"`
}

// ReportSectionEmission carries one section payload emitted over live report streams.
type ReportSectionEmission struct {
	Sequence        int                 `json:"sequence"`
	EmittedAt       time.Time           `json:"emitted_at"`
	ProgressPercent int                 `json:"progress_percent,omitempty"`
	Section         ReportSectionResult `json:"section"`
	Payload         any                 `json:"payload,omitempty"`
}

// ReportSectionLineage captures graph lineage surfaced by one report section payload.
type ReportSectionLineage struct {
	ReferencedNodeCount int      `json:"referenced_node_count,omitempty"`
	ReferencedNodeIDs   []string `json:"referenced_node_ids,omitempty"`
	ClaimCount          int      `json:"claim_count,omitempty"`
	ClaimIDs            []string `json:"claim_ids,omitempty"`
	EvidenceCount       int      `json:"evidence_count,omitempty"`
	EvidenceIDs         []string `json:"evidence_ids,omitempty"`
	SourceCount         int      `json:"source_count,omitempty"`
	SourceIDs           []string `json:"source_ids,omitempty"`
	IDsTruncated        bool     `json:"ids_truncated,omitempty"`
}

// ReportSectionMaterialization captures delivery/truncation hints for one section payload.
type ReportSectionMaterialization struct {
	Truncated         bool     `json:"truncated,omitempty"`
	TruncationSignals []string `json:"truncation_signals,omitempty"`
}

// ReportSnapshot stores materialization metadata for one report result.
type ReportSnapshot struct {
	ID           string              `json:"id"`
	ResultSchema string              `json:"result_schema"`
	GeneratedAt  time.Time           `json:"generated_at"`
	RecordedAt   time.Time           `json:"recorded_at"`
	ContentHash  string              `json:"content_hash"`
	ByteSize     int                 `json:"byte_size"`
	SectionCount int                 `json:"section_count"`
	Retained     bool                `json:"retained"`
	ExpiresAt    *time.Time          `json:"expires_at,omitempty"`
	Lineage      ReportLineage       `json:"lineage,omitempty"`
	Storage      ReportStoragePolicy `json:"storage,omitempty"`
	StoragePath  string              `json:"-"`
}

// ReportRun represents one instantiated execution of a report definition.
type ReportRun struct {
	ID              string                 `json:"id"`
	ReportID        string                 `json:"report_id"`
	Status          string                 `json:"status"`
	ExecutionMode   string                 `json:"execution_mode"`
	SubmittedAt     time.Time              `json:"submitted_at"`
	StartedAt       *time.Time             `json:"started_at,omitempty"`
	CompletedAt     *time.Time             `json:"completed_at,omitempty"`
	RequestedBy     string                 `json:"requested_by,omitempty"`
	Parameters      []ReportParameterValue `json:"parameters,omitempty"`
	TimeSlice       ReportTimeSlice        `json:"time_slice,omitempty"`
	CacheKey        string                 `json:"cache_key,omitempty"`
	JobID           string                 `json:"job_id,omitempty"`
	JobStatusURL    string                 `json:"job_status_url,omitempty"`
	StatusURL       string                 `json:"status_url"`
	LatestAttemptID string                 `json:"latest_attempt_id,omitempty"`
	AttemptCount    int                    `json:"attempt_count,omitempty"`
	EventCount      int                    `json:"event_count,omitempty"`
	RetryPolicy     ReportRetryPolicy      `json:"retry_policy,omitempty"`
	Lineage         ReportLineage          `json:"lineage,omitempty"`
	Storage         ReportStoragePolicy    `json:"storage,omitempty"`
	Snapshot        *ReportSnapshot        `json:"snapshot,omitempty"`
	Sections        []ReportSectionResult  `json:"sections,omitempty"`
	Result          map[string]any         `json:"result,omitempty"`
	Error           string                 `json:"error,omitempty"`
	Attempts        []ReportRunAttempt     `json:"-"`
	Events          []ReportRunEvent       `json:"-"`
}

// ReportRunSummary is the lightweight list representation of a report run.
type ReportRunSummary struct {
	ID              string                 `json:"id"`
	ReportID        string                 `json:"report_id"`
	Status          string                 `json:"status"`
	ExecutionMode   string                 `json:"execution_mode"`
	SubmittedAt     time.Time              `json:"submitted_at"`
	StartedAt       *time.Time             `json:"started_at,omitempty"`
	CompletedAt     *time.Time             `json:"completed_at,omitempty"`
	RequestedBy     string                 `json:"requested_by,omitempty"`
	Parameters      []ReportParameterValue `json:"parameters,omitempty"`
	TimeSlice       ReportTimeSlice        `json:"time_slice,omitempty"`
	CacheKey        string                 `json:"cache_key,omitempty"`
	JobID           string                 `json:"job_id,omitempty"`
	JobStatusURL    string                 `json:"job_status_url,omitempty"`
	StatusURL       string                 `json:"status_url"`
	LatestAttemptID string                 `json:"latest_attempt_id,omitempty"`
	AttemptCount    int                    `json:"attempt_count,omitempty"`
	EventCount      int                    `json:"event_count,omitempty"`
	RetryPolicy     ReportRetryPolicy      `json:"retry_policy,omitempty"`
	Lineage         ReportLineage          `json:"lineage,omitempty"`
	Storage         ReportStoragePolicy    `json:"storage,omitempty"`
	Snapshot        *ReportSnapshot        `json:"snapshot,omitempty"`
	Sections        []ReportSectionResult  `json:"sections,omitempty"`
	Error           string                 `json:"error,omitempty"`
}

// ReportRunCollection is the list response for report runs.
type ReportRunCollection struct {
	ReportID string             `json:"report_id"`
	Count    int                `json:"count"`
	Runs     []ReportRunSummary `json:"runs"`
}

func (value ReportParameterValue) ValueType() (string, error) {
	count := 0
	typeName := ""
	if value.StringValue != "" {
		count++
		typeName = "string"
	}
	if value.IntegerValue != nil {
		count++
		typeName = "integer"
	}
	if value.NumberValue != nil {
		count++
		typeName = "number"
	}
	if value.BooleanValue != nil {
		count++
		typeName = "boolean"
	}
	if value.TimestampValue != nil {
		count++
		typeName = "date-time"
	}
	if count == 0 {
		return "", fmt.Errorf("parameter %q must include exactly one typed value", value.Name)
	}
	if count > 1 {
		return "", fmt.Errorf("parameter %q must not include multiple typed values", value.Name)
	}
	return typeName, nil
}

func (value ReportParameterValue) QueryValue() (string, error) {
	valueType, err := value.ValueType()
	if err != nil {
		return "", err
	}
	switch valueType {
	case "string":
		return value.StringValue, nil
	case "integer":
		return fmt.Sprintf("%d", *value.IntegerValue), nil
	case "number":
		return fmt.Sprintf("%g", *value.NumberValue), nil
	case "boolean":
		return fmt.Sprintf("%t", *value.BooleanValue), nil
	case "date-time":
		return value.TimestampValue.UTC().Format(time.RFC3339), nil
	default:
		return "", fmt.Errorf("unsupported parameter value type %q", valueType)
	}
}

// ValidateReportParameterValues ensures run parameter bindings match the report definition contract.
func ValidateReportParameterValues(definition ReportDefinition, values []ReportParameterValue) error {
	allowed := make(map[string]ReportParameter, len(definition.Parameters))
	for _, parameter := range definition.Parameters {
		allowed[strings.TrimSpace(parameter.Name)] = parameter
	}

	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		name := strings.TrimSpace(value.Name)
		if name == "" {
			return fmt.Errorf("report parameter name is required")
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("duplicate report parameter %q", name)
		}
		seen[name] = struct{}{}

		definitionParameter, ok := allowed[name]
		if !ok {
			return fmt.Errorf("parameter %q is not defined for report %q", name, definition.ID)
		}

		valueType, err := value.ValueType()
		if err != nil {
			return err
		}
		if valueType != strings.TrimSpace(definitionParameter.ValueType) {
			return fmt.Errorf("parameter %q must use value type %q", name, definitionParameter.ValueType)
		}
	}

	for _, parameter := range definition.Parameters {
		if !parameter.Required {
			continue
		}
		if _, ok := seen[strings.TrimSpace(parameter.Name)]; !ok {
			return fmt.Errorf("required parameter %q is missing", parameter.Name)
		}
	}
	return nil
}

// ExtractReportTimeSlice promotes known temporal selectors into a dedicated time-slice envelope.
func ExtractReportTimeSlice(values []ReportParameterValue) ReportTimeSlice {
	slice := ReportTimeSlice{}
	for _, value := range values {
		name := strings.TrimSpace(value.Name)
		if value.TimestampValue == nil || value.TimestampValue.IsZero() {
			continue
		}
		timestamp := value.TimestampValue.UTC()
		switch name {
		case "as_of":
			slice.AsOf = &timestamp
		case "from":
			slice.From = &timestamp
		case "to":
			slice.To = &timestamp
		case "valid_at":
			slice.ValidAt = &timestamp
		case "recorded_at":
			slice.RecordedAt = &timestamp
		}
	}
	return slice
}

// BuildReportSectionResults summarizes the section-level shape of a materialized report result.
func BuildReportSectionResults(definition ReportDefinition, result map[string]any, g *Graph) []ReportSectionResult {
	sections := make([]ReportSectionResult, 0, len(definition.Sections))
	for _, section := range definition.Sections {
		summary := ReportSectionResult{
			Key:          section.Key,
			Title:        section.Title,
			Kind:         section.Kind,
			EnvelopeKind: reportEnvelopeKindForSection(section.Kind),
			MeasureIDs:   append([]string(nil), section.Measures...),
		}
		content, ok := result[section.Key]
		if !ok {
			sections = append(sections, summary)
			continue
		}
		summary.Present = true
		switch typed := content.(type) {
		case map[string]any:
			summary.ContentType = "object"
			summary.FieldCount = len(typed)
			summary.FieldKeys = sortedReportFieldKeys(typed)
		case []any:
			summary.ContentType = "array"
			summary.ItemCount = len(typed)
		case string:
			summary.ContentType = "string"
		case bool:
			summary.ContentType = "boolean"
		case float64, int, int64:
			summary.ContentType = "number"
		default:
			if content == nil {
				summary.ContentType = "null"
			} else {
				summary.ContentType = fmt.Sprintf("%T", content)
			}
		}
		summary.Lineage = BuildReportSectionLineage(g, content)
		summary.Materialization = BuildReportSectionMaterialization(content)
		sections = append(sections, summary)
	}
	return sections
}

// BuildReportSectionEmissions constructs stream-ready section payloads for one report result.
func BuildReportSectionEmissions(definition ReportDefinition, result map[string]any, g *Graph, emittedAt time.Time) []ReportSectionEmission {
	if emittedAt.IsZero() {
		emittedAt = time.Now().UTC()
	}
	summaries := BuildReportSectionResults(definition, result, g)
	emissions := make([]ReportSectionEmission, 0, len(definition.Sections))
	total := len(definition.Sections)
	for index, summary := range summaries {
		emission := ReportSectionEmission{
			Sequence:        index + 1,
			EmittedAt:       emittedAt.UTC(),
			ProgressPercent: reportSectionProgress(index+1, total),
			Section:         CloneReportSectionResults([]ReportSectionResult{summary})[0],
		}
		if payload, ok := result[summary.Key]; ok {
			emission.Payload = cloneReportJSONValue(payload)
		}
		emissions = append(emissions, emission)
	}
	return emissions
}

// BuildReportSnapshot constructs materialization metadata for one report run result.
func BuildReportSnapshot(runID string, definition ReportDefinition, result map[string]any, retained bool, now time.Time) (*ReportSnapshot, error) {
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal report result: %w", err)
	}
	sum := sha256.Sum256(payload)
	var expiresAt *time.Time
	if retained {
		expires := now.Add(7 * 24 * time.Hour)
		expiresAt = &expires
	}
	return &ReportSnapshot{
		ID:           "report_snapshot:" + strings.TrimSpace(runID),
		ResultSchema: definition.ResultSchema,
		GeneratedAt:  now,
		RecordedAt:   now,
		ContentHash:  hex.EncodeToString(sum[:]),
		ByteSize:     len(payload),
		SectionCount: len(definition.Sections),
		Retained:     retained,
		ExpiresAt:    expiresAt,
		Storage:      BuildReportStoragePolicy(true, false),
	}, nil
}

func CloneReportSectionEmissions(values []ReportSectionEmission) []ReportSectionEmission {
	if len(values) == 0 {
		return nil
	}
	cloned := append([]ReportSectionEmission(nil), values...)
	for i := range cloned {
		cloned[i].Section = CloneReportSectionResults([]ReportSectionResult{values[i].Section})[0]
		cloned[i].Payload = cloneReportJSONValue(values[i].Payload)
	}
	return cloned
}

func reportSectionProgress(index, total int) int {
	if total <= 0 {
		return 95
	}
	if index <= 0 {
		return 50
	}
	if index > total {
		index = total
	}
	return 50 + int(float64(index)/float64(total)*45)
}

func cloneReportJSONValue(value any) any {
	if value == nil {
		return nil
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return value
	}
	return decoded
}

// BuildReportRunCacheKey generates a stable cache key for one report definition + parameter binding set.
func BuildReportRunCacheKey(reportID string, values []ReportParameterValue) (string, error) {
	normalized := append([]ReportParameterValue(nil), values...)
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].Name < normalized[j].Name
	})
	payload, err := json.Marshal(struct {
		ReportID   string                 `json:"report_id"`
		Parameters []ReportParameterValue `json:"parameters,omitempty"`
	}{
		ReportID:   strings.TrimSpace(reportID),
		Parameters: normalized,
	})
	if err != nil {
		return "", fmt.Errorf("marshal report cache key payload: %w", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

// SummarizeReportRun strips the variable report payload while preserving execution metadata.
func SummarizeReportRun(run ReportRun) ReportRunSummary {
	return ReportRunSummary{
		ID:              run.ID,
		ReportID:        run.ReportID,
		Status:          run.Status,
		ExecutionMode:   run.ExecutionMode,
		SubmittedAt:     run.SubmittedAt,
		StartedAt:       cloneTimePtr(run.StartedAt),
		CompletedAt:     cloneTimePtr(run.CompletedAt),
		RequestedBy:     run.RequestedBy,
		Parameters:      CloneReportParameterValues(run.Parameters),
		TimeSlice:       cloneReportTimeSlice(run.TimeSlice),
		CacheKey:        run.CacheKey,
		JobID:           run.JobID,
		JobStatusURL:    run.JobStatusURL,
		StatusURL:       run.StatusURL,
		LatestAttemptID: run.LatestAttemptID,
		AttemptCount:    len(run.Attempts),
		EventCount:      len(run.Events),
		RetryPolicy:     NormalizeReportRetryPolicy(run.RetryPolicy),
		Lineage:         CloneReportLineage(run.Lineage),
		Storage:         CloneReportStoragePolicy(run.Storage),
		Snapshot:        cloneReportSnapshot(run.Snapshot),
		Sections:        CloneReportSectionResults(run.Sections),
		Error:           run.Error,
	}
}

// CloneReportRun returns a deep-enough copy for API storage and response safety.
func CloneReportRun(run *ReportRun) *ReportRun {
	if run == nil {
		return nil
	}
	cloned := *run
	cloned.StartedAt = cloneTimePtr(run.StartedAt)
	cloned.CompletedAt = cloneTimePtr(run.CompletedAt)
	cloned.Parameters = CloneReportParameterValues(run.Parameters)
	cloned.TimeSlice = cloneReportTimeSlice(run.TimeSlice)
	cloned.RetryPolicy = NormalizeReportRetryPolicy(run.RetryPolicy)
	cloned.Lineage = CloneReportLineage(run.Lineage)
	cloned.Storage = CloneReportStoragePolicy(run.Storage)
	cloned.Snapshot = cloneReportSnapshot(run.Snapshot)
	cloned.Sections = CloneReportSectionResults(run.Sections)
	cloned.Result = cloneReportResult(run.Result)
	cloned.Attempts = CloneReportRunAttempts(run.Attempts)
	cloned.Events = CloneReportRunEvents(run.Events)
	cloned.AttemptCount = len(cloned.Attempts)
	cloned.EventCount = len(cloned.Events)
	return &cloned
}

func CloneReportParameterValues(values []ReportParameterValue) []ReportParameterValue {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]ReportParameterValue, 0, len(values))
	for _, value := range values {
		item := value
		item.IntegerValue = cloneInt64Ptr(value.IntegerValue)
		item.NumberValue = cloneFloat64Ptr(value.NumberValue)
		item.BooleanValue = cloneBoolPtr(value.BooleanValue)
		item.TimestampValue = cloneTimePtr(value.TimestampValue)
		cloned = append(cloned, item)
	}
	return cloned
}

func CloneReportSectionResults(values []ReportSectionResult) []ReportSectionResult {
	if len(values) == 0 {
		return nil
	}
	cloned := append([]ReportSectionResult(nil), values...)
	for i := range cloned {
		cloned[i].MeasureIDs = append([]string(nil), values[i].MeasureIDs...)
		cloned[i].FieldKeys = append([]string(nil), values[i].FieldKeys...)
		cloned[i].Lineage = cloneReportSectionLineage(values[i].Lineage)
		cloned[i].Materialization = cloneReportSectionMaterialization(values[i].Materialization)
	}
	return cloned
}

const (
	reportSectionLineageIDLimit        = 24
	reportSectionTruncationSignalLimit = 8
)

// BuildReportSectionLineage extracts graph lineage references from one section payload.
func BuildReportSectionLineage(g *Graph, payload any) *ReportSectionLineage {
	if g == nil || payload == nil {
		return nil
	}
	acc := reportSectionLineageAccumulator{
		referenced: make(map[string]struct{}),
		claims:     make(map[string]struct{}),
		evidence:   make(map[string]struct{}),
		sources:    make(map[string]struct{}),
	}
	collectReportSectionPayloadRefs(g, payload, &acc)
	expandReportSectionClaimRefs(g, &acc)

	if len(acc.referenced) == 0 && len(acc.claims) == 0 && len(acc.evidence) == 0 && len(acc.sources) == 0 {
		return nil
	}
	referencedIDs, referencedTruncated := limitedSortedStrings(acc.referenced, reportSectionLineageIDLimit)
	claimIDs, claimTruncated := limitedSortedStrings(acc.claims, reportSectionLineageIDLimit)
	evidenceIDs, evidenceTruncated := limitedSortedStrings(acc.evidence, reportSectionLineageIDLimit)
	sourceIDs, sourceTruncated := limitedSortedStrings(acc.sources, reportSectionLineageIDLimit)
	return &ReportSectionLineage{
		ReferencedNodeCount: len(acc.referenced),
		ReferencedNodeIDs:   referencedIDs,
		ClaimCount:          len(acc.claims),
		ClaimIDs:            claimIDs,
		EvidenceCount:       len(acc.evidence),
		EvidenceIDs:         evidenceIDs,
		SourceCount:         len(acc.sources),
		SourceIDs:           sourceIDs,
		IDsTruncated:        referencedTruncated || claimTruncated || evidenceTruncated || sourceTruncated,
	}
}

// BuildReportSectionMaterialization inspects one section payload for truncation signals.
func BuildReportSectionMaterialization(payload any) *ReportSectionMaterialization {
	signals := make(map[string]struct{})
	collectReportSectionTruncationSignals(payload, "", signals)
	if len(signals) == 0 {
		return nil
	}
	truncationSignals, _ := limitedSortedStrings(signals, reportSectionTruncationSignalLimit)
	return &ReportSectionMaterialization{
		Truncated:         true,
		TruncationSignals: truncationSignals,
	}
}

type reportSectionLineageAccumulator struct {
	referenced map[string]struct{}
	claims     map[string]struct{}
	evidence   map[string]struct{}
	sources    map[string]struct{}
}

func collectReportSectionPayloadRefs(g *Graph, value any, acc *reportSectionLineageAccumulator) {
	if g == nil || acc == nil || value == nil {
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		for _, child := range typed {
			collectReportSectionPayloadRefs(g, child, acc)
		}
	case []any:
		for _, child := range typed {
			collectReportSectionPayloadRefs(g, child, acc)
		}
	case []string:
		for _, child := range typed {
			collectReportSectionPayloadRefs(g, child, acc)
		}
	case string:
		nodeID := strings.TrimSpace(typed)
		if nodeID == "" {
			return
		}
		node, ok := g.GetNode(nodeID)
		if !ok || node == nil {
			return
		}
		acc.referenced[node.ID] = struct{}{}
		switch node.Kind {
		case NodeKindClaim:
			acc.claims[node.ID] = struct{}{}
		case NodeKindEvidence, NodeKindObservation:
			acc.evidence[node.ID] = struct{}{}
		case NodeKindSource:
			acc.sources[node.ID] = struct{}{}
		}
	}
}

func expandReportSectionClaimRefs(g *Graph, acc *reportSectionLineageAccumulator) {
	if g == nil || acc == nil || len(acc.claims) == 0 {
		return
	}
	queue := make([]string, 0, len(acc.claims))
	visited := make(map[string]struct{}, len(acc.claims))
	for claimID := range acc.claims {
		queue = append(queue, claimID)
	}
	for len(queue) > 0 {
		claimID := queue[0]
		queue = queue[1:]
		if _, ok := visited[claimID]; ok {
			continue
		}
		visited[claimID] = struct{}{}

		for _, edge := range g.GetOutEdges(claimID) {
			reportSectionExpandClaimEdge(g, acc, edge, &queue)
		}
		for _, edge := range g.GetInEdges(claimID) {
			if edge == nil || strings.TrimSpace(edge.Source) == "" {
				continue
			}
			sourceNode, ok := g.GetNode(edge.Source)
			if !ok || sourceNode == nil || sourceNode.Kind != NodeKindClaim {
				continue
			}
			if !reportSectionClaimTraversalEdge(edge.Kind) {
				continue
			}
			acc.referenced[sourceNode.ID] = struct{}{}
			if _, ok := acc.claims[sourceNode.ID]; !ok {
				acc.claims[sourceNode.ID] = struct{}{}
				queue = append(queue, sourceNode.ID)
			}
		}
	}
}

func reportSectionExpandClaimEdge(g *Graph, acc *reportSectionLineageAccumulator, edge *Edge, queue *[]string) {
	if g == nil || acc == nil || edge == nil || strings.TrimSpace(edge.Target) == "" {
		return
	}
	targetNode, ok := g.GetNode(edge.Target)
	if !ok || targetNode == nil {
		return
	}
	acc.referenced[targetNode.ID] = struct{}{}
	switch targetNode.Kind {
	case NodeKindEvidence, NodeKindObservation:
		acc.evidence[targetNode.ID] = struct{}{}
	case NodeKindSource:
		acc.sources[targetNode.ID] = struct{}{}
	case NodeKindClaim:
		if !reportSectionClaimTraversalEdge(edge.Kind) {
			return
		}
		if _, ok := acc.claims[targetNode.ID]; ok {
			return
		}
		acc.claims[targetNode.ID] = struct{}{}
		*queue = append(*queue, targetNode.ID)
	}
}

func reportSectionClaimTraversalEdge(kind EdgeKind) bool {
	switch kind {
	case EdgeKindSupports, EdgeKindRefutes, EdgeKindSupersedes:
		return true
	default:
		return false
	}
}

func collectReportSectionTruncationSignals(value any, path string, signals map[string]struct{}) {
	if value == nil || signals == nil {
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			nextPath := strings.TrimSpace(key)
			if path != "" && nextPath != "" {
				nextPath = path + "." + nextPath
			}
			if reportSectionTruncationSignal(key, child) {
				signals[nextPath] = struct{}{}
			}
			collectReportSectionTruncationSignals(child, nextPath, signals)
		}
	case []any:
		for _, child := range typed {
			collectReportSectionTruncationSignals(child, path, signals)
		}
	}
}

func reportSectionTruncationSignal(key string, value any) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if normalized == "" {
		return false
	}
	if strings.Contains(normalized, "truncat") || strings.Contains(normalized, "partial") {
		switch typed := value.(type) {
		case bool:
			return typed
		case float64:
			return typed > 0
		case int:
			return typed > 0
		case int64:
			return typed > 0
		case string:
			trimmed := strings.TrimSpace(strings.ToLower(typed))
			return trimmed == "true" || trimmed == "partial" || trimmed == "truncated"
		}
	}
	return false
}

func limitedSortedStrings(values map[string]struct{}, limit int) ([]string, bool) {
	if len(values) == 0 {
		return nil, false
	}
	items := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		items = append(items, value)
	}
	sort.Strings(items)
	if limit <= 0 || len(items) <= limit {
		return items, false
	}
	return append([]string(nil), items[:limit]...), true
}

func cloneReportSectionLineage(lineage *ReportSectionLineage) *ReportSectionLineage {
	if lineage == nil {
		return nil
	}
	cloned := *lineage
	cloned.ReferencedNodeIDs = append([]string(nil), lineage.ReferencedNodeIDs...)
	cloned.ClaimIDs = append([]string(nil), lineage.ClaimIDs...)
	cloned.EvidenceIDs = append([]string(nil), lineage.EvidenceIDs...)
	cloned.SourceIDs = append([]string(nil), lineage.SourceIDs...)
	return &cloned
}

func cloneReportSectionMaterialization(materialization *ReportSectionMaterialization) *ReportSectionMaterialization {
	if materialization == nil {
		return nil
	}
	cloned := *materialization
	cloned.TruncationSignals = append([]string(nil), materialization.TruncationSignals...)
	return &cloned
}

func cloneReportSnapshot(snapshot *ReportSnapshot) *ReportSnapshot {
	if snapshot == nil {
		return nil
	}
	cloned := *snapshot
	cloned.ExpiresAt = cloneTimePtr(snapshot.ExpiresAt)
	cloned.Lineage = CloneReportLineage(snapshot.Lineage)
	cloned.Storage = CloneReportStoragePolicy(snapshot.Storage)
	return &cloned
}

func cloneReportResult(result map[string]any) map[string]any {
	return cloneAnyMap(result)
}

func reportEnvelopeKindForSection(kind string) string {
	switch strings.TrimSpace(kind) {
	case "scorecard", "context", "health_summary", "calibration_summary", "freshness_summary", "readiness_summary", "capability_summary", "backtest_summary":
		return "summary"
	case "timeseries_summary":
		return "timeseries"
	case "distribution", "coverage_breakdown", "health_breakdown", "breakdown_table":
		return "distribution"
	case "ranked_findings", "ranked_backlog", "action_list":
		return "ranking"
	case "embedded_report":
		return "embedded_report"
	default:
		return "object"
	}
}

func sortedReportFieldKeys(values map[string]any) []string {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func cloneReportTimeSlice(slice ReportTimeSlice) ReportTimeSlice {
	return ReportTimeSlice{
		AsOf:       cloneTimePtr(slice.AsOf),
		From:       cloneTimePtr(slice.From),
		To:         cloneTimePtr(slice.To),
		ValidAt:    cloneTimePtr(slice.ValidAt),
		RecordedAt: cloneTimePtr(slice.RecordedAt),
	}
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}

func cloneInt64Ptr(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneFloat64Ptr(value *float64) *float64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneBoolPtr(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
