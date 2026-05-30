package graphagent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

var (
	ErrRuntimeUnavailable = errors.New("graph agent runtime is unavailable")
	ErrInvalidRequest     = errors.New("invalid graph agent request")
)

const (
	maxInternalAttributeValueBytes = 4096
	maxInternalAttributesJSONBytes = 64 << 10
)

var summaryURNPattern = regexp.MustCompile(`urn:cerebro:[A-Za-z0-9_:@./#%+-]+`)

type AskRequest struct {
	TenantID string           `json:"tenant_id"`
	Question string           `json:"question"`
	ScopeURN string           `json:"scope_urn,omitempty"`
	Model    string           `json:"model,omitempty"`
	History  []HistoryMessage `json:"history,omitempty"`
}

type Emitter func(Event) error

type Service struct {
	store     ports.GraphQueryStore
	llm       LLMClient
	validator *Validator
}

func NewService(store ports.GraphQueryStore, llm LLMClient, options ValidatorOptions) *Service {
	return &Service{
		store:     store,
		llm:       llm,
		validator: NewValidator(store, options),
	}
}

func (s *Service) Stream(ctx context.Context, request AskRequest, emit Emitter) error {
	if emit == nil {
		return fmt.Errorf("%w: event emitter is required", ErrInvalidRequest)
	}
	if err := ValidateRequest(request); err != nil {
		return err
	}
	if s == nil || s.store == nil || s.llm == nil || s.validator == nil {
		return ErrRuntimeUnavailable
	}
	started := time.Now()
	var timings StageTimings
	model := normalizeModel(request.Model)
	history := normalizeHistory(request.History)
	params := askParams(request)
	traceID := newTraceID()

	if err := emitProgress(emit, started, "drafting_query", "Drafting a read-only graph query."); err != nil {
		return err
	}
	draftStarted := time.Now()
	draft, err := s.llm.DraftCypher(ctx, DraftRequest{
		TenantID:  strings.TrimSpace(request.TenantID),
		Question:  strings.TrimSpace(request.Question),
		ScopeURN:  strings.TrimSpace(request.ScopeURN),
		Model:     model,
		History:   history,
		MaxRows:   defaultMaxRows,
		Schema:    graphAgentSchemaHint,
		Guardrail: graphAgentGuardrail,
	})
	if err != nil {
		return fmt.Errorf("%w: draft cypher: %w", ErrRuntimeUnavailable, err)
	}
	timings.DraftMS = time.Since(draftStarted).Milliseconds()
	if draft == nil {
		return fmt.Errorf("%w: LLM returned no draft", ErrRuntimeUnavailable)
	}
	rationale := strings.TrimSpace(draft.Rationale)
	if rationale == "" {
		rationale = "Drafting a bounded read-only Cypher query for the requested graph question."
	}
	if err := emit(Event{Name: EventRationale, Data: RationaleEvent{Text: rationale}}); err != nil {
		return err
	}

	conversionStarted := time.Now()
	conversion := convertDraftToQuery(request, draft, defaultMaxRows)
	timings.ConversionMS = time.Since(conversionStarted).Milliseconds()
	cypher := strings.TrimSpace(conversion.Cypher)
	if err := emitQueryPlan(emit, conversion); err != nil {
		return err
	}
	if cypher == "" {
		reason := firstNonEmpty(draft.Refusal, conversion.Refusal, "LLM refused to draft Cypher")
		return emitRefusal(emit, traceID, started, cypher, reason, timings)
	}
	if err := emitProgress(emit, started, "validating_query", "Validating generated Cypher against read-only guardrails."); err != nil {
		return err
	}
	validateStarted := time.Now()
	validation, rowLimit, err := s.validateConversion(ctx, conversion, cypher, params)
	if err != nil {
		return err
	}
	timings.ValidateMS = time.Since(validateStarted).Milliseconds()
	validation.Warnings = append(validation.Warnings, conversionWarnings(conversion.Diagnostics)...)
	if err := emit(Event{Name: EventCypher, Data: CypherEvent{Cypher: cypher, Validator: validation}}); err != nil {
		return err
	}
	if !validation.OK {
		return emitRefusal(emit, traceID, started, cypher, validation.Reason, timings)
	}

	if err := emitProgress(emit, started, "executing_query", "Executing the validated graph query."); err != nil {
		return err
	}
	execStarted := time.Now()
	rows, err := s.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query:    cypher,
		Params:   params,
		RowLimit: rowLimit,
	})
	if err != nil {
		return fmt.Errorf("%w: execute cypher: %w", ErrRuntimeUnavailable, err)
	}
	timings.ExecuteMS = time.Since(execStarted).Milliseconds()
	if postProcessingCandidateLimitHit(conversion.Plan, rows, rowLimit) {
		return emitRefusal(emit, traceID, started, cypher, "The deterministic Ask query matched more graph rows than can be safely post-processed without risking an incomplete answer. Narrow the scope or ask for a more specific subset.", timings)
	}
	rowMaps := cypherRowsToMaps(rows)
	rowMaps = postProcessAskRows(conversion.Plan, rowMaps)
	sanitizeInternalRowFields(rowMaps)
	rowsEvent := RowsEvent{
		Rows:   rowMaps,
		Graph:  scopedNeighborhood(ctx, s.store, request.ScopeURN),
		ExecMS: timings.ExecuteMS,
	}
	if err := emit(Event{Name: EventRows, Data: rowsEvent}); err != nil {
		return err
	}

	if err := emitProgress(emit, started, "summarizing", "Summarizing graph rows into a user-facing answer."); err != nil {
		return err
	}
	summarizeStarted := time.Now()
	summary, err := s.llm.Summarize(ctx, SummarizeRequest{
		TenantID: strings.TrimSpace(request.TenantID),
		Question: strings.TrimSpace(request.Question),
		ScopeURN: strings.TrimSpace(request.ScopeURN),
		Model:    model,
		Cypher:   cypher,
		Rows:     rowMaps,
		History:  history,
	})
	if err != nil {
		return fmt.Errorf("%w: summarize graph rows: %w", ErrRuntimeUnavailable, err)
	}
	timings.SummarizeMS = time.Since(summarizeStarted).Milliseconds()
	if strings.TrimSpace(summary) == "" {
		summary = fallbackSummary(rowMaps)
	}
	summary = strings.TrimSpace(summary)
	citationStarted := time.Now()
	citations := citationsFor(summary, rowMaps)
	citationValidation := validateSummaryCitations(summary, rowMaps, citations)
	timings.CitationValidationMS = time.Since(citationStarted).Milliseconds()
	if err := emit(Event{Name: EventSummary, Data: SummaryEvent{Markdown: summary, Citations: citations, CitationValidation: &citationValidation}}); err != nil {
		return err
	}
	return emit(Event{Name: EventDone, Data: DoneEvent{TraceID: traceID, TotalMS: time.Since(started).Milliseconds(), Timings: timings}})
}

func (s *Service) validateConversion(ctx context.Context, conversion conversionResult, cypher string, params map[string]any) (ValidatorResult, int, error) {
	validator := s.validator
	if usesPostProcessingCandidates(conversion.Plan) && validator != nil && validator.options.MaxRows < postProcessingCandidateRowLimit {
		options := validator.options
		options.MaxRows = postProcessingCandidateRowLimit
		validator = NewValidator(validator.store, options)
	}
	return validator.validate(ctx, cypher, params)
}

func emitProgress(emit Emitter, started time.Time, stage string, message string) error {
	return emit(Event{Name: EventProgress, Data: ProgressEvent{
		Stage:     strings.TrimSpace(stage),
		Message:   strings.TrimSpace(message),
		ElapsedMS: time.Since(started).Milliseconds(),
	}})
}

func ValidateRequest(request AskRequest) error {
	if strings.TrimSpace(request.TenantID) == "" {
		return fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	question := strings.TrimSpace(request.Question)
	if question == "" {
		return fmt.Errorf("%w: question is required", ErrInvalidRequest)
	}
	if len(question) > 4096 {
		return fmt.Errorf("%w: question exceeds 4096 characters", ErrInvalidRequest)
	}
	return nil
}

func askParams(request AskRequest) map[string]any {
	return map[string]any{
		"tenant_id": strings.TrimSpace(request.TenantID),
		"scope_urn": strings.TrimSpace(request.ScopeURN),
	}
}

func emitQueryPlan(emit Emitter, conversion conversionResult) error {
	return emit(Event{Name: EventQueryPlan, Data: QueryPlanEvent{
		Plan:          conversion.Plan,
		Diagnostics:   conversion.Diagnostics,
		Source:        conversion.Source,
		Deterministic: conversion.Deterministic,
		Corrected:     conversion.Corrected,
	}})
}

func conversionWarnings(diagnostics []ConversionDiagnostic) []string {
	var warnings []string
	for _, diagnostic := range diagnostics {
		if diagnostic.Level == "warn" || diagnostic.Level == "info" {
			warnings = append(warnings, diagnostic.Code+": "+diagnostic.Message)
		}
	}
	return warnings
}

func emitRefusal(emit Emitter, traceID string, started time.Time, cypher string, reason string, timings StageTimings) error {
	reason = firstNonEmpty(reason, "Read-only Cypher validator refused the draft.")
	if cypher == "" {
		if err := emit(Event{Name: EventCypher, Data: CypherEvent{Cypher: "", Validator: ValidatorResult{OK: false, Reason: reason}}}); err != nil {
			return err
		}
	}
	rescue := unsupportedQuery(reason, traceID)
	if err := emit(Event{Name: EventSummary, Data: SummaryEvent{Markdown: reason, UnsupportedQuery: &rescue}}); err != nil {
		return err
	}
	return emit(Event{Name: EventDone, Data: DoneEvent{TraceID: traceID, TotalMS: time.Since(started).Milliseconds(), CypherRefused: true, Timings: timings}})
}

func cypherRowsToMaps(rows []ports.CypherRow) []map[string]any {
	result := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		values := make(map[string]any, len(row.Values))
		keys := make([]string, 0, len(row.Values))
		for key := range row.Values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			values[key] = row.Values[key]
		}
		result = append(result, values)
	}
	return result
}

func sanitizeInternalRowFields(rows []map[string]any) {
	for _, row := range rows {
		mergeInternalAttributes(row, "finding_attributes_json_internal", []string{"summary", "status", "severity", "effective_severity", "risk_score"})
		mergeInternalAttributes(row, "relation_attributes_json_internal", []string{"severity", "effective_severity", "risk_score"})
		mergeInternalAttributes(row, "source_attributes_json_internal", []string{"status", "health", "last_sync_at", "last_sync_minutes", "last_success_at", "last_error"})
	}
}

func postProcessAskRows(plan AskQueryPlan, rows []map[string]any) []map[string]any {
	switch plan.Intent {
	case IntentAggregateFindingsBySource:
		return postProcessFindingSourceRows(plan, rows)
	case IntentTopRiskFindings:
		return postProcessTopRiskFindingRows(plan, rows)
	default:
		return rows
	}
}

func usesPostProcessingCandidates(plan AskQueryPlan) bool {
	return plan.Intent == IntentAggregateFindingsBySource || plan.Intent == IntentTopRiskFindings
}

func postProcessingCandidateLimitHit(plan AskQueryPlan, rows []ports.CypherRow, rowLimit int) bool {
	return usesPostProcessingCandidates(plan) && rowLimit >= postProcessingCandidateRowLimit && len(rows) >= rowLimit
}

func postProcessFindingSourceRows(plan AskQueryPlan, rows []map[string]any) []map[string]any {
	counts := map[string]int64{}
	seenFindings := map[string]struct{}{}
	for index, row := range rows {
		findingURN := stringRowValue(row, "finding_urn")
		if findingURN == "" {
			findingURN = fmt.Sprintf("row:%d", index)
		}
		if _, seen := seenFindings[findingURN]; seen {
			continue
		}
		seenFindings[findingURN] = struct{}{}
		attrs := decodeInternalAttributes(row["finding_attributes_json_internal"])
		sourceFamily := firstAttributeString(attrs, "source_family", "sourceFamily", "source_system")
		if sourceFamily == "" {
			sourceFamily = stringRowValue(row, "source_id")
		}
		if sourceFamily == "" {
			sourceFamily = "Unknown"
		}
		counts[sourceFamily]++
	}
	sourceFamilies := make([]string, 0, len(counts))
	for sourceFamily := range counts {
		sourceFamilies = append(sourceFamilies, sourceFamily)
	}
	sort.Slice(sourceFamilies, func(i, j int) bool {
		left, right := sourceFamilies[i], sourceFamilies[j]
		if counts[left] != counts[right] {
			return counts[left] > counts[right]
		}
		return left < right
	})
	limit := postProcessedRowLimit(plan)
	if plan.Intent == IntentAggregateFindingsBySource && limit > 10 {
		limit = 10
	}
	if len(sourceFamilies) < limit {
		limit = len(sourceFamilies)
	}
	result := make([]map[string]any, 0, limit)
	for _, sourceFamily := range sourceFamilies[:limit] {
		result = append(result, map[string]any{
			"source_family": sourceFamily,
			"finding_count": counts[sourceFamily],
		})
	}
	return result
}

type topRiskFindingRow struct {
	FindingURN     string
	FindingLabel   string
	ResourceURNs   []string
	ResourceLabels []string
	riskScore      int
	severityRank   int
	seenResources  map[string]struct{}
}

func postProcessTopRiskFindingRows(plan AskQueryPlan, rows []map[string]any) []map[string]any {
	byFinding := map[string]*topRiskFindingRow{}
	for index, row := range rows {
		findingURN := stringRowValue(row, "finding_urn")
		if findingURN == "" {
			findingURN = fmt.Sprintf("row:%d", index)
		}
		relationAttrs := decodeInternalAttributes(row["relation_attributes_json_internal"])
		findingAttrs := decodeInternalAttributes(row["finding_attributes_json_internal"])
		severity := firstNonEmpty(
			firstAttributeString(relationAttrs, "effective_severity", "severity"),
			firstAttributeString(findingAttrs, "effective_severity", "severity"),
		)
		status := firstNonEmpty(
			firstAttributeString(relationAttrs, "status"),
			firstAttributeString(findingAttrs, "status"),
		)
		if !matchesTopRiskFilters(plan, row, severity, status) {
			continue
		}
		current := byFinding[findingURN]
		if current == nil {
			current = &topRiskFindingRow{
				FindingURN:    findingURN,
				FindingLabel:  firstNonEmpty(stringRowValue(row, "finding_label"), findingURN),
				seenResources: map[string]struct{}{},
			}
			byFinding[findingURN] = current
		}
		resourceURN := stringRowValue(row, "resource_urn")
		if resourceURN != "" {
			if _, seen := current.seenResources[resourceURN]; !seen {
				current.seenResources[resourceURN] = struct{}{}
				current.ResourceURNs = append(current.ResourceURNs, resourceURN)
				current.ResourceLabels = append(current.ResourceLabels, firstNonEmpty(stringRowValue(row, "resource_label"), resourceURN))
			}
		}
		riskScore := firstAttributeInt(relationAttrs, findingAttrs, "risk_score")
		if riskScore > current.riskScore {
			current.riskScore = riskScore
		}
		if rank := severityRank(severity); rank > current.severityRank {
			current.severityRank = rank
		}
	}
	findings := make([]*topRiskFindingRow, 0, len(byFinding))
	for _, finding := range byFinding {
		findings = append(findings, finding)
	}
	sort.Slice(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if left.riskScore != right.riskScore {
			return left.riskScore > right.riskScore
		}
		if left.severityRank != right.severityRank {
			return left.severityRank > right.severityRank
		}
		return left.FindingURN < right.FindingURN
	})
	limit := postProcessedRowLimit(plan)
	if len(findings) < limit {
		limit = len(findings)
	}
	result := make([]map[string]any, 0, limit)
	for _, finding := range findings[:limit] {
		result = append(result, map[string]any{
			"finding_urn":     finding.FindingURN,
			"finding_label":   finding.FindingLabel,
			"resource_urns":   append([]string(nil), finding.ResourceURNs...),
			"resource_labels": append([]string(nil), finding.ResourceLabels...),
			"risk_score":      finding.riskScore,
			"severity":        severityName(finding.severityRank),
		})
	}
	return result
}

func matchesTopRiskFilters(plan AskQueryPlan, row map[string]any, severity string, status string) bool {
	if want := planFilterValue(plan.Filters, "severity"); want != "" && !strings.EqualFold(severity, want) {
		return false
	}
	if want := planFilterValue(plan.Filters, "status"); want != "" && !strings.EqualFold(status, want) {
		return false
	}
	if want := firstNonEmpty(planFilterValue(plan.Filters, "resource_type"), planFilterValue(plan.Filters, "entity_type")); want != "" {
		return resourceTypeMatchesFilter(stringRowValue(row, "resource_type"), stringRowValue(row, "resource_urn"), want)
	}
	return true
}

func resourceTypeMatchesFilter(resourceType string, resourceURN string, filter string) bool {
	canonical := canonicalEntityType(filter)
	if canonical == "github.code.repository" || canonical == "github.repo" {
		return resourceType == "github.code.repository" || resourceType == "github.repo" || strings.Contains(resourceURN, ":repo:") || strings.Contains(resourceURN, ":github_repo:")
	}
	return strings.EqualFold(resourceType, canonical)
}

func postProcessedRowLimit(plan AskQueryPlan) int {
	return boundedLimit(plan.Limit, defaultMaxRows)
}

func decodeInternalAttributes(value any) map[string]any {
	raw, ok := value.(string)
	if !ok {
		return nil
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxInternalAttributesJSONBytes {
		return nil
	}
	var attrs map[string]any
	if err := json.Unmarshal([]byte(raw), &attrs); err != nil {
		return nil
	}
	return attrs
}

func firstAttributeString(attrs map[string]any, fields ...string) string {
	for _, field := range fields {
		value, ok := attrs[field]
		if !ok {
			continue
		}
		if text, ok := internalAttributeText(value); ok {
			return text
		}
	}
	return ""
}

func firstAttributeInt(primary map[string]any, fallback map[string]any, field string) int {
	if value, ok := attributeInt(primary[field]); ok {
		return value
	}
	if value, ok := attributeInt(fallback[field]); ok {
		return value
	}
	return 0
}

func attributeInt(value any) (int, bool) {
	switch typed := value.(type) {
	case float64:
		return int(typed), true
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case json.Number:
		parsed, err := typed.Int64()
		if err == nil {
			return int(parsed), true
		}
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func stringRowValue(row map[string]any, key string) string {
	if text, ok := internalAttributeText(row[key]); ok {
		return text
	}
	return ""
}

func severityRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func severityName(rank int) string {
	switch rank {
	case 4:
		return "CRITICAL"
	case 3:
		return "HIGH"
	case 2:
		return "MEDIUM"
	case 1:
		return "LOW"
	default:
		return ""
	}
}

func mergeInternalAttributes(row map[string]any, key string, fields []string) {
	raw, ok := row[key].(string)
	delete(row, key)
	if !ok || strings.TrimSpace(raw) == "" {
		return
	}
	var attrs map[string]any
	if err := json.Unmarshal([]byte(raw), &attrs); err != nil {
		return
	}
	for _, field := range fields {
		if !rowValueEmpty(row[field]) {
			continue
		}
		value, ok := attrs[field]
		if !ok {
			continue
		}
		if text, ok := internalAttributeText(value); ok {
			row[field] = text
		}
	}
}

func internalAttributeText(value any) (string, bool) {
	var text string
	switch typed := value.(type) {
	case string:
		text = typed
	case float64, int, int64, bool, json.Number:
		text = fmt.Sprint(typed)
	default:
		return "", false
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return "", false
	}
	return truncateStringBytes(text, maxInternalAttributeValueBytes), true
}

func truncateStringBytes(text string, maxBytes int) string {
	if maxBytes <= 0 || len(text) <= maxBytes {
		return text
	}
	end := 0
	for i := range text {
		if i > maxBytes {
			break
		}
		end = i
	}
	if end == 0 {
		return ""
	}
	return text[:end]
}

func rowValueEmpty(value any) bool {
	if value == nil {
		return true
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed) == ""
	default:
		return false
	}
}

func scopedNeighborhood(ctx context.Context, store ports.GraphQueryStore, scopeURN string) *ports.EntityNeighborhood {
	scopeURN = strings.TrimSpace(scopeURN)
	if scopeURN == "" || store == nil {
		return nil
	}
	graph, err := store.GetEntityNeighborhood(ctx, scopeURN, 25)
	if err != nil {
		return nil
	}
	return graph
}

func citationsFor(summary string, rows []map[string]any) []Citation {
	seen := map[string]struct{}{}
	var citations []Citation
	for _, urn := range collectRowURNs(rows) {
		if _, exists := seen[urn]; exists {
			continue
		}
		start := strings.Index(summary, urn)
		if start < 0 {
			continue
		}
		seen[urn] = struct{}{}
		citations = append(citations, Citation{URN: urn, Span: [2]int{start, start + len(urn)}})
	}
	return citations
}

func validateSummaryCitations(summary string, rows []map[string]any, citations []Citation) CitationValidation {
	rowURNs := map[string]struct{}{}
	for _, urn := range collectRowURNs(rows) {
		rowURNs[urn] = struct{}{}
	}
	referencedURNs := urnsFromSummary(summary)
	var warnings []string
	for _, citation := range citations {
		if _, ok := rowURNs[citation.URN]; !ok {
			warnings = append(warnings, "citation_not_row_backed:"+citation.URN)
		}
		if citation.Span[0] < 0 || citation.Span[1] <= citation.Span[0] || citation.Span[1] > len(summary) {
			warnings = append(warnings, "citation_invalid_span:"+citation.URN)
			continue
		}
		if summary[citation.Span[0]:citation.Span[1]] != citation.URN {
			warnings = append(warnings, "citation_span_mismatch:"+citation.URN)
		}
	}
	for _, urn := range referencedURNs {
		if _, ok := rowURNs[urn]; !ok {
			warnings = append(warnings, "summary_urn_not_row_backed:"+urn)
		}
	}
	sort.Strings(warnings)
	return CitationValidation{
		OK:                 len(warnings) == 0,
		Warnings:           warnings,
		RowURNCount:        len(rowURNs),
		ReferencedURNCount: len(referencedURNs),
	}
}

func collectRowURNs(rows []map[string]any) []string {
	seen := map[string]struct{}{}
	var urns []string
	var visit func(any)
	visit = func(value any) {
		switch typed := value.(type) {
		case string:
			if strings.HasPrefix(typed, "urn:cerebro:") {
				if _, exists := seen[typed]; !exists {
					seen[typed] = struct{}{}
					urns = append(urns, typed)
				}
			}
		case []string:
			for _, item := range typed {
				visit(item)
			}
		case []any:
			for _, item := range typed {
				visit(item)
			}
		case map[string]any:
			for _, item := range typed {
				visit(item)
			}
		}
	}
	for _, row := range rows {
		visit(row)
	}
	sort.Strings(urns)
	return urns
}

func urnsFromSummary(summary string) []string {
	matches := summaryURNPattern.FindAllString(summary, -1)
	seen := map[string]struct{}{}
	var urns []string
	for _, match := range matches {
		urn := strings.TrimRight(match, ".,;:!?")
		if _, exists := seen[urn]; exists {
			continue
		}
		seen[urn] = struct{}{}
		urns = append(urns, urn)
	}
	sort.Strings(urns)
	return urns
}

func unsupportedQuery(reason string, traceID string) UnsupportedQuery {
	return UnsupportedQuery{
		Code:             unsupportedQueryCode(reason),
		Reason:           reason,
		SupportedIntents: []string{IntentTopRiskFindings, IntentAggregateFindingsBySource, IntentExplainFinding, IntentIdentityBridge, IntentConnectorHealth},
		SuggestedRewrites: []string{
			"Summarize open high-risk findings and cite the affected entities.",
			"Count findings by source family.",
			"Show source health and freshness for security integrations.",
			"Explain the evidence for a specific finding URN.",
		},
		TraceID: traceID,
	}
}

func unsupportedQueryCode(reason string) string {
	lower := strings.ToLower(reason)
	switch {
	case strings.Contains(lower, "could not be converted"):
		return "query_plan_conversion_failed"
	case strings.Contains(lower, "refused"):
		return "llm_refusal"
	case strings.Contains(lower, "read-only") || strings.Contains(lower, "write"):
		return "validator_refusal"
	default:
		return "unsupported_query"
	}
}

func fallbackSummary(rows []map[string]any) string {
	if len(rows) == 0 {
		return "The validated read-only graph query returned no rows."
	}
	return fmt.Sprintf("The validated read-only graph query returned %d rows.", len(rows))
}

func normalizeHistory(history []HistoryMessage) []HistoryMessage {
	const maxHistory = 12
	if len(history) > maxHistory {
		history = history[len(history)-maxHistory:]
	}
	result := make([]HistoryMessage, 0, len(history))
	for _, item := range history {
		role := strings.ToLower(strings.TrimSpace(item.Role))
		if role != "user" && role != "assistant" {
			continue
		}
		content := strings.TrimSpace(item.Content)
		if content == "" {
			continue
		}
		if len(content) > 4096 {
			content = content[:4096]
		}
		result = append(result, HistoryMessage{Role: role, Content: content})
	}
	return result
}

func newTraceID() string {
	var buf [6]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf[:])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

var graphAgentSchemaHint = canonicalGraphOntology.PromptHint()

const graphAgentGuardrail = `Rules:
- Generate read-only Cypher only.
- Do not use CREATE, MERGE, DELETE, REMOVE, SET, DROP, FOREACH, LOAD CSV, USING PERIODIC, apoc.trigger, or apoc.periodic.
- Always include a numeric LIMIT <= 100.
- Use $tenant_id and, when relevant, $scope_urn parameters instead of literal tenant or entity values.`
