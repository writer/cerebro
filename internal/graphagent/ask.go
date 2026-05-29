package graphagent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

var (
	ErrRuntimeUnavailable = errors.New("graph agent runtime is unavailable")
	ErrInvalidRequest     = errors.New("invalid graph agent request")
)

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
	model := normalizeModel(request.Model)
	history := normalizeHistory(request.History)
	params := askParams(request)
	traceID := newTraceID()

	if err := emitProgress(emit, started, "drafting_query", "Drafting a read-only graph query."); err != nil {
		return err
	}
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

	conversion := convertDraftToQuery(request, draft, defaultMaxRows)
	cypher := strings.TrimSpace(conversion.Cypher)
	if err := emitQueryPlan(emit, conversion); err != nil {
		return err
	}
	if cypher == "" {
		reason := firstNonEmpty(draft.Refusal, conversion.Refusal, "LLM refused to draft Cypher")
		return emitRefusal(emit, traceID, started, cypher, reason)
	}
	if err := emitProgress(emit, started, "validating_query", "Validating generated Cypher against read-only guardrails."); err != nil {
		return err
	}
	validation, rowLimit, err := s.validator.validate(ctx, cypher, params)
	if err != nil {
		return err
	}
	validation.Warnings = append(validation.Warnings, conversionWarnings(conversion.Diagnostics)...)
	if err := emit(Event{Name: EventCypher, Data: CypherEvent{Cypher: cypher, Validator: validation}}); err != nil {
		return err
	}
	if !validation.OK {
		return emitRefusal(emit, traceID, started, cypher, validation.Reason)
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
	rowMaps := cypherRowsToMaps(rows)
	sanitizeInternalRowFields(rowMaps)
	rowsEvent := RowsEvent{
		Rows:   rowMaps,
		Graph:  scopedNeighborhood(ctx, s.store, request.ScopeURN),
		ExecMS: time.Since(execStarted).Milliseconds(),
	}
	if err := emit(Event{Name: EventRows, Data: rowsEvent}); err != nil {
		return err
	}

	if err := emitProgress(emit, started, "summarizing", "Summarizing graph rows into a user-facing answer."); err != nil {
		return err
	}
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
	if strings.TrimSpace(summary) == "" {
		summary = fallbackSummary(rowMaps)
	}
	summary = strings.TrimSpace(summary)
	if err := emit(Event{Name: EventSummary, Data: SummaryEvent{Markdown: summary, Citations: citationsFor(summary, rowMaps)}}); err != nil {
		return err
	}
	return emit(Event{Name: EventDone, Data: DoneEvent{TraceID: traceID, TotalMS: time.Since(started).Milliseconds()}})
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

func emitRefusal(emit Emitter, traceID string, started time.Time, cypher string, reason string) error {
	reason = firstNonEmpty(reason, "Read-only Cypher validator refused the draft.")
	if cypher == "" {
		if err := emit(Event{Name: EventCypher, Data: CypherEvent{Cypher: "", Validator: ValidatorResult{OK: false, Reason: reason}}}); err != nil {
			return err
		}
	}
	if err := emit(Event{Name: EventSummary, Data: SummaryEvent{Markdown: reason}}); err != nil {
		return err
	}
	return emit(Event{Name: EventDone, Data: DoneEvent{TraceID: traceID, TotalMS: time.Since(started).Milliseconds(), CypherRefused: true}})
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
		mergeFindingAttributes(row, "finding_attributes_json_internal")
	}
}

func mergeFindingAttributes(row map[string]any, key string) {
	raw, ok := row[key].(string)
	delete(row, key)
	if !ok || strings.TrimSpace(raw) == "" {
		return
	}
	var attrs map[string]any
	if err := json.Unmarshal([]byte(raw), &attrs); err != nil {
		return
	}
	for _, field := range []string{"summary", "status", "severity", "effective_severity", "risk_score"} {
		if !rowValueEmpty(row[field]) {
			continue
		}
		value, ok := attrs[field]
		if !ok {
			continue
		}
		if text := strings.TrimSpace(fmt.Sprint(value)); text != "" {
			row[field] = text
		}
	}
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
	for _, row := range rows {
		for _, value := range row {
			urn, ok := value.(string)
			if !ok || !strings.HasPrefix(urn, "urn:cerebro:") {
				continue
			}
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
	}
	return citations
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
