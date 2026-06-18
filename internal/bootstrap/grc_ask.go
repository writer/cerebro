package bootstrap

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graphagent"
	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/telemetry"
)

const maxGRCAskBodyBytes = 128 << 10

type grcAskRequestEnvelope struct {
	graphagent.AskRequest
	Context        json.RawMessage `json:"context,omitempty"`
	Surface        string          `json:"surface,omitempty"`
	ConversationID string          `json:"conversation_id,omitempty"`
}

func (a *App) handleGRCAsk(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	evt := askWideEvent{provider: a.cfg.GraphAgentLLM.Provider}

	var envelope grcAskRequestEnvelope
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGRCAskBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		evt.finish(r, started, http.StatusBadRequest, err)
		writeGRCError(w, errors.Join(errInvalidHTTPRequest, err))
		return
	}
	request := envelope.AskRequest
	evt.tenantID = request.TenantID
	evt.question = request.Question
	evt.scopeURN = request.ScopeURN
	evt.model = request.Model
	evt.historyLen = len(request.History)

	if err := authorizeTenantID(r.Context(), request.TenantID); err != nil {
		evt.finish(r, started, http.StatusForbidden, err)
		writeGRCError(w, err)
		return
	}
	if request.ScopeURN != "" {
		if err := authorizeCerebroURNTenant(r.Context(), request.ScopeURN); err != nil {
			evt.finish(r, started, http.StatusForbidden, err)
			writeGRCError(w, err)
			return
		}
	}
	if err := graphagent.ValidateRequest(request); err != nil {
		evt.finish(r, started, http.StatusBadRequest, err)
		writeGRCError(w, err)
		return
	}
	graphStore := graphQueryStore(a.deps.GraphStore)
	if graphStore == nil {
		evt.failureStage = "graph_store_nil"
		evt.finish(r, started, http.StatusServiceUnavailable, graphquery.ErrRuntimeUnavailable)
		writeGRCError(w, graphquery.ErrRuntimeUnavailable)
		return
	}
	evt.graphStoreOK = true

	llm := a.deps.GraphAgentLLM
	if llm == nil {
		err := errors.Join(graphagent.ErrRuntimeUnavailable, errors.New("graph agent llm is not configured"))
		evt.failureStage = "llm_init"
		evt.llmInitErrorKind = grcTelemetryErrorKind(err)
		evt.finish(r, started, http.StatusServiceUnavailable, err)
		writeGRCError(w, err)
		return
	}
	evt.llmPreCached = true
	evt.llmOK = true

	clearLongRunningWriteDeadline(w)
	flusher, _ := w.(http.Flusher)
	service := graphagent.NewServiceWithOptions(graphStore, llm, graphagent.ValidatorOptions{Explain: true}, graphagent.ServiceOptions{
		TrajectoryStore:             askTrajectoryStore(a.deps.StateStore),
		EnableGraphProbes:           true,
		EnableDeterministicFastPath: true,
		EnableRecovery:              true,
		EnableMapReduce:             true,
		MaxDepth:                    2,
		MaxChildren:                 2,
	})
	var eventCount int
	streamStarted := false
	err := service.Stream(r.Context(), request, func(event graphagent.Event) error {
		if !streamStarted {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache, no-transform")
			w.Header().Set("Connection", "keep-alive")
			w.WriteHeader(http.StatusOK)
			streamStarted = true
		}
		eventCount++
		if err := graphagent.WriteSSEEvent(w, event); err != nil {
			return err
		}
		evt.observe(event)
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	})
	if err != nil && !streamStarted {
		evt.failureStage = "stream"
		evt.finish(r, started, http.StatusServiceUnavailable, err)
		writeGRCError(w, err)
		return
	}
	if err != nil {
		evt.failureStage = "stream"
		timings, _ := graphagent.ErrorTimings(err)
		if timings != (graphagent.StageTimings{}) {
			evt.result.timings = timings
		}
		errorEvent := graphagent.Event{Name: graphagent.EventError, Data: graphagent.ErrorEvent{
			Code:    askRuntimeErrorCode(err),
			Message: err.Error(),
			TraceID: graphagent.ErrorTraceID(err),
			Timings: timings,
		}}
		writeErr := graphagent.WriteSSEEvent(w, errorEvent)
		if writeErr == nil {
			eventCount++
			evt.observe(errorEvent)
			if flusher != nil {
				flusher.Flush()
			}
		} else {
			log.Printf("write grc ask SSE error event: %v", writeErr)
		}
		evt.sseEvents = eventCount
		evt.finish(r, started, http.StatusOK, err)
		return
	}
	evt.sseEvents = eventCount
	evt.finish(r, started, http.StatusOK, nil)
}

func askRuntimeErrorCode(err error) string {
	if errors.Is(err, graphagent.ErrLLMAuthenticationFailed) {
		return "llm_authentication_failed"
	}
	if errors.Is(err, graphagent.ErrLLMAccessDenied) {
		return "llm_access_denied"
	}
	return "ask_failed"
}

type askWideEvent struct {
	tenantID         string
	question         string
	scopeURN         string
	model            string
	historyLen       int
	provider         string
	graphStoreOK     bool
	llmOK            bool
	llmPreCached     bool
	llmInitMs        int64
	llmInitErrorKind string
	failureStage     string
	sseEvents        int

	queryPlan askQueryPlanTelemetry
	result    askResultTelemetry
	probe     askProbeTelemetry
}

type askQueryPlanTelemetry struct {
	intent           string
	source           string
	deterministic    bool
	corrected        bool
	diagnosticsCount int
	diagnosticCodes  string
}

type askResultTelemetry struct {
	validatorOK            bool
	validatorCode          string
	validatorWarningsCount int
	rowCount               int
	citationCount          int
	citationWarningsCount  int
	unsupportedQueryCode   string
	traceID                string
	runtimeErrorCode       string
	cypherRefused          bool
	terminalEvent          string
	timings                graphagent.StageTimings
}

type askProbeTelemetry struct {
	entityTypeCount int
	relationCount   int
	warningsCount   int
	scopeFound      bool
}

func (e *askWideEvent) observe(event graphagent.Event) {
	switch data := event.Data.(type) {
	case graphagent.GraphProbeEvent:
		e.probe.entityTypeCount = len(data.Probe.EntityTypes)
		e.probe.relationCount = len(data.Probe.Relations)
		e.probe.warningsCount = len(data.Probe.Warnings)
		e.probe.scopeFound = data.Probe.ScopeFound
	case graphagent.QueryPlanEvent:
		e.queryPlan.intent = data.Plan.Intent
		e.queryPlan.source = data.Source
		e.queryPlan.deterministic = data.Deterministic
		e.queryPlan.corrected = data.Corrected
		e.queryPlan.diagnosticsCount = len(data.Diagnostics)
		e.queryPlan.diagnosticCodes = askDiagnosticCodes(data.Diagnostics)
	case graphagent.CypherEvent:
		e.result.validatorOK = data.Validator.OK
		e.result.validatorCode = data.Validator.Code
		e.result.validatorWarningsCount = len(data.Validator.Warnings)
	case graphagent.RowsEvent:
		e.result.rowCount = len(data.Rows)
	case graphagent.SummaryEvent:
		e.result.citationCount = len(data.Citations)
		if data.CitationValidation != nil {
			e.result.citationWarningsCount = len(data.CitationValidation.Warnings)
		}
		if data.UnsupportedQuery != nil {
			e.result.unsupportedQueryCode = data.UnsupportedQuery.Code
		}
	case graphagent.DoneEvent:
		e.result.traceID = data.TraceID
		e.result.cypherRefused = data.CypherRefused
		e.result.terminalEvent = graphagent.EventDone
		e.result.timings = data.Timings
	case graphagent.ErrorEvent:
		e.result.terminalEvent = graphagent.EventError
		e.result.runtimeErrorCode = data.Code
		if data.TraceID != "" {
			e.result.traceID = data.TraceID
		}
		if data.Timings != (graphagent.StageTimings{}) {
			e.result.timings = data.Timings
		}
	}
}

func (e *askWideEvent) finish(r *http.Request, started time.Time, status int, err error) {
	durationMs := time.Since(started).Milliseconds()
	outcome := "success"
	if err != nil {
		outcome = "error"
	}

	attrs := telemetry.Attrs(
		telemetry.Field{Key: "main", Value: true},
		telemetry.Field{Key: "operation", Value: "grc.ask"},
		telemetry.Field{Key: "duration_ms", Value: durationMs},
		telemetry.Field{Key: "status", Value: status},
		telemetry.Field{Key: "outcome", Value: outcome},
		telemetry.Field{Key: "tenant_id", Value: e.tenantID},
		telemetry.Field{Key: "question_len", Value: len(e.question)},
		telemetry.Field{Key: "scope_urn", Value: e.scopeURN},
		telemetry.Field{Key: "model", Value: e.model},
		telemetry.Field{Key: "history_len", Value: e.historyLen},
		telemetry.Field{Key: "llm.provider", Value: e.provider},
		telemetry.Field{Key: "llm.ok", Value: e.llmOK},
		telemetry.Field{Key: "llm.pre_cached", Value: e.llmPreCached},
		telemetry.Field{Key: "llm.init_ms", Value: e.llmInitMs},
		telemetry.Field{Key: "graph_store.ok", Value: e.graphStoreOK},
		telemetry.Field{Key: "sse_events", Value: e.sseEvents},
	)
	if e.queryPlan.intent != "" {
		attrs = attrs.
			WithField(telemetry.Field{Key: "query_plan.intent", Value: e.queryPlan.intent}).
			WithField(telemetry.Field{Key: "query_plan.source", Value: e.queryPlan.source}).
			WithField(telemetry.Field{Key: "query_plan.deterministic", Value: e.queryPlan.deterministic}).
			WithField(telemetry.Field{Key: "query_plan.corrected", Value: e.queryPlan.corrected}).
			WithField(telemetry.Field{Key: "query_plan.diagnostics_count", Value: e.queryPlan.diagnosticsCount})
	}
	if e.queryPlan.diagnosticCodes != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "query_plan.diagnostic_codes", Value: e.queryPlan.diagnosticCodes})
	}
	if e.result.terminalEvent != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "terminal_event", Value: e.result.terminalEvent})
	}
	if e.result.traceID != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "ask_trace_id", Value: e.result.traceID})
	}
	attrs = attrs.
		WithField(telemetry.Field{Key: "validator.ok", Value: e.result.validatorOK}).
		WithField(telemetry.Field{Key: "validator.warnings_count", Value: e.result.validatorWarningsCount}).
		WithField(telemetry.Field{Key: "cypher_refused", Value: e.result.cypherRefused}).
		WithField(telemetry.Field{Key: "row_count", Value: e.result.rowCount}).
		WithField(telemetry.Field{Key: "citation_count", Value: e.result.citationCount}).
		WithField(telemetry.Field{Key: "citation_validation.warnings_count", Value: e.result.citationWarningsCount}).
		WithField(telemetry.Field{Key: "graph_probe.entity_type_count", Value: e.probe.entityTypeCount}).
		WithField(telemetry.Field{Key: "graph_probe.relation_count", Value: e.probe.relationCount}).
		WithField(telemetry.Field{Key: "graph_probe.warnings_count", Value: e.probe.warningsCount}).
		WithField(telemetry.Field{Key: "graph_probe.scope_found", Value: e.probe.scopeFound}).
		WithField(telemetry.Field{Key: "stage.probe_ms", Value: e.result.timings.ProbeMS}).
		WithField(telemetry.Field{Key: "stage.draft_ms", Value: e.result.timings.DraftMS}).
		WithField(telemetry.Field{Key: "stage.conversion_ms", Value: e.result.timings.ConversionMS}).
		WithField(telemetry.Field{Key: "stage.validate_ms", Value: e.result.timings.ValidateMS}).
		WithField(telemetry.Field{Key: "stage.execute_ms", Value: e.result.timings.ExecuteMS}).
		WithField(telemetry.Field{Key: "stage.summarize_ms", Value: e.result.timings.SummarizeMS}).
		WithField(telemetry.Field{Key: "stage.citation_validation_ms", Value: e.result.timings.CitationValidationMS})
	if e.result.validatorCode != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "validator.code", Value: e.result.validatorCode})
	}
	if e.result.runtimeErrorCode != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "runtime_error.code", Value: e.result.runtimeErrorCode})
	}
	if e.result.unsupportedQueryCode != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "unsupported_query.code", Value: e.result.unsupportedQueryCode})
	}
	if e.failureStage != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "failure_stage", Value: e.failureStage})
	}
	if e.llmInitErrorKind != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "llm.init_error_kind", Value: e.llmInitErrorKind})
	}
	if err != nil {
		attrs = attrs.WithField(telemetry.Field{Key: "error_kind", Value: grcTelemetryErrorKind(err)})
	}
	if r != nil {
		attrs = attrs.WithField(telemetry.Field{Key: "http.method", Value: r.Method})
		attrs = attrs.WithField(telemetry.Field{Key: "http.route", Value: "POST /grc/ask"})
		if ua := r.Header.Get("User-Agent"); ua != "" {
			if len(ua) > 128 {
				ua = ua[:128]
			}
			attrs = attrs.WithField(telemetry.Field{Key: "http.user_agent", Value: ua})
		}
	}
	telemetry.Event(r.Context(), "cerebro.grc.ask", attrs)
	telemetry.IncrementMain(r.Context(), "grc.ask.count", 1)
	if err != nil {
		telemetry.IncrementMain(r.Context(), "grc.ask.error.count", 1)
	}
	mainAttrs := telemetry.Attrs(
		telemetry.Field{Key: "grc.ask.status_code", Value: status},
		telemetry.Field{Key: "grc.ask.outcome", Value: outcome},
		telemetry.Field{Key: "grc.ask.duration_ms", Value: durationMs},
		telemetry.Field{Key: "tenant_id", Value: e.tenantID},
		telemetry.Field{Key: "grc.ask.question_len", Value: len(e.question)},
		telemetry.Field{Key: "grc.ask.scope.present", Value: strings.TrimSpace(e.scopeURN) != ""},
		telemetry.Field{Key: "grc.ask.model", Value: e.model},
		telemetry.Field{Key: "grc.ask.history_len", Value: e.historyLen},
		telemetry.Field{Key: "grc.ask.llm.provider", Value: e.provider},
		telemetry.Field{Key: "grc.ask.llm.ok", Value: e.llmOK},
		telemetry.Field{Key: "grc.ask.llm.pre_cached", Value: e.llmPreCached},
		telemetry.Field{Key: "grc.ask.llm.init_ms", Value: e.llmInitMs},
		telemetry.Field{Key: "grc.ask.graph_store.ok", Value: e.graphStoreOK},
		telemetry.Field{Key: "grc.ask.sse_events", Value: e.sseEvents},
		telemetry.Field{Key: "grc.ask.validator.ok", Value: e.result.validatorOK},
		telemetry.Field{Key: "grc.ask.validator.warnings_count", Value: e.result.validatorWarningsCount},
		telemetry.Field{Key: "grc.ask.cypher_refused", Value: e.result.cypherRefused},
		telemetry.Field{Key: "grc.ask.row_count", Value: e.result.rowCount},
		telemetry.Field{Key: "grc.ask.citation_count", Value: e.result.citationCount},
		telemetry.Field{Key: "grc.ask.citation_validation.warnings_count", Value: e.result.citationWarningsCount},
		telemetry.Field{Key: "grc.ask.graph_probe.entity_type_count", Value: e.probe.entityTypeCount},
		telemetry.Field{Key: "grc.ask.graph_probe.relation_count", Value: e.probe.relationCount},
		telemetry.Field{Key: "grc.ask.graph_probe.warnings_count", Value: e.probe.warningsCount},
		telemetry.Field{Key: "grc.ask.graph_probe.scope_found", Value: e.probe.scopeFound},
		telemetry.Field{Key: "grc.ask.stage.probe_ms", Value: e.result.timings.ProbeMS},
		telemetry.Field{Key: "grc.ask.stage.draft_ms", Value: e.result.timings.DraftMS},
		telemetry.Field{Key: "grc.ask.stage.conversion_ms", Value: e.result.timings.ConversionMS},
		telemetry.Field{Key: "grc.ask.stage.validate_ms", Value: e.result.timings.ValidateMS},
		telemetry.Field{Key: "grc.ask.stage.execute_ms", Value: e.result.timings.ExecuteMS},
		telemetry.Field{Key: "grc.ask.stage.summarize_ms", Value: e.result.timings.SummarizeMS},
		telemetry.Field{Key: "grc.ask.stage.citation_validation_ms", Value: e.result.timings.CitationValidationMS},
	)
	if e.queryPlan.intent != "" {
		mainAttrs = mainAttrs.
			WithField(telemetry.Field{Key: "grc.ask.query_plan.intent", Value: e.queryPlan.intent}).
			WithField(telemetry.Field{Key: "grc.ask.query_plan.source", Value: e.queryPlan.source}).
			WithField(telemetry.Field{Key: "grc.ask.query_plan.deterministic", Value: e.queryPlan.deterministic}).
			WithField(telemetry.Field{Key: "grc.ask.query_plan.corrected", Value: e.queryPlan.corrected}).
			WithField(telemetry.Field{Key: "grc.ask.query_plan.diagnostics_count", Value: e.queryPlan.diagnosticsCount})
	}
	if e.queryPlan.diagnosticCodes != "" {
		mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "grc.ask.query_plan.diagnostic_codes", Value: e.queryPlan.diagnosticCodes})
	}
	if e.result.terminalEvent != "" {
		mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "grc.ask.terminal_event", Value: e.result.terminalEvent})
	}
	if e.result.validatorCode != "" {
		mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "grc.ask.validator.code", Value: e.result.validatorCode})
	}
	if e.result.runtimeErrorCode != "" {
		mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "grc.ask.runtime_error.code", Value: e.result.runtimeErrorCode})
	}
	if e.result.unsupportedQueryCode != "" {
		mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "grc.ask.unsupported_query.code", Value: e.result.unsupportedQueryCode})
	}
	if e.failureStage != "" {
		mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "grc.ask.failure_stage", Value: e.failureStage})
	}
	if e.llmInitErrorKind != "" {
		mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "grc.ask.llm.init_error_kind", Value: e.llmInitErrorKind})
	}
	if err != nil {
		mainAttrs = mainAttrs.WithField(telemetry.Field{Key: "grc.ask.error_kind", Value: grcTelemetryErrorKind(err)})
	}
	telemetry.AnnotateMain(r.Context(), mainAttrs)

	if err != nil {
		providerDesc := strings.TrimSpace(e.provider)
		if providerDesc == "" {
			providerDesc = "bedrock(default)"
		}
		log.Printf("grc ask failed stage=%s provider=%s graph_store_ok=%v llm_ok=%v error=%q",
			e.failureStage, providerDesc, e.graphStoreOK, e.llmOK, err)
	}
}

func clearLongRunningWriteDeadline(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
}

func askDiagnosticCodes(diagnostics []graphagent.ConversionDiagnostic) string {
	var codes []string
	for _, diagnostic := range diagnostics {
		code := strings.TrimSpace(diagnostic.Code)
		if code != "" {
			codes = append(codes, code)
		}
	}
	return strings.Join(codes, ",")
}
