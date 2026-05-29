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

func (a *App) handleGRCAsk(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	evt := askWideEvent{provider: a.cfg.GraphAgentLLM.Provider}

	var request graphagent.AskRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGRCAskBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		evt.finish(r, w, started, http.StatusBadRequest, err)
		writeGRCError(w, errors.Join(errInvalidHTTPRequest, err))
		return
	}
	evt.tenantID = request.TenantID
	evt.question = request.Question
	evt.scopeURN = request.ScopeURN
	evt.model = request.Model
	evt.historyLen = len(request.History)

	if err := authorizeTenantID(r.Context(), request.TenantID); err != nil {
		evt.finish(r, w, started, http.StatusForbidden, err)
		writeGRCError(w, err)
		return
	}
	if request.ScopeURN != "" {
		if err := authorizeCerebroURNTenant(r.Context(), request.ScopeURN); err != nil {
			evt.finish(r, w, started, http.StatusForbidden, err)
			writeGRCError(w, err)
			return
		}
	}
	if err := graphagent.ValidateRequest(request); err != nil {
		evt.finish(r, w, started, http.StatusBadRequest, err)
		writeGRCError(w, err)
		return
	}
	graphStore := graphQueryStore(a.deps.GraphStore)
	if graphStore == nil {
		evt.failureStage = "graph_store_nil"
		evt.finish(r, w, started, http.StatusServiceUnavailable, graphquery.ErrRuntimeUnavailable)
		writeGRCError(w, graphquery.ErrRuntimeUnavailable)
		return
	}
	evt.graphStoreOK = true

	llm := a.deps.GraphAgentLLM
	if llm == nil {
		llmStarted := time.Now()
		var err error
		llm, err = graphagent.NewLLMClientWithSecrets(r.Context(), graphagent.LLMConfigWithSecrets{
			LLMConfig: graphagent.LLMConfig{
				Provider:    a.cfg.GraphAgentLLM.Provider,
				Model:       a.cfg.GraphAgentLLM.Model,
				SonnetModel: a.cfg.GraphAgentLLM.SonnetModel,
				OpusModel:   a.cfg.GraphAgentLLM.OpusModel,
				HaikuModel:  a.cfg.GraphAgentLLM.HaikuModel,
				MaxTokens:   a.cfg.GraphAgentLLM.MaxTokens,
				Temperature: a.cfg.GraphAgentLLM.Temperature,
			},
			OpenRouterAPIKey: a.cfg.GraphAgentLLM.OpenRouterAPIKey,
			HTTPDoer:         NewHTTPDoer(),
		})
		evt.llmInitMs = time.Since(llmStarted).Milliseconds()
		if err != nil {
			evt.failureStage = "llm_init"
			evt.llmInitError = err.Error()
			evt.finish(r, w, started, http.StatusServiceUnavailable, err)
			writeGRCError(w, err)
			return
		}
	} else {
		evt.llmPreCached = true
	}
	evt.llmOK = true

	flusher, _ := w.(http.Flusher)
	service := graphagent.NewService(graphStore, llm, graphagent.ValidatorOptions{Explain: true})
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
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	})
	if err != nil && !streamStarted {
		evt.failureStage = "stream"
		evt.finish(r, w, started, http.StatusServiceUnavailable, err)
		writeGRCError(w, err)
		return
	}
	if err != nil {
		evt.failureStage = "stream"
		writeErr := graphagent.WriteSSEEvent(w, graphagent.Event{Name: graphagent.EventError, Data: graphagent.ErrorEvent{
			Code:    "ask_failed",
			Message: err.Error(),
		}})
		if writeErr == nil {
			eventCount++
			if flusher != nil {
				flusher.Flush()
			}
		} else {
			log.Printf("write grc ask SSE error event: %v", writeErr)
		}
		evt.sseEvents = eventCount
		evt.finish(r, w, started, http.StatusOK, err)
		return
	}
	evt.sseEvents = eventCount
	evt.finish(r, w, started, http.StatusOK, nil)
}

type askWideEvent struct {
	tenantID     string
	question     string
	scopeURN     string
	model        string
	historyLen   int
	provider     string
	graphStoreOK bool
	llmOK        bool
	llmPreCached bool
	llmInitMs    int64
	llmInitError string
	failureStage string
	sseEvents    int
}

func (e *askWideEvent) finish(r *http.Request, w http.ResponseWriter, started time.Time, status int, err error) {
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
	if e.failureStage != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "failure_stage", Value: e.failureStage})
	}
	if e.llmInitError != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "llm.init_error", Value: e.llmInitError})
	}
	if err != nil {
		errMsg := err.Error()
		if len(errMsg) > 256 {
			errMsg = errMsg[:256]
		}
		attrs = attrs.WithField(telemetry.Field{Key: "error", Value: errMsg})
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

	if err != nil {
		providerDesc := strings.TrimSpace(e.provider)
		if providerDesc == "" {
			providerDesc = "bedrock(default)"
		}
		log.Printf("grc ask failed stage=%s provider=%s graph_store_ok=%v llm_ok=%v error=%q",
			e.failureStage, providerDesc, e.graphStoreOK, e.llmOK, err)
	}
}
