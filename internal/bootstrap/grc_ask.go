package bootstrap

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/writer/cerebro/internal/graphagent"
	"github.com/writer/cerebro/internal/graphquery"
)

const maxGRCAskBodyBytes = 128 << 10

func (a *App) handleGRCAsk(w http.ResponseWriter, r *http.Request) {
	var request graphagent.AskRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGRCAskBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeGRCError(w, errors.Join(errInvalidHTTPRequest, err))
		return
	}
	if err := authorizeTenantID(r.Context(), request.TenantID); err != nil {
		writeGRCError(w, err)
		return
	}
	if request.ScopeURN != "" {
		if err := authorizeCerebroURNTenant(r.Context(), request.ScopeURN); err != nil {
			writeGRCError(w, err)
			return
		}
	}
	if err := graphagent.ValidateRequest(request); err != nil {
		writeGRCError(w, err)
		return
	}
	graphStore := graphQueryStore(a.deps.GraphStore)
	if graphStore == nil {
		writeGRCError(w, graphquery.ErrRuntimeUnavailable)
		return
	}
	llm := a.deps.GraphAgentLLM
	if llm == nil {
		var err error
		llm, err = graphagent.NewLLMClient(r.Context(), graphagent.LLMConfig{
			Provider:    a.cfg.GraphAgentLLM.Provider,
			Model:       a.cfg.GraphAgentLLM.Model,
			SonnetModel: a.cfg.GraphAgentLLM.SonnetModel,
			OpusModel:   a.cfg.GraphAgentLLM.OpusModel,
			HaikuModel:  a.cfg.GraphAgentLLM.HaikuModel,
			MaxTokens:   a.cfg.GraphAgentLLM.MaxTokens,
			Temperature: a.cfg.GraphAgentLLM.Temperature,
		})
		if err != nil {
			writeGRCError(w, err)
			return
		}
	}

	flusher, _ := w.(http.Flusher)
	service := graphagent.NewService(graphStore, llm, graphagent.ValidatorOptions{Explain: true})
	streamStarted := false
	if err := service.Stream(r.Context(), request, func(event graphagent.Event) error {
		if !streamStarted {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache, no-transform")
			w.Header().Set("Connection", "keep-alive")
			w.WriteHeader(http.StatusOK)
			streamStarted = true
		}
		if err := graphagent.WriteSSEEvent(w, event); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}); err != nil && !streamStarted {
		writeGRCError(w, err)
	}
}
