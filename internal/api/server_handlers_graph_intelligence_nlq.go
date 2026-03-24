package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/nlq"
)

type platformNaturalLanguageQueryRequest struct {
	Question    string         `json:"question"`
	PreviewOnly bool           `json:"preview_only"`
	Context     map[string]any `json:"context,omitempty"`
}

func (s *Server) graphIntelligenceNaturalLanguageQueries(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	var req platformNaturalLanguageQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Question = strings.TrimSpace(req.Question)
	if req.Question == "" {
		s.error(w, http.StatusBadRequest, "question is required")
		return
	}

	var nlqContext *nlq.Context
	if req.Context != nil {
		raw, err := json.Marshal(req.Context)
		if err != nil {
			s.error(w, http.StatusBadRequest, "context must be a valid JSON object")
			return
		}
		var decoded nlq.Context
		if err := json.Unmarshal(raw, &decoded); err != nil {
			s.error(w, http.StatusBadRequest, "context must match the nl query follow-up context shape")
			return
		}
		nlqContext = &decoded
	}

	translator := nlq.NewTranslator(nlq.DefaultSchemaContext(), s.nlqCompletionProvider())
	plan, err := translator.Translate(r.Context(), nlq.TranslateRequest{
		Question: req.Question,
		Context:  nlqContext,
	})
	if err != nil {
		switch {
		case errors.Is(err, nlq.ErrMutationNotAllowed):
			s.error(w, http.StatusBadRequest, err.Error())
		default:
			s.error(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	response := map[string]any{
		"question":        req.Question,
		"plan":            plan,
		"generated_query": plan.GeneratedQuery,
		"read_only":       plan.ReadOnly,
		"preview_only":    req.PreviewOnly,
	}

	if !req.PreviewOnly {
		executor := &nlq.Executor{
			Graph:    g,
			Findings: s.findingsCompliance.FindingsStore(r.Context()),
			Diffs:    s.app.GraphSnapshots,
		}
		result, err := executor.Execute(r.Context(), plan)
		if err != nil {
			switch {
			case strings.Contains(err.Error(), "not initialized"):
				s.error(w, http.StatusServiceUnavailable, err.Error())
			default:
				s.error(w, http.StatusInternalServerError, err.Error())
			}
			return
		}
		response["summary"] = result.Summary
		response["result"] = result.Result
	}

	s.json(w, http.StatusOK, response)
}

func (s *Server) nlqCompletionProvider() nlq.CompletionProvider {
	if s == nil || s.app == nil || s.app.Agents == nil {
		return nil
	}
	candidates := s.app.Agents.ListAgents()
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i] == nil || candidates[j] == nil {
			return candidates[j] != nil
		}
		return candidates[i].ID < candidates[j].ID
	})
	for _, candidate := range candidates {
		if candidate == nil || candidate.Provider == nil {
			continue
		}
		return serverAgentNLQProvider{provider: candidate.Provider}
	}
	return nil
}

type serverAgentNLQProvider struct {
	provider agents.LLMProvider
}

func (p serverAgentNLQProvider) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	if p.provider == nil {
		return "", fmt.Errorf("llm provider not configured")
	}
	resp, err := p.provider.Complete(ctx, []agents.Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userPrompt},
	}, nil)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(resp.Message.Content), nil
}
