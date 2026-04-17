package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/nlq"
)

type cerebroNaturalLanguageQueryRequest struct {
	Question    string       `json:"question"`
	PreviewOnly bool         `json:"preview_only"`
	Context     *nlq.Context `json:"context,omitempty"`
}

func (a *Runtime) toolCerebroNaturalLanguageQuery(ctx context.Context, args json.RawMessage) (string, error) {
	var req cerebroNaturalLanguageQueryRequest
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}
	req.Question = strings.TrimSpace(req.Question)
	if req.Question == "" {
		return "", fmt.Errorf("question is required")
	}

	g, err := a.requireReadableSecurityGraph()
	if err != nil {
		return "", err
	}

	translator := nlq.NewTranslator(nlq.DefaultSchemaContext(), a.nlqCompletionProvider())
	plan, err := translator.Translate(ctx, nlq.TranslateRequest{
		Question: req.Question,
		Context:  req.Context,
	})
	if err != nil {
		return "", err
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
			Findings: a.findings(),
			Diffs:    a.graphSnapshots(),
		}
		result, err := executor.Execute(ctx, plan)
		if err != nil {
			return "", err
		}
		response["summary"] = result.Summary
		response["result"] = result.Result
	}

	return marshalToolResponse(response)
}

func (a *Runtime) nlqCompletionProvider() nlq.CompletionProvider {
	if a == nil || a.agents() == nil {
		return nil
	}
	candidates := a.agents().ListAgents()
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
		return agentNLQProvider{provider: candidate.Provider}
	}
	return nil
}

type agentNLQProvider struct {
	provider agents.LLMProvider
}

func (p agentNLQProvider) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
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
