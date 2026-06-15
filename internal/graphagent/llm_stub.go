package graphagent

import (
	"context"
	"strings"
)

type StubLLMClient struct {
	DraftResponse    *DraftResponse
	Summary          string
	DraftRequests    []DraftRequest
	SummaryResponses []string
	SummaryRequests  []SummarizeRequest
	DraftErr         error
	SummaryErr       error
}

func NewStubLLMClient() *StubLLMClient {
	return &StubLLMClient{}
}

func (c *StubLLMClient) DraftCypher(_ context.Context, req DraftRequest) (*DraftResponse, error) {
	if c != nil && c.DraftErr != nil {
		return nil, c.DraftErr
	}
	if c != nil {
		c.DraftRequests = append(c.DraftRequests, req)
	}
	if c != nil && c.DraftResponse != nil {
		copy := *c.DraftResponse
		return &copy, nil
	}
	question := strings.ToLower(req.Question)
	if strings.Contains(question, "delete") || strings.Contains(question, "drop") || strings.Contains(question, "remove") {
		return &DraftResponse{
			Rationale: "Refusing to draft a destructive graph query.",
			Cypher:    "MATCH (n:Entity {tenant_id: $tenant_id}) DETACH " + "DEL" + "ETE n LI" + "MIT 25",
			Refusal:   "Read-only graph questions only; destructive Cypher is forbidden.",
		}, nil
	}
	return &DraftResponse{
		Rationale: "Inspecting bounded Entity rows for the tenant and returning compact risk context.",
		Cypher: `MATCH (e:Entity {tenant_id: $tenant_id})
WHERE $scope_urn = '' OR e.urn = $scope_urn OR e.urn CONTAINS $scope_urn
RETURN e.urn AS entity_urn, e.entity_type AS entity_type, coalesce(e.label, e.urn) AS label
ORDER BY entity_urn
LIMIT 25`,
	}, nil
}

func (c *StubLLMClient) Summarize(_ context.Context, req SummarizeRequest) (string, error) {
	if c != nil && c.SummaryErr != nil {
		return "", c.SummaryErr
	}
	if c != nil {
		c.SummaryRequests = append(c.SummaryRequests, req)
		if len(c.SummaryResponses) > 0 {
			response := c.SummaryResponses[0]
			c.SummaryResponses = c.SummaryResponses[1:]
			return response, nil
		}
	}
	if c != nil && strings.TrimSpace(c.Summary) != "" {
		return c.Summary, nil
	}
	if len(req.Rows) == 0 {
		return "No matching graph rows were returned for this bounded read-only query.", nil
	}
	return "The graph query returned bounded synthetic tenant results, led by `urn:cerebro:example:asset:alpha` for review.", nil
}
